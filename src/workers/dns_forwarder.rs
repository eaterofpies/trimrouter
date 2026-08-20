use crate::managers::ipc::{recv_msg, DnsParentToWorkerMsg};
use crate::managers::utils::{
    drop_privileges, wait_shutdown, DNS_FORWARDER_GID, DNS_FORWARDER_UID,
};
use log::{error, info, warn};
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::unix::OwnedReadHalf;
use tokio::net::{UdpSocket, UnixStream};
use tokio::sync::watch::{channel, Receiver, Sender};

// =========================================================================
// DNS Constants & Config
// =========================================================================
const DNS_PORT: u16 = 53;
const DNS_HEADER_SIZE: usize = 12;

const DEFAULT_TTL_SECS: u32 = 30;
const MAX_TTL_SECS: u32 = 3600;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const RECV_BUF_SIZE: usize = 4096;

const FALLBACK_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_PENDING_QUERIES: usize = 4096;

// =========================================================================
// Cache Structure
// =========================================================================
#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expiry: Instant,
}

struct PendingQuery {
    tx: tokio::sync::oneshot::Sender<Vec<u8>>,
    upstream_ip: Ipv4Addr,
}

type SharedCache = Arc<Mutex<HashMap<Vec<u8>, CacheEntry>>>;
type PendingQueries = Arc<Mutex<HashMap<u16, PendingQuery>>>;

pub async fn run_dns_forwarder_worker(
    ipc_fd: RawFd,
    dns_socket_fd: RawFd,
    upstream_socket_fd: RawFd,
) -> Result<(), IoError> {
    info!("[dns-forwarder-worker] Starting unprivileged DNS forwarder worker...");

    // Convert raw FDs
    let std_dns_socket = unsafe { StdUdpSocket::from_raw_fd(dns_socket_fd) };
    let std_upstream_socket = unsafe { StdUdpSocket::from_raw_fd(upstream_socket_fd) };

    std_dns_socket.set_nonblocking(true)?;
    std_upstream_socket.set_nonblocking(true)?;

    let dns_socket = UdpSocket::from_std(std_dns_socket)?;
    let upstream_socket = UdpSocket::from_std(std_upstream_socket)?;

    let std_ipc = unsafe { StdUnixStream::from_raw_fd(ipc_fd) };
    std_ipc.set_nonblocking(true)?;
    let ipc_stream = UnixStream::from_std(std_ipc)?;
    let (ipc_reader, _ipc_writer) = ipc_stream.into_split();

    // Drop privileges
    drop_privileges(DNS_FORWARDER_UID, DNS_FORWARDER_GID)
        .map_err(|e| IoError::new(ErrorKind::PermissionDenied, e))?;
    info!(
        "[dns-forwarder-worker] Privileges dropped successfully (running as dns-forwarder inside chroot jail)."
    );

    let dns_socket = Arc::new(dns_socket);
    let upstream_socket = Arc::new(upstream_socket);

    let cache: SharedCache = Arc::new(Mutex::new(HashMap::new()));
    let pending_queries: PendingQueries = Arc::new(Mutex::new(HashMap::new()));
    let upstream_dns = Arc::new(Mutex::new(Vec::<Ipv4Addr>::new()));

    let (shutdown_tx, shutdown_rx) = channel(false);

    // Spawn IPC monitor task to receive upstream DNS servers dynamically
    tokio::spawn(run_dns_ipc_monitor(
        ipc_reader,
        upstream_dns.clone(),
        shutdown_tx.clone(),
    ));

    // Spawn the background receiver task for upstream replies.
    let upstream_task = tokio::spawn(run_upstream_receiver(
        upstream_socket.clone(),
        pending_queries.clone(),
        shutdown_rx.clone(),
    ));

    // Spawn periodic cleanup task to prune expired cache entries
    let cleanup_task = tokio::spawn(run_cache_cleanup(cache.clone(), shutdown_rx.clone()));

    // Run the main query forwarder loop
    run_query_loop(
        dns_socket,
        upstream_socket,
        cache,
        pending_queries,
        upstream_dns,
        shutdown_rx,
    )
    .await;

    let _ = upstream_task.await;
    let _ = cleanup_task.await;
    Ok(())
}

async fn run_dns_ipc_monitor(
    mut reader: OwnedReadHalf,
    upstream_dns: Arc<Mutex<Vec<Ipv4Addr>>>,
    shutdown_tx: Sender<bool>,
) {
    loop {
        match recv_msg::<DnsParentToWorkerMsg, _>(&mut reader).await {
            Ok(Some(DnsParentToWorkerMsg::SetUpstreamResolvers { servers })) => {
                let mut lock = upstream_dns.lock().unwrap();
                *lock = servers;
            }
            Ok(None) => {
                info!("[dns-forwarder-worker] Parent closed IPC. Shutting down.");
                let _ = shutdown_tx.send(true);
                break;
            }
            Err(e) => {
                error!(
                    "[dns-forwarder-worker] IPC read error: {}. Shutting down.",
                    e
                );
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }
}

fn dispatch_pending_query(
    pending: PendingQuery,
    from_addr: SocketAddr,
    resp_buf: &[u8],
    len: usize,
    xid: u16,
) {
    if from_addr.ip() == IpAddr::V4(pending.upstream_ip) {
        let _ = pending.tx.send(resp_buf[..len].to_vec());
    } else {
        warn!(
            "[dns-forwarder] WARNING: Received DNS spoof attempt! IP {} mismatch for xid {}",
            from_addr.ip(),
            xid
        );
    }
}

async fn run_upstream_receiver(
    upstream_socket: Arc<tokio::net::UdpSocket>,
    pending_queries: PendingQueries,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut resp_buf = [0u8; RECV_BUF_SIZE];
    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let recv_fut = upstream_socket.recv_from(&mut resp_buf);
        let res = tokio::select! {
            _ = wait_shutdown(&mut shutdown_rx) => {
                break;
            }
            r = recv_fut => r,
        };

        let (len, from_addr) = match res {
            Ok(res) => res,
            Err(e) => {
                handle_upstream_error(e, &mut shutdown_rx).await;
                continue;
            }
        };

        if len < DNS_HEADER_SIZE {
            continue;
        }
        let xid = u16::from_be_bytes([resp_buf[0], resp_buf[1]]);

        let pending = {
            let mut lock = pending_queries.lock().unwrap();
            lock.remove(&xid)
        };

        if let Some(p) = pending {
            dispatch_pending_query(p, from_addr, &resp_buf, len, xid);
        }
    }
}

async fn handle_upstream_error(
    e: IoError,
    shutdown_rx: &mut Receiver<bool>,
) {
    error!("[dns-forwarder] Upstream socket read error: {}", e);
    tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {}
        _ = tokio::time::sleep(Duration::from_millis(100)) => {}
    }
}

async fn run_cache_cleanup(
    cache: SharedCache,
    mut shutdown_rx: Receiver<bool>,
) {
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        tokio::select! {
            _ = wait_shutdown(&mut shutdown_rx) => {
                break;
            }
            _ = tokio::time::sleep(CLEANUP_INTERVAL) => {
                let mut lock = cache.lock().unwrap();
                let now = Instant::now();
                lock.retain(|_, entry| entry.expiry > now);
            }
        }
    }
}

async fn process_next_query(
    socket: &Arc<UdpSocket>,
    upstream_socket: &Arc<UdpSocket>,
    cache: &SharedCache,
    pending_queries: &PendingQueries,
    upstream_dns: &Arc<Mutex<Vec<Ipv4Addr>>>,
    shutdown_rx: &mut Receiver<bool>,
    buf: &mut [u8],
) -> bool {
    let recv_fut = socket.recv_from(buf);
    let res = tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {
            return false;
        }
        r = recv_fut => r,
    };

    let (len, src) = match res {
        Ok(res) => res,
        Err(e) => {
            handle_query_loop_error(e, shutdown_rx).await;
            return true;
        }
    };

    let query = buf[..len].to_vec();
    let socket_clone = socket.clone();
    let cache_clone = cache.clone();
    let upstream_dns_clone = upstream_dns.clone();
    let upstream_sock_clone = upstream_socket.clone();
    let pending_queries_clone = pending_queries.clone();

    tokio::spawn(async move {
        handle_dns_query(
            query,
            src,
            socket_clone,
            cache_clone,
            upstream_dns_clone,
            upstream_sock_clone,
            pending_queries_clone,
        )
        .await;
    });
    true
}

async fn run_query_loop(
    socket: Arc<UdpSocket>,
    upstream_socket: Arc<UdpSocket>,
    cache: SharedCache,
    pending_queries: PendingQueries,
    upstream_dns: Arc<Mutex<Vec<Ipv4Addr>>>,
    mut shutdown_rx: Receiver<bool>,
) {
    let mut buf = [0u8; RECV_BUF_SIZE];
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        let proceed = process_next_query(
            &socket,
            &upstream_socket,
            &cache,
            &pending_queries,
            &upstream_dns,
            &mut shutdown_rx,
            &mut buf,
        )
        .await;
        if !proceed {
            break;
        }
    }
}

async fn handle_query_loop_error(
    e: IoError,
    shutdown_rx: &mut Receiver<bool>,
) {
    warn!(
        "[dns-forwarder] Socket receive error: {}. Retrying in 1s...",
        e
    );
    tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {}
        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
    }
}

async fn handle_dns_query(
    query: Vec<u8>,
    src: std::net::SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
    cache: SharedCache,
    upstream_dns: Arc<Mutex<Vec<Ipv4Addr>>>,
    upstream_socket: Arc<tokio::net::UdpSocket>,
    pending_queries: PendingQueries,
) {
    if query.len() < DNS_HEADER_SIZE {
        return;
    }

    let cache_key = match get_cache_key(&query) {
        Some(key) => key,
        None => return,
    };

    if let Some(mut response) = lookup_cache(&cache_key, &cache) {
        response[0] = query[0];
        response[1] = query[1];
        let _ = socket.send_to(&response, src).await;
        return;
    }

    let upstream_ip = get_upstream_dns(&upstream_dns);

    if let Some(response) =
        forward_query(&query, upstream_ip, &upstream_socket, &pending_queries).await
    {
        insert_cache(cache_key, response.clone(), &cache);
        let _ = socket.send_to(&response, src).await;
    }
}

fn get_cache_key(query_bytes: &[u8]) -> Option<Vec<u8>> {
    let packet = dns_parser::Packet::parse(query_bytes).ok()?;
    if packet.questions.is_empty() {
        return None;
    }
    let q = &packet.questions[0];
    let key = format!("{}:{:?}:{:?}", q.qname, q.qtype, q.qclass);
    Some(key.into_bytes())
}

fn lookup_cache(cache_key: &[u8], cache: &Mutex<HashMap<Vec<u8>, CacheEntry>>) -> Option<Vec<u8>> {
    let mut lock = cache.lock().unwrap();
    match lock.get(cache_key) {
        Some(entry) if entry.expiry > Instant::now() => Some(entry.response.clone()),
        Some(_) => {
            lock.remove(cache_key);
            None
        }
        None => None,
    }
}

fn insert_cache(
    cache_key: Vec<u8>,
    response: Vec<u8>,
    cache: &Mutex<HashMap<Vec<u8>, CacheEntry>>,
) {
    if response.len() < DNS_HEADER_SIZE {
        return;
    }
    let packet = match dns_parser::Packet::parse(&response) {
        Ok(p) => p,
        Err(_) => return,
    };
    let ttl = packet
        .answers
        .iter()
        .map(|ans| ans.ttl)
        .min()
        .unwrap_or(DEFAULT_TTL_SECS);
    if ttl == 0 {
        return;
    }
    let cache_ttl = std::cmp::min(MAX_TTL_SECS, ttl);
    let expiry = Instant::now() + Duration::from_secs(cache_ttl as u64);

    let mut lock = cache.lock().unwrap();
    lock.insert(cache_key, CacheEntry { response, expiry });
}

fn get_upstream_dns(upstream_dns: &Mutex<Vec<Ipv4Addr>>) -> Ipv4Addr {
    let servers = upstream_dns.lock().unwrap();
    if !servers.is_empty() {
        servers[0]
    } else {
        FALLBACK_DNS_SERVER
    }
}

// Forward query to the upstream DNS resolver using the shared socket.
// To support concurrent requests over a single socket, we:
// 1. Save the client's original transaction ID (xid).
// 2. Generate a new, unique transaction ID and write it to the DNS query header.
// 3. Register a oneshot channel mapping our unique transaction ID to the waiting task.
// 4. Send the modified query upstream.
// 5. Wait for the background loop to receive and dispatch the response payload, then restore
//    the client's original transaction ID before returning.
async fn forward_query(
    query: &[u8],
    upstream_dns: Ipv4Addr,
    upstream_socket: &tokio::net::UdpSocket,
    pending_queries: &PendingQueries,
) -> Option<Vec<u8>> {
    if query.len() < DNS_HEADER_SIZE {
        return None;
    }
    let client_xid = u16::from_be_bytes([query[0], query[1]]);

    // Generate a unique transaction ID that doesn't conflict with any active query.
    // Limit maximum pending queries to prevent infinite search loops under high load.
    let mut rng_xid = rand::random::<u16>();
    let (tx, rx) = tokio::sync::oneshot::channel();
    {
        let mut lock = pending_queries.lock().unwrap();
        if lock.len() >= MAX_PENDING_QUERIES {
            return None;
        }
        while lock.contains_key(&rng_xid) {
            rng_xid = rand::random::<u16>();
        }
        lock.insert(
            rng_xid,
            PendingQuery {
                tx,
                upstream_ip: upstream_dns,
            },
        );
    }

    let mut forwarded_query = query.to_vec();
    let xid_bytes = rng_xid.to_be_bytes();
    forwarded_query[0] = xid_bytes[0];
    forwarded_query[1] = xid_bytes[1];

    let upstream_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(upstream_dns), DNS_PORT);
    if upstream_socket
        .send_to(&forwarded_query, upstream_addr)
        .await
        .is_err()
    {
        pending_queries.lock().unwrap().remove(&rng_xid);
        return None;
    }

    let rx_res = tokio::time::timeout(UPSTREAM_TIMEOUT, rx).await;
    let mut response = match rx_res {
        Ok(Ok(resp)) => resp,
        _ => {
            // Clean up registry entry if timeout/error occurs to prevent memory leaks
            pending_queries.lock().unwrap().remove(&rng_xid);
            return None;
        }
    };

    if response.len() >= DNS_HEADER_SIZE {
        let client_xid_bytes = client_xid.to_be_bytes();
        response[0] = client_xid_bytes[0];
        response[1] = client_xid_bytes[1];
        Some(response)
    } else {
        None
    }
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cache_key_valid() {
        // DNS header (12 bytes) + "google.com" question + Type A (2 bytes) + Class IN (2 bytes)
        let mut query = vec![0u8; DNS_HEADER_SIZE];
        query[5] = 1; // QDCount = 1
        query.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query.extend_from_slice(&[0, 1]); // Type A
        query.extend_from_slice(&[0, 1]); // Class IN

        let key = get_cache_key(&query);
        assert_eq!(key, Some("google.com:A:IN".to_string().into_bytes()));
    }

    #[test]
    fn test_get_cache_key_invalid() {
        let query = vec![0u8; 10]; // Too short
        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_insert_cache_ttl() {
        // Build a raw DNS response with answers having TTL 300 and 150
        let mut resp = vec![0u8; DNS_HEADER_SIZE];
        // Question: "google.com", Type A, Class IN
        resp.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        resp.extend_from_slice(&[0, 1]); // Type A
        resp.extend_from_slice(&[0, 1]); // Class IN

        // Modify header to specify 1 question and 2 answers
        resp[5] = 1; // QDCount = 1
        resp[7] = 2; // ANCount = 2

        // Answer 1: name compression pointer 0xc00c, Type A, Class IN, TTL 300, RDLength 4, IP 8.8.8.8
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0, 1]); // Type A
        resp.extend_from_slice(&[0, 1]); // Class IN
        resp.extend_from_slice(&[0, 0, 1, 0x2c]); // TTL = 300
        resp.extend_from_slice(&[0, 4]); // RDLength
        resp.extend_from_slice(&[8, 8, 8, 8]); // IP

        // Answer 2: name compression pointer 0xc00c, Type A, Class IN, TTL 150, RDLength 4, IP 8.8.4.4
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0, 1]); // Type A
        resp.extend_from_slice(&[0, 1]); // Class IN
        resp.extend_from_slice(&[0, 0, 0, 0x96]); // TTL = 150
        resp.extend_from_slice(&[0, 4]); // RDLength
        resp.extend_from_slice(&[8, 8, 4, 4]); // IP

        let cache = Mutex::new(HashMap::new());
        insert_cache(b"key".to_vec(), resp, &cache);

        let lock = cache.lock().unwrap();
        let entry = lock.get(&b"key".to_vec()[..]).unwrap();
        let cache_ttl = entry.expiry.duration_since(Instant::now()).as_secs();
        assert!((148..=150).contains(&cache_ttl));
    }
}
