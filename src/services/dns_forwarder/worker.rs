use crate::services::ipc::{DnsParentToWorkerMsg, recv_msg};
use crate::services::utils::{
    DNS_FORWARDER_GID, DNS_FORWARDER_UID, DNS_PORT, async_udp_socket, run_sandboxed_worker,
    wait_shutdown,
};
use log::{info, warn};
use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::OwnedFd;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::net::unix::OwnedReadHalf;
use tokio::sync::watch::Receiver;

// =========================================================================
// DNS Constants & Config
// =========================================================================
const DNS_HEADER_SIZE: usize = 12;
const DEFAULT_TTL_SECS: u32 = 30;
const MAX_TTL_SECS: u32 = 3600;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const RECV_BUF_SIZE: usize = 4096;
const FALLBACK_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_PENDING_QUERIES: usize = 4096;
const MAX_CACHE_ENTRIES: usize = 4096;

#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expiry: Instant,
}

struct PendingQuery {
    client_addr: SocketAddr,
    client_xid: u16,
    cache_key: Vec<u8>,
    query_payload: Vec<u8>,
    upstream_servers: Vec<Ipv4Addr>,
    current_server_idx: usize,
    deadline: Instant,
}

pub async fn run_dns_forwarder_worker(
    ipc_fd: OwnedFd,
    dns_socket_fd: OwnedFd,
    upstream_socket_fd: OwnedFd,
) -> Result<(), IoError> {
    let dns_socket = async_udp_socket(dns_socket_fd)?;
    let upstream_socket = async_udp_socket(upstream_socket_fd)?;

    run_sandboxed_worker(
        "dns-forwarder",
        DNS_FORWARDER_UID,
        DNS_FORWARDER_GID,
        ipc_fd,
        |ipc| async move {
            let _ipc_writer = ipc.writer;
            let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

            run_forwarder_loop(dns_socket, upstream_socket, ipc.reader, shutdown_rx).await;
            Ok(())
        },
    )
    .await
}

async fn run_forwarder_loop(
    dns_socket: UdpSocket,
    upstream_socket: UdpSocket,
    mut ipc_reader: OwnedReadHalf,
    mut shutdown_rx: Receiver<bool>,
) {
    let mut cache = HashMap::<Vec<u8>, CacheEntry>::new();
    let mut pending_queries = HashMap::<u16, PendingQuery>::new();
    let mut upstream_servers = Vec::<Ipv4Addr>::new();
    let mut client_buf = [0u8; RECV_BUF_SIZE];
    let mut upstream_buf = [0u8; RECV_BUF_SIZE];
    let mut cleanup_timer = tokio::time::interval(CLEANUP_INTERVAL);

    loop {
        tokio::select! {
            _ = wait_shutdown(&mut shutdown_rx) => break,
            _ = cleanup_timer.tick() => {
                evict_expired_cache(&mut cache);
                check_pending_timeouts(&mut pending_queries, &upstream_socket).await;
            }
            ipc_msg = recv_msg::<DnsParentToWorkerMsg, _>(&mut ipc_reader) => {
                match ipc_msg {
                    Ok(Some(DnsParentToWorkerMsg::SetUpstreamResolvers { servers })) => {
                        upstream_servers = servers;
                    }
                    Ok(None) | Err(_) => {
                        info!("[dns-forwarder-worker] Parent IPC closed. Shutting down.");
                        break;
                    }
                }
            }
            client_recv = dns_socket.recv_from(&mut client_buf) => {
                if let Ok((len, src)) = client_recv {
                    handle_client_query(
                        &client_buf[..len],
                        src,
                        &dns_socket,
                        &upstream_socket,
                        &mut cache,
                        &mut pending_queries,
                        &upstream_servers,
                    ).await;
                }
            }
            upstream_recv = upstream_socket.recv_from(&mut upstream_buf) => {
                if let Ok((len, from_addr)) = upstream_recv {
                    handle_upstream_reply(
                        &upstream_buf[..len],
                        from_addr,
                        &dns_socket,
                        &mut cache,
                        &mut pending_queries,
                    ).await;
                }
            }
        }
    }
}

async fn handle_client_query(
    query: &[u8],
    src: SocketAddr,
    dns_socket: &UdpSocket,
    upstream_socket: &UdpSocket,
    cache: &mut HashMap<Vec<u8>, CacheEntry>,
    pending: &mut HashMap<u16, PendingQuery>,
    configured_servers: &[Ipv4Addr],
) {
    if query.len() < DNS_HEADER_SIZE {
        return;
    }
    let Some(cache_key) = get_cache_key(query) else {
        return;
    };

    if let Some(mut response) = lookup_cache(&cache_key, cache) {
        response[0] = query[0];
        response[1] = query[1];
        let _ = dns_socket.send_to(&response, src).await;
        return;
    }

    forward_new_client_query(
        query,
        src,
        cache_key,
        upstream_socket,
        pending,
        configured_servers,
    )
    .await;
}

async fn forward_new_client_query(
    query: &[u8],
    src: SocketAddr,
    cache_key: Vec<u8>,
    upstream_socket: &UdpSocket,
    pending: &mut HashMap<u16, PendingQuery>,
    configured_servers: &[Ipv4Addr],
) {
    if pending.len() >= MAX_PENDING_QUERIES {
        return;
    }
    let Some(upstream_xid) = allocate_unique_xid(pending) else {
        return;
    };

    let client_xid = u16::from_be_bytes([query[0], query[1]]);
    let upstream_servers = get_upstream_resolvers(configured_servers);
    let target_server = upstream_servers[0];

    let mut forwarded = query.to_vec();
    let xid_bytes = upstream_xid.to_be_bytes();
    forwarded[0] = xid_bytes[0];
    forwarded[1] = xid_bytes[1];

    let dest = SocketAddr::new(IpAddr::V4(target_server), DNS_PORT);
    if upstream_socket.send_to(&forwarded, dest).await.is_ok() {
        pending.insert(
            upstream_xid,
            PendingQuery {
                client_addr: src,
                client_xid,
                cache_key,
                query_payload: query.to_vec(),
                upstream_servers,
                current_server_idx: 0,
                deadline: Instant::now() + UPSTREAM_TIMEOUT,
            },
        );
    }
}

async fn handle_upstream_reply(
    reply: &[u8],
    from_addr: SocketAddr,
    dns_socket: &UdpSocket,
    cache: &mut HashMap<Vec<u8>, CacheEntry>,
    pending: &mut HashMap<u16, PendingQuery>,
) {
    if reply.len() < DNS_HEADER_SIZE {
        return;
    }
    let upstream_xid = u16::from_be_bytes([reply[0], reply[1]]);
    let Some(query_meta) = pending.remove(&upstream_xid) else {
        return;
    };

    let expected_ip = query_meta.upstream_servers[query_meta.current_server_idx];
    if from_addr.ip() != IpAddr::V4(expected_ip) {
        warn!(
            "[dns-forwarder] WARNING: Received DNS spoof attempt! IP {} mismatch for xid {}",
            from_addr.ip(),
            upstream_xid
        );
        return;
    }

    insert_cache(query_meta.cache_key, reply.to_vec(), cache);

    let mut client_response = reply.to_vec();
    let client_xid_bytes = query_meta.client_xid.to_be_bytes();
    client_response[0] = client_xid_bytes[0];
    client_response[1] = client_xid_bytes[1];

    let _ = dns_socket
        .send_to(&client_response, query_meta.client_addr)
        .await;
}

async fn check_pending_timeouts(
    pending: &mut HashMap<u16, PendingQuery>,
    upstream_socket: &UdpSocket,
) {
    let now = Instant::now();
    let mut retry_list = Vec::new();

    pending.retain(|&xid, query| {
        if query.deadline > now {
            return true;
        }
        if query.current_server_idx + 1 < query.upstream_servers.len() {
            retry_list.push(xid);
            return true;
        }
        false
    });

    for xid in retry_list {
        if let Some(query) = pending.get_mut(&xid) {
            query.current_server_idx += 1;
            query.deadline = now + UPSTREAM_TIMEOUT;
            let target_server = query.upstream_servers[query.current_server_idx];

            let mut forwarded = query.query_payload.clone();
            let xid_bytes = xid.to_be_bytes();
            forwarded[0] = xid_bytes[0];
            forwarded[1] = xid_bytes[1];

            let dest = SocketAddr::new(IpAddr::V4(target_server), DNS_PORT);
            let _ = upstream_socket.send_to(&forwarded, dest).await;
        }
    }
}

fn evict_expired_cache(cache: &mut HashMap<Vec<u8>, CacheEntry>) {
    let now = Instant::now();
    cache.retain(|_, entry| entry.expiry > now);
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

fn lookup_cache(cache_key: &[u8], cache: &mut HashMap<Vec<u8>, CacheEntry>) -> Option<Vec<u8>> {
    match cache.get(cache_key) {
        Some(entry) if entry.expiry > Instant::now() => Some(entry.response.clone()),
        Some(_) => {
            cache.remove(cache_key);
            None
        }
        None => None,
    }
}

fn insert_cache(cache_key: Vec<u8>, response: Vec<u8>, cache: &mut HashMap<Vec<u8>, CacheEntry>) {
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

    if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(&cache_key) {
        evict_expired_cache(cache);
        if cache.len() >= MAX_CACHE_ENTRIES
            && let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expiry)
                .map(|(k, _)| k.clone())
        {
            cache.remove(&oldest_key);
        }
    }
    cache.insert(cache_key, CacheEntry { response, expiry });
}

fn get_upstream_resolvers(configured: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    if !configured.is_empty() {
        configured.to_vec()
    } else {
        vec![FALLBACK_DNS_SERVER]
    }
}

fn allocate_unique_xid(pending: &HashMap<u16, PendingQuery>) -> Option<u16> {
    if pending.len() >= MAX_PENDING_QUERIES {
        return None;
    }
    let mut rng_xid = rand::random::<u16>();
    while pending.contains_key(&rng_xid) {
        rng_xid = rand::random::<u16>();
    }
    Some(rng_xid)
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cache_key_valid() {
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
        let query = vec![0u8; 10];
        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_insert_cache_ttl() {
        let mut resp = vec![0u8; DNS_HEADER_SIZE];
        resp.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        resp.extend_from_slice(&[0, 1]); // Type A
        resp.extend_from_slice(&[0, 1]); // Class IN

        resp[5] = 1; // QDCount = 1
        resp[7] = 2; // ANCount = 2

        resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 8, 8, 8, 8]);
        resp.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0x96, 0, 4, 8, 8, 4, 4]);

        let mut cache = HashMap::new();
        insert_cache(b"key".to_vec(), resp, &mut cache);

        let entry = cache.get(&b"key".to_vec()[..]).unwrap();
        let cache_ttl = entry.expiry.duration_since(Instant::now()).as_secs();
        assert!((148..=150).contains(&cache_ttl));
    }

    #[test]
    fn test_get_upstream_resolvers_empty_fallback() {
        let resolvers = get_upstream_resolvers(&[]);
        assert_eq!(resolvers, vec![FALLBACK_DNS_SERVER]);
    }

    #[test]
    fn test_get_upstream_resolvers_configured() {
        let primary = Ipv4Addr::new(1, 1, 1, 1);
        let secondary = Ipv4Addr::new(1, 0, 0, 1);
        let resolvers = get_upstream_resolvers(&[primary, secondary]);
        assert_eq!(resolvers, vec![primary, secondary]);
    }
}
