use crate::services::DNS_FORWARDER_SERVICE_NAME;
use crate::services::ipc::{DnsParentToWorkerMsg, DnsWorkerToParentMsg, recv_msg, send_msg};
use crate::services::utils::{
    DNS_FORWARDER_GID, DNS_FORWARDER_UID, DNS_PORT, async_udp_socket, run_sandboxed_worker,
};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::serialize::binary::BinDecodable;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::OwnedFd;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

// =========================================================================
// DNS Constants & Config
// =========================================================================
const DNS_HEADER_SIZE: usize = 12;
const DEFAULT_TTL_SECS: u32 = 30;
const MAX_TTL_SECS: u32 = 3600; // 1 hour max cache duration
const DEFAULT_NEGATIVE_TTL_SECS: u32 = 60; // 1 minute default for NXDOMAIN/NODATA
const MIN_NEGATIVE_TTL_SECS: u32 = 5;
const MAX_NEGATIVE_TTL_SECS: u32 = 300; // 5 minutes max negative cache per RFC 2308
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
        DNS_FORWARDER_SERVICE_NAME,
        DNS_FORWARDER_UID,
        DNS_FORWARDER_GID,
        ipc_fd,
        |ipc| async move {
            run_forwarder_loop(dns_socket, upstream_socket, ipc.reader, ipc.writer).await;
            Ok(())
        },
    )
    .await
}

async fn run_forwarder_loop(
    dns_socket: UdpSocket,
    upstream_socket: UdpSocket,
    mut ipc_reader: OwnedReadHalf,
    mut ipc_writer: OwnedWriteHalf,
) {
    let mut cache = HashMap::<Vec<u8>, CacheEntry>::new();
    let mut pending_queries = HashMap::<u16, PendingQuery>::new();
    let mut upstream_servers = Vec::<Ipv4Addr>::new();
    let mut client_buf = [0u8; RECV_BUF_SIZE];
    let mut upstream_buf = [0u8; RECV_BUF_SIZE];
    let mut cleanup_timer = tokio::time::interval(CLEANUP_INTERVAL);

    loop {
        tokio::select! {
            _ = cleanup_timer.tick() => {
                if let Err(e) = send_msg(&mut ipc_writer, &DnsWorkerToParentMsg::Heartbeat).await {
                    debug!("[dns-forwarder-worker] Failed to send heartbeat to parent: {}", e);
                }
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
    let expected_addr = SocketAddr::new(IpAddr::V4(expected_ip), DNS_PORT);
    if from_addr != expected_addr {
        warn!(
            "[dns-forwarder] WARNING: Received DNS spoof attempt! Address {} mismatch for xid {} (expected {})",
            from_addr, upstream_xid, expected_addr
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
    let packet = Message::from_bytes(query_bytes).ok()?;
    let queries = &packet.queries;
    if queries.is_empty() || packet.op_code != OpCode::Query {
        return None;
    }
    let q = &queries[0];
    let key = format!(
        "{}:{:?}:{:?}",
        q.name().to_ascii().to_ascii_lowercase(),
        q.query_type(),
        q.query_class()
    );
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

fn calculate_cache_ttl(packet: &Message) -> Option<Duration> {
    if packet.truncation || packet.message_type != hickory_proto::op::MessageType::Response {
        return None;
    }
    match packet.response_code {
        hickory_proto::op::ResponseCode::NoError => {
            if !packet.answers.is_empty() {
                let raw_ttl = packet
                    .answers
                    .iter()
                    .map(|ans| ans.ttl)
                    .min()
                    .unwrap_or(DEFAULT_TTL_SECS);
                if raw_ttl == 0 {
                    return None;
                }
                let cache_ttl = std::cmp::min(MAX_TTL_SECS, raw_ttl);
                Some(Duration::from_secs(cache_ttl as u64))
            } else {
                Some(calculate_negative_ttl(packet))
            }
        }
        hickory_proto::op::ResponseCode::NXDomain => Some(calculate_negative_ttl(packet)),
        _ => None,
    }
}

fn calculate_negative_ttl(packet: &Message) -> Duration {
    for record in &packet.authorities {
        if let hickory_proto::rr::RData::SOA(soa) = &record.data {
            let soa_ttl = record.ttl;
            let minimum = soa.minimum;
            let effective_ttl = std::cmp::min(soa_ttl, minimum);
            let clamped = effective_ttl.clamp(MIN_NEGATIVE_TTL_SECS, MAX_NEGATIVE_TTL_SECS);
            return Duration::from_secs(clamped as u64);
        }
    }
    Duration::from_secs(DEFAULT_NEGATIVE_TTL_SECS as u64)
}

fn insert_cache(cache_key: Vec<u8>, response: Vec<u8>, cache: &mut HashMap<Vec<u8>, CacheEntry>) {
    if response.len() < DNS_HEADER_SIZE {
        return;
    }
    let packet = match Message::from_bytes(&response) {
        Ok(p) => p,
        Err(_) => return,
    };
    let Some(ttl_duration) = calculate_cache_ttl(&packet) else {
        return;
    };
    let expiry = Instant::now() + ttl_duration;

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

fn is_valid_upstream_resolver(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !ip.is_link_local()
        && !ip.is_documentation()
}

fn get_upstream_resolvers(configured: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let valid: Vec<Ipv4Addr> = configured
        .iter()
        .copied()
        .filter(|&ip| is_valid_upstream_resolver(ip))
        .collect();
    if !valid.is_empty() {
        valid
    } else {
        vec![FALLBACK_DNS_SERVER]
    }
}

fn allocate_unique_xid(pending: &HashMap<u16, PendingQuery>) -> Option<u16> {
    if pending.len() >= MAX_PENDING_QUERIES {
        return None;
    }
    let mut rng_xid = rand::random::<u16>();
    while rng_xid == 0 || pending.contains_key(&rng_xid) {
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
        assert_eq!(key, Some("google.com.:A:IN".to_string().into_bytes()));
    }

    #[test]
    fn test_get_cache_key_invalid() {
        let query = vec![0u8; 10];
        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_insert_cache_ttl() {
        let mut resp = vec![0u8; DNS_HEADER_SIZE];
        resp[2] = 0x81; // QR = 1, RD = 1
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

    #[test]
    fn test_get_cache_key_empty_bytes_returns_none() {
        assert_eq!(get_cache_key(&[]), None);
    }

    #[test]
    fn test_get_cache_key_zero_qdcount_returns_none() {
        let query = vec![0u8; DNS_HEADER_SIZE]; // QDCount is 0 by default
        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_get_cache_key_corrupted_label_length_returns_none() {
        let mut query = vec![0u8; DNS_HEADER_SIZE];
        query[5] = 1; // QDCount = 1
        query.extend_from_slice(&[255, b'a', b'b']); // Corrupted label length pointing way beyond buffer

        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_insert_cache_corrupted_response_not_cached() {
        let mut corrupted_resp = vec![0u8; DNS_HEADER_SIZE];
        corrupted_resp[5] = 1; // QDCount = 1
        corrupted_resp[7] = 1; // ANCount = 1
        corrupted_resp.extend_from_slice(&[0xff, 0xff, 0xff]); // Garbage payload

        let mut cache = HashMap::new();
        insert_cache(b"corrupted_key".to_vec(), corrupted_resp, &mut cache);

        assert!(!cache.contains_key(&b"corrupted_key".to_vec()[..]));
    }

    #[test]
    fn test_is_valid_upstream_resolver_filters_loopback_and_special() {
        assert!(is_valid_upstream_resolver(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_valid_upstream_resolver(Ipv4Addr::new(1, 1, 1, 1)));

        // Unspecified, broadcast, and loopback are rejected (CVE-2014-0472 protection)
        assert!(!is_valid_upstream_resolver(Ipv4Addr::UNSPECIFIED));
        assert!(!is_valid_upstream_resolver(Ipv4Addr::BROADCAST));
        assert!(!is_valid_upstream_resolver(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_valid_upstream_resolver(Ipv4Addr::new(127, 0, 0, 53)));
        assert!(!is_valid_upstream_resolver(Ipv4Addr::new(224, 0, 0, 1))); // Multicast
        assert!(!is_valid_upstream_resolver(Ipv4Addr::new(169, 254, 1, 1))); // Link local
        assert!(!is_valid_upstream_resolver(Ipv4Addr::new(192, 0, 2, 1))); // Documentation
    }

    #[test]
    fn test_get_upstream_resolvers_filters_invalid_and_falls_back() {
        let invalid_servers = vec![
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
        ];
        let resolvers = get_upstream_resolvers(&invalid_servers);
        assert_eq!(resolvers, vec![FALLBACK_DNS_SERVER]);

        let mixed_servers = vec![
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(9, 9, 9, 9),
            Ipv4Addr::UNSPECIFIED,
        ];
        let resolvers = get_upstream_resolvers(&mixed_servers);
        assert_eq!(resolvers, vec![Ipv4Addr::new(9, 9, 9, 9)]);
    }

    #[test]
    fn test_insert_cache_ttl_rfc2181_behavior() {
        let mut resp = vec![0u8; DNS_HEADER_SIZE];
        resp[2] = 0x81; // QR = 1, RD = 1
        resp.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        resp.extend_from_slice(&[0, 1, 0, 1]); // Type A, Class IN
        resp[5] = 1; // QDCount = 1
        resp[7] = 1; // ANCount = 1

        // TTL == 0: RFC 2181 behavior - must NOT be cached
        let mut resp_zero = resp.clone();
        resp_zero.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 8, 8, 8, 8]);
        let mut cache = HashMap::new();
        insert_cache(b"zero_key".to_vec(), resp_zero, &mut cache);
        assert!(!cache.contains_key(&b"zero_key".to_vec()[..]));

        // Low TTL (e.g. 10s): RFC 2181 honors exact low TTL without artificial minimum floor
        let mut resp_low = resp.clone();
        resp_low.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 8, 8, 8, 8]);
        insert_cache(b"low_key".to_vec(), resp_low, &mut cache);
        let entry_low = cache.get(&b"low_key".to_vec()[..]).unwrap();
        let cache_ttl_low = entry_low.expiry.duration_since(Instant::now()).as_secs();
        assert!((9..=10).contains(&cache_ttl_low));

        // High TTL (e.g. 1,000,000s): caps at max_ttl (3600s / 1 hour)
        let mut resp_max = resp.clone();
        resp_max.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 8, 8, 8, 8]);
        let offset = resp_max.len() - 16;
        resp_max[offset + 6..offset + 10].copy_from_slice(&1_000_000u32.to_be_bytes());
        insert_cache(b"max_key".to_vec(), resp_max, &mut cache);

        let entry_max = cache.get(&b"max_key".to_vec()[..]).unwrap();
        let cache_ttl_max = entry_max.expiry.duration_since(Instant::now()).as_secs();
        assert!((3598..=3600).contains(&cache_ttl_max));
    }

    #[test]
    fn test_get_cache_key_rejects_non_standard_opcode() {
        let mut query = vec![0u8; DNS_HEADER_SIZE];
        query[2] = 0x28; // Opcode 5 (Status/Update) instead of StandardQuery (0)
        query[5] = 1; // QDCount = 1
        query.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query.extend_from_slice(&[0, 1, 0, 1]); // Type A, Class IN

        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_allocate_unique_xid_never_zero() {
        let pending = HashMap::new();
        for _ in 0..100 {
            let xid = allocate_unique_xid(&pending);
            assert!(xid.is_some());
            assert_ne!(xid.unwrap(), 0);
        }
    }

    #[test]
    fn test_lookup_cache_expired_entry_evicted_on_lookup() {
        let mut cache = HashMap::new();
        let key = b"expired_key".to_vec();
        cache.insert(
            key.clone(),
            CacheEntry {
                response: vec![1, 2, 3],
                expiry: Instant::now() - Duration::from_secs(1), // Already expired
            },
        );

        assert_eq!(lookup_cache(&key, &mut cache), None);
        assert!(!cache.contains_key(&key)); // Purged
    }

    #[test]
    fn test_insert_cache_nxdomain_rfc2308_fallback_without_soa() {
        let mut resp = vec![0u8; DNS_HEADER_SIZE];
        resp[2] = 0x81; // QR = 1, RD = 1
        resp[3] = 0x83; // RA = 1, RCODE = 3 (NXDomain)
        resp[5] = 1; // QDCount = 1
        resp.extend_from_slice(&[7, b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0]);
        resp.extend_from_slice(&[0, 1, 0, 1]); // Type A, Class IN

        let mut cache = HashMap::new();
        insert_cache(b"nxdomain_key".to_vec(), resp, &mut cache);

        let entry = cache
            .get(&b"nxdomain_key".to_vec()[..])
            .expect("NXDomain should be cached");
        let ttl = entry.expiry.duration_since(Instant::now()).as_secs();
        assert!((58..=60).contains(&ttl));
    }

    #[test]
    fn test_insert_cache_servfail_refused_not_cached() {
        // ServFail (RCODE 2)
        let mut resp_servfail = vec![0u8; DNS_HEADER_SIZE];
        resp_servfail[2] = 0x81;
        resp_servfail[3] = 0x82; // RCODE = 2
        resp_servfail[5] = 1;
        resp_servfail
            .extend_from_slice(&[7, b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0, 0, 1, 0, 1]);

        // Refused (RCODE 5)
        let mut resp_refused = vec![0u8; DNS_HEADER_SIZE];
        resp_refused[2] = 0x81;
        resp_refused[3] = 0x85; // RCODE = 5
        resp_refused[5] = 1;
        resp_refused
            .extend_from_slice(&[7, b'i', b'n', b'v', b'a', b'l', b'i', b'd', 0, 0, 1, 0, 1]);

        let mut cache = HashMap::new();
        insert_cache(b"servfail_key".to_vec(), resp_servfail, &mut cache);
        assert!(!cache.contains_key(&b"servfail_key".to_vec()[..]));

        insert_cache(b"refused_key".to_vec(), resp_refused, &mut cache);
        assert!(!cache.contains_key(&b"refused_key".to_vec()[..]));
    }

    #[test]
    fn test_insert_cache_nxdomain_rfc2308_with_soa() {
        use hickory_proto::rr::Name;
        use hickory_proto::rr::Record;
        use hickory_proto::rr::rdata::SOA;
        use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

        let mut msg = Message::new(
            1234,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        msg.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain;

        let soa = SOA::new(
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            7200,
            3600,
            1209600,
            45, // minimum TTL = 45s
        );
        let record = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120, // SOA record TTL = 120s
            hickory_proto::rr::RData::SOA(soa),
        );
        msg.add_authority(record);

        let mut buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut buf);
        msg.emit(&mut encoder).unwrap();

        let mut cache = HashMap::new();
        insert_cache(b"nxdomain_soa".to_vec(), buf, &mut cache);

        let entry = cache.get(&b"nxdomain_soa".to_vec()[..]).unwrap();
        let ttl = entry.expiry.duration_since(Instant::now()).as_secs();
        // Min(120, 45) = 45s
        assert!((44..=45).contains(&ttl));
    }

    #[test]
    fn test_get_cache_key_case_insensitive() {
        let mut query1 = vec![0u8; DNS_HEADER_SIZE];
        query1[5] = 1; // QDCount = 1
        query1.extend_from_slice(&[
            6, b'G', b'o', b'O', b'g', b'L', b'e', 3, b'C', b'o', b'M', 0,
        ]);
        query1.extend_from_slice(&[0, 1, 0, 1]); // Type A, Class IN

        let mut query2 = vec![0u8; DNS_HEADER_SIZE];
        query2[5] = 1; // QDCount = 1
        query2.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query2.extend_from_slice(&[0, 1, 0, 1]); // Type A, Class IN

        assert_eq!(get_cache_key(&query1), get_cache_key(&query2));
    }

    #[test]
    fn test_insert_cache_truncated_response_not_cached() {
        let mut resp_tc = vec![0u8; DNS_HEADER_SIZE];
        resp_tc[2] = 0x83; // QR = 1, TC = 1 (Truncated)
        resp_tc[3] = 0x80;
        resp_tc[5] = 1; // QDCount = 1
        resp_tc[7] = 1; // ANCount = 1
        resp_tc.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        resp_tc.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8]);

        let mut cache = HashMap::new();
        insert_cache(b"tc_key".to_vec(), resp_tc, &mut cache);
        assert!(!cache.contains_key(&b"tc_key".to_vec()[..]));
    }

    #[test]
    fn test_insert_cache_non_response_query_packet_not_cached() {
        let mut query = vec![0u8; DNS_HEADER_SIZE];
        query[2] = 0x01; // QR = 0 (Query, not response), RD = 1
        query[5] = 1; // QDCount = 1
        query.extend_from_slice(&[
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);

        let mut cache = HashMap::new();
        insert_cache(b"query_key".to_vec(), query, &mut cache);
        assert!(!cache.contains_key(&b"query_key".to_vec()[..]));
    }
}
