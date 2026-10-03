use crate::services::DNS_FORWARDER_SERVICE_NAME;
use crate::services::dns_forwarder::rate_limiter::DnsRateLimiter;
use crate::services::ipc::{
    DnsParentToWorkerMsg, DnsStatsInfo, DnsWorkerToParentMsg, IpcReceiver, send_msg,
};
use crate::services::utils::{
    DNS_FORWARDER_GID, DNS_FORWARDER_UID, DNS_PORT, async_tcp_listener, async_udp_socket,
    run_sandboxed_worker,
};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A, rdata::PTR};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

use log::{debug, info, warn};
use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::OwnedFd;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc::{Sender as MpscSender, channel as mpsc_channel};
use tokio::sync::oneshot::{Sender as OneshotSender, channel as oneshot_channel};

// =========================================================================
// DNS Constants & Config for DNS Forwarder Service (benchmarked)
// =========================================================================
const DNS_HEADER_SIZE: usize = 12;
const RFC1035_MAX_UDP_PAYLOAD: usize = 512;
const MAX_EDNS_PAYLOAD_SIZE: usize = 4096;
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
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_MAX_MESSAGE_SIZE: usize = 65535;
const TCP_QUERY_CHANNEL_CAPACITY: usize = 128;
const TCP_EVENT_CHANNEL_CAPACITY: usize = 128;
const UPSTREAM_TCP_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_JOINED_CLIENTS_PER_QUERY: usize = 64;

#[derive(Debug, Clone)]
struct CacheEntry {
    response: Vec<u8>,
    expiry: Instant,
}

enum UpstreamTcpEvent {
    Resolved {
        cache_key: Vec<u8>,
        reply: Vec<u8>,
        clients: Vec<PendingClient>,
    },
    Failed {
        fallback_reply: Vec<u8>,
        clients: Vec<PendingClient>,
    },
}

#[derive(Debug)]
enum ClientOrigin {
    Udp(SocketAddr),
    Tcp {
        peer_addr: SocketAddr,
        reply_tx: OneshotSender<Vec<u8>>,
    },
}

impl ClientOrigin {
    fn peer_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(addr) => *addr,
            Self::Tcp { peer_addr, .. } => *peer_addr,
        }
    }

    async fn send_reply(
        self,
        response: Vec<u8>,
        dns_socket: &UdpSocket,
        max_payload: Option<usize>,
    ) {
        match self {
            Self::Udp(src) => {
                let final_response = match max_payload {
                    Some(cap) => prepare_client_response(response, cap),
                    None => response,
                };
                let _ = dns_socket.send_to(&final_response, src).await;
            }
            Self::Tcp { reply_tx, .. } => {
                let _ = reply_tx.send(response);
            }
        }
    }
}

struct TcpQueryRequest {
    query: Vec<u8>,
    peer_addr: SocketAddr,
    reply_tx: OneshotSender<Vec<u8>>,
}

#[derive(Debug)]
struct PendingClient {
    origin: ClientOrigin,
    client_xid: u16,
    client_max_payload: usize,
}

struct PendingQuery {
    clients: Vec<PendingClient>,
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
    dns_tcp_listener_fd: OwnedFd,
) -> Result<(), IoError> {
    let dns_socket = async_udp_socket(dns_socket_fd)?;
    let upstream_socket = async_udp_socket(upstream_socket_fd)?;
    let dns_tcp_listener = async_tcp_listener(dns_tcp_listener_fd)?;

    run_sandboxed_worker(
        DNS_FORWARDER_SERVICE_NAME,
        DNS_FORWARDER_UID,
        DNS_FORWARDER_GID,
        ipc_fd,
        |ipc| async move {
            run_forwarder_loop(
                dns_socket,
                upstream_socket,
                dns_tcp_listener,
                ipc.reader,
                ipc.writer,
            )
            .await;
            Ok(())
        },
    )
    .await
}

async fn run_forwarder_loop(
    dns_socket: UdpSocket,
    upstream_socket: UdpSocket,
    dns_tcp_listener: TcpListener,
    ipc_reader: OwnedReadHalf,
    mut ipc_writer: OwnedWriteHalf,
) {
    let mut ipc_rx = IpcReceiver::new(ipc_reader);
    let mut cache = HashMap::<Vec<u8>, CacheEntry>::new();
    let mut pending_queries = HashMap::<u16, PendingQuery>::new();
    let mut upstream_servers = Vec::<Ipv4Addr>::new();
    let mut local_hosts = HashMap::<String, Ipv4Addr>::new();
    let mut local_ips = HashMap::<Ipv4Addr, String>::new();
    let mut client_buf = [0u8; RECV_BUF_SIZE];
    let mut upstream_buf = [0u8; RECV_BUF_SIZE];
    let mut cleanup_timer = tokio::time::interval(CLEANUP_INTERVAL);
    let mut rate_limiter = DnsRateLimiter::default();
    let (tcp_query_tx, mut tcp_query_rx) =
        mpsc_channel::<TcpQueryRequest>(TCP_QUERY_CHANNEL_CAPACITY);
    let (tcp_event_tx, mut tcp_event_rx) =
        mpsc_channel::<UpstreamTcpEvent>(TCP_EVENT_CHANNEL_CAPACITY);

    let mut dns_stats = DnsStatsInfo::default();

    loop {
        tokio::select! {
            _ = cleanup_timer.tick() => {
                dns_stats.cached_entries_count = cache.len();
                if let Err(e) = send_msg(
                    &mut ipc_writer,
                    &DnsWorkerToParentMsg::Heartbeat {
                        stats: dns_stats.clone(),
                    },
                )
                .await
                {
                    debug!("[dns-forwarder-worker] Failed to send heartbeat to parent: {}", e);
                }
                evict_expired_cache(&mut cache);
                rate_limiter.retain_recent();
                check_pending_timeouts(&mut pending_queries, &upstream_socket).await;
            }
            ipc_msg = ipc_rx.recv() => {
                match ipc_msg {
                    Ok(Some(DnsParentToWorkerMsg::SetUpstreamResolvers { servers })) => {
                        upstream_servers = servers;
                    }
                    Ok(Some(DnsParentToWorkerMsg::RegisterLocalHost { name, ip })) => {
                        if let Some(old_ip) = local_hosts.insert(name.clone(), ip) {
                            local_ips.remove(&old_ip);
                        }
                        local_ips.insert(ip, name);
                    }
                    Ok(Some(DnsParentToWorkerMsg::DeregisterLocalHost { name })) => {
                        if let Some(ip) = local_hosts.remove(&name) {
                            local_ips.remove(&ip);
                        }
                    }
                    Ok(None) | Err(_) => {
                        info!("[dns-forwarder-worker] Parent IPC closed. Shutting down.");
                        break;
                    }
                }
            }
            client_recv = dns_socket.recv_from(&mut client_buf) => {
                if let Ok((len, src)) = client_recv {
                    let ctx = ForwarderContext {
                        sockets: ForwarderSockets {
                            dns: &dns_socket,
                            upstream: &upstream_socket,
                        },
                        local_table: LocalDnsTable {
                            hosts: &local_hosts,
                            ips: &local_ips,
                        },
                        configured_servers: &upstream_servers,
                    };
                    handle_incoming_query(
                        &client_buf[..len],
                        ClientOrigin::Udp(src),
                        &ctx,
                        &mut cache,
                        &mut pending_queries,
                        &mut rate_limiter,
                        &mut dns_stats,
                    ).await;
                }
            }
            tcp_accept = dns_tcp_listener.accept() => {
                if let Ok((stream, peer_addr)) = tcp_accept {
                    let tx = tcp_query_tx.clone();
                    tokio::spawn(handle_tcp_client_connection(stream, peer_addr, tx));
                }
            }
            Some(tcp_req) = tcp_query_rx.recv() => {
                let ctx = ForwarderContext {
                    sockets: ForwarderSockets {
                        dns: &dns_socket,
                        upstream: &upstream_socket,
                    },
                    local_table: LocalDnsTable {
                        hosts: &local_hosts,
                        ips: &local_ips,
                    },
                    configured_servers: &upstream_servers,
                };
                handle_incoming_query(
                    &tcp_req.query,
                    ClientOrigin::Tcp {
                        peer_addr: tcp_req.peer_addr,
                        reply_tx: tcp_req.reply_tx,
                    },
                    &ctx,
                    &mut cache,
                    &mut pending_queries,
                    &mut rate_limiter,
                    &mut dns_stats,
                ).await;
            }
            upstream_recv = upstream_socket.recv_from(&mut upstream_buf) => {
                if let Ok((len, from_addr)) = upstream_recv {
                    handle_upstream_reply(
                        &upstream_buf[..len],
                        from_addr,
                        &dns_socket,
                        &upstream_socket,
                        &mut cache,
                        &mut pending_queries,
                        &tcp_event_tx,
                    ).await;
                }
            }
            Some(tcp_event) = tcp_event_rx.recv() => {
                handle_upstream_tcp_event(tcp_event, &dns_socket, &mut cache).await;
            }
        }
    }
}

struct ForwarderSockets<'a> {
    dns: &'a UdpSocket,
    upstream: &'a UdpSocket,
}

struct LocalDnsTable<'a> {
    hosts: &'a HashMap<String, Ipv4Addr>,
    ips: &'a HashMap<Ipv4Addr, String>,
}

struct ForwarderContext<'a> {
    sockets: ForwarderSockets<'a>,
    local_table: LocalDnsTable<'a>,
    configured_servers: &'a [Ipv4Addr],
}

async fn handle_tcp_client_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    tcp_query_tx: MpscSender<TcpQueryRequest>,
) {
    let (mut reader, mut writer) = stream.into_split();
    loop {
        let Some(query) = read_tcp_dns_query(&mut reader).await else {
            break;
        };

        let (reply_tx, reply_rx) = oneshot_channel();
        let req = TcpQueryRequest {
            query,
            peer_addr,
            reply_tx,
        };

        if tcp_query_tx.send(req).await.is_err() {
            break;
        }

        let Ok(reply) = reply_rx.await else {
            break;
        };
        if write_tcp_dns_reply(&mut writer, &reply).await.is_err() {
            break;
        }
    }
}

async fn read_tcp_dns_query<R: AsyncReadExt + Unpin>(reader: &mut R) -> Option<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    let read_len = tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await;
    let Ok(Ok(_)) = read_len else {
        return None;
    };

    let query_len = u16::from_be_bytes(len_buf) as usize;
    if !(DNS_HEADER_SIZE..=TCP_MAX_MESSAGE_SIZE).contains(&query_len) {
        return None;
    }

    let mut query_buf = vec![0u8; query_len];
    let read_payload =
        tokio::time::timeout(TCP_IDLE_TIMEOUT, reader.read_exact(&mut query_buf)).await;
    if let Ok(Ok(_)) = read_payload {
        Some(query_buf)
    } else {
        None
    }
}

async fn write_tcp_dns_reply<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    reply: &[u8],
) -> Result<(), std::io::Error> {
    if reply.len() > TCP_MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS reply exceeds TCP max message size",
        ));
    }
    let reply_len_bytes = (reply.len() as u16).to_be_bytes();
    writer.write_all(&reply_len_bytes).await?;
    writer.write_all(reply).await?;
    Ok(())
}

async fn handle_incoming_query(
    query: &[u8],
    origin: ClientOrigin,
    ctx: &ForwarderContext<'_>,
    cache: &mut HashMap<Vec<u8>, CacheEntry>,
    pending: &mut HashMap<u16, PendingQuery>,
    rate_limiter: &mut DnsRateLimiter,
    stats: &mut DnsStatsInfo,
) {
    if query.len() < DNS_HEADER_SIZE {
        return;
    }

    stats.queries_total = stats.queries_total.saturating_add(1);

    if let Some(local_resp) =
        try_resolve_local_query(query, ctx.local_table.hosts, ctx.local_table.ips)
    {
        origin.send_reply(local_resp, ctx.sockets.dns, None).await;
        return;
    }

    let Some(cache_key) = get_cache_key(query) else {
        return;
    };

    if let Some(mut response) = lookup_cache(&cache_key, cache) {
        stats.cache_hits_total = stats.cache_hits_total.saturating_add(1);
        response[0] = query[0];
        response[1] = query[1];
        let max_payload = extract_client_max_payload(query);
        origin
            .send_reply(response, ctx.sockets.dns, Some(max_payload))
            .await;
        return;
    }

    let client_ip = match origin.peer_addr().ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return,
    };
    if !rate_limiter.check(&client_ip) {
        stats.rate_limited_drops_total = stats.rate_limited_drops_total.saturating_add(1);
        debug!(
            "[dns-forwarder-worker] Upstream rate limit exceeded for client {}. Dropping query.",
            client_ip
        );
        return;
    }

    let mut origin_opt = Some(origin);
    if try_join_in_flight_query(pending, &cache_key, query, &mut origin_opt) {
        return;
    }
    let origin = origin_opt.expect("origin must be present if not joined");

    forward_new_client_query(
        query,
        origin,
        cache_key,
        ctx.sockets.upstream,
        pending,
        ctx.configured_servers,
    )
    .await;
}

fn try_join_in_flight_query(
    pending: &mut HashMap<u16, PendingQuery>,
    cache_key: &[u8],
    query: &[u8],
    origin: &mut Option<ClientOrigin>,
) -> bool {
    let Some(existing) = pending.values_mut().find(|p| p.cache_key == cache_key) else {
        return false;
    };
    if existing.clients.len() >= MAX_JOINED_CLIENTS_PER_QUERY {
        return false;
    }
    let Some(orig) = origin.take() else {
        return false;
    };
    let client_xid = u16::from_be_bytes([query[0], query[1]]);
    let client_max_payload = extract_client_max_payload(query);
    existing.clients.push(PendingClient {
        origin: orig,
        client_xid,
        client_max_payload,
    });
    true
}

async fn forward_new_client_query(
    query: &[u8],
    client_origin: ClientOrigin,
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
    let client_max_payload = extract_client_max_payload(query);
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
                clients: vec![PendingClient {
                    origin: client_origin,
                    client_xid,
                    client_max_payload,
                }],
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
    upstream_socket: &UdpSocket,
    cache: &mut HashMap<Vec<u8>, CacheEntry>,
    pending: &mut HashMap<u16, PendingQuery>,
    tcp_event_tx: &MpscSender<UpstreamTcpEvent>,
) {
    if reply.len() < DNS_HEADER_SIZE {
        return;
    }
    let upstream_xid = u16::from_be_bytes([reply[0], reply[1]]);
    let Some(query_meta) = pending.get(&upstream_xid) else {
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

    let is_truncated = reply[2] & 0x02 != 0;
    if is_truncated {
        let query_meta = pending
            .remove(&upstream_xid)
            .expect("query exists in pending");
        spawn_upstream_tcp_fallback(
            query_meta,
            upstream_xid,
            reply.to_vec(),
            tcp_event_tx.clone(),
        );
        return;
    }

    let Ok(msg) = Message::from_bytes(reply) else {
        return;
    };

    if (msg.response_code == hickory_proto::op::ResponseCode::ServFail
        || msg.response_code == hickory_proto::op::ResponseCode::Refused)
        && let Some(query) = pending.get_mut(&upstream_xid)
        && try_failover_upstream_query(query, upstream_xid, upstream_socket).await
    {
        debug!(
            "[dns-forwarder] Upstream {} returned {:?}, failing over to next resolver",
            expected_ip, msg.response_code
        );
        return;
    }

    let query_meta = pending
        .remove(&upstream_xid)
        .expect("query exists in pending");

    insert_cache(query_meta.cache_key, reply.to_vec(), cache);
    fanout_client_replies(query_meta.clients, reply, dns_socket).await;
}

async fn try_failover_upstream_query(
    query: &mut PendingQuery,
    upstream_xid: u16,
    upstream_socket: &UdpSocket,
) -> bool {
    if query.current_server_idx + 1 >= query.upstream_servers.len() {
        return false;
    }
    query.current_server_idx += 1;
    query.deadline = Instant::now() + UPSTREAM_TIMEOUT;
    let target_server = query.upstream_servers[query.current_server_idx];

    let mut forwarded = query.query_payload.clone();
    let xid_bytes = upstream_xid.to_be_bytes();
    if forwarded.len() >= 2 {
        forwarded[0] = xid_bytes[0];
        forwarded[1] = xid_bytes[1];
    }

    let dest = SocketAddr::new(IpAddr::V4(target_server), DNS_PORT);
    let _ = upstream_socket.send_to(&forwarded, dest).await;
    true
}

async fn fanout_client_replies(clients: Vec<PendingClient>, reply: &[u8], dns_socket: &UdpSocket) {
    for client in clients {
        let mut client_response = reply.to_vec();
        let client_xid_bytes = client.client_xid.to_be_bytes();
        client_response[0] = client_xid_bytes[0];
        client_response[1] = client_xid_bytes[1];

        client
            .origin
            .send_reply(client_response, dns_socket, Some(client.client_max_payload))
            .await;
    }
}

fn spawn_upstream_tcp_fallback(
    query_meta: PendingQuery,
    upstream_xid: u16,
    fallback_reply: Vec<u8>,
    tcp_event_tx: MpscSender<UpstreamTcpEvent>,
) {
    let target = query_meta.upstream_servers[query_meta.current_server_idx];
    let query_payload = query_meta.query_payload.clone();
    let cache_key = query_meta.cache_key.clone();
    let clients = query_meta.clients;

    tokio::spawn(async move {
        match fetch_upstream_tcp(target, &query_payload, upstream_xid).await {
            Ok(reply) => {
                let _ = tcp_event_tx
                    .send(UpstreamTcpEvent::Resolved {
                        cache_key,
                        reply,
                        clients,
                    })
                    .await;
            }
            Err(e) => {
                debug!(
                    "[dns-forwarder] Upstream TCP fallback to {} failed: {}. Returning truncated reply.",
                    target, e
                );
                let _ = tcp_event_tx
                    .send(UpstreamTcpEvent::Failed {
                        fallback_reply,
                        clients,
                    })
                    .await;
            }
        }
    });
}

async fn handle_upstream_tcp_event(
    event: UpstreamTcpEvent,
    dns_socket: &UdpSocket,
    cache: &mut HashMap<Vec<u8>, CacheEntry>,
) {
    match event {
        UpstreamTcpEvent::Resolved {
            cache_key,
            reply,
            clients,
        } => {
            insert_cache(cache_key, reply.clone(), cache);
            fanout_client_replies(clients, &reply, dns_socket).await;
        }
        UpstreamTcpEvent::Failed {
            fallback_reply,
            clients,
        } => {
            fanout_client_replies(clients, &fallback_reply, dns_socket).await;
        }
    }
}

async fn fetch_upstream_tcp(
    target_server: Ipv4Addr,
    query_payload: &[u8],
    upstream_xid: u16,
) -> Result<Vec<u8>, IoError> {
    let dest = SocketAddr::new(IpAddr::V4(target_server), DNS_PORT);
    let mut stream = tokio::time::timeout(UPSTREAM_TCP_TIMEOUT, TcpStream::connect(dest))
        .await
        .map_err(|_| IoError::new(std::io::ErrorKind::TimedOut, "TCP connect timeout"))??;

    let mut forwarded = query_payload.to_vec();
    let xid_bytes = upstream_xid.to_be_bytes();
    if forwarded.len() >= 2 {
        forwarded[0] = xid_bytes[0];
        forwarded[1] = xid_bytes[1];
    }

    write_tcp_dns_reply(&mut stream, &forwarded).await?;
    let (mut reader, _) = stream.into_split();
    read_tcp_dns_query(&mut reader).await.ok_or_else(|| {
        IoError::new(
            std::io::ErrorKind::UnexpectedEof,
            "Failed to read TCP DNS reply",
        )
    })
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
            try_failover_upstream_query(query, xid, upstream_socket).await;
        }
    }
}

fn extract_client_max_payload(query_bytes: &[u8]) -> usize {
    if let Ok(msg) = Message::from_bytes(query_bytes)
        && let Some(edns) = &msg.edns
    {
        return (edns.max_payload() as usize).clamp(RFC1035_MAX_UDP_PAYLOAD, MAX_EDNS_PAYLOAD_SIZE);
    }
    RFC1035_MAX_UDP_PAYLOAD
}

fn prepare_client_response(mut response: Vec<u8>, max_payload: usize) -> Vec<u8> {
    if response.len() <= max_payload {
        return response;
    }
    if let Ok(msg) = Message::from_bytes(&response) {
        let truncated_msg = msg.truncate();
        let mut buf = Vec::new();
        let mut encoder = BinEncoder::new(&mut buf);
        if truncated_msg.emit(&mut encoder).is_ok() && buf.len() <= max_payload {
            return buf;
        }
    }
    if response.len() >= DNS_HEADER_SIZE {
        response[2] |= 0x02; // Set TC flag (byte 2, bit 1)
        response.truncate(DNS_HEADER_SIZE);
    }
    response
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

fn get_upstream_resolvers(configured: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    let valid: Vec<Ipv4Addr> = configured
        .iter()
        .copied()
        .filter(|&ip| crate::services::utils::is_valid_upstream_resolver(ip))
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

fn extract_local_forward_name(name: &str) -> Option<(String, bool)> {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    if lower == crate::services::utils::LOCAL_DOMAIN || lower.is_empty() {
        return None;
    }
    let dot_suffix = format!(".{}", crate::services::utils::LOCAL_DOMAIN);
    if let Some(prefix) = lower.strip_suffix(&dot_suffix) {
        if !prefix.contains('.') {
            return Some((prefix.to_string(), true));
        }
        return None;
    }
    if !lower.contains('.') {
        return Some((lower, false));
    }
    None
}

fn is_mdns_local_domain(name: &str) -> bool {
    let lower = name.trim_end_matches('.').to_ascii_lowercase();
    let dot_suffix = format!(".{}", crate::services::utils::MDNS_DOMAIN);
    lower == crate::services::utils::MDNS_DOMAIN || lower.ends_with(&dot_suffix)
}

fn try_resolve_local_query(
    query_bytes: &[u8],
    local_hosts: &HashMap<String, Ipv4Addr>,
    local_ips: &HashMap<Ipv4Addr, String>,
) -> Option<Vec<u8>> {
    let query_msg = Message::from_bytes(query_bytes).ok()?;
    if query_msg.op_code != OpCode::Query || query_msg.queries.is_empty() {
        return None;
    }
    let question = &query_msg.queries[0];
    let qname = question.name();
    let qname_str = qname.to_utf8();
    let qtype = question.query_type();

    if let Some((label, is_lan_qualified)) = extract_local_forward_name(&qname_str) {
        if let Some(&ip) = local_hosts.get(&label) {
            return match qtype {
                RecordType::A => Some(build_authoritative_a_response(&query_msg, qname, ip)),
                _ => Some(build_authoritative_nodata_response(&query_msg)),
            };
        } else if is_lan_qualified {
            return Some(build_authoritative_nxdomain_response(&query_msg));
        }
    }

    if qtype == RecordType::PTR {
        if let Ok(ipnet::IpNet::V4(v4)) = qname.parse_arpa_name()
            && v4.prefix_len() == 32
            && let Some(hostname) = local_ips.get(&v4.addr())
        {
            let ptr_target = format!("{}.{}.", hostname, crate::services::utils::LOCAL_DOMAIN);
            if let Ok(target_name) = Name::from_ascii(&ptr_target) {
                return Some(build_authoritative_ptr_response(
                    &query_msg,
                    qname,
                    target_name,
                ));
            }
        }
        return None;
    }

    if is_mdns_local_domain(&qname_str) {
        return Some(build_authoritative_nxdomain_response(&query_msg));
    }

    None
}

fn build_authoritative_response(
    query_msg: &Message,
    rcode: hickory_proto::op::ResponseCode,
    answer: Option<Record>,
) -> Vec<u8> {
    let mut response = Message::response(query_msg.id, OpCode::Query);
    response.metadata.response_code = rcode;
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = query_msg.recursion_desired;
    response.queries = query_msg.queries.clone();
    if let Some(rec) = answer {
        response.add_answer(rec);
    }

    let mut buf = Vec::new();
    let mut encoder = BinEncoder::new(&mut buf);
    let _ = response.emit(&mut encoder);
    buf
}

fn build_authoritative_nodata_response(query_msg: &Message) -> Vec<u8> {
    build_authoritative_response(query_msg, hickory_proto::op::ResponseCode::NoError, None)
}

fn build_authoritative_a_response(query_msg: &Message, qname: &Name, ip: Ipv4Addr) -> Vec<u8> {
    let record = Record::from_rdata(qname.clone(), DEFAULT_TTL_SECS, RData::A(A(ip)));
    build_authoritative_response(
        query_msg,
        hickory_proto::op::ResponseCode::NoError,
        Some(record),
    )
}

fn build_authoritative_ptr_response(
    query_msg: &Message,
    qname: &Name,
    target_name: Name,
) -> Vec<u8> {
    let record = Record::from_rdata(
        qname.clone(),
        DEFAULT_TTL_SECS,
        RData::PTR(PTR(target_name)),
    );
    build_authoritative_response(
        query_msg,
        hickory_proto::op::ResponseCode::NoError,
        Some(record),
    )
}

fn build_authoritative_nxdomain_response(query_msg: &Message) -> Vec<u8> {
    build_authoritative_response(query_msg, hickory_proto::op::ResponseCode::NXDomain, None)
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::utils::is_valid_upstream_resolver;
    use hickory_proto::rr::rdata::SOA;

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

    #[test]
    fn test_extract_local_forward_name_and_mdns() {
        assert_eq!(
            extract_local_forward_name("printer"),
            Some(("printer".to_string(), false))
        );
        assert_eq!(
            extract_local_forward_name("printer.lan"),
            Some(("printer".to_string(), true))
        );
        assert_eq!(
            extract_local_forward_name("printer.lan."),
            Some(("printer".to_string(), true))
        );
        assert_eq!(
            extract_local_forward_name("PRINTER.LAN"),
            Some(("printer".to_string(), true))
        );
        assert_eq!(extract_local_forward_name("google.com"), None);
        assert_eq!(extract_local_forward_name("foo.bar.lan"), None);
        assert_eq!(extract_local_forward_name("lan"), None);

        assert!(is_mdns_local_domain("printer.local"));
        assert!(is_mdns_local_domain("device.local."));
        assert!(is_mdns_local_domain("local"));
        assert!(!is_mdns_local_domain("printer.lan"));
        assert!(!is_mdns_local_domain("example.com"));
    }

    #[test]
    fn test_try_resolve_local_query_a_record_hit() {
        let mut local_hosts = HashMap::new();
        let local_ips = HashMap::new();
        local_hosts.insert("printer".to_string(), Ipv4Addr::new(192, 168, 1, 50));

        let mut query = Message::new(1234, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("printer.lan.").unwrap();
        let query_item = hickory_proto::op::Query::query(qname, RecordType::A);
        query.add_query(query_item);

        let mut query_bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut query_bytes);
        query.emit(&mut encoder).unwrap();

        let resp_bytes = try_resolve_local_query(&query_bytes, &local_hosts, &local_ips)
            .expect("must resolve printer.lan");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp_msg.id, 1234);
        assert!(resp_msg.authoritative);
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_msg.answers.len(), 1);
        if let RData::A(A(ip)) = &resp_msg.answers[0].data {
            assert_eq!(*ip, Ipv4Addr::new(192, 168, 1, 50));
        } else {
            panic!("expected A record");
        }
    }

    #[test]
    fn test_try_resolve_local_query_aaaa_nodata_hit() {
        let mut local_hosts = HashMap::new();
        let local_ips = HashMap::new();
        local_hosts.insert("printer".to_string(), Ipv4Addr::new(192, 168, 1, 50));

        let mut query = Message::new(1235, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("printer.lan.").unwrap();
        let query_item = hickory_proto::op::Query::query(qname, RecordType::AAAA);
        query.add_query(query_item);

        let mut query_bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut query_bytes);
        query.emit(&mut encoder).unwrap();

        let resp_bytes = try_resolve_local_query(&query_bytes, &local_hosts, &local_ips)
            .expect("must resolve printer.lan with NODATA");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp_msg.id, 1235);
        assert!(resp_msg.authoritative);
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_msg.answers.len(), 0);
    }

    #[test]
    fn test_try_resolve_local_query_lan_nxdomain() {
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();

        let mut query = Message::new(5678, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("unknown.lan.").unwrap();
        let query_item = hickory_proto::op::Query::query(qname, RecordType::A);
        query.add_query(query_item);

        let mut query_bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut query_bytes);
        query.emit(&mut encoder).unwrap();

        let resp_bytes = try_resolve_local_query(&query_bytes, &local_hosts, &local_ips)
            .expect("must return authoritative NXDOMAIN for unknown .lan");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp_msg.id, 5678);
        assert!(resp_msg.authoritative);
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
        assert_eq!(resp_msg.answers.len(), 0);
    }

    #[test]
    fn test_try_resolve_local_query_local_mdns_nxdomain() {
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();

        let mut query = Message::new(9999, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("printer.local.").unwrap();
        let query_item = hickory_proto::op::Query::query(qname, RecordType::A);
        query.add_query(query_item);

        let mut query_bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut query_bytes);
        query.emit(&mut encoder).unwrap();

        let resp_bytes = try_resolve_local_query(&query_bytes, &local_hosts, &local_ips)
            .expect("must return authoritative NXDOMAIN for .local query on port 53");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp_msg.id, 9999);
        assert!(resp_msg.authoritative);
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
        assert_eq!(resp_msg.answers.len(), 0);
    }

    #[test]
    fn test_try_resolve_local_query_ptr_reverse_lookup() {
        let local_hosts = HashMap::new();
        let mut local_ips = HashMap::new();
        local_ips.insert(Ipv4Addr::new(192, 168, 1, 50), "printer".to_string());

        let mut query = Message::new(4321, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("50.1.168.192.in-addr.arpa.").unwrap();
        let query_item = hickory_proto::op::Query::query(qname, RecordType::PTR);
        query.add_query(query_item);

        let mut query_bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut query_bytes);
        query.emit(&mut encoder).unwrap();

        let resp_bytes = try_resolve_local_query(&query_bytes, &local_hosts, &local_ips)
            .expect("must resolve reverse PTR query");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp_msg.id, 4321);
        assert!(resp_msg.authoritative);
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_msg.answers.len(), 1);
        if let RData::PTR(name) = &resp_msg.answers[0].data {
            assert_eq!(name.to_utf8(), "printer.lan.");
        } else {
            panic!("expected PTR record");
        }
    }

    #[test]
    fn test_try_resolve_local_query_external_domain_returns_none() {
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();

        let mut query = Message::new(1111, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("google.com.").unwrap();
        let query_item = hickory_proto::op::Query::query(qname, RecordType::A);
        query.add_query(query_item);

        let mut query_bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut query_bytes);
        query.emit(&mut encoder).unwrap();

        assert_eq!(
            try_resolve_local_query(&query_bytes, &local_hosts, &local_ips),
            None
        );
    }

    #[test]
    fn test_try_resolve_local_query_case_insensitive() {
        let mut local_hosts = HashMap::new();
        let mut local_ips = HashMap::new();
        local_hosts.insert("printer".to_string(), Ipv4Addr::new(192, 168, 1, 50));
        local_ips.insert(Ipv4Addr::new(192, 168, 1, 50), "printer".to_string());

        // Forward uppercase query
        let mut query = Message::new(2222, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("PRINTER.LAN.").unwrap();
        let query_item = hickory_proto::op::Query::query(qname, RecordType::A);
        query.add_query(query_item);

        let mut query_bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut query_bytes);
        query.emit(&mut encoder).unwrap();

        let resp_bytes = try_resolve_local_query(&query_bytes, &local_hosts, &local_ips)
            .expect("must resolve uppercase PRINTER.LAN");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_msg.answers.len(), 1);

        // Reverse uppercase query
        let mut ptr_query =
            Message::new(3333, hickory_proto::op::MessageType::Query, OpCode::Query);
        let ptr_qname = Name::from_ascii("50.1.168.192.IN-ADDR.ARPA.").unwrap();
        let ptr_item = hickory_proto::op::Query::query(ptr_qname, RecordType::PTR);
        ptr_query.add_query(ptr_item);

        let mut ptr_bytes = Vec::new();
        let mut ptr_encoder = BinEncoder::new(&mut ptr_bytes);
        ptr_query.emit(&mut ptr_encoder).unwrap();

        let ptr_resp_bytes = try_resolve_local_query(&ptr_bytes, &local_hosts, &local_ips)
            .expect("must resolve uppercase IN-ADDR.ARPA");
        let ptr_resp_msg = Message::from_bytes(&ptr_resp_bytes).unwrap();
        assert_eq!(
            ptr_resp_msg.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
    }

    #[test]
    fn test_try_resolve_local_query_single_label_hit_and_miss() {
        let mut local_hosts = HashMap::new();
        let local_ips = HashMap::new();
        local_hosts.insert("printer".to_string(), Ipv4Addr::new(192, 168, 1, 50));

        // Single label hit: "printer"
        let mut query_hit =
            Message::new(4444, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname_hit = Name::from_ascii("printer.").unwrap();
        let item_hit = hickory_proto::op::Query::query(qname_hit, RecordType::A);
        query_hit.add_query(item_hit);

        let mut bytes_hit = Vec::new();
        let mut enc_hit = BinEncoder::new(&mut bytes_hit);
        query_hit.emit(&mut enc_hit).unwrap();

        let resp_bytes = try_resolve_local_query(&bytes_hit, &local_hosts, &local_ips)
            .expect("must resolve single-label printer");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(resp_msg.answers.len(), 1);

        // Single label miss: "unregistered" -> returns None to fall through to search list / upstream
        let mut query_miss =
            Message::new(5555, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname_miss = Name::from_ascii("unregistered.").unwrap();
        let item_miss = hickory_proto::op::Query::query(qname_miss, RecordType::A);
        query_miss.add_query(item_miss);

        let mut bytes_miss = Vec::new();
        let mut enc_miss = BinEncoder::new(&mut bytes_miss);
        query_miss.emit(&mut enc_miss).unwrap();

        assert_eq!(
            try_resolve_local_query(&bytes_miss, &local_hosts, &local_ips),
            None
        );
    }

    #[test]
    fn test_try_resolve_local_query_unknown_lan_all_types_return_nxdomain() {
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();

        // AAAA query on unknown .lan -> NXDOMAIN
        let mut query = Message::new(6666, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("unknown.lan.").unwrap();
        let item = hickory_proto::op::Query::query(qname, RecordType::AAAA);
        query.add_query(item);

        let mut bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut bytes);
        query.emit(&mut enc).unwrap();

        let resp_bytes = try_resolve_local_query(&bytes, &local_hosts, &local_ips)
            .expect("must return NXDOMAIN for unknown.lan AAAA");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();
        assert_eq!(
            resp_msg.response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
    }

    #[test]
    fn test_try_resolve_local_query_ptr_unknown_ip_returns_none() {
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();

        let mut query = Message::new(7777, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("99.1.168.192.in-addr.arpa.").unwrap();
        let item = hickory_proto::op::Query::query(qname, RecordType::PTR);
        query.add_query(item);

        let mut bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut bytes);
        query.emit(&mut enc).unwrap();

        assert_eq!(
            try_resolve_local_query(&bytes, &local_hosts, &local_ips),
            None
        );
    }

    #[test]
    fn test_calculate_cache_ttl_and_negative_ttl_bounds() {
        // Truncated packet returns None

        let mut msg_tc = Message::new(100, hickory_proto::op::MessageType::Response, OpCode::Query);
        msg_tc.metadata.truncation = true;
        assert_eq!(calculate_cache_ttl(&msg_tc), None);

        // Query packet (not response) returns None
        let msg_query = Message::new(101, hickory_proto::op::MessageType::Query, OpCode::Query);
        assert_eq!(calculate_cache_ttl(&msg_query), None);

        // NXDomain without SOA returns DEFAULT_NEGATIVE_TTL_SECS (60s)
        let mut msg_nx = Message::new(102, hickory_proto::op::MessageType::Response, OpCode::Query);
        msg_nx.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain;
        assert_eq!(
            calculate_cache_ttl(&msg_nx),
            Some(Duration::from_secs(DEFAULT_NEGATIVE_TTL_SECS as u64))
        );

        // NXDomain with SOA minimum = 30s
        let mut msg_soa =
            Message::new(103, hickory_proto::op::MessageType::Response, OpCode::Query);
        msg_soa.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain;
        let soa = SOA::new(
            Name::from_ascii("ns1.example.com.").unwrap(),
            Name::from_ascii("hostmaster.example.com.").unwrap(),
            1,
            7200,
            3600,
            1209600,
            30, // minimum TTL = 30s
        );
        let record = Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            120,
            hickory_proto::rr::RData::SOA(soa),
        );
        msg_soa.add_authority(record);
        assert_eq!(calculate_cache_ttl(&msg_soa), Some(Duration::from_secs(30)));
    }

    #[test]
    fn test_try_resolve_local_query_case_insensitivity_matrix() {
        let mut local_hosts = HashMap::new();
        let mut local_ips = HashMap::new();

        let my_ip = Ipv4Addr::new(192, 168, 1, 100);
        local_hosts.insert("my-laptop".to_string(), my_ip);
        local_ips.insert(my_ip, "my-laptop".to_string());

        // Both .lan and single label resolve to A record with case insensitivity
        for domain in ["MY-LAPTOP.LAN.", "My-Laptop.lan.", "mY-lApToP."] {
            let mut query =
                Message::new(1234, hickory_proto::op::MessageType::Query, OpCode::Query);
            let qname = Name::from_ascii(domain).unwrap();
            let item = hickory_proto::op::Query::query(qname, RecordType::A);
            query.add_query(item);

            let mut bytes = Vec::new();
            let mut enc = BinEncoder::new(&mut bytes);
            query.emit(&mut enc).unwrap();

            let resp_bytes = try_resolve_local_query(&bytes, &local_hosts, &local_ips)
                .unwrap_or_else(|| panic!("Domain {} should resolve", domain));
            let resp_msg = Message::from_bytes(&resp_bytes).unwrap();
            assert_eq!(
                resp_msg.response_code,
                hickory_proto::op::ResponseCode::NoError
            );
            assert_eq!(resp_msg.answers.len(), 1);
        }

        // Case-insensitive .local mDNS query returns authoritative NXDomain
        for domain in ["MY-LAPTOP.LOCAL.", "My-Laptop.Local."] {
            let mut query =
                Message::new(5678, hickory_proto::op::MessageType::Query, OpCode::Query);
            let qname = Name::from_ascii(domain).unwrap();
            let item = hickory_proto::op::Query::query(qname, RecordType::A);
            query.add_query(item);

            let mut bytes = Vec::new();
            let mut enc = BinEncoder::new(&mut bytes);
            query.emit(&mut enc).unwrap();

            let resp_bytes = try_resolve_local_query(&bytes, &local_hosts, &local_ips)
                .unwrap_or_else(|| panic!("Domain {} should return mDNS NXDomain", domain));
            let resp_msg = Message::from_bytes(&resp_bytes).unwrap();
            assert_eq!(
                resp_msg.response_code,
                hickory_proto::op::ResponseCode::NXDomain
            );
        }
    }

    #[test]
    fn test_get_cache_key_pointer_loop_rejected() {
        // Construct DNS query with a compression pointer loop (0xC0 0x0C pointing to itself)
        let mut query = vec![0u8; DNS_HEADER_SIZE];
        query[5] = 1; // QDCount = 1
        query.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);

        assert_eq!(get_cache_key(&query), None);
    }

    #[test]
    fn test_extract_client_max_payload_standard_and_edns() {
        // Standard query without EDNS
        let mut query = Message::new(1234, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("example.com.").unwrap();
        query.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        let mut query_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut query_bytes);
        query.emit(&mut enc).unwrap();

        assert_eq!(extract_client_max_payload(&query_bytes), 512);

        // Query with EDNS0 OPT specifying 2048 buffer size
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(2048);
        query.set_edns(edns);

        let mut edns_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut edns_bytes);
        query.emit(&mut enc).unwrap();

        assert_eq!(extract_client_max_payload(&edns_bytes), 2048);
    }

    #[test]
    fn test_prepare_client_response_truncation() {
        // Build a large response with many A records (>512 bytes)
        let mut response = Message::new(
            1234,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        let qname = Name::from_ascii("example.com.").unwrap();
        response.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        for i in 0..50 {
            let record = Record::from_rdata(
                qname.clone(),
                300,
                RData::A(A(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))),
            );
            response.add_answer(record);
        }
        let mut large_resp = Vec::new();
        let mut enc = BinEncoder::new(&mut large_resp);
        response.emit(&mut enc).unwrap();
        assert!(large_resp.len() > 512);

        // For a client with 512-byte max payload, prepare_client_response must set TC=1 and truncate
        let truncated = prepare_client_response(large_resp.clone(), 512);
        assert!(truncated.len() <= 512);
        let decoded = Message::from_bytes(&truncated).unwrap();
        assert!(
            decoded.truncation,
            "TC flag must be set on truncated response"
        );

        // For a client with 4096-byte max payload, large_resp should fit untouched
        let untouched = prepare_client_response(large_resp.clone(), 4096);
        assert_eq!(untouched.len(), large_resp.len());
        let decoded = Message::from_bytes(&untouched).unwrap();
        assert!(
            !decoded.truncation,
            "TC flag must not be set when response fits"
        );
    }

    #[tokio::test]
    async fn test_tcp_dns_framing_read_and_write() {
        let (client_sock, server_sock) = tokio::net::UnixStream::pair().unwrap();
        let (mut client_r, mut client_w) = client_sock.into_split();
        let (mut server_r, mut server_w) = server_sock.into_split();

        // Write a 16-byte dummy DNS query with 2-byte big-endian length prefix
        let payload = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x61,
            0x00, 0x01,
        ];
        let len_bytes = (payload.len() as u16).to_be_bytes();
        client_w.write_all(&len_bytes).await.unwrap();
        client_w.write_all(&payload).await.unwrap();

        let read_query = read_tcp_dns_query(&mut server_r)
            .await
            .expect("query read successfully");
        assert_eq!(read_query, payload);

        // Write response back to client
        let response_payload = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        write_tcp_dns_reply(&mut server_w, &response_payload)
            .await
            .unwrap();

        let mut resp_len_buf = [0u8; 2];
        client_r.read_exact(&mut resp_len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;
        assert_eq!(resp_len, response_payload.len());

        let mut resp_buf = vec![0u8; resp_len];
        client_r.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf, response_payload);
    }

    #[tokio::test]
    async fn test_handle_tcp_query_local_resolution() {
        let mut local_hosts = HashMap::new();
        let mut local_ips = HashMap::new();
        let router_ip = Ipv4Addr::new(192, 168, 1, 1);
        local_hosts.insert("router".to_string(), router_ip);
        local_ips.insert(router_ip, "router".to_string());

        let mut query = Message::new(0x4321, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("router.lan.").unwrap();
        query.add_query(hickory_proto::op::Query::query(qname, RecordType::A));
        let mut query_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut query_bytes);
        query.emit(&mut enc).unwrap();

        let (reply_tx, reply_rx) = oneshot_channel();
        let req = TcpQueryRequest {
            query: query_bytes,
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 54321),
            reply_tx,
        };

        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_servers = vec![Ipv4Addr::new(8, 8, 8, 8)];
        let ctx = ForwarderContext {
            sockets: ForwarderSockets {
                dns: &dummy_dns,
                upstream: &dummy_upstream,
            },
            local_table: LocalDnsTable {
                hosts: &local_hosts,
                ips: &local_ips,
            },
            configured_servers: &upstream_servers,
        };
        let mut cache = HashMap::new();
        let mut pending = HashMap::new();
        let mut rate_limiter = DnsRateLimiter::default();

        handle_incoming_query(
            &req.query,
            ClientOrigin::Tcp {
                peer_addr: req.peer_addr,
                reply_tx: req.reply_tx,
            },
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;

        let reply = reply_rx.await.expect("received reply on oneshot channel");
        let decoded = Message::from_bytes(&reply).expect("valid DNS message");
        assert_eq!(decoded.id, 0x4321);
        assert_eq!(
            decoded.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert_eq!(decoded.answers.len(), 1);
        if let RData::A(A(ip)) = &decoded.answers[0].data {
            assert_eq!(*ip, router_ip);
        } else {
            panic!("expected A record");
        }
    }

    #[tokio::test]
    async fn test_handle_tcp_query_cache_hit() {
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_servers = vec![Ipv4Addr::new(8, 8, 8, 8)];
        let ctx = ForwarderContext {
            sockets: ForwarderSockets {
                dns: &dummy_dns,
                upstream: &dummy_upstream,
            },
            local_table: LocalDnsTable {
                hosts: &local_hosts,
                ips: &local_ips,
            },
            configured_servers: &upstream_servers,
        };

        // Populate cache for example.com
        let mut cached_msg = Message::new(
            0x1111,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        let qname = Name::from_ascii("example.com.").unwrap();
        cached_msg.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        cached_msg.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        let mut cached_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut cached_bytes);
        cached_msg.emit(&mut enc).unwrap();

        let mut cache = HashMap::new();
        let cache_key = get_cache_key(&cached_bytes).unwrap();
        insert_cache(cache_key, cached_bytes, &mut cache);

        // Client query with a different XID (0x9999)
        let mut client_query =
            Message::new(0x9999, hickory_proto::op::MessageType::Query, OpCode::Query);
        client_query.add_query(hickory_proto::op::Query::query(qname, RecordType::A));
        let mut query_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut query_bytes);
        client_query.emit(&mut enc).unwrap();

        let (reply_tx, reply_rx) = oneshot_channel();
        let req = TcpQueryRequest {
            query: query_bytes,
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 54321),
            reply_tx,
        };
        let mut pending = HashMap::new();
        let mut rate_limiter = DnsRateLimiter::default();

        handle_incoming_query(
            &req.query,
            ClientOrigin::Tcp {
                peer_addr: req.peer_addr,
                reply_tx: req.reply_tx,
            },
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;

        let reply = reply_rx.await.expect("received reply on oneshot channel");
        let decoded = Message::from_bytes(&reply).expect("valid DNS message");
        assert_eq!(decoded.id, 0x9999, "Response ID must match query ID");
        assert_eq!(decoded.answers.len(), 1);
    }

    #[tokio::test]
    async fn test_handle_tcp_query_upstream_reply_routing() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_server = Ipv4Addr::new(8, 8, 8, 8);
        let from_addr = SocketAddr::new(IpAddr::V4(upstream_server), DNS_PORT);

        let (reply_tx, reply_rx) = oneshot_channel();
        let mut pending = HashMap::new();
        let upstream_xid = 0xbeef;
        let client_xid = 0x1234;

        let qname = Name::from_ascii("example.com.").unwrap();
        let cache_key = b"example.com.:A:IN".to_vec();

        pending.insert(
            upstream_xid,
            PendingQuery {
                clients: vec![PendingClient {
                    origin: ClientOrigin::Tcp {
                        peer_addr: from_addr,
                        reply_tx,
                    },
                    client_xid,
                    client_max_payload: MAX_EDNS_PAYLOAD_SIZE,
                }],
                cache_key: cache_key.clone(),
                query_payload: vec![],
                upstream_servers: vec![upstream_server],
                current_server_idx: 0,
                deadline: Instant::now() + UPSTREAM_TIMEOUT,
            },
        );

        let mut upstream_resp = Message::new(
            upstream_xid,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        upstream_resp.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        upstream_resp.add_answer(Record::from_rdata(
            qname,
            300,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        ));
        let mut resp_bytes = Vec::new();
        let mut resp_enc = BinEncoder::new(&mut resp_bytes);
        upstream_resp.emit(&mut resp_enc).unwrap();

        let mut cache = HashMap::new();
        let dummy_upstream = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let (tcp_event_tx, _tcp_event_rx) = mpsc_channel(32);
        handle_upstream_reply(
            &resp_bytes,
            from_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;

        let reply = reply_rx
            .await
            .expect("received reply on TCP oneshot channel");
        let decoded = Message::from_bytes(&reply).expect("valid DNS message");
        assert_eq!(decoded.id, client_xid, "Response ID must match client XID");
        assert_eq!(decoded.answers.len(), 1);
        assert!(cache.contains_key(&cache_key[..]));
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn test_in_flight_query_deduplication_and_multi_client_fanout() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let upstream_servers = vec![Ipv4Addr::new(8, 8, 8, 8)];
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();
        let ctx = ForwarderContext {
            sockets: ForwarderSockets {
                dns: &dummy_dns,
                upstream: &dummy_upstream,
            },
            local_table: LocalDnsTable {
                hosts: &local_hosts,
                ips: &local_ips,
            },
            configured_servers: &upstream_servers,
        };

        let mut cache = HashMap::new();
        let mut pending = HashMap::new();
        let mut rate_limiter = DnsRateLimiter::default();

        let qname = Name::from_ascii("dedup.test.").unwrap();
        let client_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 11111);
        let client_addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 22222);

        let q1 = build_test_query(0x1111, qname.clone());
        let q2 = build_test_query(0x2222, qname.clone());
        let q3 = build_test_query(0x3333, qname.clone());

        // Client 1 (UDP) initiates upstream query
        handle_incoming_query(
            &q1,
            ClientOrigin::Udp(client_addr1),
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;
        assert_eq!(pending.len(), 1);

        // Client 2 (UDP) joins in-flight query
        handle_incoming_query(
            &q2,
            ClientOrigin::Udp(client_addr2),
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;
        assert_eq!(pending.len(), 1);

        // Client 3 (TCP) joins in-flight query
        let (reply_tx, reply_rx) = oneshot_channel();
        let tcp_origin = ClientOrigin::Tcp {
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 30)), 33333),
            reply_tx,
        };
        handle_incoming_query(
            &q3,
            tcp_origin,
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;
        assert_eq!(pending.len(), 1);

        let (upstream_xid, in_flight) = pending.iter().next().unwrap();
        let upstream_xid = *upstream_xid;
        assert_eq!(in_flight.clients.len(), 3, "All 3 clients must be joined");

        // Send upstream reply
        let resp_bytes = build_test_response(upstream_xid, qname, Ipv4Addr::new(4, 3, 2, 1));
        let from_addr = SocketAddr::new(IpAddr::V4(upstream_servers[0]), DNS_PORT);
        let (tcp_event_tx, _tcp_event_rx) = mpsc_channel(32);
        handle_upstream_reply(
            &resp_bytes,
            from_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;

        assert!(
            pending.is_empty(),
            "Pending map must be cleared after reply"
        );
        let tcp_reply = reply_rx.await.expect("TCP client must receive response");
        let tcp_msg = Message::from_bytes(&tcp_reply).unwrap();
        assert_eq!(tcp_msg.id, 0x3333, "TCP client must receive its own XID");
    }

    #[test]
    fn test_try_join_in_flight_query_capacity_limit() {
        let mut pending = HashMap::new();
        let cache_key = b"limit.test.:A:IN".to_vec();
        let mut clients = Vec::new();
        for idx in 0..MAX_JOINED_CLIENTS_PER_QUERY {
            clients.push(PendingClient {
                origin: ClientOrigin::Udp(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    1000 + idx as u16,
                )),
                client_xid: idx as u16,
                client_max_payload: 512,
            });
        }
        pending.insert(
            0x4444,
            PendingQuery {
                clients,
                cache_key: cache_key.clone(),
                query_payload: vec![],
                upstream_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
                current_server_idx: 0,
                deadline: Instant::now() + UPSTREAM_TIMEOUT,
            },
        );

        let query = vec![0u8; DNS_HEADER_SIZE];
        let origin = ClientOrigin::Udp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            9999,
        ));
        let mut origin_opt = Some(origin);
        let joined = try_join_in_flight_query(&mut pending, &cache_key, &query, &mut origin_opt);
        assert!(
            !joined,
            "Joining must be rejected once MAX_JOINED_CLIENTS_PER_QUERY is reached"
        );
        assert!(
            origin_opt.is_some(),
            "Origin must not be consumed when joining fails"
        );
    }

    fn build_test_query(id: u16, qname: Name) -> Vec<u8> {
        let mut query = Message::new(id, hickory_proto::op::MessageType::Query, OpCode::Query);
        query.add_query(hickory_proto::op::Query::query(qname, RecordType::A));
        let mut bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut bytes);
        query.emit(&mut enc).unwrap();
        bytes
    }

    fn build_test_response(id: u16, qname: Name, ip: Ipv4Addr) -> Vec<u8> {
        let mut resp = Message::new(id, hickory_proto::op::MessageType::Response, OpCode::Query);
        resp.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        resp.add_answer(Record::from_rdata(qname, 300, RData::A(A(ip))));
        let mut bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut bytes);
        resp.emit(&mut enc).unwrap();
        bytes
    }

    #[tokio::test]
    async fn test_multiple_concurrent_tcp_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let (tcp_query_tx, mut tcp_query_rx) = mpsc_channel::<TcpQueryRequest>(64);
        let mut local_hosts = HashMap::new();
        let mut local_ips = HashMap::new();
        let router_ip = Ipv4Addr::new(192, 168, 1, 1);
        local_hosts.insert("router".to_string(), router_ip);
        local_ips.insert(router_ip, "router".to_string());

        let tx_accept = tcp_query_tx.clone();
        tokio::spawn(async move {
            while let Ok((stream, peer_addr)) = listener.accept().await {
                let tx = tx_accept.clone();
                tokio::spawn(handle_tcp_client_connection(stream, peer_addr, tx));
            }
        });

        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_servers = vec![Ipv4Addr::new(8, 8, 8, 8)];
        tokio::spawn(async move {
            let ctx = ForwarderContext {
                sockets: ForwarderSockets {
                    dns: &dummy_dns,
                    upstream: &dummy_upstream,
                },
                local_table: LocalDnsTable {
                    hosts: &local_hosts,
                    ips: &local_ips,
                },
                configured_servers: &upstream_servers,
            };
            let mut cache = HashMap::new();
            let mut pending = HashMap::new();
            let mut rate_limiter = DnsRateLimiter::default();
            while let Some(req) = tcp_query_rx.recv().await {
                handle_incoming_query(
                    &req.query,
                    ClientOrigin::Tcp {
                        peer_addr: req.peer_addr,
                        reply_tx: req.reply_tx,
                    },
                    &ctx,
                    &mut cache,
                    &mut pending,
                    &mut rate_limiter,
                    &mut DnsStatsInfo::default(),
                )
                .await;
            }
        });

        let mut handles = Vec::new();
        for client_idx in 0..8u16 {
            handles.push(tokio::spawn(perform_client_tcp_query(
                server_addr,
                client_idx,
            )));
        }

        for h in handles {
            h.await.unwrap();
        }
    }

    async fn perform_client_tcp_query(server_addr: SocketAddr, client_idx: u16) {
        let mut stream = TcpStream::connect(server_addr).await.unwrap();
        let xid = 0x1000 + client_idx;
        let mut query = Message::new(xid, hickory_proto::op::MessageType::Query, OpCode::Query);
        let qname = Name::from_ascii("router.lan.").unwrap();
        query.add_query(hickory_proto::op::Query::query(qname, RecordType::A));
        let mut query_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut query_bytes);
        query.emit(&mut enc).unwrap();

        let len_prefix = (query_bytes.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await.unwrap();
        stream.write_all(&query_bytes).await.unwrap();

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).await.unwrap();

        let resp_msg = Message::from_bytes(&resp_buf).unwrap();
        assert_eq!(resp_msg.id, xid);
        assert_eq!(resp_msg.answers.len(), 1);
    }

    #[tokio::test]
    async fn test_in_flight_fanout_heterogeneous_edns_truncation() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let upstream_servers = vec![Ipv4Addr::new(8, 8, 8, 8)];
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();
        let ctx = ForwarderContext {
            sockets: ForwarderSockets {
                dns: &dummy_dns,
                upstream: &dummy_upstream,
            },
            local_table: LocalDnsTable {
                hosts: &local_hosts,
                ips: &local_ips,
            },
            configured_servers: &upstream_servers,
        };

        let mut cache = HashMap::new();
        let mut pending = HashMap::new();
        let mut rate_limiter = DnsRateLimiter::default();
        let qname = Name::from_ascii("large.example.com.").unwrap();

        let q1 = build_test_query(0x1001, qname.clone());
        let (reply_tx_tcp, reply_rx_tcp) = oneshot_channel();

        let mut q2_msg = Message::new(0x2002, hickory_proto::op::MessageType::Query, OpCode::Query);
        q2_msg.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        let mut q2 = Vec::new();
        let mut enc = BinEncoder::new(&mut q2);
        q2_msg.emit(&mut enc).unwrap();

        handle_incoming_query(
            &q1,
            ClientOrigin::Udp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                10001,
            )),
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;

        handle_incoming_query(
            &q2,
            ClientOrigin::Tcp {
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 20002),
                reply_tx: reply_tx_tcp,
            },
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;

        let (&upstream_xid, _) = pending.iter().next().unwrap();

        let mut large_resp = Message::new(
            upstream_xid,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        large_resp.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        for i in 0..40 {
            large_resp.add_answer(Record::from_rdata(
                qname.clone(),
                300,
                RData::A(A(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8))),
            ));
        }
        let mut large_resp_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut large_resp_bytes);
        large_resp.emit(&mut enc).unwrap();
        assert!(large_resp_bytes.len() > 512);

        let from_addr = SocketAddr::new(IpAddr::V4(upstream_servers[0]), DNS_PORT);
        let (tcp_event_tx, _tcp_event_rx) = mpsc_channel(32);
        handle_upstream_reply(
            &large_resp_bytes,
            from_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;

        let tcp_reply = reply_rx_tcp.await.unwrap();
        assert_eq!(
            tcp_reply.len(),
            large_resp_bytes.len(),
            "TCP client receives full untruncated payload"
        );
    }

    #[tokio::test]
    async fn test_handle_upstream_reply_spoofed_source_ip_and_port_rejected() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let upstream_server = Ipv4Addr::new(8, 8, 8, 8);
        let legitimate_addr = SocketAddr::new(IpAddr::V4(upstream_server), DNS_PORT);

        let (reply_tx, mut reply_rx) = oneshot_channel();
        let (tcp_event_tx, _tcp_event_rx) = mpsc_channel(32);
        let mut pending = HashMap::new();
        let upstream_xid = 0xbeef;
        let client_xid = 0x1234;
        let qname = Name::from_ascii("secure.test.").unwrap();
        let cache_key = b"secure.test.:A:IN".to_vec();

        pending.insert(
            upstream_xid,
            PendingQuery {
                clients: vec![PendingClient {
                    origin: ClientOrigin::Tcp {
                        peer_addr: SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                            50000,
                        ),
                        reply_tx,
                    },
                    client_xid,
                    client_max_payload: 512,
                }],
                cache_key: cache_key.clone(),
                query_payload: vec![],
                upstream_servers: vec![upstream_server],
                current_server_idx: 0,
                deadline: Instant::now() + UPSTREAM_TIMEOUT,
            },
        );

        let resp_bytes =
            build_test_response(upstream_xid, qname.clone(), Ipv4Addr::new(6, 6, 6, 6));
        let mut cache = HashMap::new();

        // 1. Spoofed IP (1.1.1.1:53) rejected
        let spoofed_ip_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), DNS_PORT);
        handle_upstream_reply(
            &resp_bytes,
            spoofed_ip_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;
        assert!(cache.is_empty(), "Spoofed IP packet must not be cached");
        assert_eq!(
            pending.len(),
            1,
            "Query must remain pending after spoofed IP"
        );
        assert!(
            reply_rx.try_recv().is_err(),
            "Client must not receive spoofed reply"
        );

        // 2. Spoofed port (8.8.8.8:5353) rejected
        let spoofed_port_addr = SocketAddr::new(IpAddr::V4(upstream_server), 5353);
        handle_upstream_reply(
            &resp_bytes,
            spoofed_port_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;
        assert!(cache.is_empty(), "Spoofed port packet must not be cached");
        assert_eq!(
            pending.len(),
            1,
            "Query must remain pending after spoofed port"
        );

        // 3. Legitimate response accepted
        handle_upstream_reply(
            &resp_bytes,
            legitimate_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;
        assert_eq!(cache.len(), 1, "Legitimate packet is cached");
        assert!(pending.is_empty(), "Pending query cleared");
        let delivered = reply_rx
            .try_recv()
            .expect("Client receives legitimate reply");
        assert_eq!(delivered.len(), resp_bytes.len());
    }

    #[tokio::test]
    async fn test_in_flight_dedup_cross_type_isolation() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let upstream_servers = vec![Ipv4Addr::new(8, 8, 8, 8)];
        let local_hosts = HashMap::new();
        let local_ips = HashMap::new();
        let ctx = ForwarderContext {
            sockets: ForwarderSockets {
                dns: &dummy_dns,
                upstream: &dummy_upstream,
            },
            local_table: LocalDnsTable {
                hosts: &local_hosts,
                ips: &local_ips,
            },
            configured_servers: &upstream_servers,
        };

        let mut cache = HashMap::new();
        let mut pending = HashMap::new();
        let mut rate_limiter = DnsRateLimiter::default();
        let qname = Name::from_ascii("isolation.test.").unwrap();

        let mut q_a_msg =
            Message::new(0x1000, hickory_proto::op::MessageType::Query, OpCode::Query);
        q_a_msg.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        let mut q_a = Vec::new();
        let mut enc = BinEncoder::new(&mut q_a);
        q_a_msg.emit(&mut enc).unwrap();

        let mut q_aaaa_msg =
            Message::new(0x2000, hickory_proto::op::MessageType::Query, OpCode::Query);
        q_aaaa_msg.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::AAAA,
        ));
        let mut q_aaaa = Vec::new();
        let mut enc = BinEncoder::new(&mut q_aaaa);
        q_aaaa_msg.emit(&mut enc).unwrap();

        handle_incoming_query(
            &q_a,
            ClientOrigin::Udp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                10000,
            )),
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;

        handle_incoming_query(
            &q_aaaa,
            ClientOrigin::Udp(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
                20000,
            )),
            &ctx,
            &mut cache,
            &mut pending,
            &mut rate_limiter,
            &mut DnsStatsInfo::default(),
        )
        .await;

        assert_eq!(
            pending.len(),
            2,
            "A and AAAA queries must NOT coalesce into one request"
        );
    }

    #[tokio::test]
    async fn test_tcp_dns_framing_invalid_lengths_and_eof() {
        let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
        client.write_all(&5u16.to_be_bytes()).await.unwrap();
        client.write_all(&[1, 2, 3, 4, 5]).await.unwrap();
        assert_eq!(read_tcp_dns_query(&mut server).await, None);

        let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
        client.write_all(&0u16.to_be_bytes()).await.unwrap();
        assert_eq!(read_tcp_dns_query(&mut server).await, None);

        let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
        client.write_all(&20u16.to_be_bytes()).await.unwrap();
        client.write_all(&[1, 2, 3]).await.unwrap();
        drop(client);
        assert_eq!(read_tcp_dns_query(&mut server).await, None);
    }

    #[test]
    fn test_extract_client_max_payload_bounds_clamping() {
        let qname = Name::from_ascii("bounds.test.").unwrap();

        let mut q_small = Message::new(0x100, hickory_proto::op::MessageType::Query, OpCode::Query);
        q_small.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        let mut edns_small = hickory_proto::op::Edns::new();
        edns_small.set_max_payload(100);
        q_small.set_edns(edns_small);
        let mut bytes_small = Vec::new();
        let mut enc = BinEncoder::new(&mut bytes_small);
        q_small.emit(&mut enc).unwrap();
        assert_eq!(extract_client_max_payload(&bytes_small), 512);

        let mut q_large = Message::new(0x200, hickory_proto::op::MessageType::Query, OpCode::Query);
        q_large.add_query(hickory_proto::op::Query::query(qname, RecordType::A));
        let mut edns_large = hickory_proto::op::Edns::new();
        edns_large.set_max_payload(65535);
        q_large.set_edns(edns_large);
        let mut bytes_large = Vec::new();
        let mut enc = BinEncoder::new(&mut bytes_large);
        q_large.emit(&mut enc).unwrap();
        assert_eq!(extract_client_max_payload(&bytes_large), 4096);
    }

    #[test]
    fn test_negative_caching_soa_clamping_bounds() {
        let mut msg_low = Message::new(1, hickory_proto::op::MessageType::Response, OpCode::Query);

        msg_low.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain;
        let soa_low = SOA::new(
            Name::from_ascii("ns.test.").unwrap(),
            Name::from_ascii("hostmaster.test.").unwrap(),
            1,
            7200,
            3600,
            1209600,
            0,
        );
        msg_low.add_authority(Record::from_rdata(
            Name::from_ascii("test.").unwrap(),
            300,
            RData::SOA(soa_low),
        ));
        assert_eq!(calculate_cache_ttl(&msg_low), Some(Duration::from_secs(5)));

        let mut msg_high = Message::new(2, hickory_proto::op::MessageType::Response, OpCode::Query);
        msg_high.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain;
        let soa_high = SOA::new(
            Name::from_ascii("ns.test.").unwrap(),
            Name::from_ascii("hostmaster.test.").unwrap(),
            1,
            7200,
            3600,
            1209600,
            100_000,
        );
        msg_high.add_authority(Record::from_rdata(
            Name::from_ascii("test.").unwrap(),
            100_000,
            RData::SOA(soa_high),
        ));
        assert_eq!(
            calculate_cache_ttl(&msg_high),
            Some(Duration::from_secs(300))
        );
    }

    #[tokio::test]
    async fn test_upstream_failover_on_servfail_advances_to_secondary() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let server1 = Ipv4Addr::new(8, 8, 8, 8);
        let server2 = Ipv4Addr::new(8, 8, 4, 4);
        let upstream_servers = vec![server1, server2];

        let (reply_tx, mut reply_rx) = oneshot_channel();
        let (tcp_event_tx, _tcp_event_rx) = mpsc_channel(32);
        let mut pending = HashMap::new();
        let upstream_xid = 0x5555;
        let client_xid = 0x1111;
        let qname = Name::from_ascii("failover.test.").unwrap();
        let cache_key = b"failover.test.:A:IN".to_vec();

        pending.insert(
            upstream_xid,
            PendingQuery {
                clients: vec![PendingClient {
                    origin: ClientOrigin::Tcp {
                        peer_addr: SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                            50000,
                        ),
                        reply_tx,
                    },
                    client_xid,
                    client_max_payload: 512,
                }],
                cache_key: cache_key.clone(),
                query_payload: build_test_query(client_xid, qname.clone()),
                upstream_servers: upstream_servers.clone(),
                current_server_idx: 0,
                deadline: Instant::now() + UPSTREAM_TIMEOUT,
            },
        );

        let mut cache = HashMap::new();

        // 1. Server 1 returns SERVFAIL
        let mut servfail_msg = Message::new(
            upstream_xid,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        servfail_msg.metadata.response_code = hickory_proto::op::ResponseCode::ServFail;
        servfail_msg.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        let mut servfail_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut servfail_bytes);
        servfail_msg.emit(&mut enc).unwrap();

        let server1_addr = SocketAddr::new(IpAddr::V4(server1), DNS_PORT);
        handle_upstream_reply(
            &servfail_bytes,
            server1_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;

        // Query must still be pending and advanced to server 2
        assert_eq!(pending.len(), 1);
        let query = pending.get(&upstream_xid).unwrap();
        assert_eq!(query.current_server_idx, 1);
        assert!(reply_rx.try_recv().is_err(), "No reply sent to client yet");

        // 2. Server 2 returns valid NoError response
        let success_bytes =
            build_test_response(upstream_xid, qname.clone(), Ipv4Addr::new(9, 9, 9, 9));
        let server2_addr = SocketAddr::new(IpAddr::V4(server2), DNS_PORT);
        handle_upstream_reply(
            &success_bytes,
            server2_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;

        assert!(pending.is_empty(), "Pending query cleared after success");
        assert_eq!(cache.len(), 1, "Successful response is cached");
        let delivered = reply_rx.try_recv().expect("Client receives reply");
        let decoded = Message::from_bytes(&delivered).unwrap();
        assert_eq!(
            decoded.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
    }

    #[tokio::test]
    async fn test_upstream_failover_all_servers_servfail_delivers_error() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dummy_upstream = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let server1 = Ipv4Addr::new(8, 8, 8, 8);
        let server2 = Ipv4Addr::new(8, 8, 4, 4);
        let upstream_servers = vec![server1, server2];

        let (reply_tx, mut reply_rx) = oneshot_channel();
        let (tcp_event_tx, _tcp_event_rx) = mpsc_channel(32);
        let mut pending = HashMap::new();
        let upstream_xid = 0x6666;
        let client_xid = 0x2222;
        let qname = Name::from_ascii("allfail.test.").unwrap();
        let cache_key = b"allfail.test.:A:IN".to_vec();

        pending.insert(
            upstream_xid,
            PendingQuery {
                clients: vec![PendingClient {
                    origin: ClientOrigin::Tcp {
                        peer_addr: SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                            50000,
                        ),
                        reply_tx,
                    },
                    client_xid,
                    client_max_payload: 512,
                }],
                cache_key: cache_key.clone(),
                query_payload: build_test_query(client_xid, qname.clone()),
                upstream_servers: upstream_servers.clone(),
                current_server_idx: 1, // Already on last server
                deadline: Instant::now() + UPSTREAM_TIMEOUT,
            },
        );

        let mut cache = HashMap::new();
        let mut servfail_msg = Message::new(
            upstream_xid,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        servfail_msg.metadata.response_code = hickory_proto::op::ResponseCode::ServFail;
        servfail_msg.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::A,
        ));
        let mut servfail_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut servfail_bytes);
        servfail_msg.emit(&mut enc).unwrap();

        let server2_addr = SocketAddr::new(IpAddr::V4(server2), DNS_PORT);
        handle_upstream_reply(
            &servfail_bytes,
            server2_addr,
            &dummy_dns,
            &dummy_upstream,
            &mut cache,
            &mut pending,
            &tcp_event_tx,
        )
        .await;

        assert!(pending.is_empty(), "Pending query cleared");
        assert!(cache.is_empty(), "ServFail must NOT be cached");
        let delivered = reply_rx.try_recv().expect("Client receives error response");
        let decoded = Message::from_bytes(&delivered).unwrap();
        assert_eq!(
            decoded.response_code,
            hickory_proto::op::ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn test_upstream_tcp_fallback_event_handling() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut cache = HashMap::new();
        let (reply_tx, reply_rx) = oneshot_channel();
        let client_xid = 0x7777;
        let qname = Name::from_ascii("tcpfallback.test.").unwrap();
        let cache_key = b"tcpfallback.test.:A:IN".to_vec();

        let full_resp = build_test_response(0x9999, qname, Ipv4Addr::new(1, 2, 3, 4));
        let clients = vec![PendingClient {
            origin: ClientOrigin::Tcp {
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 50000),
                reply_tx,
            },
            client_xid,
            client_max_payload: 4096,
        }];

        let event = UpstreamTcpEvent::Resolved {
            cache_key: cache_key.clone(),
            reply: full_resp.clone(),
            clients,
        };

        handle_upstream_tcp_event(event, &dummy_dns, &mut cache).await;

        assert!(cache.contains_key(&cache_key[..]));
        let delivered = reply_rx
            .await
            .expect("Client receives reply via TCP fallback event");
        let decoded = Message::from_bytes(&delivered).unwrap();
        assert_eq!(decoded.id, client_xid);
        assert_eq!(decoded.answers.len(), 1);
    }

    #[tokio::test]
    async fn test_upstream_tcp_fallback_failed_event_delivers_truncated() {
        let dummy_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut cache = HashMap::new();
        let (reply_tx, reply_rx) = oneshot_channel();
        let client_xid = 0x8888;
        let qname = Name::from_ascii("tcptrunc.test.").unwrap();

        let mut trunc_msg = Message::new(
            0x9999,
            hickory_proto::op::MessageType::Response,
            OpCode::Query,
        );
        trunc_msg.metadata.truncation = true;
        trunc_msg.add_query(hickory_proto::op::Query::query(qname, RecordType::A));
        let mut trunc_bytes = Vec::new();
        let mut enc = BinEncoder::new(&mut trunc_bytes);
        trunc_msg.emit(&mut enc).unwrap();

        let clients = vec![PendingClient {
            origin: ClientOrigin::Tcp {
                peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 50000),
                reply_tx,
            },
            client_xid,
            client_max_payload: 512,
        }];

        let event = UpstreamTcpEvent::Failed {
            fallback_reply: trunc_bytes.clone(),
            clients,
        };

        handle_upstream_tcp_event(event, &dummy_dns, &mut cache).await;

        assert!(cache.is_empty(), "Failed TCP response not cached");
        let delivered = reply_rx
            .await
            .expect("Client receives fallback truncated reply");
        let decoded = Message::from_bytes(&delivered).unwrap();
        assert!(decoded.truncation);
        assert_eq!(decoded.id, client_xid);
    }
}
