use crate::packet::build_raw_packet;
use crate::services::ipc::{DhcpServerParentToWorkerMsg, recv_msg};
use crate::services::utils::{
    DHCP_SERVER_GID, DHCP_SERVER_UID, get_interface_mac, mac_from_slice, parse_dhcp_payload,
    read_raw_packet, run_sandboxed_worker, send_raw_packet, wait_shutdown,
};
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Encodable, Encoder};
use log::{debug, error, info, warn};
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage};
use std::net::Ipv4Addr;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::watch::Sender;

use super::lease_table::{LeaseHandle, LeaseTable, spawn_lease_actor, update_lease_from_neighbor};

const LAN_LEASE_SECS: u32 = 3600;
const ARP_RESOLUTION_DELAY: Duration = Duration::from_millis(100);
const DISCARD_PORT: u16 = 9;
const CONFLICT_HOLD_DURATION: Duration = Duration::from_secs(300);

// =========================================================================
// DHCP Server (LAN)
// =========================================================================

/// Fixed server configuration derived from the LAN interface at startup.
/// Passed by reference throughout the server loop to avoid repeating
/// individual fields as function arguments.
struct ServerConfig {
    server_ip: Ipv4Addr,
    subnet_mask: Ipv4Addr,
    server_mac: MacAddr,
    net: ipnet::Ipv4Net,
}

pub async fn run_dhcp_server_worker(
    ipc_fd: OwnedFd,
    raw_socket_fd: OwnedFd,
    lan_interface: String,
    lan_ip: String,
) -> Result<(), std::io::Error> {
    let net: ipnet::Ipv4Net = lan_ip.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid LAN IP: {}", e),
        )
    })?;
    let server_ip = net.addr();
    let subnet_mask = net.netmask();

    let mac = get_interface_mac(&lan_interface)
        .await
        .map_err(std::io::Error::other)?;
    let async_sock = AsyncFd::new(raw_socket_fd)?;

    run_sandboxed_worker(
        "dhcp-server",
        DHCP_SERVER_UID,
        DHCP_SERVER_GID,
        ipc_fd,
        |ipc| async move {
            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            let leases = spawn_lease_actor(shutdown_rx.clone());

            tokio::spawn(run_dhcp_server_ipc_monitor(
                ipc.reader,
                ipc.writer,
                leases.clone(),
                shutdown_tx,
            ));

            let config = Arc::new(ServerConfig {
                server_ip,
                subnet_mask,
                server_mac: mac,
                net,
            });

            let async_sock_shared = Arc::new(async_sock);
            let mut shutdown_rx_clone = shutdown_rx.clone();
            let _ =
                run_server_loop(async_sock_shared, config, leases, &mut shutdown_rx_clone).await;
            Ok(())
        },
    )
    .await
}

async fn run_dhcp_server_ipc_monitor(
    mut reader: OwnedReadHalf,
    _writer: OwnedWriteHalf,
    leases: LeaseHandle,
    shutdown_tx: Sender<bool>,
) {
    let _keep_writer = _writer;
    loop {
        match recv_msg::<DhcpServerParentToWorkerMsg, _>(&mut reader).await {
            Ok(Some(DhcpServerParentToWorkerMsg::AddNeighbor {
                ip_address,
                mac_address,
            })) => {
                let mac = MacAddr::from(mac_address);
                leases.add_neighbor(mac, ip_address).await;
            }
            Ok(None) | Err(_) => {
                info!("[dhcp-server-worker] Parent closed IPC or error. Shutting down.");
                let _ = shutdown_tx.send(true);
                break;
            }
        }
    }
}

async fn receive_next_packet(
    async_sock: &AsyncFd<OwnedFd>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    buf: &mut [u8],
) -> Result<Option<usize>, std::io::Error> {
    let read_fut = read_raw_packet(async_sock, buf);
    let res = tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {
            return Ok(None);
        }
        r = read_fut => r,
    };

    match res {
        Ok(n) => Ok(Some(n)),
        Err(e) => {
            error!("[dhcp-server] Socket read error: {}. Recreating socket.", e);
            Err(e)
        }
    }
}

async fn run_server_loop(
    async_sock: Arc<AsyncFd<OwnedFd>>,
    config: Arc<ServerConfig>,
    leases: LeaseHandle,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 2048];
    loop {
        if *shutdown_rx.borrow() {
            return Ok(());
        }

        let Some(bytes_read) = receive_next_packet(&async_sock, shutdown_rx, &mut buf).await?
        else {
            return Ok(());
        };

        let pkt_data = buf[..bytes_read].to_vec();
        let async_sock_clone = Arc::clone(&async_sock);
        let config_clone = Arc::clone(&config);
        let leases_clone = leases.clone();

        tokio::spawn(async move {
            process_incoming_packet(pkt_data, async_sock_clone, config_clone, leases_clone).await;
        });
    }
}

async fn process_incoming_packet(
    buf: Vec<u8>,
    async_sock: Arc<AsyncFd<OwnedFd>>,
    config: Arc<ServerConfig>,
    leases: LeaseHandle,
) {
    let dhcp = match parse_dhcp_payload(&buf, dhcproto::v4::SERVER_PORT) {
        Some(d) => d,
        None => return,
    };

    if dhcp.opcode() != dhcproto::v4::Opcode::BootRequest {
        return;
    }

    let chaddr = dhcp.chaddr();
    let client_mac = match <[u8; 6]>::try_from(&chaddr[..dhcp.hlen() as usize]) {
        Ok(bytes) => MacAddr::from(bytes),
        Err(_) => return,
    };

    // Server-side anti-spoofing MAC check
    let eth = match EthernetPacket::new(&buf) {
        Some(e) => e,
        None => return,
    };
    let src_mac = eth.get_source();
    if dhcp.giaddr().is_unspecified() && src_mac != client_mac {
        warn!(
            "[dhcp-server] WARNING: Dropping spoofed DHCP packet: L2 source MAC ({}) does not match chaddr ({})!",
            src_mac, client_mac
        );
        return;
    }

    let msg_type = match dhcp.opts().get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(mtype)) => *mtype,
        _ => return,
    };

    match msg_type {
        MessageType::Discover => {
            handle_dhcp_discover(async_sock, &config, &dhcp, client_mac, leases).await;
        }
        MessageType::Request => {
            handle_dhcp_request(async_sock, &config, &dhcp, client_mac, leases).await;
        }
        MessageType::Decline => {
            let removed_ip = leases.release(client_mac).await;
            if let Some(ip) = removed_ip {
                info!(
                    "[dhcp-server] Received DHCPDECLINE from client MAC: {}. Removed lease for IP: {}.",
                    client_mac, ip
                );
            }
        }
        MessageType::Release => {
            let removed_ip = leases.release(client_mac).await;
            if let Some(ip) = removed_ip {
                info!(
                    "[dhcp-server] Received DHCPRELEASE from client MAC: {}. Released lease for IP: {}.",
                    client_mac, ip
                );
            }
        }
        _ => {}
    }
}

/// Builds and encodes the common DHCPOFFER / DHCPACK payload, differing only
/// in `msg_type`. Returns the encoded bytes or an error string.
fn build_dhcp_reply_payload(
    msg_type: MessageType,
    dhcp: &Message,
    leased_ip: Ipv4Addr,
    config: &ServerConfig,
) -> Result<Vec<u8>, String> {
    let mut reply = Message::default();
    reply.set_opcode(Opcode::BootReply);
    reply.set_xid(dhcp.xid());
    reply.set_flags(dhcp.flags());
    reply.set_yiaddr(leased_ip);
    reply.set_siaddr(config.server_ip);
    reply.set_chaddr(dhcp.chaddr());

    reply.opts_mut().insert(DhcpOption::MessageType(msg_type));
    reply
        .opts_mut()
        .insert(DhcpOption::ServerIdentifier(config.server_ip));
    reply
        .opts_mut()
        .insert(DhcpOption::SubnetMask(config.subnet_mask));
    reply
        .opts_mut()
        .insert(DhcpOption::Router(vec![config.server_ip]));
    reply
        .opts_mut()
        .insert(DhcpOption::DomainNameServer(vec![config.server_ip]));
    reply
        .opts_mut()
        .insert(DhcpOption::AddressLeaseTime(LAN_LEASE_SECS));

    let mut payload = Vec::new();
    reply
        .encode(&mut Encoder::new(&mut payload))
        .map_err(|e| format!("Failed to encode DHCP reply: {}", e))?;
    Ok(payload)
}

async fn send_dhcp_nak(
    async_sock: &AsyncFd<OwnedFd>,
    dhcp: &Message,
    client_mac: MacAddr,
    config: &ServerConfig,
) {
    let mut nak = Message::default();
    nak.set_opcode(Opcode::BootReply);
    nak.set_xid(dhcp.xid());
    nak.set_chaddr(dhcp.chaddr());
    nak.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Nak));
    nak.opts_mut()
        .insert(DhcpOption::ServerIdentifier(config.server_ip));

    let mut payload = Vec::new();
    if let Err(e) = nak.encode(&mut Encoder::new(&mut payload)) {
        error!("[dhcp-server] Failed to encode DHCPNAK: {}", e);
        return;
    }

    let (dest_mac, dest_ip) =
        get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, Ipv4Addr::BROADCAST);
    let frame = build_raw_packet(
        config.server_mac,
        dest_mac,
        config.server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &payload,
    );

    send_raw_packet(async_sock, &frame).await;
}

async fn trigger_arp_resolution(server_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    if let Ok(socket) = std::net::UdpSocket::bind((server_ip, 0)) {
        let _ = socket.send_to(&[0u8], (target_ip, DISCARD_PORT));
    }
    tokio::time::sleep(ARP_RESOLUTION_DELAY).await;
}

/// Process incoming Netlink neighbour table events (ARP additions/updates).
/// Maps active MAC-to-IP pairings directly into the DHCP lease table dynamically.
#[allow(dead_code)]
fn handle_neigh_message(msg: NeighbourMessage, leases: &mut LeaseTable) {
    let mut ip_opt = None;
    let mut mac_opt = None;

    // Parse out IP and MAC addresses from the Netlink message attributes
    for nla in msg.attributes {
        match nla {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)) => {
                ip_opt = Some(ip);
            }
            NeighbourAttribute::LinkLayerAddress(mac_bytes) if mac_bytes.len() == 6 => {
                mac_opt = mac_from_slice(&mac_bytes).ok();
            }
            _ => {}
        }
    }

    // Ignore messages lacking both IP and MAC attributes
    let (Some(ip), Some(mac)) = (ip_opt, mac_opt) else {
        return;
    };

    update_lease_from_neighbor(mac, ip, leases);
}

async fn probe_and_allocate_ip(
    config: &ServerConfig,
    client_mac: MacAddr,
    leases: &LeaseHandle,
) -> Option<Ipv4Addr> {
    loop {
        let ip = leases
            .allocate_candidate(client_mac, config.net, config.server_ip)
            .await?;

        debug!(
            "[dhcp-server] Probing if IP {} is already in use on the LAN...",
            ip
        );
        trigger_arp_resolution(config.server_ip, ip).await;

        if leases.check_conflict(ip, client_mac).await {
            warn!(
                "[dhcp-server] CONFLICT DETECTED: IP {} is active on LAN. Marking as temporarily reserved.",
                ip
            );
            leases.record_conflict(ip, CONFLICT_HOLD_DURATION).await;
        } else {
            return Some(ip);
        }
    }
}

async fn find_or_allocate_discover_ip(
    config: &ServerConfig,
    client_mac: MacAddr,
    leases: &LeaseHandle,
) -> Option<Ipv4Addr> {
    let existing_ip = leases.get_existing_ip(client_mac).await;

    if let Some(ip) = existing_ip {
        Some(ip)
    } else {
        probe_and_allocate_ip(config, client_mac, leases).await
    }
}

async fn send_dhcp_offer_reply(
    async_sock: &AsyncFd<OwnedFd>,
    config: &ServerConfig,
    dhcp: &Message,
    client_mac: MacAddr,
    leased_ip: Ipv4Addr,
) {
    let payload = match build_dhcp_reply_payload(MessageType::Offer, dhcp, leased_ip, config) {
        Ok(p) => p,
        Err(e) => {
            error!("[dhcp-server] ERROR: {}", e);
            return;
        }
    };

    let (dest_mac, dest_ip) = get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, leased_ip);
    let frame = build_raw_packet(
        config.server_mac,
        dest_mac,
        config.server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &payload,
    );

    send_raw_packet(async_sock, &frame).await;
    info!(
        "[dhcp-server] Sent DHCPOFFER of IP: {} to client.",
        leased_ip
    );
}

async fn handle_dhcp_discover(
    async_sock: Arc<AsyncFd<OwnedFd>>,
    config: &ServerConfig,
    dhcp: &Message,
    client_mac: MacAddr,
    leases: LeaseHandle,
) {
    debug!(
        "[dhcp-server] Received DHCPDISCOVER from client MAC: {}",
        client_mac
    );

    let Some(leased_ip) = find_or_allocate_discover_ip(config, client_mac, &leases).await else {
        error!("[dhcp-server] DHCP IP pool exhausted!");
        return;
    };

    leases
        .confirm_lease(
            client_mac,
            leased_ip,
            Duration::from_secs(LAN_LEASE_SECS as u64),
        )
        .await;

    send_dhcp_offer_reply(&async_sock, config, dhcp, client_mac, leased_ip).await;
}

async fn verify_arp_conflict(
    leased_ip: Ipv4Addr,
    client_mac: MacAddr,
    config: &ServerConfig,
    leases: &LeaseHandle,
) -> bool {
    debug!(
        "[dhcp-server] Performing ARP verification for requested IP {}...",
        leased_ip
    );
    trigger_arp_resolution(config.server_ip, leased_ip).await;

    if leases.check_conflict(leased_ip, client_mac).await {
        warn!(
            "[dhcp-server] CONFLICT DETECTED: IP {} is active on LAN with another MAC (requested by {}).",
            leased_ip, client_mac
        );
        leases
            .record_conflict(leased_ip, CONFLICT_HOLD_DURATION)
            .await;
        return true;
    }
    false
}

async fn send_dhcp_ack(
    async_sock: &AsyncFd<OwnedFd>,
    dhcp: &Message,
    client_mac: MacAddr,
    leased_ip: Ipv4Addr,
    config: &ServerConfig,
) {
    let payload = match build_dhcp_reply_payload(MessageType::Ack, dhcp, leased_ip, config) {
        Ok(p) => p,
        Err(e) => {
            error!("[dhcp-server] ERROR: {}", e);
            return;
        }
    };

    let (dest_mac, dest_ip) = get_dest_mac_ip(dhcp.flags().broadcast(), client_mac, leased_ip);
    let frame = build_raw_packet(
        config.server_mac,
        dest_mac,
        config.server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        &payload,
    );

    send_raw_packet(async_sock, &frame).await;
    info!("[dhcp-server] Sent DHCPACK of IP: {} to client.", leased_ip);
}

async fn handle_dhcp_request(
    async_sock: Arc<AsyncFd<OwnedFd>>,
    config: &ServerConfig,
    dhcp: &Message,
    client_mac: MacAddr,
    leases: LeaseHandle,
) {
    debug!(
        "[dhcp-server] Received DHCPREQUEST from client MAC: {}",
        client_mac
    );

    let requested_ip_opt = match dhcp.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    };

    let Some(leased_ip) = leases
        .validate_and_confirm_request(
            client_mac,
            requested_ip_opt,
            config.server_ip,
            config.net,
            Duration::from_secs(LAN_LEASE_SECS as u64),
        )
        .await
    else {
        warn!(
            "[dhcp-server] WARNING: Client {} requested invalid or conflicting IP. Sending NAK.",
            client_mac
        );
        send_dhcp_nak(&async_sock, dhcp, client_mac, config).await;
        return;
    };

    if verify_arp_conflict(leased_ip, client_mac, config, &leases).await {
        send_dhcp_nak(&async_sock, dhcp, client_mac, config).await;
        return;
    }

    send_dhcp_ack(&async_sock, dhcp, client_mac, leased_ip, config).await;
}

/// Returns true if `leased_ip` is valid for the requesting client:
/// - Within the server's subnet
/// - Not the server's own IP
/// - Not actively leased to a different MAC
#[cfg(test)]
fn validate_requested_ip(
    leased_ip: Ipv4Addr,
    client_mac: MacAddr,
    config: &ServerConfig,
    leases: &LeaseTable,
) -> bool {
    if leased_ip == config.server_ip || !config.net.contains(&leased_ip) {
        return false;
    }
    !leases.is_ip_taken_by_other(leased_ip, client_mac)
}

fn get_dest_mac_ip(
    broadcast: bool,
    client_mac: MacAddr,
    leased_ip: Ipv4Addr,
) -> (MacAddr, Ipv4Addr) {
    if broadcast {
        (MacAddr::broadcast(), Ipv4Addr::BROADCAST)
    } else {
        (client_mac, leased_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::dhcp_server::ClientLease;
    use rtnetlink::packet_route::neighbour::NeighbourMessage;
    use std::time::Instant;

    fn make_config(cidr: &str) -> ServerConfig {
        let net: ipnet::Ipv4Net = cidr.parse().unwrap();
        ServerConfig {
            server_ip: net.addr(),
            subnet_mask: net.netmask(),
            server_mac: MacAddr::new(0, 0, 0, 0, 0, 1),
            net,
        }
    }

    /// Mirrors the allocation path in `handle_dhcp_discover`: re-offer an
    /// existing lease, only scan the pool for first-time clients.
    fn discover_ip(
        leases: &mut LeaseTable,
        mac: MacAddr,
        net: ipnet::Ipv4Net,
        server_ip: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        if let Some(existing) = leases.get(&mac) {
            return Some(existing.ip);
        }
        let ip = leases.next_available_ip(net, server_ip)?;
        leases.insert(
            mac,
            ClientLease {
                ip,
                expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
            },
        );
        Some(ip)
    }

    #[test]
    fn test_lease_table_basic_allocation() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);

        // First allocation
        let ip1 = discover_ip(&mut leases, client1, net, server_ip).unwrap();
        assert_ne!(ip1, server_ip);
        assert!(net.hosts().any(|h| h == ip1));
        assert!(!leases.is_ip_available(ip1));

        // Same client gets same IP
        assert_eq!(discover_ip(&mut leases, client1, net, server_ip), Some(ip1));
        assert_eq!(leases.len(), 1);

        // Different client gets a different IP
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip3 = discover_ip(&mut leases, client2, net, server_ip).unwrap();
        assert_ne!(ip3, ip1);
        assert_ne!(ip3, server_ip);
        assert!(!leases.is_ip_available(ip3));
    }

    #[test]
    fn test_lease_table_pool_exhaustion() {
        // /30: usable hosts are .1 and .2; server_ip is .1, so only .2 is available
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();

        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        assert_eq!(
            discover_ip(&mut leases, client1, net, server_ip),
            Some(Ipv4Addr::new(192, 168, 1, 2))
        );

        // Pool exhausted for a second client
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        assert_eq!(discover_ip(&mut leases, client2, net, server_ip), None);
    }

    #[test]
    fn test_lease_table_remove_frees_ip() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let ip = discover_ip(&mut leases, client, net, server_ip).unwrap();
        assert!(!leases.is_ip_available(ip));

        // Decline removes the lease and frees the IP atomically
        let removed = leases.remove(&client);
        assert_eq!(removed.map(|l| l.ip), Some(ip));
        assert_eq!(leases.len(), 0);
        assert!(leases.is_ip_available(ip));

        // Re-allocation returns the same IP
        let ip2 = discover_ip(&mut leases, client, net, server_ip).unwrap();
        assert_eq!(ip2, ip);
        assert_eq!(leases.len(), 1);

        // Release also frees the IP atomically
        let released = leases.remove(&client);
        assert_eq!(released.map(|l| l.ip), Some(ip));
        assert_eq!(leases.len(), 0);
        assert!(leases.is_ip_available(ip));
    }

    /// Verifies that expired leases are evicted and their IPs returned to the
    /// pool when `next_available_ip` is called.
    #[test]
    fn test_evict_expired_returns_ip_to_pool() {
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        // Insert a lease that has already expired.
        leases.insert(
            client,
            ClientLease {
                ip: Ipv4Addr::new(192, 168, 1, 2),
                expiry: Instant::now() - Duration::from_secs(1),
            },
        );
        assert_eq!(leases.len(), 1);
        assert!(!leases.is_ip_available(Ipv4Addr::new(192, 168, 1, 2)));

        // A new client should be able to claim the expired IP after eviction.
        let new_client = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip = discover_ip(&mut leases, new_client, net, server_ip);
        assert_eq!(
            ip,
            Some(Ipv4Addr::new(192, 168, 1, 2)),
            "expired lease IP must be returned to the pool"
        );
        // The expired entry must have been removed.
        assert_eq!(leases.len(), 1);
        assert!(leases.get(&client).is_none());
    }

    /// Regression test: re-discovering client must always get the same IP,
    /// not a freshly allocated one from the pool.
    #[test]
    fn test_discover_reoffers_existing_lease_ip() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        let ip_first = discover_ip(&mut leases, client, net, server_ip).unwrap();
        assert_ne!(ip_first, server_ip);
        assert_eq!(leases.len(), 1);

        let ip_second = discover_ip(&mut leases, client, net, server_ip).unwrap();
        assert_eq!(ip_second, ip_first, "re-DISCOVER must re-offer the same IP");
        assert_eq!(leases.len(), 1);
        assert!(!leases.is_ip_available(ip_first));
    }

    /// Ensures an existing client can still be re-offered its IP even when
    /// the pool is exhausted for new clients.
    #[test]
    fn test_discover_exhausted_pool_reoffers_existing_client() {
        // /30: only .2 is available (server is .1)
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();

        let existing_client = MacAddr::new(1, 2, 3, 4, 5, 6);
        let new_client = MacAddr::new(1, 2, 3, 4, 5, 7);

        let ip = discover_ip(&mut leases, existing_client, net, server_ip).unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 2));

        // Pool is exhausted — new client gets None.
        assert_eq!(discover_ip(&mut leases, new_client, net, server_ip), None);

        // Existing client still gets its IP re-offered.
        assert_eq!(
            discover_ip(&mut leases, existing_client, net, server_ip),
            Some(ip)
        );
    }

    #[test]
    fn test_validate_requested_ip_rejects_server_ip() {
        let config = make_config("192.168.1.1/24");
        let leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(!validate_requested_ip(
            config.server_ip,
            client,
            &config,
            &leases
        ));
    }

    #[test]
    fn test_validate_requested_ip_rejects_out_of_subnet() {
        let config = make_config("192.168.1.1/24");
        let leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(!validate_requested_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            client,
            &config,
            &leases
        ));
    }

    #[test]
    fn test_validate_requested_ip_rejects_conflicting_lease() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();

        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let contested_ip = Ipv4Addr::new(192, 168, 1, 2);

        leases.insert(
            client1,
            ClientLease {
                ip: contested_ip,
                expiry: Instant::now() + Duration::from_secs(LAN_LEASE_SECS as u64),
            },
        );

        // Another client cannot claim it
        assert!(!validate_requested_ip(
            contested_ip,
            client2,
            &config,
            &leases
        ));
        // But the owning client can renew it
        assert!(validate_requested_ip(
            contested_ip,
            client1,
            &config,
            &leases
        ));
    }

    #[test]
    fn test_validate_requested_ip_accepts_valid() {
        let config = make_config("192.168.1.1/24");
        let leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        assert!(validate_requested_ip(
            Ipv4Addr::new(192, 168, 1, 100),
            client,
            &config,
            &leases
        ));
    }

    #[test]
    fn test_handle_neigh_message() {
        let mut leases = LeaseTable::new();
        let mut msg = NeighbourMessage::default();
        msg.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet(Ipv4Addr::new(192, 168, 1, 50))),
            NeighbourAttribute::LinkLayerAddress(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ];

        handle_neigh_message(msg, &mut leases);

        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let lease = leases.get(&mac).unwrap();
        assert_eq!(lease.ip, Ipv4Addr::new(192, 168, 1, 50));
    }

    #[tokio::test]
    async fn test_verify_arp_conflict_detects_conflict() {
        let config = make_config("192.168.1.1/24");
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let leases = spawn_lease_actor(shutdown_rx);

        let client_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let owner_mac = MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        // Pre-populate lease table with another owner for the target IP (simulating Netlink catching it)
        leases.add_neighbor(owner_mac, target_ip).await;

        // Running verify_arp_conflict for client_mac should return true (conflict)
        let is_conflict = verify_arp_conflict(target_ip, client_mac, &config, &leases).await;
        assert!(is_conflict);

        // Verify that a conflict was recorded
        assert!(leases.check_conflict(target_ip, client_mac).await);
    }

    #[test]
    fn test_handle_neigh_message_preserves_longer_lease() {
        let mut leases = LeaseTable::new();
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let ip = Ipv4Addr::new(192, 168, 1, 50);
        let long_expiry = Instant::now() + Duration::from_secs(3600);

        // Pre-populate with a long lease
        leases.insert(
            mac,
            ClientLease {
                ip,
                expiry: long_expiry,
            },
        );

        // Send a NeighbourMessage with the same MAC and IP
        let mut msg = NeighbourMessage::default();
        msg.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)),
            NeighbourAttribute::LinkLayerAddress(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ];

        handle_neigh_message(msg, &mut leases);

        // Verify the long expiry is preserved and NOT shortened
        let lease = leases.get(&mac).unwrap();
        assert_eq!(lease.ip, ip);
        assert_eq!(lease.expiry, long_expiry);
    }

    #[tokio::test]
    async fn test_concurrent_discover_allocations_no_duplicates() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let leases = spawn_lease_actor(shutdown_rx);

        let mac1 = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x01);
        let mac2 = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x02);

        let (res1, res2) = tokio::join!(
            leases.allocate_candidate(mac1, net, server_ip),
            leases.allocate_candidate(mac2, net, server_ip)
        );

        let ip1 = res1.expect("client 1 allocated ip");
        let ip2 = res2.expect("client 2 allocated ip");

        assert_ne!(ip1, ip2, "concurrent allocations MUST receive distinct IPs");
        assert_ne!(ip1, server_ip);
        assert_ne!(ip2, server_ip);
    }
}
