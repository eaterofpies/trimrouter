use crate::packet::build_raw_packet;
use crate::services::DHCP_SERVER_SERVICE_NAME;
use crate::services::ipc::{
    DhcpServerParentToWorkerMsg, DhcpServerWorkerToParentMsg, recv_msg, send_msg,
};
use crate::services::utils::{
    DHCP_SERVER_GID, DHCP_SERVER_UID, get_interface_mac, parse_dhcp_payload, read_raw_packet,
    run_sandboxed_worker, send_raw_packet,
};
use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Encodable, Encoder};
use log::{debug, error, info, warn};
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::time::interval;

use super::lease_table::{LeaseHandle, spawn_lease_actor};

const LAN_LEASE_SECS: u32 = 3600;
const ARP_RESOLUTION_DELAY: Duration = Duration::from_millis(100);
const DISCARD_PORT: u16 = 9;
const CONFLICT_HOLD_DURATION: Duration = Duration::from_secs(300);
const SERVER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

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
        DHCP_SERVER_SERVICE_NAME,
        DHCP_SERVER_UID,
        DHCP_SERVER_GID,
        ipc_fd,
        |ipc| async move {
            let leases = spawn_lease_actor();

            let config = Arc::new(ServerConfig {
                server_ip,
                subnet_mask,
                server_mac: mac,
                net,
            });

            let async_sock_shared = Arc::new(async_sock);
            let _ =
                run_server_loop(async_sock_shared, config, leases, ipc.reader, ipc.writer).await;
            Ok(())
        },
    )
    .await
}

async fn run_server_loop(
    async_sock: Arc<AsyncFd<OwnedFd>>,
    config: Arc<ServerConfig>,
    leases: LeaseHandle,
    mut ipc_reader: OwnedReadHalf,
    mut ipc_writer: OwnedWriteHalf,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 2048];
    let mut heartbeat_timer = interval(SERVER_HEARTBEAT_INTERVAL);
    let (ipc_tx, mut ipc_rx) = tokio::sync::mpsc::channel::<DhcpServerWorkerToParentMsg>(32);

    loop {
        tokio::select! {
            _ = heartbeat_timer.tick() => {
                if let Err(e) = send_msg(&mut ipc_writer, &DhcpServerWorkerToParentMsg::Heartbeat).await {
                    debug!("[dhcp-server-worker] Failed to send heartbeat to parent: {}", e);
                }
                let expired_hostnames = leases.evict_expired().await;
                for name in expired_hostnames {
                    let msg = DhcpServerWorkerToParentMsg::DeregisterLocalHost { name };
                    if let Err(e) = send_msg(&mut ipc_writer, &msg).await {
                        debug!("[dhcp-server-worker] Failed to send DeregisterLocalHost: {}", e);
                    }
                }
            }
            Some(msg) = ipc_rx.recv() => {
                if let Err(e) = send_msg(&mut ipc_writer, &msg).await {
                    debug!("[dhcp-server-worker] Failed to send IPC msg to parent: {}", e);
                }
            }
            ipc_msg = recv_msg::<DhcpServerParentToWorkerMsg, _>(&mut ipc_reader) => {
                match ipc_msg {
                    Ok(Some(DhcpServerParentToWorkerMsg::AddNeighbor {
                        ip_address,
                        mac_address,
                    })) => {
                        let mac = MacAddr::from(mac_address);
                        leases.add_neighbor(mac, ip_address).await;
                    }
                    Ok(None) | Err(_) => {
                        info!("[dhcp-server-worker] Parent closed IPC or error. Shutting down.");
                        break;
                    }
                }
            }
            read_res = read_raw_packet(&async_sock, &mut buf) => {
                match read_res {
                    Ok(bytes_read) => {
                        let pkt_data = buf[..bytes_read].to_vec();
                        let async_sock_clone = Arc::clone(&async_sock);
                        let config_clone = Arc::clone(&config);
                        let leases_clone = leases.clone();
                        let ipc_tx_clone = ipc_tx.clone();

                        tokio::spawn(async move {
                            process_incoming_packet(
                                pkt_data,
                                async_sock_clone,
                                config_clone,
                                leases_clone,
                                ipc_tx_clone,
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        error!("[dhcp-server] Socket read error: {}. Recreating socket.", e);
                        return Err(e);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn process_incoming_packet(
    buf: Vec<u8>,
    async_sock: Arc<AsyncFd<OwnedFd>>,
    config: Arc<ServerConfig>,
    leases: LeaseHandle,
    ipc_tx: tokio::sync::mpsc::Sender<DhcpServerWorkerToParentMsg>,
) {
    let dhcp = match parse_dhcp_payload(&buf, dhcproto::v4::SERVER_PORT) {
        Some(d) => d,
        None => return,
    };

    if dhcp.opcode() != dhcproto::v4::Opcode::BootRequest {
        return;
    }

    let client_mac = match extract_client_mac(&dhcp) {
        Some(mac) => mac,
        None => return,
    };

    // Server-side anti-spoofing MAC check
    let eth = match EthernetPacket::new(&buf) {
        Some(e) => e,
        None => return,
    };
    let src_mac = eth.get_source();
    if is_spoofed_l2_packet(src_mac, client_mac, dhcp.giaddr()) {
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
            handle_dhcp_request(async_sock, &config, &dhcp, client_mac, leases, ipc_tx).await;
        }
        MessageType::Decline | MessageType::Release => {
            let label = if msg_type == MessageType::Decline {
                "DHCPDECLINE"
            } else {
                "DHCPRELEASE"
            };
            if let Some((ip, maybe_name)) = leases.release(client_mac).await {
                info!(
                    "[dhcp-server] Received {} from client MAC: {}. Released lease for IP: {}.",
                    label, client_mac, ip
                );
                if let Some(name) = maybe_name {
                    let _ = ipc_tx
                        .send(DhcpServerWorkerToParentMsg::DeregisterLocalHost { name })
                        .await;
                }
            }
        }
        _ => {}
    }
}

fn extract_client_mac(dhcp: &Message) -> Option<MacAddr> {
    if dhcp.hlen() != 6 {
        return None;
    }
    let chaddr = dhcp.chaddr();
    if chaddr.len() < 6 {
        return None;
    }
    let bytes: [u8; 6] = chaddr[..6].try_into().ok()?;
    let mac = MacAddr::from(bytes);
    if mac.is_zero() || mac == MacAddr::broadcast() {
        return None;
    }
    Some(mac)
}

fn is_spoofed_l2_packet(eth_src: MacAddr, client_mac: MacAddr, giaddr: Ipv4Addr) -> bool {
    giaddr.is_unspecified() && eth_src != client_mac
}

fn should_process_request_server_id(dhcp: &Message, server_ip: Ipv4Addr) -> bool {
    match dhcp.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(id)) => *id == server_ip,
        _ => true,
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

async fn send_dhcp_frame(
    async_sock: &AsyncFd<OwnedFd>,
    config: &ServerConfig,
    dest_mac: MacAddr,
    dest_ip: Ipv4Addr,
    payload: &[u8],
) {
    let frame = match build_raw_packet(
        config.server_mac,
        dest_mac,
        config.server_ip,
        dest_ip,
        dhcproto::v4::SERVER_PORT,
        dhcproto::v4::CLIENT_PORT,
        payload,
    ) {
        Ok(f) => f,
        Err(e) => {
            warn!("[dhcp-server] Failed to build raw packet frame: {}", e);
            return;
        }
    };
    send_raw_packet(async_sock, &frame).await;
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
    send_dhcp_frame(async_sock, config, dest_mac, dest_ip, &payload).await;
}

async fn trigger_arp_resolution(server_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    if let Ok(socket) = std::net::UdpSocket::bind((server_ip, 0)) {
        let _ = socket.send_to(&[0u8], (target_ip, DISCARD_PORT));
    }
    tokio::time::sleep(ARP_RESOLUTION_DELAY).await;
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
    send_dhcp_frame(async_sock, config, dest_mac, dest_ip, &payload).await;
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

    let requested_hostname = extract_sanitized_hostname(dhcp);
    leases
        .confirm_lease(
            client_mac,
            leased_ip,
            Duration::from_secs(LAN_LEASE_SECS as u64),
            requested_hostname,
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
    send_dhcp_frame(async_sock, config, dest_mac, dest_ip, &payload).await;
    info!("[dhcp-server] Sent DHCPACK of IP: {} to client.", leased_ip);
}

async fn handle_dhcp_request(
    async_sock: Arc<AsyncFd<OwnedFd>>,
    config: &ServerConfig,
    dhcp: &Message,
    client_mac: MacAddr,
    leases: LeaseHandle,
    ipc_tx: tokio::sync::mpsc::Sender<DhcpServerWorkerToParentMsg>,
) {
    debug!(
        "[dhcp-server] Received DHCPREQUEST from client MAC: {}",
        client_mac
    );

    if !should_process_request_server_id(dhcp, config.server_ip) {
        debug!(
            "[dhcp-server] DHCPREQUEST ServerIdentifier does not match server IP {}. Ignoring.",
            config.server_ip
        );
        return;
    }

    let requested_ip_opt = match dhcp.opts().get(OptionCode::RequestedIpAddress) {
        Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
        _ => None,
    };

    let requested_hostname = extract_sanitized_hostname(dhcp);

    let Some(confirmation) = leases
        .validate_and_confirm_request(
            client_mac,
            requested_ip_opt,
            config.server_ip,
            config.net,
            Duration::from_secs(LAN_LEASE_SECS as u64),
            requested_hostname,
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

    let leased_ip = confirmation.ip;
    if verify_arp_conflict(leased_ip, client_mac, config, &leases).await {
        send_dhcp_nak(&async_sock, dhcp, client_mac, config).await;
        return;
    }

    send_dhcp_ack(&async_sock, dhcp, client_mac, leased_ip, config).await;

    if let Some(old_name) = confirmation.old_hostname_to_deregister {
        info!(
            "[dhcp-server] Deregistering previous local hostname '{}' for client MAC: {}",
            old_name, client_mac
        );
        let _ = ipc_tx
            .send(DhcpServerWorkerToParentMsg::DeregisterLocalHost { name: old_name })
            .await;
    }

    if let Some(name) = confirmation.hostname {
        info!(
            "[dhcp-server] Registered local hostname '{}' for IP {} (MAC: {})",
            name, leased_ip, client_mac
        );
        let _ = ipc_tx
            .send(DhcpServerWorkerToParentMsg::RegisterLocalHost {
                name,
                ip: leased_ip,
            })
            .await;
    }
}

pub fn sanitize_hostname(raw: &str) -> Option<String> {
    let label = raw.split('.').next()?.trim();
    if label.is_empty() || label.len() > 63 {
        return None;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return None;
    }
    if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    Some(label.to_ascii_lowercase())
}

fn extract_sanitized_hostname(dhcp: &Message) -> Option<String> {
    match dhcp.opts().get(OptionCode::Hostname) {
        Some(DhcpOption::Hostname(name)) => sanitize_hostname(name),
        _ => None,
    }
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
    use crate::services::dhcp_server::{ClientLease, LeaseConfirmation, LeaseTable};
    use dhcproto::{Decodable, Decoder};
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

    #[test]
    fn test_lease_table_basic_allocation() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);

        // First allocation
        let ip1 = leases
            .allocate_candidate(client1, net, server_ip)
            .expect("first allocation");
        assert_ne!(ip1, server_ip);
        assert!(net.hosts().any(|h| h == ip1));
        assert!(!leases.is_ip_available(ip1));

        // Different client gets a different IP
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip2 = leases
            .allocate_candidate(client2, net, server_ip)
            .expect("second allocation");
        assert_ne!(ip2, ip1);
        assert_ne!(ip2, server_ip);
        assert!(!leases.is_ip_available(ip2));
    }

    #[test]
    fn test_lease_table_pool_exhaustion() {
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();

        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        assert_eq!(
            leases.allocate_candidate(client1, net, server_ip),
            Some(Ipv4Addr::new(192, 168, 1, 2))
        );

        // Pool exhausted for a second client
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        assert_eq!(leases.allocate_candidate(client2, net, server_ip), None);
    }

    #[test]
    fn test_lease_table_remove_frees_ip() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let ip = leases.allocate_candidate(client, net, server_ip).unwrap();
        assert!(!leases.is_ip_available(ip));

        // Decline/Release removes the lease and frees the IP atomically
        let removed = leases.remove(&client);
        assert_eq!(removed.map(|l| l.ip), Some(ip));
        assert_eq!(leases.len(), 0);
        assert!(leases.is_ip_available(ip));

        // Re-allocation returns the same IP
        let ip2 = leases.allocate_candidate(client, net, server_ip).unwrap();
        assert_eq!(ip2, ip);
        assert_eq!(leases.len(), 1);
    }

    #[test]
    fn test_evict_expired_returns_ip_to_pool() {
        let net: ipnet::Ipv4Net = "192.168.1.1/30".parse().unwrap();
        let server_ip = net.addr();
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        leases.insert(
            client,
            ClientLease {
                ip: Ipv4Addr::new(192, 168, 1, 2),
                expiry: Instant::now() - Duration::from_secs(1),
                hostname: Some("old-host".to_string()),
            },
        );
        assert_eq!(leases.len(), 1);
        assert!(!leases.is_ip_available(Ipv4Addr::new(192, 168, 1, 2)));

        let new_client = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip = leases.allocate_candidate(new_client, net, server_ip);
        assert_eq!(
            ip,
            Some(Ipv4Addr::new(192, 168, 1, 2)),
            "expired lease IP must be returned to the pool"
        );
        assert_eq!(leases.len(), 1);
        assert!(leases.get(&client).is_none());
    }

    #[tokio::test]
    async fn test_discover_reoffers_existing_lease_ip() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let leases = spawn_lease_actor();
        let client = MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);

        let ip_first = leases
            .allocate_candidate(client, net, server_ip)
            .await
            .unwrap();
        leases
            .confirm_lease(client, ip_first, Duration::from_secs(3600), None)
            .await;

        let ip_second = leases.get_existing_ip(client).await.unwrap();
        assert_eq!(ip_second, ip_first, "re-DISCOVER must re-offer the same IP");
    }

    #[test]
    fn test_validate_and_confirm_rejects_server_ip() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let result = leases.validate_and_confirm(
            client,
            Some(config.server_ip),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            None,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_validate_and_confirm_rejects_out_of_subnet() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let result = leases.validate_and_confirm(
            client,
            Some(Ipv4Addr::new(10, 0, 0, 5)),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            None,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_validate_and_confirm_rejects_conflicting_lease() {
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
                hostname: None,
            },
        );

        // Another client cannot claim it
        assert_eq!(
            leases.validate_and_confirm(
                client2,
                Some(contested_ip),
                config.server_ip,
                config.net,
                Duration::from_secs(3600),
                None,
            ),
            None
        );
        // But the owning client can renew it
        assert_eq!(
            leases.validate_and_confirm(
                client1,
                Some(contested_ip),
                config.server_ip,
                config.net,
                Duration::from_secs(3600),
                None,
            ),
            Some(LeaseConfirmation {
                ip: contested_ip,
                hostname: None,
                old_hostname_to_deregister: None,
            })
        );
    }

    #[test]
    fn test_validate_and_confirm_accepts_valid() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let valid_ip = Ipv4Addr::new(192, 168, 1, 100);
        let res = leases.validate_and_confirm(
            client,
            Some(valid_ip),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            Some("printer".to_string()),
        );
        assert_eq!(
            res,
            Some(LeaseConfirmation {
                ip: valid_ip,
                hostname: Some("printer".to_string()),
                old_hostname_to_deregister: None,
            })
        );
    }

    #[tokio::test]
    async fn test_verify_arp_conflict_detects_conflict() {
        let config = make_config("192.168.1.1/24");
        let leases = spawn_lease_actor();

        let client_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let owner_mac = MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56);
        let target_ip = Ipv4Addr::new(192, 168, 1, 50);

        leases.add_neighbor(owner_mac, target_ip).await;

        let is_conflict = verify_arp_conflict(target_ip, client_mac, &config, &leases).await;
        assert!(is_conflict);
        assert!(leases.check_conflict(target_ip, client_mac).await);
    }

    #[test]
    fn test_update_from_neighbor_preserves_different_ip() {
        let mut leases = LeaseTable::new();
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let ip = Ipv4Addr::new(192, 168, 1, 50);

        leases.update_from_neighbor(mac, ip);
        let lease = leases.get(&mac).unwrap();
        assert_eq!(lease.ip, ip);
    }

    #[tokio::test]
    async fn test_concurrent_discover_allocations_no_duplicates() {
        let net: ipnet::Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let server_ip = net.addr();
        let leases = spawn_lease_actor();

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

    #[test]
    fn test_validate_and_confirm_unspecified_zero_ip_rejected() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let res = leases.validate_and_confirm(
            client,
            Some(Ipv4Addr::UNSPECIFIED),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            None,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn test_validate_and_confirm_broadcast_ip_rejected() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let broadcast_ip = config.net.broadcast();
        let res = leases.validate_and_confirm(
            client,
            Some(broadcast_ip),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            None,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn test_validate_and_confirm_network_ip_rejected() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);

        let network_ip = config.net.network();
        let res = leases.validate_and_confirm(
            client,
            Some(network_ip),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            None,
        );
        assert_eq!(res, None);
    }

    #[test]
    fn test_sanitize_hostname_valid_and_edge_cases() {
        assert_eq!(sanitize_hostname("printer"), Some("printer".to_string()));
        assert_eq!(
            sanitize_hostname("PRINTER-01"),
            Some("printer-01".to_string())
        );
        assert_eq!(
            sanitize_hostname("printer.local"),
            Some("printer".to_string())
        );
        assert_eq!(
            sanitize_hostname("server01.lab.internal"),
            Some("server01".to_string())
        );
        assert_eq!(sanitize_hostname("laptop.lan"), Some("laptop".to_string()));
        assert_eq!(
            sanitize_hostname("my-box.home.arpa"),
            Some("my-box".to_string())
        );

        // Invalid cases
        assert_eq!(sanitize_hostname(""), None);
        assert_eq!(sanitize_hostname("-invalid"), None);
        assert_eq!(sanitize_hostname("invalid-"), None);
        assert_eq!(sanitize_hostname("invalid_underscore"), None);
        assert_eq!(sanitize_hostname("a".repeat(64).as_str()), None);
    }

    #[test]
    fn test_hostname_collision_rfc4703_skips_registration() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();

        let client1 = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let client2 = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0xAA, 0xBB);

        // Client 1 registers "laptop"
        let res1 = leases.validate_and_confirm(
            client1,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            Some("laptop".to_string()),
        );
        assert_eq!(
            res1,
            Some(LeaseConfirmation {
                ip: Ipv4Addr::new(192, 168, 1, 10),
                hostname: Some("laptop".to_string()),
                old_hostname_to_deregister: None,
            })
        );

        // Client 2 requests "laptop" -> lease granted, but hostname registration skipped per RFC 4703
        let res2 = leases.validate_and_confirm(
            client2,
            Some(Ipv4Addr::new(192, 168, 1, 20)),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            Some("laptop".to_string()),
        );
        assert_eq!(
            res2,
            Some(LeaseConfirmation {
                ip: Ipv4Addr::new(192, 168, 1, 20),
                hostname: None,
                old_hostname_to_deregister: None,
            })
        );

        // Client 1 renews "laptop" -> retains "laptop" without collision
        let res1_renew = leases.validate_and_confirm(
            client1,
            Some(Ipv4Addr::new(192, 168, 1, 10)),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            Some("laptop".to_string()),
        );
        assert_eq!(
            res1_renew,
            Some(LeaseConfirmation {
                ip: Ipv4Addr::new(192, 168, 1, 10),
                hostname: Some("laptop".to_string()),
                old_hostname_to_deregister: None,
            })
        );
    }

    #[test]
    fn test_validate_and_confirm_hostname_change_deregisters_old() {
        let config = make_config("192.168.1.1/24");
        let mut leases = LeaseTable::new();
        let client = MacAddr::new(1, 2, 3, 4, 5, 6);
        let valid_ip = Ipv4Addr::new(192, 168, 1, 100);

        // Initial lease with "laptop"
        let res1 = leases.validate_and_confirm(
            client,
            Some(valid_ip),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            Some("laptop".to_string()),
        );
        assert_eq!(
            res1,
            Some(LeaseConfirmation {
                ip: valid_ip,
                hostname: Some("laptop".to_string()),
                old_hostname_to_deregister: None,
            })
        );

        // Renewal with changed hostname "workstation" -> returns old "laptop" to deregister
        let res2 = leases.validate_and_confirm(
            client,
            Some(valid_ip),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            Some("workstation".to_string()),
        );
        assert_eq!(
            res2,
            Some(LeaseConfirmation {
                ip: valid_ip,
                hostname: Some("workstation".to_string()),
                old_hostname_to_deregister: Some("laptop".to_string()),
            })
        );

        // Renewal with no hostname -> returns old "workstation" to deregister
        let res3 = leases.validate_and_confirm(
            client,
            Some(valid_ip),
            config.server_ip,
            config.net,
            Duration::from_secs(3600),
            None,
        );
        assert_eq!(
            res3,
            Some(LeaseConfirmation {
                ip: valid_ip,
                hostname: None,
                old_hostname_to_deregister: Some("workstation".to_string()),
            })
        );
    }

    #[test]
    fn test_extract_client_mac_valid_and_invalid() {
        // Valid 6-byte Ethernet MAC
        let mut msg_valid = Message::default();
        msg_valid.set_chaddr(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(
            extract_client_mac(&msg_valid),
            Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55))
        );

        // hlen = 0 (invalid)
        let mut msg_zero_len = Message::default();
        msg_zero_len.set_chaddr(&[]);
        assert_eq!(extract_client_mac(&msg_zero_len), None);

        // hlen = 16 (invalid non-Ethernet hlen)
        let mut msg_long_len = Message::default();
        msg_long_len.set_chaddr(&[0x00; 16]);
        assert_eq!(extract_client_mac(&msg_long_len), None);

        // All-zero MAC (00:00:00:00:00:00) should be rejected
        let mut msg_zero_mac = Message::default();
        msg_zero_mac.set_chaddr(&[0x00; 6]);
        assert_eq!(extract_client_mac(&msg_zero_mac), None);

        // Broadcast MAC (FF:FF:FF:FF:FF:FF) should be rejected
        let mut msg_bcast_mac = Message::default();
        msg_bcast_mac.set_chaddr(&[0xFF; 6]);
        assert_eq!(extract_client_mac(&msg_bcast_mac), None);

        // Corrupted packet with hlen = 255 (CVE-2016-2774 out-of-bounds guard: must not panic)
        let mut raw_bytes = vec![0u8; 300];
        raw_bytes[0] = 1; // BootRequest
        raw_bytes[1] = 1; // Ethernet
        raw_bytes[2] = 255; // hlen = 255
        // Magic cookie at 236
        raw_bytes[236..240].copy_from_slice(&[99, 130, 83, 99]);
        if let Ok(msg_oob) = Message::decode(&mut Decoder::new(&raw_bytes)) {
            assert_eq!(extract_client_mac(&msg_oob), None);
        }
    }

    #[test]
    fn test_is_spoofed_l2_packet_anti_spoofing() {
        let mac1 = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x01);
        let mac2 = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x02);

        // Non-relayed packet with matching MACs: valid
        assert!(!is_spoofed_l2_packet(mac1, mac1, Ipv4Addr::UNSPECIFIED));

        // Non-relayed packet with spoofed L2 MAC: spoofed
        assert!(is_spoofed_l2_packet(mac1, mac2, Ipv4Addr::UNSPECIFIED));

        // Relayed packet through DHCP relay agent (giaddr set): allowed
        let relay_ip = Ipv4Addr::new(192, 168, 1, 254);
        assert!(!is_spoofed_l2_packet(mac1, mac2, relay_ip));
    }

    #[test]
    fn test_should_process_request_server_id() {
        let server_ip = Ipv4Addr::new(192, 168, 1, 1);
        let other_server_ip = Ipv4Addr::new(192, 168, 1, 254);

        // Request with matching server ID: should process
        let mut msg_match = Message::default();
        msg_match
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(server_ip));
        assert!(should_process_request_server_id(&msg_match, server_ip));

        // Request with mismatched server ID: should ignore (RFC 2131 Section 4.3.2)
        let mut msg_mismatch = Message::default();
        msg_mismatch
            .opts_mut()
            .insert(DhcpOption::ServerIdentifier(other_server_ip));
        assert!(!should_process_request_server_id(&msg_mismatch, server_ip));

        // Request without server ID (e.g. RENEWING): should process
        let msg_none = Message::default();
        assert!(should_process_request_server_id(&msg_none, server_ip));
    }

    #[test]
    fn test_get_dest_mac_ip_broadcast_and_unicast() {
        let client_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let leased_ip = Ipv4Addr::new(192, 168, 1, 100);

        let (b_mac, b_ip) = get_dest_mac_ip(true, client_mac, leased_ip);
        assert_eq!(b_mac, MacAddr::broadcast());
        assert_eq!(b_ip, Ipv4Addr::BROADCAST);

        let (u_mac, u_ip) = get_dest_mac_ip(false, client_mac, leased_ip);
        assert_eq!(u_mac, client_mac);
        assert_eq!(u_ip, leased_ip);
    }

    #[test]
    fn test_record_multiple_conflicts_held_simultaneously() {
        let mut leases = LeaseTable::new();
        let ip1 = Ipv4Addr::new(192, 168, 1, 10);
        let ip2 = Ipv4Addr::new(192, 168, 1, 20);

        leases.record_conflict(ip1, Duration::from_secs(300));
        leases.record_conflict(ip2, Duration::from_secs(300));

        // Both IPs should be actively on hold and unavailable
        assert!(!leases.is_ip_available(ip1));
        assert!(!leases.is_ip_available(ip2));
        assert!(leases.is_conflict_active(ip1));
        assert!(leases.is_conflict_active(ip2));
    }

    #[test]
    fn test_release_non_existent_and_existing_leases() {
        let mut leases = LeaseTable::new();
        let client1 = MacAddr::new(1, 2, 3, 4, 5, 6);
        let client2 = MacAddr::new(1, 2, 3, 4, 5, 7);
        let ip = Ipv4Addr::new(192, 168, 1, 50);

        // Releasing a non-existent client MAC returns None
        assert_eq!(leases.remove(&client1), None);

        // Insert and then release
        leases.insert(
            client1,
            ClientLease {
                ip,
                expiry: Instant::now() + Duration::from_secs(3600),
                hostname: None,
            },
        );
        assert!(!leases.is_ip_available(ip));

        let released = leases.remove(&client1);
        assert!(released.is_some());
        assert_eq!(released.unwrap().ip, ip);
        assert!(leases.is_ip_available(ip));

        // Unknown client2 still returns None
        assert_eq!(leases.remove(&client2), None);
    }
}
