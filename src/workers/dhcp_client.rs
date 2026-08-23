use crate::managers::dhcp_client::{configure_wan, deconfigure_wan};
use crate::managers::ipc::{DhcpClientToParentMsg, send_msg};
use crate::managers::utils::{
    CleanOption, DHCP_CLIENT_GID, DHCP_CLIENT_UID, RawPacketSocket, SharedWanLease, WanLease,
    get_interface_mac, mask_to_prefix_len as utils_mask_to_prefix_len, parse_dhcp_payload,
    run_sandboxed_worker, wait_shutdown,
};
use crate::packet::build_raw_packet;
use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Encodable, Encoder};
use log::{debug, error, info, warn};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

const DEFAULT_LEASE_SECS: u32 = 3600;
const MAX_RETRY_DELAY_SECS: u32 = 64;
const INITIAL_RETRY_DELAY_SECS: u32 = 4;
const DEFAULT_SUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const SOCKET_RESTART_DELAY_SECS: u64 = 5;

#[derive(Debug)]
pub enum DhcpError {
    Io(std::io::Error),
    Protocol(String),
    Nak,
    InterfaceNotFound(String),
    RtNetlink(rtnetlink::Error),
}

impl std::fmt::Display for DhcpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpError::Io(e) => write!(f, "IO error: {}", e),
            DhcpError::Protocol(s) => write!(f, "DHCP protocol error: {}", s),
            DhcpError::Nak => write!(f, "DHCPNAK received"),
            DhcpError::InterfaceNotFound(iface) => write!(f, "Interface not found: {}", iface),
            DhcpError::RtNetlink(e) => write!(f, "Netlink error: {}", e),
        }
    }
}

impl std::error::Error for DhcpError {}

impl From<std::io::Error> for DhcpError {
    fn from(e: std::io::Error) -> Self {
        DhcpError::Io(e)
    }
}

impl From<rtnetlink::Error> for DhcpError {
    fn from(e: rtnetlink::Error) -> Self {
        DhcpError::RtNetlink(e)
    }
}

struct DhcpOffer {
    offered_ip: Ipv4Addr,
    server_ip: Option<Ipv4Addr>,
}

struct DhcpAck {
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    server_ip: Option<Ipv4Addr>,
    lease_secs: u32,
    dns_servers: Vec<Ipv4Addr>,
}

struct LeaseOptions {
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    dns_servers: Vec<Ipv4Addr>,
    lease_secs: u32,
}

enum ParseAckResult {
    Ack(DhcpAck),
    Nak,
    None,
}

/// A wrapper around a RawPacketSocket that handles DHCP-specific Layer-2
/// packet formatting, filtering, and payload parsing.
struct DhcpClientSocket {
    raw_socket: RawPacketSocket,
    mac: MacAddr,
}

impl DhcpClientSocket {
    fn from_raw_socket(raw_socket: RawPacketSocket, mac: MacAddr) -> Self {
        Self { raw_socket, mac }
    }

    async fn send(
        &self,
        message: &dhcproto::v4::Message,
        dest_ip: Ipv4Addr,
    ) -> Result<(), DhcpError> {
        let mut payload = Vec::new();
        message
            .encode(&mut Encoder::new(&mut payload))
            .map_err(|e| DhcpError::Protocol(e.to_string()))?;

        let src_ip = if message.ciaddr().is_unspecified() {
            Ipv4Addr::UNSPECIFIED
        } else {
            message.ciaddr()
        };

        let frame = build_raw_packet(
            self.mac,
            MacAddr::broadcast(),
            src_ip,
            dest_ip,
            dhcproto::v4::CLIENT_PORT,
            dhcproto::v4::SERVER_PORT,
            &payload,
        );
        self.raw_socket.send(&frame).await?;
        Ok(())
    }

    async fn recv(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Option<dhcproto::v4::Message>, DhcpError> {
        let mut raw_buf = [0u8; 2048];
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let Some(n) = self
                .raw_socket
                .recv_timeout(&mut raw_buf, remaining)
                .await?
            else {
                return Ok(None);
            };

            if let Some(dhcp) = parse_dhcp_payload(&raw_buf[..n], dhcproto::v4::CLIENT_PORT) {
                return Ok(Some(dhcp));
            }
        }
        Ok(None)
    }
}

struct DhcpClientInternal {
    socket: DhcpClientSocket,
    mac: MacAddr,
    lease_state: SharedWanLease,
    wan_interface: String,
    ipc_writer: Option<Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>>,
}

impl DhcpClientInternal {
    async fn run(&self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        loop {
            if *shutdown_rx.borrow() {
                self.deconfigure().await;
                break;
            }

            tokio::select! {
                _ = wait_shutdown(&mut shutdown_rx) => {
                    self.deconfigure().await;
                    break;
                }
                phase_res = self.execute_phases() => {
                    if let Err(e) = phase_res {
                        self.handle_phase_failure(e, &mut shutdown_rx).await;
                    }
                }
            }
        }
    }

    async fn execute_phases(&self) -> Result<(), DhcpError> {
        let (xid, offer) = self.discover_phase().await?;
        let ack = self.request_phase(xid, offer).await?;
        self.bound_phase(ack).await?;
        Ok(())
    }

    async fn handle_phase_failure(
        &self,
        e: DhcpError,
        shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        warn!(
            "[dhcp-client] Phase failed: {}. Retrying in {}s...",
            e, SOCKET_RESTART_DELAY_SECS
        );
        self.deconfigure().await;
        tokio::select! {
            _ = wait_shutdown(shutdown_rx) => {}
            _ = tokio::time::sleep(std::time::Duration::from_secs(SOCKET_RESTART_DELAY_SECS)) => {}
        }
    }

    async fn discover_phase(&self) -> Result<(u32, DhcpOffer), DhcpError> {
        let xid = rand::random::<u32>();
        let mut retry_delay_secs = INITIAL_RETRY_DELAY_SECS;

        loop {
            self.send_discover(xid).await;
            let timeout = get_jittered_duration(retry_delay_secs);

            if let Some(offer) = self.wait_for_offer(xid, timeout).await? {
                info!(
                    "[dhcp-client] Received DHCPOFFER for IP: {}, server: {:?}",
                    offer.offered_ip,
                    CleanOption(&offer.server_ip)
                );
                return Ok((xid, offer));
            }

            retry_delay_secs = calculate_next_delay(retry_delay_secs);
        }
    }
}

fn handle_ack_result(ack_res: ParseAckResult) -> Option<Result<DhcpAck, DhcpError>> {
    match ack_res {
        ParseAckResult::Ack(ack) => {
            info!("[dhcp-client] Received DHCPACK for IP: {}", ack.ip);
            Some(Ok(ack))
        }
        ParseAckResult::Nak => {
            warn!("[dhcp-client] Received DHCPNAK!");
            Some(Err(DhcpError::Nak))
        }
        ParseAckResult::None => None,
    }
}

impl DhcpClientInternal {
    async fn request_phase(&self, xid: u32, offer: DhcpOffer) -> Result<DhcpAck, DhcpError> {
        let mut retry_delay_secs = INITIAL_RETRY_DELAY_SECS;

        loop {
            self.send_request(
                xid,
                offer.offered_ip,
                offer.server_ip,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::BROADCAST,
            )
            .await;
            let timeout = get_jittered_duration(retry_delay_secs);

            if let Some(result) = self
                .wait_for_ack(xid, timeout)
                .await?
                .and_then(handle_ack_result)
            {
                return result;
            }

            retry_delay_secs = calculate_next_delay(retry_delay_secs);
        }
    }

    async fn bound_phase(&self, mut ack: DhcpAck) -> Result<(), DhcpError> {
        self.apply_lease_config(ack.ip, ack.mask, ack.gateway, &ack.dns_servers)
            .await?;
        let mut bound_at = std::time::Instant::now();

        loop {
            let elapsed = bound_at.elapsed().as_secs() as u32;
            if elapsed >= ack.lease_secs {
                warn!("[dhcp-client] Lease expired!");
                self.deconfigure().await;
                return Err(DhcpError::Protocol("Lease expired".to_string()));
            }

            // T1 Renewal time is lease_secs / 2
            let t1_secs = ack.lease_secs / 2;
            if elapsed < t1_secs {
                let sleep_duration = std::time::Duration::from_secs((t1_secs - elapsed) as u64);
                tokio::time::sleep(sleep_duration).await;
                continue;
            }

            // T2 Rebinding time is 87.5% of lease (RFC 2131 section 4.4.5)
            let t2_secs = (ack.lease_secs as f64 * 0.875) as u32;

            // Perform lease renewal phase
            match self
                .renew_lease(ack.ip, t2_secs, ack.lease_secs, ack.server_ip, bound_at)
                .await
            {
                Ok(new_ack) => {
                    ack = new_ack;
                    self.apply_lease_config(ack.ip, ack.mask, ack.gateway, &ack.dns_servers)
                        .await?;
                    bound_at = std::time::Instant::now();
                }
                Err(e) => {
                    self.deconfigure().await;
                    return Err(e);
                }
            }
        }
    }

    async fn renew_lease(
        &self,
        ip: Ipv4Addr,
        t2_secs: u32,
        lease_secs: u32,
        server_ip: Option<Ipv4Addr>,
        bound_at: std::time::Instant,
    ) -> Result<DhcpAck, DhcpError> {
        let renew_xid = rand::random::<u32>();
        let mut renew_sent: Option<std::time::Instant> = None;

        loop {
            let current_elapsed = bound_at.elapsed().as_secs() as u32;
            if current_elapsed >= lease_secs {
                return Err(DhcpError::Protocol(
                    "Lease expired during renewal".to_string(),
                ));
            }

            let (retry_interval, dest_ip, in_rebinding) =
                calculate_renewal_params(current_elapsed, t2_secs, lease_secs, server_ip);

            let should_send = match renew_sent {
                None => true,
                Some(t) => t.elapsed().as_secs() as u32 >= retry_interval,
            };

            if should_send {
                if in_rebinding {
                    debug!("[dhcp-client] REBINDING: sending broadcast DHCPREQUEST...");
                } else {
                    debug!("[dhcp-client] RENEWING: sending unicast DHCPREQUEST to server...");
                }
                self.send_request(renew_xid, ip, None, ip, dest_ip).await;
                renew_sent = Some(std::time::Instant::now());
            }

            let listen_timeout = std::time::Duration::from_secs(retry_interval as u64);
            if let Some(ack_res) = self.wait_for_ack(renew_xid, listen_timeout).await? {
                match ack_res {
                    ParseAckResult::Ack(new_ack) => {
                        info!("[dhcp-client] Renewal successful!");
                        return Ok(new_ack);
                    }
                    ParseAckResult::Nak => {
                        warn!("[dhcp-client] Renewal NAK'd!");
                        return Err(DhcpError::Nak);
                    }
                    ParseAckResult::None => {}
                }
            }
        }
    }

    async fn wait_for_offer(
        &self,
        xid: u32,
        timeout: std::time::Duration,
    ) -> Result<Option<DhcpOffer>, DhcpError> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let Some(dhcp) = self.socket.recv(remaining).await? else {
                break; // Timeout
            };

            if let Some(offer) = parse_offer(&dhcp, xid) {
                return Ok(Some(offer));
            }
        }
        Ok(None)
    }

    async fn wait_for_ack(
        &self,
        xid: u32,
        timeout: std::time::Duration,
    ) -> Result<Option<ParseAckResult>, DhcpError> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let Some(dhcp) = self.socket.recv(remaining).await? else {
                break; // Timeout
            };

            let res = parse_ack_nak(&dhcp, xid);
            if !matches!(res, ParseAckResult::None) {
                return Ok(Some(res));
            }
        }
        Ok(None)
    }

    async fn send_dhcp_message(
        &self,
        message: dhcproto::v4::Message,
        dest_ip: Ipv4Addr,
    ) -> Result<(), DhcpError> {
        self.socket.send(&message, dest_ip).await
    }

    async fn apply_lease_config(
        &self,
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        dns_servers: &[Ipv4Addr],
    ) -> Result<(), DhcpError> {
        if let Some(ref writer_mutex) = self.ipc_writer {
            let prefix_len = utils_mask_to_prefix_len(mask).unwrap_or(24);
            let msg = DhcpClientToParentMsg::ApplyWanLease {
                ip_address: ip,
                prefix_len,
                gateway: gateway.unwrap_or(Ipv4Addr::UNSPECIFIED),
                dns_servers: dns_servers.to_vec(),
            };
            let mut writer = writer_mutex.lock().await;
            send_msg(&mut *writer, &msg).await.map_err(DhcpError::Io)?;
            Ok(())
        } else {
            let changed = {
                let mut lease = self.lease_state.lock().unwrap();
                let changed = lease.ip != Some(ip)
                    || lease.mask != Some(mask)
                    || lease.gateway != gateway
                    || lease.dns_servers != dns_servers;

                if changed {
                    lease.ip = Some(ip);
                    lease.mask = Some(mask);
                    lease.gateway = gateway;
                    lease.dns_servers = dns_servers.to_vec();
                    info!("[dhcp-client] Lease parameters updated: {:?}", *lease);
                }
                changed
            };

            if changed {
                configure_wan(&self.wan_interface, ip, mask, gateway).await?;
            }
            Ok(())
        }
    }

    async fn deconfigure(&self) {
        if let Some(ref writer_mutex) = self.ipc_writer {
            let msg = DhcpClientToParentMsg::ClearWanLease;
            let mut writer = writer_mutex.lock().await;
            let _ = send_msg(&mut *writer, &msg).await;
        } else {
            let (ip, mask) = {
                let mut lease = self.lease_state.lock().unwrap();
                let ip = lease.ip;
                let mask = lease.mask;
                *lease = WanLease::default();
                (ip, mask)
            };

            if let Some(ip) = ip
                && let Some(mask) = mask
                && let Err(e) = deconfigure_wan(&self.wan_interface, ip, mask).await
            {
                error!(
                    "[dhcp-client] Failed to deconfigure WAN interface via netlink: {}",
                    e
                );
            }
        }
    }

    async fn send_discover(&self, xid: u32) {
        let mut discover = Message::default();
        discover.set_opcode(Opcode::BootRequest);
        discover.set_xid(xid);
        discover.set_flags(Flags::default().set_broadcast());
        discover.set_chaddr(&self.mac.octets());

        discover
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        discover
            .opts_mut()
            .insert(DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer,
            ]));

        if let Err(e) = self.send_dhcp_message(discover, Ipv4Addr::BROADCAST).await {
            error!("[dhcp-client] Failed to send DHCPDISCOVER: {}", e);
        } else {
            debug!("[dhcp-client] Sent DHCPDISCOVER.");
        }
    }

    async fn send_request(
        &self,
        xid: u32,
        requested_ip: Ipv4Addr,
        server_ip: Option<Ipv4Addr>,
        ciaddr: Ipv4Addr,
        dest_ip: Ipv4Addr,
    ) {
        let mut request = Message::default();
        request.set_opcode(Opcode::BootRequest);
        request.set_xid(xid);
        request.set_ciaddr(ciaddr);
        request.set_chaddr(&self.mac.octets());

        if ciaddr.is_unspecified() {
            request.set_flags(Flags::default().set_broadcast());
            request
                .opts_mut()
                .insert(DhcpOption::RequestedIpAddress(requested_ip));
            if let Some(srv) = server_ip {
                request.opts_mut().insert(DhcpOption::ServerIdentifier(srv));
            }
        }

        request
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));

        if let Err(e) = self.send_dhcp_message(request, dest_ip).await {
            error!("[dhcp-client] Failed to send DHCPREQUEST: {}", e);
        } else {
            debug!(
                "[dhcp-client] Sent DHCPREQUEST (ciaddr: {}, dest_ip: {}).",
                ciaddr, dest_ip
            );
        }
    }
}

async fn monitor_parent_ipc(
    mut reader: tokio::net::unix::OwnedReadHalf,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) {
    let mut buf = [0u8; 1024];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
    info!("[dhcp-client-worker] Parent closed IPC. Shutting down.");
    let _ = shutdown_tx.send(true);
}

pub async fn run_dhcp_client_worker(
    ipc_fd: OwnedFd,
    raw_socket_fd: OwnedFd,
    wan_interface: String,
) -> Result<(), std::io::Error> {
    let socket = RawPacketSocket::from_owned_fd(raw_socket_fd)?;
    let mac = match get_interface_mac(&wan_interface).await {
        Ok(m) => m,
        Err(e) => {
            return Err(std::io::Error::other(e));
        }
    };
    let client_socket = DhcpClientSocket::from_raw_socket(socket, mac);

    run_sandboxed_worker(
        "dhcp-client",
        DHCP_CLIENT_UID,
        DHCP_CLIENT_GID,
        ipc_fd,
        |ipc| async move {
            let dummy_lease_state = Arc::new(std::sync::Mutex::new(WanLease::default()));
            let client = DhcpClientInternal {
                socket: client_socket,
                mac,
                lease_state: dummy_lease_state,
                wan_interface: wan_interface.clone(),
                ipc_writer: Some(ipc.writer),
            };

            let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
            tokio::spawn(monitor_parent_ipc(ipc.reader, shutdown_tx));

            client.run(shutdown_rx).await;
            Ok(())
        },
    )
    .await
}

fn calculate_next_delay(current_delay: u32) -> u32 {
    let doubled = current_delay * 2;
    if doubled > MAX_RETRY_DELAY_SECS {
        MAX_RETRY_DELAY_SECS
    } else {
        doubled
    }
}

fn get_jittered_duration(base_secs: u32) -> std::time::Duration {
    let jitter = (rand::random::<f64>() * 2.0) - 1.0;
    let secs = base_secs as f64 + jitter;
    std::cmp::max(
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs_f64(secs),
    )
}

fn calculate_renewal_params(
    current_elapsed: u32,
    t2_secs: u32,
    lease_secs: u32,
    server_ip: Option<Ipv4Addr>,
) -> (u32, Ipv4Addr, bool) {
    let in_rebinding = current_elapsed >= t2_secs;
    let (retry_interval, dest_ip) = if in_rebinding {
        let remaining = lease_secs.saturating_sub(current_elapsed);
        let interval = std::cmp::max(remaining / 2, 60);
        (interval, Ipv4Addr::BROADCAST)
    } else {
        let remaining = t2_secs.saturating_sub(current_elapsed);
        let interval = std::cmp::max(remaining / 2, 60);
        (interval, server_ip.unwrap_or(Ipv4Addr::BROADCAST))
    };
    (retry_interval, dest_ip, in_rebinding)
}

fn parse_offer(dhcp: &dhcproto::v4::Message, xid: u32) -> Option<DhcpOffer> {
    if dhcp.xid() != xid {
        return None;
    }
    let msg_type = dhcp.opts().get(OptionCode::MessageType)?;
    if let DhcpOption::MessageType(MessageType::Offer) = msg_type {
        let offered_ip = dhcp.yiaddr();
        let server_ip = get_server_identifier(dhcp);
        Some(DhcpOffer {
            offered_ip,
            server_ip,
        })
    } else {
        None
    }
}

fn parse_ack_nak(dhcp: &dhcproto::v4::Message, xid: u32) -> ParseAckResult {
    if dhcp.xid() != xid {
        return ParseAckResult::None;
    }
    match dhcp.opts().get(OptionCode::MessageType) {
        Some(DhcpOption::MessageType(MessageType::Ack)) => {
            let opts = parse_lease_options(dhcp);
            ParseAckResult::Ack(DhcpAck {
                ip: dhcp.yiaddr(),
                mask: opts.mask,
                gateway: opts.gateway,
                server_ip: get_server_identifier(dhcp),
                lease_secs: opts.lease_secs,
                dns_servers: opts.dns_servers,
            })
        }
        Some(DhcpOption::MessageType(MessageType::Nak)) => ParseAckResult::Nak,
        _ => ParseAckResult::None,
    }
}

fn get_server_identifier(dhcp: &dhcproto::v4::Message) -> Option<Ipv4Addr> {
    match dhcp.opts().get(dhcproto::v4::OptionCode::ServerIdentifier) {
        Some(dhcproto::v4::DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

fn parse_lease_options(dhcp: &dhcproto::v4::Message) -> LeaseOptions {
    let mask = match dhcp.opts().get(OptionCode::SubnetMask) {
        Some(DhcpOption::SubnetMask(m)) => *m,
        _ => DEFAULT_SUBNET_MASK,
    };

    let gateway = match dhcp.opts().get(OptionCode::Router) {
        Some(DhcpOption::Router(routers)) if !routers.is_empty() => Some(routers[0]),
        _ => None,
    };

    let dns = match dhcp.opts().get(OptionCode::DomainNameServer) {
        Some(DhcpOption::DomainNameServer(list)) => list.clone(),
        _ => Vec::new(),
    };

    let lease_secs = match dhcp.opts().get(OptionCode::AddressLeaseTime) {
        Some(DhcpOption::AddressLeaseTime(t)) => *t,
        _ => DEFAULT_LEASE_SECS,
    };

    LeaseOptions {
        mask,
        gateway,
        dns_servers: dns,
        lease_secs,
    }
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::{DhcpOption, Message, MessageType};

    const MOCK_SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const MOCK_CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const DEFAULT_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
    const DNS_IP_1: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    const DNS_IP_2: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);

    #[test]
    fn test_parse_offer_valid() {
        let mut msg = Message::default();
        msg.set_xid(0x12345678);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        msg.opts_mut()
            .insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
        msg.set_yiaddr(MOCK_CLIENT_IP);

        let res = parse_offer(&msg, 0x12345678).unwrap();
        assert_eq!(res.offered_ip, MOCK_CLIENT_IP);
        assert_eq!(res.server_ip, Some(MOCK_SERVER_IP));
    }

    #[test]
    fn test_parse_offer_mismatched_xid() {
        let mut msg = Message::default();
        msg.set_xid(0x11111111);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));

        let res = parse_offer(&msg, 0x22222222);
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_offer_missing_server_id() {
        let mut msg = Message::default();
        msg.set_xid(0x12345678);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        msg.set_yiaddr(MOCK_CLIENT_IP);

        let res = parse_offer(&msg, 0x12345678).unwrap();
        assert_eq!(res.offered_ip, MOCK_CLIENT_IP);
        assert_eq!(res.server_ip, None);
    }

    #[test]
    fn test_parse_ack_valid() {
        let mut msg = Message::default();
        msg.set_xid(0xabcdef);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        msg.opts_mut().insert(DhcpOption::SubnetMask(DEFAULT_MASK));
        msg.opts_mut()
            .insert(DhcpOption::Router(vec![MOCK_SERVER_IP]));
        msg.opts_mut()
            .insert(DhcpOption::DomainNameServer(vec![DNS_IP_1, DNS_IP_2]));
        msg.opts_mut().insert(DhcpOption::AddressLeaseTime(1800));
        msg.opts_mut()
            .insert(DhcpOption::ServerIdentifier(MOCK_SERVER_IP));
        msg.set_yiaddr(MOCK_CLIENT_IP);

        let res = parse_ack_nak(&msg, 0xabcdef);
        if let ParseAckResult::Ack(ack) = res {
            assert_eq!(ack.ip, MOCK_CLIENT_IP);
            assert_eq!(ack.mask, DEFAULT_MASK);
            assert_eq!(ack.gateway, Some(MOCK_SERVER_IP));
            assert_eq!(ack.dns_servers, vec![DNS_IP_1, DNS_IP_2]);
            assert_eq!(ack.lease_secs, 1800);
            assert_eq!(ack.server_ip, Some(MOCK_SERVER_IP));
        } else {
            panic!("Expected Ack");
        }
    }

    #[test]
    fn test_parse_nak() {
        let mut msg = Message::default();
        msg.set_xid(0x9999);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Nak));

        let res = parse_ack_nak(&msg, 0x9999);
        assert!(matches!(res, ParseAckResult::Nak));
    }

    #[test]
    fn test_parse_lease_options_missing_fields() {
        let mut msg = Message::default();
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));

        let opts = parse_lease_options(&msg);
        assert_eq!(opts.mask, DEFAULT_MASK);
        assert_eq!(opts.gateway, None);
        assert!(opts.dns_servers.is_empty());
        assert_eq!(opts.lease_secs, DEFAULT_LEASE_SECS);
    }
}
