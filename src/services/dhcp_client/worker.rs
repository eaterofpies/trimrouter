use crate::packet::build_raw_packet;
use crate::services::DHCP_CLIENT_SERVICE_NAME;
use crate::services::ipc::{DhcpClientToParentMsg, send_msg};
use crate::services::utils::{
    CleanOption, DHCP_CLIENT_GID, DHCP_CLIENT_UID, RawPacketSocket, get_interface_mac,
    mask_to_prefix_len as utils_mask_to_prefix_len, parse_dhcp_payload, run_sandboxed_worker,
    wait_ipc_eof,
};
use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Encodable, Encoder};
use log::{debug, error, info, warn};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::os::unix::io::OwnedFd;
use std::time::{Duration, Instant};
use tokio::net::unix::OwnedReadHalf;
use tokio::time::sleep;

const DEFAULT_LEASE_SECS: u32 = 3600;
const MAX_RETRY_DELAY_SECS: u32 = 64;
const INITIAL_RETRY_DELAY_SECS: u32 = 4;
const DEFAULT_SUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const SOCKET_RESTART_DELAY_SECS: u64 = 5;
const BOUND_HEARTBEAT_INTERVAL_SECS: u64 = 3;

#[derive(Debug)]
pub enum DhcpError {
    Io(std::io::Error),
    Protocol(String),
    Nak,
    InterfaceNotFound(String),
    RtNetlink(rtnetlink::Error),
}

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

#[derive(Clone, Debug)]
struct DhcpOffer {
    offered_ip: Ipv4Addr,
    server_ip: Option<Ipv4Addr>,
}

#[derive(Clone, Debug)]
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
        )
        .map_err(|e| DhcpError::Protocol(e.to_string()))?;
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
    ipc_writer: Option<tokio::net::unix::OwnedWriteHalf>,
}

impl DhcpClientInternal {
    async fn run(&mut self, mut ipc_reader: OwnedReadHalf) {
        loop {
            tokio::select! {
                _ = wait_ipc_eof(&mut ipc_reader) => {
                    info!("[dhcp-client-worker] Parent closed IPC. Shutting down.");
                    self.deconfigure().await;
                    break;
                }
                phase_res = self.execute_phases() => {
                    if let Err(e) = phase_res
                        && !self.handle_phase_failure(e, &mut ipc_reader).await
                    {
                        break;
                    }
                }
            }
        }
    }

    async fn execute_phases(&mut self) -> Result<(), DhcpError> {
        let (xid, offer) = self.discover_phase().await?;
        let ack = self.request_phase(xid, offer).await?;
        self.bound_phase(ack).await?;
        Ok(())
    }

    async fn handle_phase_failure(&mut self, e: DhcpError, ipc_reader: &mut OwnedReadHalf) -> bool {
        warn!(
            "[dhcp-client] Phase failed: {}. Retrying in {}s...",
            e, SOCKET_RESTART_DELAY_SECS
        );
        self.deconfigure().await;
        tokio::select! {
            _ = wait_ipc_eof(ipc_reader) => {
                info!("[dhcp-client-worker] Parent closed IPC. Shutting down.");
                false
            }
            _ = sleep(Duration::from_secs(SOCKET_RESTART_DELAY_SECS)) => true,
        }
    }

    async fn send_heartbeat(&mut self) {
        if let Some(ref mut writer) = self.ipc_writer
            && let Err(e) = send_msg(writer, &DhcpClientToParentMsg::Heartbeat).await
        {
            debug!("[dhcp-client] Failed to send heartbeat to parent: {}", e);
        }
    }

    async fn discover_phase(&mut self) -> Result<(u32, DhcpOffer), DhcpError> {
        let xid = rand::random::<u32>();
        let mut retry_delay_secs = INITIAL_RETRY_DELAY_SECS;

        loop {
            self.send_heartbeat().await;
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
    async fn request_phase(&mut self, xid: u32, offer: DhcpOffer) -> Result<DhcpAck, DhcpError> {
        let mut retry_delay_secs = INITIAL_RETRY_DELAY_SECS;

        loop {
            self.send_heartbeat().await;
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

    async fn bound_phase(&mut self, mut ack: DhcpAck) -> Result<(), DhcpError> {
        self.apply_lease_config(ack.ip, ack.mask, ack.gateway, &ack.dns_servers)
            .await?;
        let mut bound_at = Instant::now();

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
                self.send_heartbeat().await;
                let sleep_duration = Duration::from_secs(std::cmp::min(
                    BOUND_HEARTBEAT_INTERVAL_SECS,
                    (t1_secs - elapsed) as u64,
                ));
                sleep(sleep_duration).await;
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
                    bound_at = Instant::now();
                }
                Err(e) => {
                    self.deconfigure().await;
                    return Err(e);
                }
            }
        }
    }

    async fn renew_lease(
        &mut self,
        ip: Ipv4Addr,
        t2_secs: u32,
        lease_secs: u32,
        server_ip: Option<Ipv4Addr>,
        bound_at: Instant,
    ) -> Result<DhcpAck, DhcpError> {
        let renew_xid = rand::random::<u32>();
        let mut renew_sent: Option<Instant> = None;

        loop {
            self.send_heartbeat().await;
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
                renew_sent = Some(Instant::now());
            }

            let listen_timeout = Duration::from_secs(retry_interval as u64);
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
        &mut self,
        ip: Ipv4Addr,
        mask: Ipv4Addr,
        gateway: Option<Ipv4Addr>,
        dns_servers: &[Ipv4Addr],
    ) -> Result<(), DhcpError> {
        let writer = self.ipc_writer.as_mut().ok_or_else(|| {
            DhcpError::Io(std::io::Error::other("IPC writer unavailable in worker"))
        })?;
        let prefix_len = utils_mask_to_prefix_len(mask).unwrap_or(24);
        let msg = DhcpClientToParentMsg::ApplyWanLease {
            ip_address: ip,
            prefix_len,
            gateway: gateway.unwrap_or(Ipv4Addr::UNSPECIFIED),
            dns_servers: dns_servers.to_vec(),
        };
        send_msg(writer, &msg).await.map_err(DhcpError::Io)?;
        Ok(())
    }

    async fn deconfigure(&mut self) {
        if let Some(ref mut writer) = self.ipc_writer {
            let msg = DhcpClientToParentMsg::ClearWanLease;
            if let Err(e) = send_msg(writer, &msg).await {
                debug!(
                    "[dhcp-client] Failed to send ClearWanLease to parent: {}",
                    e
                );
            }
        }
    }

    async fn send_discover(&self, xid: u32) {
        let discover = build_discover_message(self.mac, xid);
        let dest_ip = Ipv4Addr::BROADCAST;
        if let Err(e) = self.send_dhcp_message(discover, dest_ip).await {
            error!("[dhcp-client] Failed to send DHCPDISCOVER: {}", e);
        } else {
            debug!("[dhcp-client] Sent DHCPDISCOVER (xid: {}).", xid);
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
        let request = build_request_message(self.mac, xid, requested_ip, server_ip, ciaddr);
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

fn build_discover_message(mac: MacAddr, xid: u32) -> Message {
    let mut discover = Message::default();
    discover.set_opcode(Opcode::BootRequest);
    discover.set_xid(xid);
    discover.set_flags(Flags::default().set_broadcast());
    discover.set_chaddr(&mac.octets());

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

    discover
}

fn build_request_message(
    mac: MacAddr,
    xid: u32,
    requested_ip: Ipv4Addr,
    server_ip: Option<Ipv4Addr>,
    ciaddr: Ipv4Addr,
) -> Message {
    let mut request = Message::default();
    request.set_opcode(Opcode::BootRequest);
    request.set_xid(xid);
    request.set_ciaddr(ciaddr);
    request.set_chaddr(&mac.octets());

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

    request
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
        DHCP_CLIENT_SERVICE_NAME,
        DHCP_CLIENT_UID,
        DHCP_CLIENT_GID,
        ipc_fd,
        |ipc| async move {
            let mut client = DhcpClientInternal {
                socket: client_socket,
                mac,
                ipc_writer: Some(ipc.writer),
            };

            client.run(ipc.reader).await;
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
    let secs = (base_secs as f64 + jitter).max(1.0);
    std::time::Duration::from_secs_f64(secs)
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
        let interval = if remaining > 60 {
            (remaining / 2).max(60)
        } else {
            (remaining / 2).max(1)
        };
        (interval, Ipv4Addr::BROADCAST)
    } else {
        let remaining = t2_secs.saturating_sub(current_elapsed);
        let interval = if remaining > 60 {
            (remaining / 2).max(60)
        } else {
            (remaining / 2).max(1)
        };
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

    #[test]
    fn test_parse_offer_wrong_msg_type_returns_none() {
        let mut msg = Message::default();
        msg.set_xid(0x12345678);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        msg.set_yiaddr(MOCK_CLIENT_IP);

        let res = parse_offer(&msg, 0x12345678);
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_ack_nak_mismatched_xid_returns_none() {
        let mut msg = Message::default();
        msg.set_xid(0x1111);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));

        let res = parse_ack_nak(&msg, 0x2222);
        assert!(matches!(res, ParseAckResult::None));
    }

    #[test]
    fn test_parse_ack_nak_wrong_message_type_returns_none() {
        let mut msg = Message::default();
        msg.set_xid(0x3333);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));

        let res = parse_ack_nak(&msg, 0x3333);
        assert!(matches!(res, ParseAckResult::None));
    }

    #[test]
    fn test_parse_ack_nak_missing_message_type_returns_none() {
        let mut msg = Message::default();
        msg.set_xid(0x4444);

        let res = parse_ack_nak(&msg, 0x4444);
        assert!(matches!(res, ParseAckResult::None));
    }

    #[test]
    fn test_build_discover_message() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let xid = 0xabcdef01;
        let msg = build_discover_message(mac, xid);

        assert_eq!(msg.opcode(), Opcode::BootRequest);
        assert_eq!(msg.xid(), xid);
        assert_eq!(msg.chaddr(), &mac.octets());
        assert!(msg.flags().broadcast());

        let msg_type = msg.opts().get(OptionCode::MessageType);
        assert_eq!(
            msg_type,
            Some(&DhcpOption::MessageType(MessageType::Discover))
        );

        let params = msg.opts().get(OptionCode::ParameterRequestList);
        assert_eq!(
            params,
            Some(&DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer,
            ]))
        );
    }

    #[test]
    fn test_build_request_message_selecting() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let xid = 0x12345678;
        let requested_ip = Ipv4Addr::new(10, 0, 2, 15);
        let server_ip = Ipv4Addr::new(10, 0, 2, 2);

        let msg = build_request_message(
            mac,
            xid,
            requested_ip,
            Some(server_ip),
            Ipv4Addr::UNSPECIFIED,
        );

        assert_eq!(msg.opcode(), Opcode::BootRequest);
        assert_eq!(msg.xid(), xid);
        assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(msg.chaddr(), &mac.octets());
        assert!(msg.flags().broadcast());

        assert_eq!(
            msg.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Request))
        );
        assert_eq!(
            msg.opts().get(OptionCode::RequestedIpAddress),
            Some(&DhcpOption::RequestedIpAddress(requested_ip))
        );
        assert_eq!(
            msg.opts().get(OptionCode::ServerIdentifier),
            Some(&DhcpOption::ServerIdentifier(server_ip))
        );
    }

    #[test]
    fn test_build_request_message_renewing() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let xid = 0x87654321;
        let client_ip = Ipv4Addr::new(10, 0, 2, 15);

        let msg = build_request_message(mac, xid, client_ip, None, client_ip);

        assert_eq!(msg.opcode(), Opcode::BootRequest);
        assert_eq!(msg.xid(), xid);
        assert_eq!(msg.ciaddr(), client_ip);
        assert_eq!(msg.chaddr(), &mac.octets());
        assert!(!msg.flags().broadcast());

        assert_eq!(
            msg.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Request))
        );
        // In RENEWING, Requested IP Address and Server ID should not be set in options
        assert_eq!(msg.opts().get(OptionCode::RequestedIpAddress), None);
        assert_eq!(msg.opts().get(OptionCode::ServerIdentifier), None);
    }

    #[test]
    fn test_calculate_next_delay() {
        assert_eq!(calculate_next_delay(2), 4);
        assert_eq!(calculate_next_delay(32), 64);
        assert_eq!(calculate_next_delay(40), MAX_RETRY_DELAY_SECS);
        assert_eq!(
            calculate_next_delay(MAX_RETRY_DELAY_SECS),
            MAX_RETRY_DELAY_SECS
        );
    }

    #[test]
    fn test_calculate_renewal_params() {
        let server_ip = Ipv4Addr::new(10, 0, 2, 2);
        let lease_secs = 3600;
        let t2_secs = 3150;

        // T1 renewal phase (unicast to server): remaining to T2 = 1350s -> 1350 / 2 = 675s
        let (interval, dest_ip, rebinding) =
            calculate_renewal_params(1800, t2_secs, lease_secs, Some(server_ip));
        assert!(!rebinding);
        assert_eq!(dest_ip, server_ip);
        assert_eq!(interval, 675);

        // T2 rebinding phase (broadcast): remaining to expiry = 400s -> 400 / 2 = 200s
        let (interval, dest_ip, rebinding) =
            calculate_renewal_params(3200, t2_secs, lease_secs, Some(server_ip));
        assert!(rebinding);
        assert_eq!(dest_ip, Ipv4Addr::BROADCAST);
        assert_eq!(interval, 200);

        // Sub-minute remaining in T1: remaining = 50s -> 50 / 2 = 25s
        let (interval, _, _) = calculate_renewal_params(3100, t2_secs, lease_secs, Some(server_ip));
        assert_eq!(interval, 25);
    }

    #[test]
    fn test_handle_ack_result() {
        let ack_data = DhcpAck {
            ip: MOCK_CLIENT_IP,
            mask: DEFAULT_MASK,
            gateway: Some(MOCK_SERVER_IP),
            dns_servers: vec![],
            lease_secs: 1800,
            server_ip: Some(MOCK_SERVER_IP),
        };

        let ok_res = handle_ack_result(ParseAckResult::Ack(ack_data.clone()));
        assert!(matches!(ok_res, Some(Ok(_))));

        let nak_res = handle_ack_result(ParseAckResult::Nak);
        assert!(matches!(nak_res, Some(Err(DhcpError::Nak))));

        let none_res = handle_ack_result(ParseAckResult::None);
        assert!(none_res.is_none());
    }

    #[test]
    fn test_parse_ack_empty_router_option_returns_none_gateway() {
        let mut msg = Message::default();
        msg.set_xid(0x1234);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        msg.opts_mut().insert(DhcpOption::Router(vec![]));

        if let ParseAckResult::Ack(ack) = parse_ack_nak(&msg, 0x1234) {
            assert_eq!(ack.gateway, None);
        } else {
            panic!("Expected Ack");
        }
    }

    #[test]
    fn test_parse_ack_multiple_routers_takes_first() {
        let mut msg = Message::default();
        msg.set_xid(0x1234);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        let router1 = Ipv4Addr::new(10, 0, 2, 1);
        let router2 = Ipv4Addr::new(10, 0, 2, 254);
        msg.opts_mut()
            .insert(DhcpOption::Router(vec![router1, router2]));

        if let ParseAckResult::Ack(ack) = parse_ack_nak(&msg, 0x1234) {
            assert_eq!(ack.gateway, Some(router1));
        } else {
            panic!("Expected Ack");
        }
    }

    #[test]
    fn test_parse_ack_extreme_lease_times() {
        // Zero lease time
        let mut msg_zero = Message::default();
        msg_zero.set_xid(0x1000);
        msg_zero
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        msg_zero.opts_mut().insert(DhcpOption::AddressLeaseTime(0));

        if let ParseAckResult::Ack(ack) = parse_ack_nak(&msg_zero, 0x1000) {
            assert_eq!(ack.lease_secs, 0);
        } else {
            panic!("Expected Ack");
        }

        // Max lease time (u32::MAX)
        let mut msg_max = Message::default();
        msg_max.set_xid(0x2000);
        msg_max
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Ack));
        msg_max
            .opts_mut()
            .insert(DhcpOption::AddressLeaseTime(u32::MAX));

        if let ParseAckResult::Ack(ack) = parse_ack_nak(&msg_max, 0x2000) {
            assert_eq!(ack.lease_secs, u32::MAX);
        } else {
            panic!("Expected Ack");
        }
    }

    #[test]
    fn test_parse_offer_special_yiaddr() {
        let mut msg_zero = Message::default();
        msg_zero.set_xid(0x5555);
        msg_zero
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        msg_zero.set_yiaddr(Ipv4Addr::UNSPECIFIED);

        let res = parse_offer(&msg_zero, 0x5555).unwrap();
        assert_eq!(res.offered_ip, Ipv4Addr::UNSPECIFIED);

        let mut msg_bcast = Message::default();
        msg_bcast.set_xid(0x6666);
        msg_bcast
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        msg_bcast.set_yiaddr(Ipv4Addr::BROADCAST);

        let res_bcast = parse_offer(&msg_bcast, 0x6666).unwrap();
        assert_eq!(res_bcast.offered_ip, Ipv4Addr::BROADCAST);
    }

    #[test]
    fn test_parse_ack_nak_unexpected_message_types_returns_none() {
        for unexpected_type in [
            MessageType::Decline,
            MessageType::Release,
            MessageType::Inform,
        ] {
            let mut msg = Message::default();
            msg.set_xid(0x7777);
            msg.opts_mut()
                .insert(DhcpOption::MessageType(unexpected_type));

            let res = parse_ack_nak(&msg, 0x7777);
            assert!(matches!(res, ParseAckResult::None));
        }
    }

    #[test]
    fn test_calculate_renewal_params_edge_cases() {
        // Zero lease time: should not panic, returns minimum 1s interval
        let (interval, _dest, rebinding) = calculate_renewal_params(0, 0, 0, None);
        assert!(rebinding);
        assert_eq!(interval, 1);

        // Very short lease time (e.g. lease=10s, t2=8s, elapsed=2s):
        // Remaining time to T2 is 6s; interval must scale down to remaining / 2 = 3s (strictly < 6s)
        let (interval, _dest, rebinding) = calculate_renewal_params(2, 8, 10, None);
        assert!(!rebinding);
        assert_eq!(interval, 3);
        assert!(
            interval < 6,
            "Retry interval must be strictly less than remaining time"
        );

        // In rebinding for short lease (elapsed=9s, lease=10s): remaining=1s -> interval=1s
        let (interval, dest, rebinding) = calculate_renewal_params(9, 8, 10, None);
        assert!(rebinding);
        assert_eq!(dest, Ipv4Addr::BROADCAST);
        assert_eq!(interval, 1);

        // Max lease time: should handle large bounds without arithmetic overflow
        let t2_max = (u32::MAX as f64 * 0.875) as u32;
        let remaining_to_t2 = t2_max - 100;
        let (interval, dest, rebinding) =
            calculate_renewal_params(100, t2_max, u32::MAX, Some(MOCK_SERVER_IP));
        assert!(!rebinding);
        assert_eq!(dest, MOCK_SERVER_IP);
        assert_eq!(interval, remaining_to_t2 / 2);
    }

    #[test]
    fn test_calculate_next_delay_bounds() {
        assert_eq!(calculate_next_delay(4), 8);
        assert_eq!(calculate_next_delay(8), 16);
        assert_eq!(calculate_next_delay(16), 32);
        assert_eq!(calculate_next_delay(32), 64);
        assert_eq!(calculate_next_delay(64), 64);
        assert_eq!(calculate_next_delay(100), 64);
    }

    #[test]
    fn test_get_jittered_duration_bounds() {
        for _ in 0..100 {
            let dur = get_jittered_duration(4);
            assert!(dur.as_secs_f64() >= 3.0);
            assert!(dur.as_secs_f64() <= 5.0);
        }

        for _ in 0..50 {
            let dur = get_jittered_duration(0);
            assert_eq!(dur, Duration::from_secs(1));
        }
    }

    #[test]
    fn test_build_discover_message_structure() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let msg = build_discover_message(mac, 0x12345678);

        assert_eq!(msg.opcode(), Opcode::BootRequest);
        assert_eq!(msg.xid(), 0x12345678);
        assert!(msg.flags().broadcast());
        assert_eq!(
            msg.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Discover))
        );
    }

    #[test]
    fn test_build_request_message_selecting_and_renewing() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let req_ip = Ipv4Addr::new(192, 168, 1, 100);
        let srv_ip = Ipv4Addr::new(192, 168, 1, 1);

        // Selecting request (ciaddr = 0.0.0.0)
        let msg_sel =
            build_request_message(mac, 0x1111, req_ip, Some(srv_ip), Ipv4Addr::UNSPECIFIED);
        assert_eq!(msg_sel.ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            msg_sel.opts().get(OptionCode::RequestedIpAddress),
            Some(&DhcpOption::RequestedIpAddress(req_ip))
        );
        assert_eq!(
            msg_sel.opts().get(OptionCode::ServerIdentifier),
            Some(&DhcpOption::ServerIdentifier(srv_ip))
        );
        assert!(msg_sel.flags().broadcast());

        // Renewing request (ciaddr = req_ip)
        let msg_ren = build_request_message(mac, 0x2222, req_ip, Some(srv_ip), req_ip);
        assert_eq!(msg_ren.ciaddr(), req_ip);
        assert_eq!(msg_ren.opts().get(OptionCode::RequestedIpAddress), None);
        assert_eq!(msg_ren.opts().get(OptionCode::ServerIdentifier), None);
        assert!(!msg_ren.flags().broadcast());
    }

    #[test]
    fn test_parse_offer_and_ack_edge_cases() {
        let mut msg = dhcproto::v4::Message::default();
        msg.set_xid(0x5555);
        msg.set_yiaddr(Ipv4Addr::new(10, 0, 2, 15));

        // Wrong xid returns None
        assert!(parse_offer(&msg, 0x9999).is_none());

        // Message without OptionCode::MessageType returns None
        assert!(parse_offer(&msg, 0x5555).is_none());

        // DHCPOFFER without server identifier
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Offer));
        let offer = parse_offer(&msg, 0x5555).expect("Valid offer");
        assert_eq!(offer.offered_ip, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(offer.server_ip, None);

        // DHCPNAK
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Nak));
        assert!(matches!(parse_ack_nak(&msg, 0x5555), ParseAckResult::Nak));
    }
}
