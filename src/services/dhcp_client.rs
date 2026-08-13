use super::utils::{
    CleanOption, RawPacketSocket, SharedWanLease, WanLease, get_interface_mac,
    mask_to_prefix_len as utils_mask_to_prefix_len, wait_shutdown, open_raw_socket,
};
use crate::packet::build_raw_packet;
use futures_util::TryStreamExt;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::os::unix::io::{FromRawFd, RawFd};
use tokio::io::AsyncReadExt;
use super::ipc::{recv_msg, DhcpClientToParentMsg};

const DEFAULT_LEASE_SECS: u32 = 3600;
const MAX_RETRY_DELAY_SECS: u32 = 64;
const INITIAL_RETRY_DELAY_SECS: u32 = 4;
const DEFAULT_SUBNET_MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
const SOCKET_RESTART_DELAY_SECS: u64 = 5;

#[derive(Debug)]
enum DhcpError {
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
    fn new(interface_name: &str, mac: MacAddr) -> Result<Self, std::io::Error> {
        let raw_socket = RawPacketSocket::new(interface_name)?;
        Ok(Self { raw_socket, mac })
    }

    fn from_raw_socket(raw_socket: RawPacketSocket, mac: MacAddr) -> Self {
        Self { raw_socket, mac }
    }

    async fn send(
        &self,
        message: &dhcproto::v4::Message,
        dest_ip: Ipv4Addr,
    ) -> Result<(), DhcpError> {
        use dhcproto::{Encodable, Encoder};
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

            if let Some(dhcp) =
                super::utils::parse_dhcp_payload(&raw_buf[..n], dhcproto::v4::CLIENT_PORT)
            {
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
    fn new(
        socket: DhcpClientSocket,
        mac: MacAddr,
        lease_state: SharedWanLease,
        wan_interface: String,
    ) -> Self {
        Self {
            socket,
            mac,
            lease_state,
            wan_interface,
            ipc_writer: None,
        }
    }

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
        println!(
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
                println!(
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
            println!("[dhcp-client] Received DHCPACK for IP: {}", ack.ip);
            Some(Ok(ack))
        }
        ParseAckResult::Nak => {
            println!("[dhcp-client] Received DHCPNAK!");
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
                println!("[dhcp-client] Lease expired!");
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
                    println!("[dhcp-client] REBINDING: sending broadcast DHCPREQUEST...");
                } else {
                    println!("[dhcp-client] RENEWING: sending unicast DHCPREQUEST to server...");
                }
                self.send_request(renew_xid, ip, None, ip, dest_ip).await;
                renew_sent = Some(std::time::Instant::now());
            }

            let listen_timeout = std::time::Duration::from_secs(retry_interval as u64);
            if let Some(ack_res) = self.wait_for_ack(renew_xid, listen_timeout).await? {
                match ack_res {
                    ParseAckResult::Ack(new_ack) => {
                        println!("[dhcp-client] Renewal successful!");
                        return Ok(new_ack);
                    }
                    ParseAckResult::Nak => {
                        println!("[dhcp-client] Renewal NAK'd!");
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
            let msg = super::ipc::DhcpClientToParentMsg::ApplyWanLease {
                ip_address: ip,
                prefix_len,
                gateway: gateway.unwrap_or(Ipv4Addr::UNSPECIFIED),
                dns_servers: dns_servers.to_vec(),
            };
            let mut writer = writer_mutex.lock().await;
            super::ipc::send_msg(&mut *writer, &msg).await
                .map_err(|e| DhcpError::Io(e))?;
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
                    println!("[dhcp-client] Lease parameters updated: {:?}", *lease);
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
            let msg = super::ipc::DhcpClientToParentMsg::ClearWanLease;
            let mut writer = writer_mutex.lock().await;
            let _ = super::ipc::send_msg(&mut *writer, &msg).await;
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
                println!(
                    "[dhcp-client] ERROR: Failed to deconfigure WAN interface via netlink: {}",
                    e
                );
            }
        }
    }

    async fn send_discover(&self, xid: u32) {
        use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};

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
            println!("[dhcp-client] ERROR: Failed to send DHCPDISCOVER: {}", e);
        } else {
            println!("[dhcp-client] Sent DHCPDISCOVER.");
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
        use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode};

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
            println!("[dhcp-client] ERROR: Failed to send DHCPREQUEST: {}", e);
        } else {
            println!(
                "[dhcp-client] Sent DHCPREQUEST (ciaddr: {}, dest_ip: {}).",
                ciaddr, dest_ip
            );
        }
    }
}

use super::{Service, ServiceError};

const NOBODY_UID: u32 = 65534;
const NOBODY_GID: u32 = 65534;

pub struct DhcpClient {
    wan_interface: String,
    lease_state: SharedWanLease,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    child_pid: Option<u32>,
}

impl DhcpClient {
    pub fn new(wan_interface: String, lease_state: SharedWanLease) -> Self {
        Self {
            wan_interface,
            lease_state,
            task_handle: None,
            child_pid: None,
        }
    }
}

fn prefix_len_to_mask(prefix_len: u8) -> Ipv4Addr {
    let mask_u32 = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(mask_u32)
}

fn setup_worker_sockets(wan_interface: &str) -> Result<(RawFd, RawFd, RawFd), ServiceError> {
    let raw_socket_fd = open_raw_socket(wan_interface)
        .map_err(|e| ServiceError::FailedToStart(e))?;

    let mut fds = [0; 2];
    let res = unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
    };
    if res < 0 {
        unsafe { libc::close(raw_socket_fd); }
        return Err(ServiceError::FailedToStart(format!(
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((raw_socket_fd, fds[0], fds[1]))
}

fn spawn_worker_process(
    child_ipc_fd: RawFd,
    raw_socket_fd: RawFd,
    wan_interface: &str,
) -> Result<std::process::Child, ServiceError> {
    use std::process::Command;
    use std::os::unix::process::CommandExt;

    let binary_path = if std::path::Path::new("/bin/trimrouter").exists() {
        "/bin/trimrouter"
    } else {
        "/proc/self/exe"
    };

    let mut cmd = Command::new(binary_path);
    cmd.arg("worker");
    cmd.arg("dhcp-client");
    cmd.arg(child_ipc_fd.to_string());
    cmd.arg(raw_socket_fd.to_string());
    cmd.arg(wan_interface);

    unsafe {
        cmd.pre_exec(move || {
            libc::fcntl(child_ipc_fd, libc::F_SETFD, 0);
            libc::fcntl(raw_socket_fd, libc::F_SETFD, 0);
            Ok(())
        });
    }

    cmd.spawn().map_err(|e| ServiceError::FailedToStart(format!("spawn failed: {}", e)))
}

async fn apply_parent_lease(
    lease_state: &SharedWanLease,
    wan_interface: &str,
    ip_address: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns_servers: Vec<Ipv4Addr>,
) {
    let changed = {
        let mut lease = lease_state.lock().unwrap();
        let changed = lease.ip != Some(ip_address)
            || lease.mask != Some(mask)
            || lease.gateway != Some(gateway)
            || lease.dns_servers != dns_servers;

        if changed {
            lease.ip = Some(ip_address);
            lease.mask = Some(mask);
            lease.gateway = Some(gateway);
            lease.dns_servers = dns_servers;
            println!(
                "[dhcp-client-parent] Applied WAN lease configuration: {:?}",
                *lease
            );
        }
        changed
    };

    if changed {
        if let Err(e) = configure_wan(wan_interface, ip_address, mask, Some(gateway)).await {
            eprintln!("[dhcp-client-parent] ERROR: Failed to configure WAN: {}", e);
        }
    }
}

async fn clear_parent_lease(lease_state: &SharedWanLease, wan_interface: &str) {
    let (ip, mask) = {
        let mut lease = lease_state.lock().unwrap();
        let ip = lease.ip;
        let mask = lease.mask;
        *lease = WanLease::default();
        (ip, mask)
    };

    if let Some(ip) = ip
        && let Some(mask) = mask
    {
        if let Err(e) = deconfigure_wan(wan_interface, ip, mask).await {
            eprintln!("[dhcp-client-parent] ERROR: Failed to deconfigure WAN: {}", e);
        }
    }
}

fn start_parent_supervisor_task(
    parent_ipc_fd: RawFd,
    child_pid: u32,
    wan_interface: String,
    lease_state: SharedWanLease,
) -> Result<tokio::task::JoinHandle<()>, ServiceError> {
    use std::os::unix::net::UnixStream as StdUnixStream;

    let std_stream = unsafe { StdUnixStream::from_raw_fd(parent_ipc_fd) };
    std_stream.set_nonblocking(true).map_err(ServiceError::Io)?;
    let mut parent_ipc_stream = tokio::net::UnixStream::from_std(std_stream).map_err(ServiceError::Io)?;

    let handle = tokio::spawn(async move {
        println!(
            "[dhcp-client-parent] Supervising DHCP client worker (PID {})",
            child_pid
        );
        loop {
            match recv_msg::<DhcpClientToParentMsg, _>(&mut parent_ipc_stream).await {
                Ok(Some(DhcpClientToParentMsg::ApplyWanLease {
                    ip_address,
                    prefix_len,
                    gateway,
                    dns_servers,
                })) => {
                    let mask = prefix_len_to_mask(prefix_len);
                    apply_parent_lease(
                        &lease_state,
                        &wan_interface,
                        ip_address,
                        mask,
                        gateway,
                        dns_servers,
                    )
                    .await;
                }
                Ok(Some(DhcpClientToParentMsg::ClearWanLease)) => {
                    clear_parent_lease(&lease_state, &wan_interface).await;
                }
                Ok(None) => {
                    println!("[dhcp-client-parent] Worker IPC socket closed.");
                    break;
                }
                Err(e) => {
                    eprintln!("[dhcp-client-parent] IPC recv error: {}", e);
                    break;
                }
            }
        }

        let pid = nix::unistd::Pid::from_raw(child_pid as i32);
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    });

    Ok(handle)
}

impl Service for DhcpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        if self.task_handle.is_some() {
            return Err(ServiceError::AlreadyRunning);
        }

        let _ = get_interface_mac(&self.wan_interface).await
            .map_err(|e| ServiceError::FailedToStart(e))?;

        let (raw_socket_fd, parent_ipc_fd, child_ipc_fd) = setup_worker_sockets(&self.wan_interface)?;

        let child = match spawn_worker_process(child_ipc_fd, raw_socket_fd, &self.wan_interface) {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    libc::close(raw_socket_fd);
                    libc::close(parent_ipc_fd);
                    libc::close(child_ipc_fd);
                }
                return Err(e);
            }
        };

        unsafe {
            libc::close(child_ipc_fd);
            libc::close(raw_socket_fd);
        }

        let child_pid = child.id();
        let handle = start_parent_supervisor_task(
            parent_ipc_fd,
            child_pid,
            self.wan_interface.clone(),
            self.lease_state.clone(),
        )?;

        self.child_pid = Some(child_pid);
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        let child_pid = self.child_pid.take().ok_or(ServiceError::NotRunning)?;
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;

        println!("[dhcp-client-parent] Stopping worker process PID {}", child_pid);
        let pid = nix::unistd::Pid::from_raw(child_pid as i32);
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);

        let start = std::time::Instant::now();
        loop {
            match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                    if start.elapsed() > std::time::Duration::from_secs(1) {
                        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                _ => break,
            }
        }

        let _ = handle.await;
        Ok(())
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
    println!("[dhcp-client-worker] Parent closed IPC. Shutting down.");
    let _ = shutdown_tx.send(true);
}

pub async fn run_dhcp_client_worker(
    ipc_fd: RawFd,
    raw_socket_fd: RawFd,
    wan_interface: String,
) -> Result<(), std::io::Error> {
    use std::os::unix::net::UnixStream as StdUnixStream;

    println!(
        "[dhcp-client-worker] Starting unprivileged WAN DHCP client worker on {}...",
        wan_interface
    );

    let socket = RawPacketSocket::from_raw_fd(raw_socket_fd)?;
    let mac = match get_interface_mac(&wan_interface).await {
        Ok(m) => m,
        Err(e) => {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
    };
    let client_socket = DhcpClientSocket::from_raw_socket(socket, mac);

    let std_stream = unsafe { StdUnixStream::from_raw_fd(ipc_fd) };
    std_stream.set_nonblocking(true)?;
    let ipc_stream = tokio::net::UnixStream::from_std(std_stream)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(tokio::sync::Mutex::new(ipc_writer));

    if let Err(e) = drop_privileges() {
        eprintln!("[dhcp-client-worker] FATAL: Failed to drop privileges: {}", e);
        std::process::exit(1);
    }
    println!("[dhcp-client-worker] Privileges dropped successfully (running as nobody inside chroot jail).");

    let dummy_lease_state = Arc::new(std::sync::Mutex::new(WanLease::default()));
    let client = DhcpClientInternal {
        socket: client_socket,
        mac,
        lease_state: dummy_lease_state,
        wan_interface: wan_interface.clone(),
        ipc_writer: Some(shared_ipc_writer),
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(monitor_parent_ipc(ipc_reader, shutdown_tx));

    client.run(shutdown_rx).await;
    Ok(())
}

fn drop_privileges() -> Result<(), std::io::Error> {
    use nix::unistd::{setuid, setgid, Uid, Gid};

    let _ = std::fs::create_dir_all("/run/empty");
    if let Ok(metadata) = std::fs::metadata("/run/empty") {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = metadata.permissions();
        perms.set_mode(0o555);
        let _ = std::fs::set_permissions("/run/empty", perms);
    }

    let chroot_path = std::ffi::CString::new("/run/empty").unwrap();
    let res = unsafe { libc::chroot(chroot_path.as_ptr()) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let chdir_path = std::ffi::CString::new("/").unwrap();
    let res = unsafe { libc::chdir(chdir_path.as_ptr()) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }

    caps::clear(None, caps::CapSet::Bounding).map_err(std::io::Error::other)?;

    setgid(Gid::from_raw(NOBODY_GID)).map_err(std::io::Error::other)?;

    setuid(Uid::from_raw(NOBODY_UID)).map_err(std::io::Error::other)?;

    let _ = caps::clear(None, caps::CapSet::Inheritable);
    let _ = caps::clear(None, caps::CapSet::Effective);
    let _ = caps::clear(None, caps::CapSet::Permitted);

    Ok(())
}

async fn handle_mac_address_error(
    wan_interface: &str,
    e: &str,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    eprintln!(
        "[dhcp-client] ERROR: Failed to get MAC address for {}: {}. Retrying in {}s...",
        wan_interface, e, SOCKET_RESTART_DELAY_SECS
    );
    tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {}
        _ = tokio::time::sleep(std::time::Duration::from_secs(SOCKET_RESTART_DELAY_SECS)) => {}
    }
}

async fn run_client_loop(
    wan_interface: String,
    lease_state: SharedWanLease,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    println!(
        "[dhcp-client] Starting WAN DHCP client on {}...",
        wan_interface
    );

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        let mac = match get_interface_mac(&wan_interface).await {
            Ok(m) => m,
            Err(e) => {
                handle_mac_address_error(&wan_interface, &e, &mut shutdown_rx).await;
                continue;
            }
        };
        println!(
            "[dhcp-client] Interface {} MAC address: {}",
            wan_interface, mac
        );

        let socket = match DhcpClientSocket::new(&wan_interface, mac) {
            Ok(s) => s,
            Err(e) => {
                handle_socket_creation_error(e, &mut shutdown_rx).await;
                continue;
            }
        };

        let client =
            DhcpClientInternal::new(socket, mac, lease_state.clone(), wan_interface.clone());

        let mut shutdown_rx_clone = shutdown_rx.clone();
        let shutdown_rx_for_run = shutdown_rx.clone();

        tokio::select! {
            _ = wait_shutdown(&mut shutdown_rx_clone) => {
                client.deconfigure().await;
                break;
            }
            _ = client.run(shutdown_rx_for_run) => {
                handle_run_exit(&mut shutdown_rx).await;
            }
        }
    }
}

async fn handle_socket_creation_error(
    e: std::io::Error,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    eprintln!(
        "[dhcp-client] ERROR: Failed to create client socket: {}. Retrying in {}s...",
        e, SOCKET_RESTART_DELAY_SECS
    );
    tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {}
        _ = tokio::time::sleep(std::time::Duration::from_secs(SOCKET_RESTART_DELAY_SECS)) => {}
    }
}

async fn handle_run_exit(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    println!(
        "[dhcp-client] Socket closed or client loop exited. Restarting in {}s...",
        SOCKET_RESTART_DELAY_SECS
    );
    tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {}
        _ = tokio::time::sleep(std::time::Duration::from_secs(SOCKET_RESTART_DELAY_SECS)) => {}
    }
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
    use dhcproto::v4::{DhcpOption, MessageType, OptionCode};

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
    use dhcproto::v4::{DhcpOption, MessageType, OptionCode};

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

async fn deconfigure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<(), DhcpError> {
    let prefix_len =
        utils_mask_to_prefix_len(mask).map_err(|e| DhcpError::Protocol(e.to_string()))?;
    println!(
        "[dhcp-client] Deconfiguring WAN interface via netlink: removing IP {}/{}",
        ip, prefix_len
    );

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(wan_interface.to_string())
        .execute();
    let link = match links.try_next().await? {
        Some(l) => l,
        None => return Err(DhcpError::InterfaceNotFound(wan_interface.to_string())),
    };
    let index = link.header.index;

    // Filter and delete the matching address
    let mut addresses = handle.address().get().execute();
    while let Some(addr) = addresses.try_next().await? {
        if addr.header.index == index {
            let mut matches_ip = false;
            for nla in addr.attributes.iter() {
                if let rtnetlink::packet_route::address::AddressAttribute::Local(ip_attr) = nla
                    && ip_attr == &std::net::IpAddr::V4(ip)
                {
                    matches_ip = true;
                    break;
                }
            }
            if matches_ip && let Err(e) = handle.address().del(addr).execute().await {
                println!("[dhcp-client] WARNING: Failed to delete IP address: {}", e);
            }
        }
    }
    Ok(())
}

async fn configure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
) -> Result<(), DhcpError> {
    let prefix_len =
        utils_mask_to_prefix_len(mask).map_err(|e| DhcpError::Protocol(e.to_string()))?;
    println!(
        "[dhcp-client] Configuring WAN interface via netlink: IP={}/{}, Gateway={:?}",
        ip,
        prefix_len,
        CleanOption(&gateway)
    );

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = handle
        .link()
        .get()
        .match_name(wan_interface.to_string())
        .execute();
    let link = match links.try_next().await? {
        Some(l) => l,
        None => return Err(DhcpError::InterfaceNotFound(wan_interface.to_string())),
    };
    let index = link.header.index;

    // Flush existing addresses on WAN first
    let mut addresses = handle.address().get().execute();
    while let Some(addr) = addresses.try_next().await? {
        if addr.header.index == index
            && let Err(e) = handle.address().del(addr).execute().await
        {
            println!(
                "[dhcp-client] WARNING: Failed to delete existing address: {}",
                e
            );
        }
    }

    // Set link state UP (if not already)
    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;

    // Add new IP
    handle
        .address()
        .add(index, std::net::IpAddr::V4(ip), prefix_len)
        .execute()
        .await?;

    // Add default route
    if let Some(gw) = gateway {
        let route = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .gateway(gw)
            .output_interface(index)
            .build();
        if let Err(e) = handle.route().add(route).execute().await {
            println!("[dhcp-client] WARNING: Failed to add default route: {}", e);
        }
    }

    Ok(())
}

fn get_server_identifier(dhcp: &dhcproto::v4::Message) -> Option<Ipv4Addr> {
    match dhcp.opts().get(dhcproto::v4::OptionCode::ServerIdentifier) {
        Some(dhcproto::v4::DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

fn parse_lease_options(dhcp: &dhcproto::v4::Message) -> LeaseOptions {
    use dhcproto::v4::DhcpOption;
    use dhcproto::v4::OptionCode;

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
