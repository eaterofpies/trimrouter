use super::ipc::IpcEndpoint;
use crate::error::RouterError;
use dhcproto::v4::Message;
use dhcproto::{Decodable, Decoder};
use futures_util::TryStreamExt;
use log::{info, warn};
use nix::unistd::{Gid, Uid, setgid, setuid};
use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::util::MacAddr;
use rtnetlink::packet_route::link::LinkAttribute;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub const CHROOT_JAIL_PATH: &str = "/run/empty";
pub const NOBODY_UID: u32 = 65534;
pub const NOBODY_GID: u32 = 65534;
pub const SELF_EXE_PATH: &str = "/proc/self/exe";
pub const ROUTER_BINARY_PATH: &str = "/bin/trimrouter";

// Unique isolated service UID/GID configurations
pub const SNTP_UID: u32 = 10001;
pub const SNTP_GID: u32 = 10001;
pub const DHCP_CLIENT_UID: u32 = 10002;
pub const DHCP_CLIENT_GID: u32 = 10002;
pub const DHCP_SERVER_UID: u32 = 10003;
pub const DHCP_SERVER_GID: u32 = 10003;
pub const DNS_FORWARDER_UID: u32 = 10004;
pub const DNS_FORWARDER_GID: u32 = 10004;

// Standard network protocol ports
pub const DNS_PORT: u16 = 53;
pub const NTP_PORT: u16 = 123;

// =========================================================================
// Shared WAN Lease Info
// =========================================================================
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WanLease {
    pub ip: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
}

pub type WanLeaseSender = tokio::sync::watch::Sender<WanLease>;
pub type WanLeaseReceiver = tokio::sync::watch::Receiver<WanLease>;

pub struct CleanOption<'a, T>(pub &'a Option<T>);

impl<'a, T: std::fmt::Display> std::fmt::Debug for CleanOption<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl<'a, T: std::fmt::Display> std::fmt::Display for CleanOption<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(val) => write!(f, "\"{}\"", val),
            None => write!(f, "None"),
        }
    }
}

impl std::fmt::Debug for WanLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WanLease")
            .field("ip", &CleanOption(&self.ip))
            .field("mask", &CleanOption(&self.mask))
            .field("gateway", &CleanOption(&self.gateway))
            .field("dns_servers", &self.dns_servers)
            .finish()
    }
}

pub fn mask_to_prefix_len(mask: Ipv4Addr) -> Result<u8, RouterError> {
    let mask_u32 = u32::from(mask);
    let leading_ones = mask_u32.leading_ones();
    let trailing_zeros = mask_u32.trailing_zeros();

    if leading_ones + trailing_zeros != 32 {
        return Err(RouterError::Generic(format!(
            "Invalid non-contiguous subnet mask: {}",
            mask
        )));
    }
    Ok(leading_ones as u8)
}

pub fn prefix_len_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 || prefix_len > 32 {
        Ipv4Addr::UNSPECIFIED
    } else {
        let mask_u32 = u32::MAX << (32 - prefix_len);
        Ipv4Addr::from(mask_u32)
    }
}

// =========================================================================
// Helper Functions for Raw Sockets
// =========================================================================
pub fn mac_from_slice(slice: &[u8]) -> Result<MacAddr, RouterError> {
    if slice.len() == 6 {
        Ok(MacAddr(
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5],
        ))
    } else {
        Err(RouterError::Generic(format!(
            "Invalid MAC address length: expected 6, found {}",
            slice.len()
        )))
    }
}

fn find_mac_address_attribute(attributes: Vec<LinkAttribute>) -> Option<MacAddr> {
    attributes.into_iter().find_map(|attr| match attr {
        LinkAttribute::Address(mac_vec) => mac_from_slice(&mac_vec).ok(),
        _ => None,
    })
}

pub async fn get_interface_mac(ifname: &str) -> Result<MacAddr, String> {
    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| format!("Failed to open netlink connection: {}", e))?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(ifname.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Err(format!("Interface {} not found", ifname)),
        Err(e) => return Err(format!("Netlink request failed: {}", e)),
    };

    find_mac_address_attribute(link.attributes).ok_or_else(|| {
        format!(
            "No hardware address attribute found for interface {}",
            ifname
        )
    })
}

pub fn open_raw_socket(ifname: &str) -> Result<OwnedFd, String> {
    // Create the packet raw socket
    let socket = Socket::new(
        Domain::from(libc::AF_PACKET),
        Type::RAW,
        Some(Protocol::from((libc::ETH_P_ALL as u16).to_be() as i32)),
    )
    .map_err(|e| format!("socket(AF_PACKET) failed: {}", e))?;

    // Enable nonblocking mode in pure Rust
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("Failed to set nonblocking mode: {}", e))?;

    // Resolve interface name to its index
    let c_ifname =
        std::ffi::CString::new(ifname).map_err(|e| format!("Invalid interface name: {}", e))?;
    let if_index = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) };
    if if_index == 0 {
        return Err(format!("Interface not found: {}", ifname));
    }

    // Set up Link-Layer address struct
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = if_index as i32;

    // Wrap in SockAddr and bind
    let mut storage = socket2::SockAddrStorage::zeroed();
    let sockaddr = unsafe {
        let storage_ptr = &mut storage as *mut socket2::SockAddrStorage as *mut u8;
        std::ptr::copy_nonoverlapping(
            &addr as *const libc::sockaddr_ll as *const u8,
            storage_ptr,
            std::mem::size_of::<libc::sockaddr_ll>(),
        );
        SockAddr::new(
            storage,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };

    socket
        .bind(&sockaddr)
        .map_err(|e| format!("bind(AF_PACKET) failed: {}", e))?;

    Ok(socket.into())
}

pub fn parse_dhcp_payload(buf: &[u8], expected_port: u16) -> Option<Message> {
    let eth_pkt = EthernetPacket::new(buf)?;
    if eth_pkt.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return None;
    }
    let ip_pkt = Ipv4Packet::new(eth_pkt.payload())?;
    if ip_pkt.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Udp {
        return None;
    }
    let udp_pkt = UdpPacket::new(ip_pkt.payload())?;
    if udp_pkt.get_destination() != expected_port {
        return None;
    }
    Message::decode(&mut Decoder::new(udp_pkt.payload())).ok()
}

pub fn try_read_raw(
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, OwnedFd>,
    buf: &mut [u8],
) -> Result<Option<usize>, std::io::Error> {
    match guard.try_io(|inner| {
        let res = unsafe {
            libc::recv(
                inner.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }) {
        Ok(res) => res.map(Some),
        Err(_would_block) => Ok(None),
    }
}

pub async fn read_raw_packet(
    async_sock: &tokio::io::unix::AsyncFd<OwnedFd>,
    buf: &mut [u8],
) -> Result<usize, std::io::Error> {
    loop {
        let mut guard = async_sock.readable().await?;
        if let Some(n) = try_read_raw(&mut guard, buf)? {
            return Ok(n);
        }
    }
}

pub fn try_write_raw(
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, OwnedFd>,
    frame: &[u8],
) -> Result<Option<isize>, std::io::Error> {
    match guard.try_io(|inner| {
        let res = unsafe {
            libc::send(
                inner.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }) {
        Ok(res) => res.map(Some),
        Err(_would_block) => Ok(None),
    }
}

pub async fn send_raw_packet(async_sock: &tokio::io::unix::AsyncFd<OwnedFd>, frame: &[u8]) {
    loop {
        let mut guard = match async_sock.writable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        match try_write_raw(&mut guard, frame) {
            Ok(None) => continue,
            _ => break,
        }
    }
}

/// A generic asynchronous wrapper around an AF_PACKET raw socket for sending
/// and receiving raw Ethernet frames on a specific network interface.
pub struct RawPacketSocket {
    socket: tokio::io::unix::AsyncFd<OwnedFd>,
}

impl RawPacketSocket {
    pub fn from_owned_fd(owned_fd: OwnedFd) -> Result<Self, std::io::Error> {
        let socket = tokio::io::unix::AsyncFd::new(owned_fd)?;
        Ok(Self { socket })
    }

    pub async fn send(&self, frame: &[u8]) -> Result<(), std::io::Error> {
        send_raw_packet(&self.socket, frame).await;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        read_raw_packet(&self.socket, buf).await
    }

    pub async fn recv_timeout(
        &self,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> Result<Option<usize>, std::io::Error> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let Ok(Ok(mut guard)) = tokio::time::timeout(remaining, self.socket.readable()).await
            else {
                return Ok(None);
            };

            if let Some(n) = try_read_raw(&mut guard, buf)? {
                return Ok(Some(n));
            }
        }
        Ok(None)
    }
}

pub fn get_timestamp_prefix() -> String {
    let now = chrono::Utc::now();
    now.format("[%Y-%m-%dT%H:%M:%S%.3fZ] ").to_string()
}

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const LOCAL_DNS_BIND: &str = "127.0.0.1:0";

fn find_first_a_record(answers: Vec<dns_parser::ResourceRecord<'_>>) -> Option<std::net::Ipv4Addr> {
    for answer in answers {
        if let dns_parser::RData::A(ip) = answer.data {
            return Some(ip.0);
        }
    }
    None
}

pub async fn resolve_dns_a_record(host: &str) -> Result<std::net::Ipv4Addr, String> {
    let socket = UdpSocket::bind(LOCAL_DNS_BIND)
        .await
        .map_err(|e| format!("Failed to bind DNS query socket: {}", e))?;

    // Generate unique randomized transaction ID
    let query_id = rand::random::<u16>();

    // Build DNS standard query for the host (A record)
    let mut builder = dns_parser::Builder::new_query(query_id, true);
    builder.add_question(
        host,
        false,
        dns_parser::QueryType::A,
        dns_parser::QueryClass::IN,
    );
    let query = builder
        .build()
        .map_err(|_| "Failed to build DNS query packet".to_string())?;

    let dns_server = std::net::SocketAddr::new(std::net::IpAddr::V4(LOCALHOST), DNS_PORT);

    socket
        .send_to(&query, dns_server)
        .await
        .map_err(|e| format!("Failed to send DNS query: {}", e))?;

    let mut buf = [0u8; 512];
    let recv_res = timeout(Duration::from_secs(3), socket.recv_from(&mut buf)).await;
    let (len, _) = match recv_res {
        Ok(Ok((l, addr))) => {
            if addr == dns_server {
                (l, addr)
            } else {
                return Err("Received packet from unexpected source".to_string());
            }
        }
        Ok(Err(e)) => return Err(format!("Socket receive error: {}", e)),
        Err(_) => return Err("DNS query timed out".to_string()),
    };

    parse_dns_a_record_response(&buf[..len], query_id, host)
}

pub fn parse_dns_a_record_response(
    buf: &[u8],
    query_id: u16,
    host: &str,
) -> Result<Ipv4Addr, String> {
    let packet = dns_parser::Packet::parse(buf)
        .map_err(|e| format!("Failed to parse DNS response: {}", e))?;

    if packet.header.id != query_id {
        return Err("Transaction ID mismatch".to_string());
    }

    find_first_a_record(packet.answers).ok_or_else(|| format!("No A record resolved for {}", host))
}

pub async fn wait_ipc_eof(reader: &mut tokio::net::unix::OwnedReadHalf) {
    let mut buf = [0u8; 128];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
}

const ALLOWED_SYSCALLS: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_fstat,
    libc::SYS_lseek,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_shutdown,
    libc::SYS_fcntl,
    libc::SYS_getsockopt,
    libc::SYS_setsockopt,
    libc::SYS_socket,
    libc::SYS_bind,
    libc::SYS_connect,
    libc::SYS_accept,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_epoll_create,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_create1,
    libc::SYS_eventfd2,
    libc::SYS_futex,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_clone,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_clone3,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_sched_yield,
    libc::SYS_madvise,
    libc::SYS_gettid,
    libc::SYS_set_robust_list,
    libc::SYS_prctl,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_arch_prctl,
    libc::SYS_clock_gettime,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_clock_nanosleep,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_getpid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getrandom,
    libc::SYS_ioctl,
    libc::SYS_uname,
    libc::SYS_pipe,
    libc::SYS_pipe2,
];

pub fn apply_seccomp() -> Result<(), std::io::Error> {
    let mut rules = BTreeMap::new();
    for &syscall in ALLOWED_SYSCALLS {
        rules.insert(syscall, vec![]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Trap,  // mismatch triggers SIGSYS
        SeccompAction::Allow, // match allows syscall
        std::env::consts::ARCH
            .try_into()
            .map_err(std::io::Error::other)?,
    )
    .map_err(std::io::Error::other)?;

    let prog: BpfProgram = filter.try_into().map_err(std::io::Error::other)?;
    seccompiler::apply_filter(&prog).map_err(std::io::Error::other)?;

    Ok(())
}

pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), std::io::Error> {
    fs::create_dir_all(CHROOT_JAIL_PATH)?;
    let metadata = fs::metadata(CHROOT_JAIL_PATH)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o555);
    fs::set_permissions(CHROOT_JAIL_PATH, perms)?;

    let chroot_path = std::ffi::CString::new(CHROOT_JAIL_PATH).map_err(std::io::Error::other)?;
    let res = unsafe { libc::chroot(chroot_path.as_ptr()) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let chdir_path = std::ffi::CString::new("/").map_err(std::io::Error::other)?;
    let res = unsafe { libc::chdir(chdir_path.as_ptr()) };
    if res != 0 {
        return Err(std::io::Error::last_os_error());
    }

    caps::clear(None, caps::CapSet::Bounding).map_err(std::io::Error::other)?;

    setgid(Gid::from_raw(gid)).map_err(std::io::Error::other)?;

    setuid(Uid::from_raw(uid)).map_err(std::io::Error::other)?;

    caps::clear(None, caps::CapSet::Inheritable).map_err(std::io::Error::other)?;
    caps::clear(None, caps::CapSet::Effective).map_err(std::io::Error::other)?;
    caps::clear(None, caps::CapSet::Permitted).map_err(std::io::Error::other)?;

    apply_seccomp()?;

    Ok(())
}

/// Runs an asynchronous worker function in an unprivileged sandboxed process environment.
///
/// NOTE: The provided `IpcEndpoint` (specifically both `ipc.reader` and `ipc.writer`) must
/// remain in scope for the worker's entire execution. Dropping either half closes that direction
/// on the Unix socket, which the parent supervisor detects as EOF and terminates the worker.
pub async fn run_sandboxed_worker<F, Fut>(
    service_name: &str,
    uid: u32,
    gid: u32,
    ipc_fd: OwnedFd,
    worker_fn: F,
) -> Result<(), std::io::Error>
where
    F: FnOnce(IpcEndpoint) -> Fut,
    Fut: std::future::Future<Output = Result<(), std::io::Error>>,
{
    info!("[{}-worker] Starting unprivileged worker...", service_name);
    let ipc = IpcEndpoint::from_owned_fd(ipc_fd)?;

    drop_privileges(uid, gid)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
    info!(
        "[{}-worker] Privileges dropped successfully (running as {} inside chroot jail).",
        service_name, service_name
    );

    worker_fn(ipc).await
}

pub fn setup_worker_sockets(interface: &str) -> std::io::Result<(OwnedFd, OwnedFd, OwnedFd)> {
    let raw_socket = open_raw_socket(interface).map_err(std::io::Error::other)?;
    let (parent_stream, child_stream) = tokio::net::UnixStream::pair()?;
    let parent_std = parent_stream.into_std()?;
    let child_std = child_stream.into_std()?;
    Ok((raw_socket, parent_std.into(), child_std.into()))
}

pub fn create_ipc_fds() -> Result<(OwnedFd, OwnedFd), std::io::Error> {
    let (parent_stream, child_stream) = tokio::net::UnixStream::pair()?;
    let parent_std = parent_stream.into_std()?;
    let child_std = child_stream.into_std()?;
    Ok((parent_std.into(), child_std.into()))
}

pub fn async_udp_socket(fd: OwnedFd) -> Result<tokio::net::UdpSocket, std::io::Error> {
    let std_sock = std::net::UdpSocket::from(fd);
    std_sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(std_sock)
}

pub async fn handle_supervisor_restart_delay(
    service_name: &str,
    attempt: &mut u32,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    if *attempt > 0 {
        let delay = std::time::Duration::from_secs(std::cmp::min(1 << *attempt, 60));
        warn!(
            "[{}-parent] Worker crashed/exited. Restarting in {:?}",
            service_name, delay
        );
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    return false;
                }
            }
        }
    }
    *attempt += 1;
    true
}

pub async fn terminate_worker(pid: u32) {
    let pid = nix::unistd::Pid::from_raw(pid as i32);
    if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
        if e != nix::errno::Errno::ESRCH {
            warn!(
                "[utils] Failed to send SIGTERM to worker process {}: {}",
                pid, e
            );
        }
        return;
    }

    let start = std::time::Instant::now();
    let mut sigkill_sent = false;

    while let Ok(nix::sys::wait::WaitStatus::StillAlive) =
        nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG))
    {
        if !sigkill_sent && start.elapsed() > std::time::Duration::from_secs(1) {
            sigkill_sent = true;
            if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
                && e != nix::errno::Errno::ESRCH
            {
                warn!(
                    "[utils] Failed to send SIGKILL to worker process {}: {}",
                    pid, e
                );
            }
        }

        if start.elapsed() > std::time::Duration::from_secs(2) {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_to_prefix_len_valid() {
        assert_eq!(
            mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 0)).unwrap(),
            24
        );
        assert_eq!(
            mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 255)).unwrap(),
            32
        );
        assert_eq!(mask_to_prefix_len(Ipv4Addr::new(0, 0, 0, 0)).unwrap(), 0);
    }

    #[test]
    fn test_mask_to_prefix_len_invalid() {
        assert!(mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 10)).is_err());
        assert!(mask_to_prefix_len(Ipv4Addr::new(255, 0, 255, 0)).is_err());
    }

    #[tokio::test]
    async fn test_supervisor_restart_delay_zero_attempt() {
        let (_tx, mut rx) = tokio::sync::watch::channel(false);
        let mut attempt = 0;
        let proceed = handle_supervisor_restart_delay("test-service", &mut attempt, &mut rx).await;
        assert!(proceed);
        assert_eq!(attempt, 1);
    }

    #[test]
    fn test_parse_dhcp_payload_truncated_packet_returns_none() {
        let truncated = [0u8; 10];
        assert!(parse_dhcp_payload(&truncated, 67).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_non_ipv4_returns_none() {
        // Ethernet header with ARP ethertype 0x0806
        let mut frame = vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x06; // ARP
        assert!(parse_dhcp_payload(&frame, 67).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_non_udp_returns_none() {
        // Ethernet header (IPv4 0x0800) + IPv4 header with TCP protocol (6)
        let mut frame = vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        frame[14] = 0x45; // Version 4, IHL 5
        frame[23] = 6; // Protocol = TCP
        assert!(parse_dhcp_payload(&frame, 67).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_wrong_destination_port_returns_none() {
        // Ethernet (14) + IPv4 (20) + UDP (8) with destination port 80
        let mut frame = vec![0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        frame[14] = 0x45; // Version 4, IHL 5
        frame[23] = 17; // Protocol = UDP
        frame[36] = 0x00;
        frame[37] = 80; // Dest port 80
        assert!(parse_dhcp_payload(&frame, 67).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_truncated_ip_header() {
        // Ethernet (14) + truncated IP header (10 bytes instead of 20)
        let mut frame = vec![0u8; 24];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        frame[14] = 0x45; // Version 4, IHL 5
        assert!(parse_dhcp_payload(&frame, 68).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_truncated_udp_header() {
        // Ethernet (14) + IPv4 (20) + truncated UDP (4 bytes instead of 8)
        let mut frame = vec![0u8; 38];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 17; // UDP
        assert!(parse_dhcp_payload(&frame, 68).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_truncated_dhcp_body() {
        // Ethernet (14) + IPv4 (20) + UDP (8) + only 10 bytes DHCP payload
        let mut frame = vec![0u8; 52];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x45;
        frame[23] = 17;
        frame[36] = 0x00;
        frame[37] = 68; // Dest port 68 (Client port)
        assert!(parse_dhcp_payload(&frame, 68).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_vlan_tagged_packet() {
        // 802.1Q VLAN tagged frame (EtherType 0x8100) should return None
        let mut frame = vec![0u8; 60];
        frame[12] = 0x81;
        frame[13] = 0x00;
        assert!(parse_dhcp_payload(&frame, 68).is_none());
    }

    #[test]
    fn test_parse_dhcp_payload_ipv6_packet() {
        // IPv6 frame (EtherType 0x86DD) should return None
        let mut frame = vec![0u8; 60];
        frame[12] = 0x86;
        frame[13] = 0xDD;
        assert!(parse_dhcp_payload(&frame, 68).is_none());
    }

    #[test]
    fn test_parse_dns_response_corrupted_returns_err() {
        let corrupted = [0u8; 5];
        let res = parse_dns_a_record_response(&corrupted, 0x1234, "google.com");
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_dns_response_xid_mismatch_returns_err() {
        let mut dns_resp = vec![0u8; 12];
        dns_resp[0] = 0x11;
        dns_resp[1] = 0x11; // ID = 0x1111

        let res = parse_dns_a_record_response(&dns_resp, 0x2222, "google.com");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Transaction ID mismatch");
    }
}
