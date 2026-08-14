use crate::error::RouterError;
use pnet::util::MacAddr;
use rtnetlink::packet_route::link::LinkAttribute;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};

pub const CHROOT_JAIL_PATH: &str = "/run/empty";
pub const NOBODY_UID: u32 = 65534;
pub const NOBODY_GID: u32 = 65534;
pub const SELF_EXE_PATH: &str = "/proc/self/exe";
pub const ROUTER_BINARY_PATH: &str = "/bin/trimrouter";

// =========================================================================
// Shared WAN Lease Info
// =========================================================================
#[derive(Clone, Default)]
pub struct WanLease {
    pub ip: Option<Ipv4Addr>,
    pub mask: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
}

pub struct CleanOption<'a, T>(pub &'a Option<T>);

impl<'a, T: std::fmt::Display> std::fmt::Debug for CleanOption<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(val) => write!(f, "\"{}\"", val),
            None => write!(f, "None"),
        }
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

pub type SharedWanLease = Arc<Mutex<WanLease>>;

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

    use futures_util::TryStreamExt;
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

pub fn open_raw_socket(ifname: &str) -> Result<RawFd, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::os::unix::io::IntoRawFd;

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
    let c_ifname = std::ffi::CString::new(ifname).unwrap();
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

    Ok(socket.into_raw_fd())
}

pub fn parse_dhcp_payload(buf: &[u8], expected_port: u16) -> Option<dhcproto::v4::Message> {
    use dhcproto::v4::Message;
    use dhcproto::{Decodable, Decoder};
    use pnet::packet::Packet;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::udp::UdpPacket;

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
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, std::os::unix::io::RawFd>,
    buf: &mut [u8],
) -> Result<Option<usize>, std::io::Error> {
    use std::os::unix::io::AsRawFd;
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
    async_sock: &tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>,
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
    guard: &mut tokio::io::unix::AsyncFdReadyGuard<'_, std::os::unix::io::RawFd>,
    frame: &[u8],
) -> Result<Option<isize>, std::io::Error> {
    use std::os::unix::io::AsRawFd;
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

pub async fn send_raw_packet(
    async_sock: &tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>,
    frame: &[u8],
) {
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
    socket: Option<tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>>,
}

impl RawPacketSocket {
    pub fn new(interface_name: &str) -> Result<Self, std::io::Error> {
        let raw_fd = open_raw_socket(interface_name).map_err(std::io::Error::other)?;
        let socket = tokio::io::unix::AsyncFd::new(raw_fd).inspect_err(|_| unsafe {
            let _ = libc::close(raw_fd);
        })?;
        Ok(Self {
            socket: Some(socket),
        })
    }

    pub fn from_raw_fd(raw_fd: std::os::unix::io::RawFd) -> Result<Self, std::io::Error> {
        let socket = tokio::io::unix::AsyncFd::new(raw_fd)?;
        Ok(Self {
            socket: Some(socket),
        })
    }

    pub async fn send(&self, frame: &[u8]) -> Result<(), std::io::Error> {
        let socket = self.socket.as_ref().expect("socket is active");
        send_raw_packet(socket, frame).await;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let socket = self.socket.as_ref().expect("socket is active");
        read_raw_packet(socket, buf).await
    }

    pub async fn recv_timeout(
        &self,
        buf: &mut [u8],
        timeout: std::time::Duration,
    ) -> Result<Option<usize>, std::io::Error> {
        let socket = self.socket.as_ref().expect("socket is active");
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            let Ok(Ok(mut guard)) = tokio::time::timeout(remaining, socket.readable()).await else {
                return Ok(None);
            };

            if let Some(n) = try_read_raw(&mut guard, buf)? {
                return Ok(Some(n));
            }
        }
        Ok(None)
    }
}

impl Drop for RawPacketSocket {
    fn drop(&mut self) {
        if let Some(async_fd) = self.socket.take() {
            let fd = async_fd.into_inner();
            unsafe {
                let _ = libc::close(fd);
            }
        }
    }
}

pub fn get_timestamp_prefix() -> String {
    let now = chrono::Utc::now();
    now.format("[%Y-%m-%dT%H:%M:%S%.3fZ] ").to_string()
}

const LOCALHOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const DNS_PORT: u16 = 53;
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
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

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
    let recv_res = timeout(
        std::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await;
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

    let packet = dns_parser::Packet::parse(&buf[..len])
        .map_err(|e| format!("Failed to parse DNS response: {}", e))?;

    if packet.header.id != query_id {
        return Err("Transaction ID mismatch".to_string());
    }

    find_first_a_record(packet.answers).ok_or_else(|| format!("No A record resolved for {}", host))
}

pub async fn wait_shutdown(shutdown_rx: &mut tokio::sync::watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            break;
        }
    }
}

pub fn apply_seccomp() -> Result<(), std::io::Error> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;
    use std::convert::TryInto;

    let allowed_syscalls = [
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

    let mut rules = BTreeMap::new();
    for &syscall in &allowed_syscalls {
        rules.insert(syscall, vec![]);
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Trap,  // mismatch triggers SIGSYS
        SeccompAction::Allow, // match allows syscall
        std::env::consts::ARCH
            .try_into()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    seccompiler::apply_filter(&prog)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    Ok(())
}

pub fn drop_privileges() -> Result<(), std::io::Error> {
    use nix::unistd::{Gid, Uid, setgid, setuid};

    std::fs::create_dir_all(CHROOT_JAIL_PATH)?;
    let metadata = std::fs::metadata(CHROOT_JAIL_PATH)?;
    use std::os::unix::fs::PermissionsExt;
    let mut perms = metadata.permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(CHROOT_JAIL_PATH, perms)?;

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

    setgid(Gid::from_raw(NOBODY_GID)).map_err(std::io::Error::other)?;

    setuid(Uid::from_raw(NOBODY_UID)).map_err(std::io::Error::other)?;

    caps::clear(None, caps::CapSet::Inheritable).map_err(std::io::Error::other)?;
    caps::clear(None, caps::CapSet::Effective).map_err(std::io::Error::other)?;
    caps::clear(None, caps::CapSet::Permitted).map_err(std::io::Error::other)?;

    apply_seccomp()?;

    Ok(())
}

pub fn setup_worker_sockets(interface: &str) -> std::io::Result<(RawFd, RawFd, RawFd)> {
    let raw_socket_fd = open_raw_socket(interface).map_err(std::io::Error::other)?;

    let mut fds = [0; 2];
    let res = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if res < 0 {
        unsafe {
            libc::close(raw_socket_fd);
        }
        return Err(std::io::Error::last_os_error());
    }
    Ok((raw_socket_fd, fds[0], fds[1]))
}

pub fn create_ipc_fds() -> Result<(RawFd, RawFd), std::io::Error> {
    use std::os::unix::io::IntoRawFd;
    let (parent_stream, child_stream) = tokio::net::UnixStream::pair()?;
    let parent_std = parent_stream.into_std()?;
    let parent_fd = parent_std.into_raw_fd();

    let child_std = match child_stream.into_std() {
        Ok(std_stream) => std_stream,
        Err(e) => {
            unsafe {
                libc::close(parent_fd);
            }
            return Err(e);
        }
    };
    let child_fd = child_std.into_raw_fd();
    Ok((parent_fd, child_fd))
}

pub async fn handle_supervisor_restart_delay(
    service_name: &str,
    attempt: &mut u32,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    if *attempt > 0 {
        let delay = std::time::Duration::from_secs(std::cmp::min(1 << *attempt, 60));
        println!(
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
        eprintln!(
            "[utils] Warning: Failed to send SIGTERM to worker process {}: {}",
            pid, e
        );
    }

    let start = std::time::Instant::now();
    while let Ok(nix::sys::wait::WaitStatus::StillAlive) =
        nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG))
    {
        if start.elapsed() > std::time::Duration::from_secs(1)
            && let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
        {
            eprintln!(
                "[utils] Warning: Failed to send SIGKILL to worker process {}: {}",
                pid, e
            );
        }
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
}
