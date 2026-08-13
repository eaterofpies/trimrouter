use super::dhcp_client::DhcpError;
use super::ipc::{DhcpClientToParentMsg, recv_msg};
use super::utils::{
    CleanOption, SharedWanLease, WanLease, get_interface_mac, mask_to_prefix_len,
    prefix_len_to_mask, setup_worker_sockets, terminate_worker,
};
use super::{Service, ServiceError};
use futures_util::TryStreamExt;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

pub struct DhcpClient {
    pub(super) wan_interface: String,
    pub(super) lease_state: SharedWanLease,
    pub(super) task_handle: Option<tokio::task::JoinHandle<()>>,
    pub(super) child_pid: Option<u32>,
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

fn spawn_worker_process(
    child_ipc_fd: RawFd,
    raw_socket_fd: RawFd,
    wan_interface: &str,
) -> Result<std::process::Child, ServiceError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

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

    cmd.spawn()
        .map_err(|e| ServiceError::FailedToStart(format!("spawn failed: {}", e)))
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
            eprintln!(
                "[dhcp-client-parent] ERROR: Failed to deconfigure WAN: {}",
                e
            );
        }
    }
}

fn start_parent_supervisor_task(
    parent_ipc_fd: RawFd,
    child_pid: u32,
    wan_interface: String,
    lease_state: SharedWanLease,
) -> Result<tokio::task::JoinHandle<()>, ServiceError> {
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    let std_stream = unsafe { StdUnixStream::from_raw_fd(parent_ipc_fd) };
    std_stream.set_nonblocking(true).map_err(ServiceError::Io)?;
    let mut parent_ipc_stream =
        tokio::net::UnixStream::from_std(std_stream).map_err(ServiceError::Io)?;

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

        let _ = get_interface_mac(&self.wan_interface)
            .await
            .map_err(|e| ServiceError::FailedToStart(e))?;

        let (raw_socket_fd, parent_ipc_fd, child_ipc_fd) =
            setup_worker_sockets(&self.wan_interface)
                .map_err(|e| ServiceError::FailedToStart(format!("Socket setup failed: {}", e)))?;

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

        println!(
            "[dhcp-client-parent] Stopping worker process PID {}",
            child_pid
        );
        terminate_worker(child_pid).await;

        let _ = handle.await;
        Ok(())
    }
}

pub async fn deconfigure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<(), DhcpError> {
    let prefix_len = mask_to_prefix_len(mask).map_err(|e| DhcpError::Protocol(e.to_string()))?;
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

pub async fn configure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
) -> Result<(), DhcpError> {
    let prefix_len = mask_to_prefix_len(mask).map_err(|e| DhcpError::Protocol(e.to_string()))?;
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

    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;

    handle
        .address()
        .add(index, std::net::IpAddr::V4(ip), prefix_len)
        .execute()
        .await?;

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
