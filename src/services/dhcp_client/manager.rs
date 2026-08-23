use super::worker::DhcpError;
use crate::services::ipc::{DhcpClientToParentMsg, async_unix_stream, recv_msg};
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{
    CleanOption, SharedWanLease, WanLease, mask_to_prefix_len, prefix_len_to_mask,
    setup_worker_sockets, terminate_worker,
};
use log::{error, info, warn};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::OwnedFd;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

pub struct DhcpClient {
    pub(super) wan_interface: String,
    pub(super) lease_state: SharedWanLease,
    state: ExternalWorker,
}

impl DhcpClient {
    pub fn new(wan_interface: String, lease_state: SharedWanLease) -> Self {
        Self {
            wan_interface,
            lease_state,
            state: ExternalWorker::new("dhcp-client"),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
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
            info!(
                "[dhcp-client-parent] Applied WAN lease configuration: {:?}",
                *lease
            );
        }
        changed
    };

    if changed && let Err(e) = configure_wan(wan_interface, ip_address, mask, Some(gateway)).await {
        error!("[dhcp-client-parent] Failed to configure WAN: {}", e);
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
        && let Err(e) = deconfigure_wan(wan_interface, ip, mask).await
    {
        error!("[dhcp-client-parent] Failed to deconfigure WAN: {}", e);
    }
}

fn start_parent_supervisor_task(
    parent_ipc_fd: OwnedFd,
    child_pid: u32,
    wan_interface: String,
    lease_state: SharedWanLease,
) -> Result<JoinHandle<()>, ServiceError> {
    let parent_ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;

    let handle = tokio::spawn(run_parent_dhcp_monitor(
        parent_ipc_stream,
        child_pid,
        wan_interface,
        lease_state,
    ));

    Ok(handle)
}

async fn run_parent_dhcp_monitor(
    mut parent_ipc_stream: UnixStream,
    child_pid: u32,
    wan_interface: String,
    lease_state: SharedWanLease,
) {
    info!(
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
                info!("[dhcp-client-parent] Worker IPC socket closed.");
                break;
            }
            Err(e) => {
                error!("[dhcp-client-parent] IPC recv error: {}", e);
                break;
            }
        }
    }

    terminate_worker(child_pid).await;
}

fn setup_dhcp_client_attempt(
    wan_interface: &str,
) -> Result<(crate::cli::WorkerService, OwnedFd), ServiceError> {
    let (raw_socket_fd, parent_ipc, child_ipc) = setup_worker_sockets(wan_interface)
        .map_err(|e| ServiceError::FailedToStart(format!("Socket setup failed: {}", e)))?;

    let worker_service = crate::cli::WorkerService::DhcpClient {
        ipc_fd: child_ipc.into(),
        raw_socket_fd: raw_socket_fd.into(),
        wan_interface: wan_interface.to_string(),
    };

    Ok((worker_service, parent_ipc))
}

impl Service for DhcpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let wan_interface = self.wan_interface.clone();
        let wan_interface_setup = wan_interface.clone();
        let lease_state = self.lease_state.clone();

        self.state.start_supervised(
            move || setup_dhcp_client_attempt(&wan_interface_setup),
            move |parent_ipc_fd, child_pid, _shutdown_rx| {
                start_parent_supervisor_task(
                    parent_ipc_fd,
                    child_pid,
                    wan_interface.clone(),
                    lease_state.clone(),
                )
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}

pub async fn deconfigure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
) -> Result<(), DhcpError> {
    let prefix_len = mask_to_prefix_len(mask).map_err(|e| DhcpError::Protocol(e.to_string()))?;
    info!(
        "[dhcp-client] Deconfiguring WAN interface via netlink: removing IP {}/{}",
        ip, prefix_len
    );

    let index = match crate::network::get_interface_index(wan_interface).await {
        Some(idx) => idx,
        None => return Err(DhcpError::InterfaceNotFound(wan_interface.to_string())),
    };

    crate::network::flush_ipv4_addresses(wan_interface, index)
        .await
        .map_err(|e| DhcpError::Protocol(e.to_string()))?;
    Ok(())
}

pub async fn configure_wan(
    wan_interface: &str,
    ip: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
) -> Result<(), DhcpError> {
    let prefix_len = mask_to_prefix_len(mask).map_err(|e| DhcpError::Protocol(e.to_string()))?;
    info!(
        "[dhcp-client] Configuring WAN interface via netlink: IP={}/{}, Gateway={:?}",
        ip,
        prefix_len,
        CleanOption(&gateway)
    );

    let index = match crate::network::get_interface_index(wan_interface).await {
        Some(idx) => idx,
        None => return Err(DhcpError::InterfaceNotFound(wan_interface.to_string())),
    };

    crate::network::flush_ipv4_addresses(wan_interface, index)
        .await
        .map_err(|e| DhcpError::Protocol(e.to_string()))?;

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;

    handle
        .address()
        .add(index, IpAddr::V4(ip), prefix_len)
        .execute()
        .await?;

    if let Some(gw) = gateway {
        let route = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
            .gateway(gw)
            .output_interface(index)
            .build();
        if let Err(e) = handle.route().add(route).execute().await {
            warn!("[dhcp-client] Failed to add default route: {}", e);
        }
    }

    Ok(())
}
