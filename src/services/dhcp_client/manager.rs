use super::worker::DhcpError;
use crate::init::watchdog::{HeartbeatSender, MonitoredService, send_service_heartbeat};
use crate::services::DHCP_CLIENT_SERVICE_NAME;
use crate::services::ipc::{DhcpClientToParentMsg, async_unix_stream, recv_msg};
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{
    CleanOption, WanLease, WanLeaseSender, mask_to_prefix_len, prefix_len_to_mask,
    setup_worker_sockets, terminate_worker,
};
use ipnet::Ipv4Net;
use log::{error, info, warn};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::OwnedFd;
use tokio::net::UnixStream;
use tokio::task::JoinHandle;

pub struct DhcpClient {
    pub(super) wan_interface: String,
    pub(super) lease_tx: WanLeaseSender,
    state: ExternalWorker,
    heartbeat_tx: Option<HeartbeatSender>,
}

impl DhcpClient {
    pub fn new(wan_interface: String, lease_tx: WanLeaseSender) -> Self {
        Self {
            wan_interface,
            lease_tx,
            state: ExternalWorker::new(DHCP_CLIENT_SERVICE_NAME),
            heartbeat_tx: None,
        }
    }

    pub fn with_heartbeat(
        wan_interface: String,
        lease_tx: WanLeaseSender,
        heartbeat_tx: HeartbeatSender,
    ) -> Self {
        Self {
            wan_interface,
            lease_tx,
            state: ExternalWorker::new(DHCP_CLIENT_SERVICE_NAME),
            heartbeat_tx: Some(heartbeat_tx),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
}

async fn apply_parent_lease(
    lease_tx: &WanLeaseSender,
    wan_interface: &str,
    ip_address: Ipv4Addr,
    mask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns_servers: Vec<Ipv4Addr>,
) {
    let new_lease = WanLease {
        ip: Some(ip_address),
        mask: Some(mask),
        gateway: Some(gateway),
        dns_servers: dns_servers.clone(),
    };

    let changed = {
        let current = lease_tx.borrow();
        *current != new_lease
    };

    if changed {
        info!(
            "[dhcp-client-parent] Applied WAN lease configuration: {:?}",
            new_lease
        );
        let _ = lease_tx.send(new_lease);
        if let Err(e) = configure_wan(wan_interface, ip_address, mask, Some(gateway)).await {
            error!("[dhcp-client-parent] Failed to configure WAN: {}", e);
        }
    }
}

async fn clear_parent_lease(lease_tx: &WanLeaseSender, wan_interface: &str) {
    let (ip, mask) = {
        let current = lease_tx.borrow();
        (current.ip, current.mask)
    };

    let _ = lease_tx.send(WanLease::default());

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
    lease_tx: WanLeaseSender,
    heartbeat_tx: Option<HeartbeatSender>,
) -> Result<JoinHandle<()>, ServiceError> {
    let parent_ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;

    let handle = tokio::spawn(run_parent_dhcp_monitor(
        parent_ipc_stream,
        child_pid,
        wan_interface,
        lease_tx,
        heartbeat_tx,
    ));

    Ok(handle)
}

async fn run_parent_dhcp_monitor(
    mut parent_ipc_stream: UnixStream,
    child_pid: u32,
    wan_interface: String,
    lease_tx: WanLeaseSender,
    heartbeat_tx: Option<HeartbeatSender>,
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
                send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::DhcpClient);
                let mask = prefix_len_to_mask(prefix_len);
                apply_parent_lease(
                    &lease_tx,
                    &wan_interface,
                    ip_address,
                    mask,
                    gateway,
                    dns_servers,
                )
                .await;
            }
            Ok(Some(DhcpClientToParentMsg::Heartbeat)) => {
                send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::DhcpClient);
            }
            Ok(Some(DhcpClientToParentMsg::ClearWanLease)) => {
                send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::DhcpClient);
                clear_parent_lease(&lease_tx, &wan_interface).await;
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
        let lease_tx = self.lease_tx.clone();
        let heartbeat_tx = self.heartbeat_tx.clone();

        self.state.start_supervised(
            move || setup_dhcp_client_attempt(&wan_interface_setup),
            move |parent_ipc_fd, child_pid, _shutdown_rx| {
                start_parent_supervisor_task(
                    parent_ipc_fd,
                    child_pid,
                    wan_interface.clone(),
                    lease_tx.clone(),
                    heartbeat_tx.clone(),
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
        if is_valid_gateway(gw, ip, prefix_len) {
            let route = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .gateway(gw)
                .output_interface(index)
                .build();
            if let Err(e) = handle.route().add(route).execute().await {
                warn!("[dhcp-client] Failed to add default route: {}", e);
            }
        } else {
            warn!(
                "[dhcp-client] Ignoring invalid or off-subnet gateway IP: {}",
                gw
            );
        }
    }

    Ok(())
}

fn is_valid_gateway(gw: Ipv4Addr, ip: Ipv4Addr, prefix_len: u8) -> bool {
    !gw.is_unspecified()
        && !gw.is_broadcast()
        && Ipv4Net::new(ip, prefix_len)
            .map(|net| net.contains(&gw))
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_apply_and_clear_parent_lease_channel_updates() {
        let (lease_tx, lease_rx) = tokio::sync::watch::channel(WanLease::default());
        let ip = Ipv4Addr::new(192, 168, 100, 5);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let gw = Ipv4Addr::new(192, 168, 100, 1);
        let dns = vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)];

        // Note: wan interface doesn't exist so configure_wan logs error, but lease channel is updated
        apply_parent_lease(&lease_tx, "nonexistent_wan", ip, mask, gw, dns.clone()).await;

        let current = lease_rx.borrow().clone();
        assert_eq!(current.ip, Some(ip));
        assert_eq!(current.mask, Some(mask));
        assert_eq!(current.gateway, Some(gw));
        assert_eq!(current.dns_servers, dns);

        clear_parent_lease(&lease_tx, "nonexistent_wan").await;
        let cleared = lease_rx.borrow().clone();
        assert_eq!(cleared, WanLease::default());
    }

    #[tokio::test]
    async fn test_interface_not_found_errors() {
        let ip = Ipv4Addr::new(10, 0, 0, 10);
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let gw = Some(Ipv4Addr::new(10, 0, 0, 1));

        let res_cfg = configure_wan("nonexistent_wan_999", ip, mask, gw).await;
        assert!(matches!(res_cfg, Err(DhcpError::InterfaceNotFound(_))));

        let res_decfg = deconfigure_wan("nonexistent_wan_999", ip, mask).await;
        assert!(matches!(res_decfg, Err(DhcpError::InterfaceNotFound(_))));
    }

    #[test]
    fn test_is_valid_gateway_validation() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let prefix_len = 24;

        // Valid gateway within subnet
        assert!(is_valid_gateway(
            Ipv4Addr::new(192, 168, 1, 1),
            ip,
            prefix_len
        ));
        assert!(is_valid_gateway(
            Ipv4Addr::new(192, 168, 1, 254),
            ip,
            prefix_len
        ));

        // Off-subnet gateway (rogue or misconfigured DHCP server)
        assert!(!is_valid_gateway(
            Ipv4Addr::new(10, 0, 0, 1),
            ip,
            prefix_len
        ));
        assert!(!is_valid_gateway(
            Ipv4Addr::new(192, 168, 2, 1),
            ip,
            prefix_len
        ));

        // Unspecified (0.0.0.0) and broadcast (255.255.255.255)
        assert!(!is_valid_gateway(Ipv4Addr::UNSPECIFIED, ip, prefix_len));
        assert!(!is_valid_gateway(Ipv4Addr::BROADCAST, ip, prefix_len));
    }
}
