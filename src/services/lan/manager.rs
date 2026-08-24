use crate::network;
use crate::services::utils::{WanLeaseReceiver, mask_to_prefix_len};
use crate::services::{DhcpServer, Service, ServiceError};
use futures_util::StreamExt;
use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use tokio::sync::watch::Sender;
use tokio::task::JoinHandle;

pub struct LanManager {
    lan_interface: String,
    initial_ip: String,
    backup_ip: String,
    lease_rx: WanLeaseReceiver,
    shutdown_tx: Option<Sender<bool>>,
    task_handle: Option<JoinHandle<()>>,
}

impl LanManager {
    pub fn new(
        lan_interface: String,
        initial_ip: String,
        backup_ip: String,
        lease_rx: WanLeaseReceiver,
    ) -> Self {
        Self {
            lan_interface,
            initial_ip,
            backup_ip,
            lease_rx,
            shutdown_tx: None,
            task_handle: None,
        }
    }
}

impl Service for LanManager {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let lan_interface = self.lan_interface.clone();
        let initial_ip = self.initial_ip.clone();
        let backup_ip = self.backup_ip.clone();
        let lease_rx = self.lease_rx.clone();

        let handle = tokio::spawn(async move {
            run_lan_manager_loop(lan_interface, initial_ip, backup_ip, lease_rx, shutdown_rx).await;
        });

        self.task_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;
        let _ = tx.send(true);
        let _ = handle.await;
        Ok(())
    }
}

async fn run_lan_manager_loop(
    lan_interface: String,
    initial_ip: String,
    backup_ip: String,
    lease_rx: WanLeaseReceiver,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    info!(
        "[lan-manager] Starting LAN manager service on {}...",
        lan_interface
    );

    let current_ip = initial_ip.clone();
    if let Err(e) = network::configure_interface_ip(&lan_interface, &current_ip).await {
        error!("[lan-manager] Failed to configure initial LAN IP: {}", e);
        return;
    }

    let mut dhcp_server = DhcpServer::new(lan_interface.clone(), current_ip.clone());
    if let Err(e) = dhcp_server.start().await {
        error!("[lan-manager] Failed to start LAN DHCP server: {}", e);
        return;
    }

    let (connection, _handle, messages) = match rtnetlink::new_multicast_connection(&[
        MulticastGroup::Link,
        MulticastGroup::Ipv4Ifaddr,
    ]) {
        Ok(res) => res,
        Err(e) => {
            error!("[lan-manager] Failed to create multicast netlink: {}", e);
            let _ = dhcp_server.stop().await;
            return;
        }
    };
    tokio::spawn(connection);

    debug!("[lan-manager] Conflict monitoring started.");
    listen_for_conflicts(
        &lan_interface,
        current_ip,
        &backup_ip,
        lease_rx,
        &mut dhcp_server,
        messages,
        shutdown_rx,
    )
    .await;

    info!("[lan-manager] Stopping LAN DHCP server...");
    if let Err(e) = dhcp_server.stop().await {
        error!("[lan-manager] Failed to stop LAN DHCP server: {}", e);
    }
    info!("[lan-manager] LAN manager service stopped.");
}

async fn listen_for_conflicts(
    lan_interface: &str,
    mut active_ip: String,
    backup_ip: &str,
    mut lease_rx: WanLeaseReceiver,
    dhcp_server: &mut DhcpServer,
    mut messages: impl futures_util::Stream<
        Item = (
            rtnetlink::packet_core::NetlinkMessage<rtnetlink::packet_route::RouteNetlinkMessage>,
            rtnetlink::sys::SocketAddr,
        ),
    > + Unpin,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let _ = check_and_resolve(
        lan_interface,
        &mut active_ip,
        backup_ip,
        &lease_rx,
        dhcp_server,
    )
    .await;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
            res = lease_rx.changed() => {
                if res.is_err() {
                    break;
                }
                let _ = check_and_resolve(
                    lan_interface,
                    &mut active_ip,
                    backup_ip,
                    &lease_rx,
                    dhcp_server,
                )
                .await;
            }
            Some((message, _addr)) = messages.next() => {
                let should_check = if let NetlinkPayload::InnerMessage(rtnl_msg) = message.payload {
                    matches!(
                        rtnl_msg,
                        RouteNetlinkMessage::NewLink(_)
                        | RouteNetlinkMessage::NewAddress(_)
                        | RouteNetlinkMessage::DelAddress(_)
                    )
                } else {
                    false
                };

                if should_check {
                    let _ = check_and_resolve(
                        lan_interface,
                        &mut active_ip,
                        backup_ip,
                        &lease_rx,
                        dhcp_server,
                    )
                    .await;
                }
            }
        }
    }
}

async fn shift_lan_subnet(
    lan_interface: &str,
    current_ip: &mut String,
    new_ip: String,
    dhcp_server: &mut DhcpServer,
) -> bool {
    info!("[lan-manager] Stopping LAN DHCP server...");
    if let Err(e) = dhcp_server.stop().await {
        error!("[lan-manager] Failed to stop LAN DHCP server: {}", e);
    }

    if let Some(index) = network::get_interface_index(lan_interface).await {
        debug!(
            "[lan-manager] Cleaning up IP addresses on interface {}...",
            lan_interface
        );
        if let Err(e) = network::flush_ipv4_addresses(lan_interface, index).await {
            error!("[lan-manager] Failed to flush LAN interface IPs: {}", e);
        }
    } else {
        error!("[lan-manager] Failed to get index for {}", lan_interface);
    }

    info!(
        "[lan-manager] Reconfiguring interface {} with new subnet {}...",
        lan_interface, new_ip
    );
    if let Err(e) = network::configure_interface_ip(lan_interface, &new_ip).await {
        error!("[lan-manager] Failed to reconfigure LAN IP: {}", e);
        return false;
    }

    *current_ip = new_ip.clone();

    info!("[lan-manager] Restarting LAN DHCP server on new subnet...");
    *dhcp_server = DhcpServer::new(lan_interface.to_string(), current_ip.clone());
    if let Err(e) = dhcp_server.start().await {
        error!("[lan-manager] Failed to start LAN DHCP server: {}", e);
    }

    info!("[lan-manager] LAN subnet shifted successfully.");
    true
}

async fn check_and_resolve(
    lan_interface: &str,
    current_ip: &mut String,
    backup_ip: &str,
    lease_rx: &WanLeaseReceiver,
    dhcp_server: &mut DhcpServer,
) -> bool {
    let wan_opt = {
        let lease = lease_rx.borrow();
        lease.ip.zip(lease.mask)
    };

    let Some((wan_ip, wan_mask)) = wan_opt else {
        return false;
    };

    let Ok(wan_prefix) = mask_to_prefix_len(wan_mask) else {
        return false;
    };
    let Ok(wan_net) = Ipv4Net::new(wan_ip, wan_prefix) else {
        return false;
    };
    let Ok(lan_net) = current_ip.parse::<Ipv4Net>() else {
        return false;
    };

    if wan_net.contains(&lan_net.network()) || lan_net.contains(&wan_net.network()) {
        warn!(
            "[lan-manager] CONFLICT DETECTED: WAN subnet ({}) overlaps with LAN subnet ({}).",
            wan_net, lan_net
        );

        let new_ip = backup_ip.to_string();
        if *current_ip == new_ip {
            // Already on backup subnet, can't shift further
            return false;
        }

        return shift_lan_subnet(lan_interface, current_ip, new_ip, dhcp_server).await;
    }
    false
}
