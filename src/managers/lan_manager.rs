use crate::error::RouterError;
use crate::managers::utils::{mask_to_prefix_len, SharedWanLease};
use crate::managers::{DhcpServer, Service, ServiceError};
use crate::network;
use futures_util::{StreamExt, TryStreamExt};
use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::MulticastGroup;
use tokio::sync::watch::Sender;
use tokio::task::JoinHandle;

pub struct LanManager {
    lan_interface: String,
    initial_ip: String,
    backup_ip: String,
    lease_state: SharedWanLease,
    shutdown_tx: Option<Sender<bool>>,
    task_handle: Option<JoinHandle<()>>,
}

impl LanManager {
    pub fn new(
        lan_interface: String,
        initial_ip: String,
        backup_ip: String,
        lease_state: SharedWanLease,
    ) -> Self {
        Self {
            lan_interface,
            initial_ip,
            backup_ip,
            lease_state,
            shutdown_tx: None,
            task_handle: None,
        }
    }
}

impl Service for LanManager {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let lan_interface = self.lan_interface.clone();
        let initial_ip = self.initial_ip.clone();
        let backup_ip = self.backup_ip.clone();
        let lease_state = self.lease_state.clone();

        let handle = tokio::spawn(async move {
            info!(
                "[lan-manager] Starting LAN manager service on {}...",
                lan_interface
            );

            // 1. Initial IP configuration
            let current_ip = initial_ip.clone();
            if let Err(e) = network::configure_interface_ip(&lan_interface, &current_ip).await {
                error!("[lan-manager] Failed to configure initial LAN IP: {}", e);
                return;
            }

            // 2. Start child DHCP server
            let mut dhcp_server = DhcpServer::new(lan_interface.clone(), current_ip.clone());
            if let Err(e) = dhcp_server.start().await {
                error!("[lan-manager] Failed to start LAN DHCP server: {}", e);
                return;
            }

            // 3. Setup netlink connection to listen for links and addresses
            let (connection, _handle, mut messages) = match rtnetlink::new_multicast_connection(&[
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

            // Run initial check
            let mut active_ip = current_ip.clone();
            let _ = check_and_resolve(
                &lan_interface,
                &mut active_ip,
                &backup_ip,
                &lease_state,
                &mut dhcp_server,
            )
            .await;

            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
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
                                &lan_interface,
                                &mut active_ip,
                                &backup_ip,
                                &lease_state,
                                &mut dhcp_server,
                            )
                            .await;
                        }
                    }
                }
            }

            info!("[lan-manager] Stopping LAN DHCP server...");
            if let Err(e) = dhcp_server.stop().await {
                error!("[lan-manager] Failed to stop LAN DHCP server: {}", e);
            }
            info!("[lan-manager] LAN manager service stopped.");
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

async fn check_and_resolve(
    lan_interface: &str,
    current_ip: &mut String,
    backup_ip: &str,
    lease_state: &SharedWanLease,
    dhcp_server: &mut DhcpServer,
) -> bool {
    let wan_opt = {
        let lease = lease_state.lock().unwrap();
        if let (Some(ip), Some(mask)) = (lease.ip, lease.mask) {
            Some((ip, mask))
        } else {
            None
        }
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

        info!("[lan-manager] Stopping LAN DHCP server...");
        if let Err(e) = dhcp_server.stop().await {
            error!("[lan-manager] Failed to stop LAN DHCP server: {}", e);
        }

        if let Some(index) = get_interface_index(lan_interface).await {
            debug!(
                "[lan-manager] Cleaning up IP addresses on interface {}...",
                lan_interface
            );
            if let Err(e) = flush_ipv4_addresses(lan_interface, index).await {
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
        return true;
    }
    false
}

/// Helper to get the interface index by name
async fn get_interface_index(name: &str) -> Option<u32> {
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return None;
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let index = link.header.index;
        for nla in link.attributes {
            if let LinkAttribute::IfName(n) = nla
                && n == name
            {
                return Some(index);
            }
        }
    }
    None
}

/// Helper to delete all configured IPv4 addresses on the interface.
async fn flush_ipv4_addresses(name: &str, index: u32) -> Result<(), RouterError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // Delete all IPv4 addresses on this interface
    let mut addrs = handle.address().get().execute();
    while let Ok(Some(addr_msg)) = addrs.try_next().await {
        if addr_msg.header.index == index && matches!(addr_msg.header.family, AddressFamily::Inet) {
            debug!(
                "[lan-manager] Deleting address on interface {} (prefix_len={}) during cleanup",
                name, addr_msg.header.prefix_len
            );
            if let Err(e) = handle.address().del(addr_msg).execute().await {
                warn!("[lan-manager] Failed to delete address: {}", e);
            }
        }
    }
    Ok(())
}
