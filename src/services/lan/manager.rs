use crate::network;
use crate::services::supervisor::ServiceController;
use crate::services::utils::{WanLeaseReceiver, mask_to_prefix_len};
use crate::services::{DhcpServer, Service, ServiceError};
use futures_util::StreamExt;
use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use tokio::sync::watch::Receiver;

pub struct LanManager {
    lan_interface: String,
    initial_ip: String,
    backup_ip: String,
    lease_rx: WanLeaseReceiver,
    controller: ServiceController,
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
            controller: ServiceController::new(),
        }
    }
}

impl Service for LanManager {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let lan_interface = self.lan_interface.clone();
        let initial_ip = self.initial_ip.clone();
        let backup_ip = self.backup_ip.clone();
        let lease_rx = self.lease_rx.clone();

        self.controller.start(|shutdown_rx| async move {
            run_lan_manager_loop(lan_interface, initial_ip, backup_ip, lease_rx, shutdown_rx).await;
        })
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.controller.stop().await
    }
}

async fn run_lan_manager_loop(
    lan_interface: String,
    initial_ip: String,
    backup_ip: String,
    mut lease_rx: WanLeaseReceiver,
    mut shutdown_rx: Receiver<bool>,
) {
    info!(
        "[lan-manager] Starting LAN manager service on {}...",
        lan_interface
    );

    let mut current_ip = initial_ip.clone();
    if let Err(e) = network::configure_interface_ip(&lan_interface, &current_ip).await {
        error!("[lan-manager] Failed to configure initial LAN IP: {}", e);
        return;
    }

    let mut dhcp_server = DhcpServer::new(lan_interface.clone(), current_ip.clone());
    if let Err(e) = dhcp_server.start().await {
        error!("[lan-manager] Failed to start LAN DHCP server: {}", e);
        return;
    }

    let (connection, _handle, mut messages) = match rtnetlink::new_multicast_connection(&[
        MulticastGroup::Link,
        MulticastGroup::Ipv4Ifaddr,
    ]) {
        Ok(res) => res,
        Err(e) => {
            error!("[lan-manager] Failed to create multicast netlink: {}", e);
            if let Err(stop_err) = dhcp_server.stop().await {
                error!(
                    "[lan-manager] Failed to stop LAN DHCP server on error: {}",
                    stop_err
                );
            }
            return;
        }
    };
    tokio::spawn(connection);

    debug!("[lan-manager] Conflict monitoring started.");
    check_and_resolve(
        &lan_interface,
        &mut current_ip,
        &backup_ip,
        &lease_rx,
        &mut dhcp_server,
    )
    .await;

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            res = lease_rx.changed() => {
                if res.is_err() {
                    break;
                }
                check_and_resolve(
                    &lan_interface,
                    &mut current_ip,
                    &backup_ip,
                    &lease_rx,
                    &mut dhcp_server,
                )
                .await;
            }
            Some((message, _addr)) = messages.next() => {
                if is_address_or_link_event(&message.payload) {
                    check_and_resolve(
                        &lan_interface,
                        &mut current_ip,
                        &backup_ip,
                        &lease_rx,
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
}

fn is_address_or_link_event(payload: &NetlinkPayload<RouteNetlinkMessage>) -> bool {
    let NetlinkPayload::InnerMessage(rtnl_msg) = payload else {
        return false;
    };
    matches!(
        rtnl_msg,
        RouteNetlinkMessage::NewLink(_)
            | RouteNetlinkMessage::NewAddress(_)
            | RouteNetlinkMessage::DelAddress(_)
    )
}

async fn shift_lan_subnet(
    lan_interface: &str,
    current_ip: &mut String,
    new_ip: String,
    dhcp_server: &mut DhcpServer,
) {
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
        return;
    }

    *current_ip = new_ip.clone();

    info!("[lan-manager] Restarting LAN DHCP server on new subnet...");
    *dhcp_server = DhcpServer::new(lan_interface.to_string(), current_ip.clone());
    if let Err(e) = dhcp_server.start().await {
        error!("[lan-manager] Failed to start LAN DHCP server: {}", e);
    }

    info!("[lan-manager] LAN subnet shifted successfully.");
}

/// Checks for IP subnet collisions between the active WAN lease and current LAN subnet.
///
/// If an overlap is detected (e.g., both WAN and LAN are on 192.168.1.0/24), this function
/// resolves the conflict by migrating the LAN interface and its DHCP server to `backup_ip`.
async fn check_and_resolve(
    lan_interface: &str,
    current_ip: &mut String,
    backup_ip: &str,
    lease_rx: &WanLeaseReceiver,
    dhcp_server: &mut DhcpServer,
) {
    let wan_opt = {
        let lease = lease_rx.borrow();
        lease.ip.zip(lease.mask)
    };

    let Some((wan_ip, wan_mask)) = wan_opt else {
        return;
    };

    let Ok(wan_prefix) = mask_to_prefix_len(wan_mask) else {
        return;
    };
    let Ok(wan_net) = Ipv4Net::new(wan_ip, wan_prefix) else {
        return;
    };
    let Ok(lan_net) = current_ip.parse::<Ipv4Net>() else {
        return;
    };

    if wan_net.contains(&lan_net.network()) || lan_net.contains(&wan_net.network()) {
        warn!(
            "[lan-manager] CONFLICT DETECTED: WAN subnet ({}) overlaps with LAN subnet ({}).",
            wan_net, lan_net
        );

        let new_ip = backup_ip.to_string();
        if *current_ip == new_ip {
            // Already on backup subnet, can't shift further
            return;
        }

        shift_lan_subnet(lan_interface, current_ip, new_ip, dhcp_server).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::utils::WanLease;
    use rtnetlink::packet_core::NetlinkPayload;
    use rtnetlink::packet_route::RouteNetlinkMessage;
    use rtnetlink::packet_route::address::AddressMessage;
    use rtnetlink::packet_route::link::LinkMessage;
    use rtnetlink::packet_route::route::RouteMessage;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_address_or_link_event_new_link_returns_true() {
        let msg = RouteNetlinkMessage::NewLink(LinkMessage::default());
        let payload = NetlinkPayload::InnerMessage(msg);
        assert!(is_address_or_link_event(&payload));
    }

    #[test]
    fn test_is_address_or_link_event_del_address_returns_true() {
        let msg = RouteNetlinkMessage::DelAddress(AddressMessage::default());
        let payload = NetlinkPayload::InnerMessage(msg);
        assert!(is_address_or_link_event(&payload));
    }

    #[test]
    fn test_is_address_or_link_event_unrelated_returns_false() {
        let msg = RouteNetlinkMessage::NewRoute(RouteMessage::default());
        let payload = NetlinkPayload::InnerMessage(msg);
        assert!(!is_address_or_link_event(&payload));
    }

    #[tokio::test]
    async fn test_check_and_resolve_no_wan_lease_no_shift() {
        let (_tx, lease_rx) = tokio::sync::watch::channel(WanLease::default());
        let mut current_ip = "192.168.1.1/24".to_string();
        let backup_ip = "10.0.0.1/24";
        let mut dhcp_server = DhcpServer::new("lan".to_string(), current_ip.clone());

        check_and_resolve(
            "lan",
            &mut current_ip,
            backup_ip,
            &lease_rx,
            &mut dhcp_server,
        )
        .await;

        assert_eq!(current_ip, "192.168.1.1/24");
    }

    #[tokio::test]
    async fn test_check_and_resolve_disjoint_subnets_no_shift() {
        let lease = WanLease {
            ip: Some(Ipv4Addr::new(10, 0, 2, 15)),
            mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            gateway: Some(Ipv4Addr::new(10, 0, 2, 2)),
            dns_servers: vec![],
        };
        let (_tx, lease_rx) = tokio::sync::watch::channel(lease);
        let mut current_ip = "192.168.1.1/24".to_string();
        let backup_ip = "10.0.0.1/24";
        let mut dhcp_server = DhcpServer::new("lan".to_string(), current_ip.clone());

        check_and_resolve(
            "lan",
            &mut current_ip,
            backup_ip,
            &lease_rx,
            &mut dhcp_server,
        )
        .await;

        assert_eq!(current_ip, "192.168.1.1/24");
    }

    #[tokio::test]
    async fn test_check_and_resolve_invalid_wan_mask_no_shift() {
        let lease = WanLease {
            ip: Some(Ipv4Addr::new(192, 168, 1, 50)),
            mask: Some(Ipv4Addr::new(255, 0, 255, 0)), // Non-contiguous mask
            gateway: None,
            dns_servers: vec![],
        };
        let (_tx, lease_rx) = tokio::sync::watch::channel(lease);
        let mut current_ip = "192.168.1.1/24".to_string();
        let backup_ip = "10.0.0.1/24";
        let mut dhcp_server = DhcpServer::new("lan".to_string(), current_ip.clone());

        check_and_resolve(
            "lan",
            &mut current_ip,
            backup_ip,
            &lease_rx,
            &mut dhcp_server,
        )
        .await;

        assert_eq!(current_ip, "192.168.1.1/24");
    }
}
