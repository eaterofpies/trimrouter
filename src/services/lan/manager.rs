use crate::config::PortForwardRule;
use crate::init::firewall;
use crate::init::watchdog::{HeartbeatSender, MonitoredService, send_service_heartbeat};
use crate::network;
use crate::services::ipc::LocalHostSender;
use crate::services::supervisor::ServiceController;
use crate::services::utils::{WanLeaseReceiver, mask_to_prefix_len};
use crate::services::{DhcpServer, Service, ServiceError};
use futures_util::StreamExt;
use ipnet::Ipv4Net;
use log::{debug, error, info, warn};
use pnet::util::MacAddr;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::watch::Receiver;
use tokio::time::sleep;

const LAN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

pub struct LanManager {
    lan_interface: String,
    wan_interface: String,
    initial_ip: String,
    backup_ip: String,
    lease_rx: WanLeaseReceiver,
    controller: ServiceController,
    heartbeat_tx: Option<HeartbeatSender>,
    local_hosts_tx: Option<LocalHostSender>,
    static_leases: HashMap<MacAddr, Ipv4Addr>,
    port_forwards: Vec<PortForwardRule>,
}

impl LanManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lan_interface: String,
        wan_interface: String,
        initial_ip: String,
        backup_ip: String,
        lease_rx: WanLeaseReceiver,
        heartbeat_tx: Option<HeartbeatSender>,
        local_hosts_tx: Option<LocalHostSender>,
        static_leases: HashMap<MacAddr, Ipv4Addr>,
        port_forwards: Vec<PortForwardRule>,
    ) -> Self {
        Self {
            lan_interface,
            wan_interface,
            initial_ip,
            backup_ip,
            lease_rx,
            controller: ServiceController::new(),
            heartbeat_tx,
            local_hosts_tx,
            static_leases,
            port_forwards,
        }
    }
}

impl Service for LanManager {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let mut runner = LanRunner::new(
            self.lan_interface.clone(),
            self.wan_interface.clone(),
            self.initial_ip.clone(),
            self.backup_ip.clone(),
            self.lease_rx.clone(),
            self.heartbeat_tx.clone(),
            self.local_hosts_tx.clone(),
            self.static_leases.clone(),
            self.port_forwards.clone(),
        );

        self.controller.start(|shutdown_rx| async move {
            runner.run(shutdown_rx).await;
        })
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.controller.stop().await
    }
}

struct LanRunner {
    lan_interface: String,
    wan_interface: String,
    initial_ip: String,
    current_ip: String,
    backup_ip: String,
    lease_rx: WanLeaseReceiver,
    heartbeat_tx: Option<HeartbeatSender>,
    local_hosts_tx: Option<LocalHostSender>,
    static_leases: HashMap<MacAddr, Ipv4Addr>,
    port_forwards: Vec<PortForwardRule>,
    dhcp_server: DhcpServer,
}

impl LanRunner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        lan_interface: String,
        wan_interface: String,
        initial_ip: String,
        backup_ip: String,
        lease_rx: WanLeaseReceiver,
        heartbeat_tx: Option<HeartbeatSender>,
        local_hosts_tx: Option<LocalHostSender>,
        static_leases: HashMap<MacAddr, Ipv4Addr>,
        port_forwards: Vec<PortForwardRule>,
    ) -> Self {
        let dhcp_server = DhcpServer::new(
            lan_interface.clone(),
            initial_ip.clone(),
            heartbeat_tx.clone(),
            local_hosts_tx.clone(),
            static_leases.clone(),
        );
        Self {
            lan_interface,
            wan_interface,
            initial_ip: initial_ip.clone(),
            current_ip: initial_ip,
            backup_ip,
            lease_rx,
            heartbeat_tx,
            local_hosts_tx,
            static_leases,
            port_forwards,
            dhcp_server,
        }
    }

    async fn run(&mut self, mut shutdown_rx: Receiver<bool>) {
        send_service_heartbeat(self.heartbeat_tx.as_ref(), MonitoredService::LanManager);
        info!(
            "[lan-manager] Starting LAN manager service on {}...",
            self.lan_interface
        );

        if let Err(e) = network::configure_interface_ip(&self.lan_interface, &self.current_ip).await
        {
            error!("[lan-manager] Failed to configure initial LAN IP: {}", e);
            return;
        }

        if let Err(e) = self.dhcp_server.start().await {
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
                if let Err(stop_err) = self.dhcp_server.stop().await {
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
        self.check_and_resolve().await;

        loop {
            send_service_heartbeat(self.heartbeat_tx.as_ref(), MonitoredService::LanManager);
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                _ = sleep(LAN_HEARTBEAT_INTERVAL) => {
                    send_service_heartbeat(self.heartbeat_tx.as_ref(), MonitoredService::LanManager);
                }
                res = self.lease_rx.changed() => {
                    if res.is_err() {
                        break;
                    }
                    send_service_heartbeat(self.heartbeat_tx.as_ref(), MonitoredService::LanManager);
                    self.check_and_resolve().await;
                }
                Some((message, _addr)) = messages.next() => {
                    if is_address_or_link_event(&message.payload) {
                        self.check_and_resolve().await;
                    }
                }
            }
        }

        info!("[lan-manager] Stopping LAN DHCP server...");
        if let Err(e) = self.dhcp_server.stop().await {
            error!("[lan-manager] Failed to stop LAN DHCP server: {}", e);
        }
        info!("[lan-manager] LAN manager service stopped.");
    }

    async fn shift_lan_subnet(&mut self, new_ip: String) {
        info!("[lan-manager] Stopping LAN DHCP server...");
        if let Err(e) = self.dhcp_server.stop().await {
            error!("[lan-manager] Failed to stop LAN DHCP server: {}", e);
        }

        self.reconfigure_lan_interface_ip(&new_ip).await;
        self.current_ip = new_ip.clone();
        self.notify_router_dns_host(&new_ip);

        let (remapped_leases, remapped_forwards) = self.compute_remapped_rules(&new_ip);
        self.update_firewall_for_subnet(&remapped_forwards);
        self.restart_dhcp_server_on_subnet(remapped_leases).await;

        info!("[lan-manager] LAN subnet shifted successfully.");
    }

    async fn reconfigure_lan_interface_ip(&self, new_ip: &str) {
        if let Some(index) = network::get_interface_index(&self.lan_interface).await {
            debug!(
                "[lan-manager] Cleaning up IP addresses on interface {}...",
                self.lan_interface
            );
            if let Err(e) = network::flush_ipv4_addresses(&self.lan_interface, index).await {
                error!("[lan-manager] Failed to flush LAN interface IPs: {}", e);
            }
        } else {
            error!(
                "[lan-manager] Failed to get index for {}",
                self.lan_interface
            );
        }

        info!(
            "[lan-manager] Reconfiguring interface {} with new subnet {}...",
            self.lan_interface, new_ip
        );
        if let Err(e) = network::configure_interface_ip(&self.lan_interface, new_ip).await {
            error!("[lan-manager] Failed to reconfigure LAN IP: {}", e);
        }
    }

    fn notify_router_dns_host(&self, new_ip: &str) {
        if let Some(ref tx) = self.local_hosts_tx
            && let Ok(new_net) = new_ip.parse::<Ipv4Net>()
        {
            let _ = tx.try_send(crate::services::LocalHostEvent::Register {
                name: crate::services::utils::ROUTER_HOSTNAME.to_string(),
                ip: new_net.addr(),
            });
        }
    }

    fn compute_remapped_rules(
        &self,
        new_ip: &str,
    ) -> (HashMap<MacAddr, Ipv4Addr>, Vec<PortForwardRule>) {
        let Ok(primary_net) = self.initial_ip.parse::<Ipv4Net>() else {
            error!("[lan-manager] Invalid initial IP: {}", self.initial_ip);
            return (self.static_leases.clone(), self.port_forwards.clone());
        };
        let Ok(target_net) = new_ip.parse::<Ipv4Net>() else {
            error!("[lan-manager] Invalid target IP: {}", new_ip);
            return (self.static_leases.clone(), self.port_forwards.clone());
        };

        let remapped_leases =
            remap_static_leases_for_subnet(&self.static_leases, &primary_net, &target_net);
        let remapped_forwards =
            remap_port_forwards_for_subnet(&self.port_forwards, &primary_net, &target_net);
        (remapped_leases, remapped_forwards)
    }

    fn update_firewall_for_subnet(&self, remapped_forwards: &[PortForwardRule]) {
        if let Err(e) = firewall::configure_firewall(
            &self.wan_interface,
            &self.lan_interface,
            remapped_forwards,
        ) {
            error!(
                "[lan-manager] Failed to update firewall rules for fallback subnet: {}",
                e
            );
        }
    }

    async fn restart_dhcp_server_on_subnet(&mut self, remapped_leases: HashMap<MacAddr, Ipv4Addr>) {
        info!("[lan-manager] Restarting LAN DHCP server on new subnet...");
        self.dhcp_server = DhcpServer::new(
            self.lan_interface.clone(),
            self.current_ip.clone(),
            self.heartbeat_tx.clone(),
            self.local_hosts_tx.clone(),
            remapped_leases,
        );
        if let Err(e) = self.dhcp_server.start().await {
            error!("[lan-manager] Failed to start LAN DHCP server: {}", e);
        }
    }

    /// Checks for IP subnet collisions between the active WAN lease and current LAN subnet.
    ///
    /// If an overlap is detected (e.g., both WAN and LAN are on 192.168.1.0/24), this function
    /// resolves the conflict by migrating the LAN interface and its DHCP server to `backup_ip`.
    async fn check_and_resolve(&mut self) {
        let wan_opt = {
            let lease = self.lease_rx.borrow();
            lease.ip.zip(lease.mask)
        };

        let Some((wan_ip, wan_mask)) = wan_opt else {
            return;
        };

        let Ok(wan_prefix) = mask_to_prefix_len(wan_mask) else {
            return;
        };

        if !is_valid_subnet_prefix(wan_prefix) {
            return;
        }

        let Ok(wan_net) = Ipv4Net::new(wan_ip, wan_prefix) else {
            return;
        };

        let Ok(current_net) = self.current_ip.parse::<Ipv4Net>() else {
            error!(
                "[lan-manager] Invalid current IP format: {}",
                self.current_ip
            );
            return;
        };

        if !is_subnet_overlap(&wan_net, &current_net) {
            return;
        }

        warn!(
            "[lan-manager] CONFLICT DETECTED: WAN subnet ({}) overlaps with LAN subnet ({}).",
            wan_net, current_net
        );

        if self.current_ip == self.backup_ip {
            error!(
                "[lan-manager] Already operating on backup subnet {}. Cannot shift further.",
                self.backup_ip
            );
            return;
        }

        let Ok(backup_net) = self.backup_ip.parse::<Ipv4Net>() else {
            error!("[lan-manager] Invalid backup IP format: {}", self.backup_ip);
            return;
        };

        if is_subnet_overlap(&wan_net, &backup_net) {
            error!(
                "[lan-manager] ERROR: Backup subnet ({}) also conflicts with WAN ({}).",
                backup_net, wan_net
            );
            return;
        }

        let new_ip = self.backup_ip.clone();
        self.shift_lan_subnet(new_ip).await;
    }
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

fn is_valid_subnet_prefix(prefix: u8) -> bool {
    (8..=30).contains(&prefix)
}

fn is_subnet_overlap(net1: &Ipv4Net, net2: &Ipv4Net) -> bool {
    net1.contains(&net2.network()) || net2.contains(&net1.network())
}

/// Translates an IPv4 address from `from_net` to `to_net` by preserving the host offset from the network base address.
///
/// Returns `Some(mapped_ip)` if `mapped_ip` is within `to_net`, is not the gateway (`to_net.addr()`),
/// and is not the broadcast address (`to_net.broadcast()`).
/// Returns `None` otherwise.
pub fn translate_ip_to_subnet(
    ip: Ipv4Addr,
    from_net: &Ipv4Net,
    to_net: &Ipv4Net,
) -> Option<Ipv4Addr> {
    if !from_net.contains(&ip) {
        return None;
    }
    let from_base = u32::from(from_net.network());
    let ip_u32 = u32::from(ip);
    let offset = ip_u32.checked_sub(from_base)?;
    let to_base = u32::from(to_net.network());
    let mapped_u32 = to_base.checked_add(offset)?;
    let mapped_ip = Ipv4Addr::from(mapped_u32);

    if to_net.contains(&mapped_ip) && mapped_ip != to_net.addr() && mapped_ip != to_net.broadcast()
    {
        Some(mapped_ip)
    } else {
        None
    }
}

pub fn remap_static_leases_for_subnet(
    static_leases: &HashMap<MacAddr, Ipv4Addr>,
    primary_net: &Ipv4Net,
    target_net: &Ipv4Net,
) -> HashMap<MacAddr, Ipv4Addr> {
    if primary_net == target_net {
        return static_leases.clone();
    }
    let mut remapped = HashMap::new();
    for (&mac, &ip) in static_leases {
        if let Some(mapped_ip) = translate_ip_to_subnet(ip, primary_net, target_net) {
            remapped.insert(mac, mapped_ip);
        } else {
            warn!(
                "[lan-manager] Static lease for MAC {} ({}) cannot be mapped to fallback subnet {}. Falling back to dynamic allocation.",
                mac, ip, target_net
            );
        }
    }
    remapped
}

pub fn remap_port_forwards_for_subnet(
    port_forwards: &[PortForwardRule],
    primary_net: &Ipv4Net,
    target_net: &Ipv4Net,
) -> Vec<PortForwardRule> {
    if primary_net == target_net {
        return port_forwards.to_vec();
    }
    let mut remapped = Vec::new();
    for rule in port_forwards {
        if let Some(mapped_ip) = translate_ip_to_subnet(rule.internal_ip, primary_net, target_net) {
            let mut new_rule = rule.clone();
            new_rule.internal_ip = mapped_ip;
            remapped.push(new_rule);
        } else {
            warn!(
                "[lan-manager] Port forward {} (target {}) cannot be mapped to fallback subnet {}. Skipping rule.",
                rule.external_port, rule.internal_ip, target_net
            );
        }
    }
    remapped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ForwardProtocol;
    use crate::services::utils::WanLease;
    use rtnetlink::packet_core::NetlinkPayload;
    use rtnetlink::packet_route::RouteNetlinkMessage;
    use rtnetlink::packet_route::address::AddressMessage;
    use rtnetlink::packet_route::link::LinkMessage;
    use rtnetlink::packet_route::route::RouteMessage;
    use std::net::Ipv4Addr;

    fn create_test_runner(
        current_ip: &str,
        backup_ip: &str,
        lease_rx: WanLeaseReceiver,
    ) -> LanRunner {
        LanRunner::new(
            "lan".to_string(),
            "wan".to_string(),
            current_ip.to_string(),
            backup_ip.to_string(),
            lease_rx,
            None,
            None,
            HashMap::new(),
            Vec::new(),
        )
    }

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
        let mut runner = create_test_runner("192.168.1.1/24", "10.0.0.1/24", lease_rx);

        runner.check_and_resolve().await;

        assert_eq!(runner.current_ip, "192.168.1.1/24");
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
        let mut runner = create_test_runner("192.168.1.1/24", "10.0.0.1/24", lease_rx);

        runner.check_and_resolve().await;

        assert_eq!(runner.current_ip, "192.168.1.1/24");
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
        let mut runner = create_test_runner("192.168.1.1/24", "10.0.0.1/24", lease_rx);

        runner.check_and_resolve().await;

        assert_eq!(runner.current_ip, "192.168.1.1/24");
    }

    #[test]
    fn test_is_subnet_overlap() {
        let net1: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        let net2: Ipv4Net = "192.168.1.0/25".parse().unwrap();
        let net3: Ipv4Net = "10.0.0.0/24".parse().unwrap();

        // Subnet 1 and Subnet 2 overlap (subset/superset)
        assert!(is_subnet_overlap(&net1, &net2));
        assert!(is_subnet_overlap(&net2, &net1));

        // Subnet 1 and Subnet 3 are disjoint
        assert!(!is_subnet_overlap(&net1, &net3));
        assert!(!is_subnet_overlap(&net3, &net1));
    }

    #[test]
    fn test_is_valid_subnet_prefix() {
        assert!(is_valid_subnet_prefix(8));
        assert!(is_valid_subnet_prefix(24));
        assert!(is_valid_subnet_prefix(30));

        // Degenerate prefixes (default route /0, point-to-point /31, host /32)
        assert!(!is_valid_subnet_prefix(0));
        assert!(!is_valid_subnet_prefix(7));
        assert!(!is_valid_subnet_prefix(31));
        assert!(!is_valid_subnet_prefix(32));
    }

    #[tokio::test]
    async fn test_check_and_resolve_wan_prefix_zero_ignored() {
        let lease = WanLease {
            ip: Some(Ipv4Addr::new(192, 168, 1, 50)),
            mask: Some(Ipv4Addr::new(0, 0, 0, 0)), // /0 default route mask
            gateway: None,
            dns_servers: vec![],
        };
        let (_tx, lease_rx) = tokio::sync::watch::channel(lease);
        let mut runner = create_test_runner("192.168.1.1/24", "10.0.0.1/24", lease_rx);

        runner.check_and_resolve().await;

        assert_eq!(runner.current_ip, "192.168.1.1/24"); // Not shifted
    }

    #[tokio::test]
    async fn test_check_and_resolve_wan_prefix_32_ignored() {
        let lease = WanLease {
            ip: Some(Ipv4Addr::new(192, 168, 1, 50)),
            mask: Some(Ipv4Addr::new(255, 255, 255, 255)), // /32 host route
            gateway: None,
            dns_servers: vec![],
        };
        let (_tx, lease_rx) = tokio::sync::watch::channel(lease);
        let mut runner = create_test_runner("192.168.1.1/24", "10.0.0.1/24", lease_rx);

        runner.check_and_resolve().await;

        assert_eq!(runner.current_ip, "192.168.1.1/24"); // Not shifted
    }

    #[tokio::test]
    async fn test_check_and_resolve_backup_also_conflicts_does_not_shift() {
        let lease = WanLease {
            ip: Some(Ipv4Addr::new(192, 168, 1, 50)),
            mask: Some(Ipv4Addr::new(255, 255, 255, 0)), // 192.168.1.0/24
            gateway: None,
            dns_servers: vec![],
        };
        let (_tx, lease_rx) = tokio::sync::watch::channel(lease);
        let mut runner = create_test_runner("192.168.1.1/24", "192.168.1.100/24", lease_rx);

        runner.check_and_resolve().await;

        assert_eq!(runner.current_ip, "192.168.1.1/24"); // Refuses to shift to another conflicting IP
    }

    #[tokio::test]
    async fn test_check_and_resolve_already_on_backup_no_op() {
        let lease = WanLease {
            ip: Some(Ipv4Addr::new(10, 0, 0, 50)),
            mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            gateway: None,
            dns_servers: vec![],
        };
        let (_tx, lease_rx) = tokio::sync::watch::channel(lease);
        let mut runner = create_test_runner("10.0.0.1/24", "10.0.0.1/24", lease_rx);

        runner.check_and_resolve().await;

        assert_eq!(runner.current_ip, "10.0.0.1/24");
    }

    #[test]
    fn test_lan_manager_constructors() {
        let (_tx, lease_rx) = tokio::sync::watch::channel(WanLease::default());
        let (hb_tx, _hb_rx) = tokio::sync::mpsc::channel(1);
        let (lh_tx, _lh_rx) = tokio::sync::mpsc::channel(1);
        let _mgr = LanManager::new(
            "lan".to_string(),
            "wan".to_string(),
            "192.168.1.1/24".to_string(),
            "10.0.0.1/24".to_string(),
            lease_rx,
            Some(hb_tx),
            Some(lh_tx),
            HashMap::new(),
            Vec::new(),
        );
    }

    #[test]
    fn test_translate_ip_to_subnet_valid() {
        let from_net: Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let to_net: Ipv4Net = "10.0.0.1/24".parse().unwrap();

        let mapped = translate_ip_to_subnet(Ipv4Addr::new(192, 168, 1, 50), &from_net, &to_net);
        assert_eq!(mapped, Some(Ipv4Addr::new(10, 0, 0, 50)));

        let mapped_high =
            translate_ip_to_subnet(Ipv4Addr::new(192, 168, 1, 200), &from_net, &to_net);
        assert_eq!(mapped_high, Some(Ipv4Addr::new(10, 0, 0, 200)));
    }

    #[test]
    fn test_translate_ip_to_subnet_rejects_gateway_and_broadcast() {
        let from_net: Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let to_net: Ipv4Net = "10.0.0.1/24".parse().unwrap();

        // 192.168.1.1 maps to 10.0.0.1 (gateway), which should be rejected
        assert_eq!(
            translate_ip_to_subnet(Ipv4Addr::new(192, 168, 1, 1), &from_net, &to_net),
            None
        );

        // 192.168.1.255 maps to 10.0.0.255 (broadcast), which should be rejected
        assert_eq!(
            translate_ip_to_subnet(Ipv4Addr::new(192, 168, 1, 255), &from_net, &to_net),
            None
        );

        // Off-subnet IP should be rejected
        assert_eq!(
            translate_ip_to_subnet(Ipv4Addr::new(172, 16, 0, 1), &from_net, &to_net),
            None
        );
    }

    #[test]
    fn test_translate_ip_to_subnet_narrower_subnet_overflow() {
        let from_net: Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let to_net: Ipv4Net = "10.0.0.1/28".parse().unwrap(); // hosts .1 to .14

        // Host .50 exceeds /28 range -> rejected
        assert_eq!(
            translate_ip_to_subnet(Ipv4Addr::new(192, 168, 1, 50), &from_net, &to_net),
            None
        );

        // Host .5 is within /28 range -> accepted
        assert_eq!(
            translate_ip_to_subnet(Ipv4Addr::new(192, 168, 1, 5), &from_net, &to_net),
            Some(Ipv4Addr::new(10, 0, 0, 5))
        );
    }

    #[test]
    fn test_remap_static_leases_and_port_forwards() {
        let primary_net: Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let backup_net: Ipv4Net = "10.0.0.1/24".parse().unwrap();

        let mac1 = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mac2 = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x66);
        let mut static_leases = HashMap::new();
        static_leases.insert(mac1, Ipv4Addr::new(192, 168, 1, 50));
        static_leases.insert(mac2, Ipv4Addr::new(192, 168, 1, 60));

        let remapped_leases =
            remap_static_leases_for_subnet(&static_leases, &primary_net, &backup_net);
        assert_eq!(remapped_leases.len(), 2);
        assert_eq!(
            remapped_leases.get(&mac1),
            Some(&Ipv4Addr::new(10, 0, 0, 50))
        );
        assert_eq!(
            remapped_leases.get(&mac2),
            Some(&Ipv4Addr::new(10, 0, 0, 60))
        );

        let port_forwards = vec![PortForwardRule {
            protocol: ForwardProtocol::Tcp,
            external_port: 8080,
            internal_ip: Ipv4Addr::new(192, 168, 1, 50),
            internal_port: 80,
            description: Some("HTTP".to_string()),
        }];

        let remapped_forwards =
            remap_port_forwards_for_subnet(&port_forwards, &primary_net, &backup_net);
        assert_eq!(remapped_forwards.len(), 1);
        assert_eq!(
            remapped_forwards[0].internal_ip,
            Ipv4Addr::new(10, 0, 0, 50)
        );
        assert_eq!(remapped_forwards[0].external_port, 8080);
        assert_eq!(remapped_forwards[0].internal_port, 80);
    }

    #[test]
    fn test_remap_static_leases_and_port_forwards_identical_subnets() {
        let primary_net: Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let mac1 = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mut static_leases = HashMap::new();
        static_leases.insert(mac1, Ipv4Addr::new(192, 168, 1, 50));

        let remapped_leases =
            remap_static_leases_for_subnet(&static_leases, &primary_net, &primary_net);
        assert_eq!(remapped_leases.len(), 1);
        assert_eq!(
            remapped_leases.get(&mac1),
            Some(&Ipv4Addr::new(192, 168, 1, 50))
        );

        let port_forwards = vec![PortForwardRule {
            protocol: ForwardProtocol::Tcp,
            external_port: 8080,
            internal_ip: Ipv4Addr::new(192, 168, 1, 50),
            internal_port: 80,
            description: None,
        }];
        let remapped_forwards =
            remap_port_forwards_for_subnet(&port_forwards, &primary_net, &primary_net);
        assert_eq!(remapped_forwards.len(), 1);
        assert_eq!(
            remapped_forwards[0].internal_ip,
            Ipv4Addr::new(192, 168, 1, 50)
        );
    }

    #[test]
    fn test_remap_static_leases_and_port_forwards_unmappable_skipped() {
        let primary_net: Ipv4Net = "192.168.1.1/24".parse().unwrap();
        let backup_net: Ipv4Net = "10.0.0.1/28".parse().unwrap(); // hosts .1 to .14

        let mac1 = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mac2 = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x66);
        let mut static_leases = HashMap::new();
        static_leases.insert(mac1, Ipv4Addr::new(192, 168, 1, 5)); // offset 5 -> valid
        static_leases.insert(mac2, Ipv4Addr::new(192, 168, 1, 50)); // offset 50 -> out of /28 bounds

        let remapped_leases =
            remap_static_leases_for_subnet(&static_leases, &primary_net, &backup_net);
        assert_eq!(remapped_leases.len(), 1);
        assert_eq!(
            remapped_leases.get(&mac1),
            Some(&Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(remapped_leases.get(&mac2), None);

        let port_forwards = vec![
            PortForwardRule {
                protocol: ForwardProtocol::Tcp,
                external_port: 8080,
                internal_ip: Ipv4Addr::new(192, 168, 1, 5),
                internal_port: 80,
                description: None,
            },
            PortForwardRule {
                protocol: ForwardProtocol::Tcp,
                external_port: 9090,
                internal_ip: Ipv4Addr::new(192, 168, 1, 50),
                internal_port: 90,
                description: None,
            },
        ];

        let remapped_forwards =
            remap_port_forwards_for_subnet(&port_forwards, &primary_net, &backup_net);
        assert_eq!(remapped_forwards.len(), 1);
        assert_eq!(remapped_forwards[0].external_port, 8080);
        assert_eq!(remapped_forwards[0].internal_ip, Ipv4Addr::new(10, 0, 0, 5));
    }
}
