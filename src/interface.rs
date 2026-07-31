//! Dynamic interface lifecycle management and service dependency coordination.
//!
//! This module monitors interface state events from the Linux kernel using Netlink multicast,
//! handles interface renaming based on MAC address mapping to avoid conflicts, configures IP addresses,
//! and orchestrates starting/stopping dependent network services when links appear or disappear.

use crate::network;
use crate::services::utils::SharedWanLease;
use crate::services::{self, Service};
use futures_util::{StreamExt, TryStreamExt};
use rtnetlink::MulticastGroup;
use std::str::FromStr;

/// Classification of interface roles in the router system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    /// Wide Area Network (Internet facing).
    Wan,
    /// Local Area Network (Local client facing).
    Lan,
}

/// A wrapper enum containing concrete implementations of router services.
///
/// This avoids dyn-compatibility limitations under async traits and represents
/// the collection of services managed by the interface controller.
pub enum RouterService {
    /// WAN DHCP Client service.
    DhcpClient(services::DhcpClient),
    /// LAN DHCP Server service.
    DhcpServer(services::DhcpServer),
    /// DNS caching forwarder service.
    DnsForwarder(services::DnsForwarder),
    /// SNTP Client time synchronization service.
    SntpClient(services::SntpClient),
}

impl RouterService {
    /// Starts the underlying router service.
    pub async fn start(&mut self) -> Result<(), services::ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.start().await,
            RouterService::DhcpServer(s) => s.start().await,
            RouterService::DnsForwarder(s) => s.start().await,
            RouterService::SntpClient(s) => s.start().await,
        }
    }

    /// Stops the underlying router service.
    pub async fn stop(&mut self) -> Result<(), services::ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.stop().await,
            RouterService::DhcpServer(s) => s.stop().await,
            RouterService::DnsForwarder(s) => s.stop().await,
            RouterService::SntpClient(s) => s.stop().await,
        }
    }
}

/// Represents a physical interface managed dynamically by the router init daemon.
pub struct ManagedInterface {
    /// The target name of the interface (e.g., "wan", "lan").
    pub name: String,
    /// The target MAC address mapping to detect and identify the hardware interface.
    pub mac: String,
    /// Optional IP configuration CIDR (e.g. "192.168.1.1/24") for static assignment.
    pub ip_config: Option<String>,
    /// The type / role of this interface.
    pub service_type: InterfaceType,
    /// Collection of active services bound to this interface.
    pub active_services: Vec<RouterService>,
    /// The resolved Linux kernel interface index, if currently detected and active.
    pub active_index: Option<u32>,
}

impl ManagedInterface {
    /// Creates a new managed interface description.
    pub fn new(
        name: String,
        mac: String,
        ip_config: Option<String>,
        service_type: InterfaceType,
    ) -> Self {
        Self {
            name,
            mac,
            ip_config,
            service_type,
            active_services: Vec::new(),
            active_index: None,
        }
    }

    /// Instantiates the dependent services for this interface based on its type.
    pub fn instantiate_services(&mut self, lease_state: SharedWanLease) {
        let mut services: Vec<RouterService> = Vec::new();
        match self.service_type {
            InterfaceType::Wan => {
                let client = services::DhcpClient::new(self.name.clone(), lease_state.clone());
                let sntp = services::SntpClient::new(lease_state.clone());
                services.push(RouterService::DhcpClient(client));
                services.push(RouterService::SntpClient(sntp));
            }
            InterfaceType::Lan => {
                let ip_str = self.ip_config.as_deref().unwrap_or("192.168.1.1/24");
                let server = services::DhcpServer::new(self.name.clone(), ip_str.to_string());
                let dns = services::DnsForwarder::new(lease_state.clone());
                services.push(RouterService::DhcpServer(server));
                services.push(RouterService::DnsForwarder(dns));
            }
        }
        self.active_services = services;
    }

    /// Starts all instantiated services bound to this interface.
    pub async fn start_services(&mut self) {
        for service in &mut self.active_services {
            if let Err(e) = service.start().await {
                eprintln!(
                    "[interface] Failed to start service on interface {}: {}",
                    self.name, e
                );
            }
        }
    }

    /// Stops and terminates all running services bound to this interface.
    pub async fn stop_services(&mut self) {
        for service in &mut self.active_services {
            let _ = service.stop().await;
        }
        self.active_services.clear();
    }
}

/// Subscribes to Netlink link multicast groups and monitors the lifecycle of the interface.
///
/// If the interface already exists at boot, it is detected and initialized.
/// If it appears or changes state dynamically, it is configured reactively.
pub async fn monitor_interface(mut iface: ManagedInterface, lease_state: SharedWanLease) {
    let (connection, _handle, mut messages) =
        match rtnetlink::new_multicast_connection(&[MulticastGroup::Link]) {
            Ok(res) => res,
            Err(e) => {
                eprintln!(
                    "[interface] Failed to create Netlink multicast socket: {}",
                    e
                );
                return;
            }
        };
    tokio::spawn(connection);

    // Initial check (catch up on startup)
    if let Some((index, name)) = find_interface_by_mac(&iface.mac).await {
        println!(
            "[interface] Interface {} (MAC: {}) detected at startup. Renaming and starting services...",
            iface.name, iface.mac
        );
        activate_interface(&mut iface, index, &name, &lease_state).await;
    }

    while let Some((message, _addr)) = messages.next().await {
        let payload = message.payload;
        if let rtnetlink::packet_core::NetlinkPayload::InnerMessage(rtnl_msg) = payload {
            match rtnl_msg {
                rtnetlink::packet_route::RouteNetlinkMessage::NewLink(link_msg) => {
                    handle_new_link(&mut iface, &lease_state, link_msg).await;
                }
                rtnetlink::packet_route::RouteNetlinkMessage::DelLink(link_msg) => {
                    handle_del_link(&mut iface, link_msg).await;
                }
                _ => {}
            }
        }
    }
}

/// Helper function to perform renaming, IP configuration, and start dependent services.
async fn activate_interface(
    iface: &mut ManagedInterface,
    index: u32,
    current_name: &str,
    lease_state: &SharedWanLease,
) {
    if rename_and_up_interface(&iface.name, &iface.mac, index, current_name)
        .await
        .is_ok()
    {
        configure_interface(iface).await;
        iface.instantiate_services(lease_state.clone());
        iface.start_services().await;
        iface.active_index = Some(index);
    }
}

/// Handles incoming `RTM_NEWLINK` events from the kernel multicast stream.
///
/// Reacts to interface appearance/hotplugging, name collisions, and acts as a watchdog.
async fn handle_new_link(
    iface: &mut ManagedInterface,
    lease_state: &SharedWanLease,
    link_msg: rtnetlink::packet_route::link::LinkMessage,
) {
    let index = link_msg.header.index;
    let mut name = None;
    let mut address = None;
    for nla in link_msg.attributes {
        match nla {
            rtnetlink::packet_route::link::LinkAttribute::IfName(n) => name = Some(n),
            rtnetlink::packet_route::link::LinkAttribute::Address(addr) => address = Some(addr),
            _ => {}
        }
    }

    if let (Some(n), Some(addr)) = (name, address) {
        let Ok(target_mac) = pnet::util::MacAddr::from_str(&iface.mac) else {
            return;
        };
        if addr == target_mac.octets()[..] {
            if iface.active_index.is_none() {
                println!(
                    "[interface] Interface {} (MAC: {}) appeared. Renaming and starting services...",
                    iface.name, iface.mac
                );
                activate_interface(iface, index, &n, lease_state).await;
            } else if iface.active_index == Some(index) {
                // Watchdog: keep configured
                configure_interface(iface).await;
            }
        } else if n == iface.name {
            // Collision: another interface has our target name but different MAC.
            // Rename it out of the way.
            let temp_name = format!("{}_old_{}", iface.name, index);
            println!(
                "[interface] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
                iface.name, index, temp_name
            );
            let _ = rename_interface_by_index(index, &temp_name).await;
        }
    }
}

/// Handles `RTM_DELLINK` events to clean up services when the interface disappears.
async fn handle_del_link(
    iface: &mut ManagedInterface,
    link_msg: rtnetlink::packet_route::link::LinkMessage,
) {
    let index = link_msg.header.index;
    if iface.active_index == Some(index) {
        println!(
            "[interface] Interface {} (MAC: {}) disappeared. Stopping and deleting services...",
            iface.name, iface.mac
        );
        iface.stop_services().await;
        iface.active_index = None;
    }
}

/// Configures IP address routing rules and ensures the administrative state is UP.
async fn configure_interface(iface: &ManagedInterface) {
    if let Some(ref cidr) = iface.ip_config {
        let _ = network::ensure_interface_up_and_configured(&iface.name, cidr).await;
    } else {
        let _ = network::ensure_interface_up(&iface.name).await;
    }
}

/// Finds the kernel interface index and current name matching the target MAC address.
async fn find_interface_by_mac(mac_str: &str) -> Option<(u32, String)> {
    let Ok(target_mac) = pnet::util::MacAddr::from_str(mac_str) else {
        return None;
    };
    let target_bytes = target_mac.octets();

    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return None;
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let index = link.header.index;
        let mut name = None;
        let mut address = None;
        for nla in link.attributes {
            match nla {
                rtnetlink::packet_route::link::LinkAttribute::IfName(n) => name = Some(n),
                rtnetlink::packet_route::link::LinkAttribute::Address(addr) => address = Some(addr),
                _ => {}
            }
        }
        if let (Some(n), Some(_)) = (name, address.filter(|a| a == &target_bytes)) {
            return Some((index, n));
        }
    }
    None
}

/// Safe helper to rename an interface collision-free and set its link administrative state UP.
async fn rename_and_up_interface(
    target_name: &str,
    mac: &str,
    index: u32,
    current_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if current_name != target_name {
        // Check for collisions and rename the colliding interface out of the way
        if let Some(collision_idx) = find_interface_by_name(target_name).await {
            let temp_name = format!("{}_old_{}", target_name, collision_idx);
            println!(
                "[interface] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
                target_name, collision_idx, temp_name
            );
            let _ = rename_interface_by_index(collision_idx, &temp_name).await;
        }

        println!(
            "[interface] Renaming interface {} (index {}) to {} based on MAC {}",
            current_name, index, target_name, mac
        );
        rename_interface_by_index(index, target_name).await?;
    }
    Ok(())
}

/// Queries the kernel for an interface index matching a given name.
async fn find_interface_by_name(name: &str) -> Option<u32> {
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return None;
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    if let Ok(Some(link)) = links.try_next().await {
        return Some(link.header.index);
    }
    None
}

/// Modifies the administrative state and changes the name of an interface by its index.
async fn rename_interface_by_index(
    index: u32,
    new_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let msg_down = rtnetlink::LinkUnspec::new_with_index(index).down().build();
    handle.link().change(msg_down).execute().await?;

    let msg_name = rtnetlink::LinkUnspec::new_with_index(index)
        .name(new_name.to_string())
        .build();
    handle.link().change(msg_name).execute().await?;

    let msg_up = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(msg_up).execute().await?;

    Ok(())
}
