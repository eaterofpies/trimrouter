//! Dynamic interface lifecycle management and service dependency coordination.
//!
//! This module monitors interface state events from the Linux kernel using Netlink multicast,
//! handles interface renaming based on MAC address mapping to avoid conflicts, configures IP addresses,
//! and orchestrates starting/stopping dependent network services when links appear or disappear.

use crate::error::RouterError;
use crate::network;
use crate::services::utils::SharedWanLease;
use crate::services::{self, Service};
use futures_util::{StreamExt, TryStreamExt};
use pnet::util::MacAddr;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_route::link::LinkAttribute;

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
    /// SNTP Client time synchronization service.
    SntpClient(services::SntpClient),
}

impl RouterService {
    /// Starts the underlying router service.
    pub async fn start(&mut self) -> Result<(), services::ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.start().await,
            RouterService::DhcpServer(s) => s.start().await,
            RouterService::SntpClient(s) => s.start().await,
        }
    }

    /// Stops the underlying router service.
    pub async fn stop(&mut self) -> Result<(), services::ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.stop().await,
            RouterService::DhcpServer(s) => s.stop().await,
            RouterService::SntpClient(s) => s.stop().await,
        }
    }
}

/// Represents a physical interface managed dynamically by the router init daemon.
pub struct ManagedInterface {
    /// The target name of the interface (e.g., "wan", "lan").
    pub name: String,
    /// The target MAC address mapping to detect and identify the hardware interface.
    pub mac: MacAddr,
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
        mac: MacAddr,
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
                services.push(RouterService::DhcpServer(server));
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

/// Subscribes to Netlink link multicast groups and monitors the lifecycle of all managed interfaces.
///
/// Deduplicates dynamic hardware detection logs, handles interface renaming on match,
/// and manages dynamic service transitions.
pub async fn monitor_interfaces(
    mut interfaces: Vec<ManagedInterface>,
    lease_state: SharedWanLease,
) {
    let (connection, _handle, mut messages) =
        match rtnetlink::new_multicast_connection(&[MulticastGroup::Link]) {
            Ok(res) => res,
            Err(e) => {
                panic!(
                    "[interface] Failed to create Netlink multicast socket: {}",
                    e
                );
            }
        };
    tokio::spawn(connection);

    // Local set tracking discovered interfaces to deduplicate logs (no static globals needed)
    let mut detected_indices = std::collections::HashSet::new();

    // Initial check (catch up on startup for all interfaces)
    for iface in &mut interfaces {
        if let Some((index, name)) = find_interface_by_mac(iface.mac).await {
            println!(
                "[interface] Interface {} (MAC: {}) detected at startup. Renaming and starting services...",
                iface.name, iface.mac
            );
            detected_indices.insert(index);
            if let Err(e) = activate_interface(iface, index, &name, &lease_state).await {
                panic!(
                    "CRITICAL: Failed to activate interface {} on startup: {}",
                    iface.name, e
                );
            }
        }
    }

    while let Some((message, _addr)) = messages.next().await {
        if let rtnetlink::packet_core::NetlinkPayload::InnerMessage(rtnl_msg) = message.payload {
            let res = process_netlink_message(
                rtnl_msg,
                &mut interfaces,
                &lease_state,
                &mut detected_indices,
            )
            .await;
            if let Err(e) = res {
                panic!(
                    "CRITICAL: Interface monitoring or configuration failure: {}",
                    e
                );
            }
        }
    }
}

/// Helper function to parse link attributes from a LinkMessage.
fn parse_link_attributes(attributes: Vec<LinkAttribute>) -> (Option<String>, Option<MacAddr>) {
    let mut name = None;
    let mut address = None;
    for nla in attributes {
        match nla {
            LinkAttribute::IfName(n) => name = Some(n),
            LinkAttribute::Address(addr) => {
                address = services::utils::mac_from_slice(&addr).ok();
            }
            _ => {}
        }
    }
    (name, address)
}

/// Formats and logs the newly detected network device's MAC address.
fn log_detected_device(name: &str, mac: MacAddr) {
    println!(
        "[interface] Detected network device: {} (MAC: {})",
        name, mac
    );
}

/// Helper function to route incoming Netlink route messages to their handlers.
async fn process_netlink_message(
    rtnl_msg: rtnetlink::packet_route::RouteNetlinkMessage,
    interfaces: &mut [ManagedInterface],
    lease_state: &SharedWanLease,
    detected_indices: &mut std::collections::HashSet<u32>,
) -> Result<(), RouterError> {
    match rtnl_msg {
        rtnetlink::packet_route::RouteNetlinkMessage::NewLink(link_msg) => {
            handle_new_link_event(link_msg, interfaces, lease_state, detected_indices).await?;
        }
        rtnetlink::packet_route::RouteNetlinkMessage::DelLink(link_msg) => {
            handle_del_link_event(link_msg, interfaces, detected_indices).await;
        }
        _ => {}
    }
    Ok(())
}

/// Handles incoming NewLink netlink events by parsing attributes and routing to managed interfaces.
async fn handle_new_link_event(
    link_msg: rtnetlink::packet_route::link::LinkMessage,
    interfaces: &mut [ManagedInterface],
    lease_state: &SharedWanLease,
    detected_indices: &mut std::collections::HashSet<u32>,
) -> Result<(), RouterError> {
    let index = link_msg.header.index;
    let (name, address) = parse_link_attributes(link_msg.attributes);

    let (Some(n), Some(addr)) = (name, address) else {
        return Ok(());
    };

    // 1. Dedup and log detection of any new physical/USB interface
    if n != "lo" && detected_indices.insert(index) {
        log_detected_device(&n, addr);
    }

    // 2. Route hotplug matching to the respective managed interface
    for iface in interfaces {
        handle_new_link(iface, lease_state, index, &n, addr).await?;
    }
    Ok(())
}

/// Handles incoming DelLink netlink events by removing from detected index and stopping active services.
async fn handle_del_link_event(
    link_msg: rtnetlink::packet_route::link::LinkMessage,
    interfaces: &mut [ManagedInterface],
    detected_indices: &mut std::collections::HashSet<u32>,
) {
    let index = link_msg.header.index;
    detected_indices.remove(&index);
    for iface in interfaces {
        handle_del_link(iface, index).await;
    }
}

/// Helper function to perform renaming, IP configuration, and start dependent services.
async fn activate_interface(
    iface: &mut ManagedInterface,
    index: u32,
    current_name: &str,
    lease_state: &SharedWanLease,
) -> Result<(), RouterError> {
    rename_and_up_interface(&iface.name, iface.mac, index, current_name).await?;
    configure_interface(iface).await?;
    iface.instantiate_services(lease_state.clone());
    iface.start_services().await;
    iface.active_index = Some(index);
    Ok(())
}

/// Handles interface appearance/hotplugging, name collisions, and acts as a watchdog.
async fn handle_new_link(
    iface: &mut ManagedInterface,
    lease_state: &SharedWanLease,
    index: u32,
    name: &str,
    mac: MacAddr,
) -> Result<(), RouterError> {
    if mac == iface.mac {
        if iface.active_index.is_none() {
            println!(
                "[interface] Interface {} (MAC: {}) appeared. Renaming and starting services...",
                iface.name, iface.mac
            );
            activate_interface(iface, index, name, lease_state).await?;
        } else if iface.active_index == Some(index) {
            // Watchdog: keep configured
            configure_interface(iface).await?;
        }
    } else if name == iface.name {
        // Collision: another interface has our target name but different MAC.
        // Rename it out of the way.
        let temp_name = format!("{}_old_{}", iface.name, index);
        println!(
            "[interface] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
            iface.name, index, temp_name
        );
        rename_interface_by_index(index, &temp_name).await?;
    }
    Ok(())
}

/// Handles dynamic cleanup of services when an active interface disappears.
async fn handle_del_link(iface: &mut ManagedInterface, index: u32) {
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
async fn configure_interface(iface: &ManagedInterface) -> Result<(), RouterError> {
    if let Some(ref cidr) = iface.ip_config {
        network::ensure_interface_up_and_configured(&iface.name, cidr).await?;
    } else {
        network::ensure_interface_up(&iface.name).await?;
    }
    Ok(())
}

/// Finds the kernel interface index and current name matching the target MAC address.
async fn find_interface_by_mac(target_mac: MacAddr) -> Option<(u32, String)> {
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
    mac: MacAddr,
    index: u32,
    current_name: &str,
) -> Result<(), RouterError> {
    if current_name != target_name {
        // Check for collisions and rename the colliding interface out of the way
        if let Some(collision_idx) = find_interface_by_name(target_name).await {
            let temp_name = format!("{}_old_{}", target_name, collision_idx);
            println!(
                "[interface] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
                target_name, collision_idx, temp_name
            );
            rename_interface_by_index(collision_idx, &temp_name).await?;
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
async fn rename_interface_by_index(index: u32, new_name: &str) -> Result<(), RouterError> {
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
