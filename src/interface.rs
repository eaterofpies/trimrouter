//! Dynamic interface lifecycle management and service dependency coordination.
//!
//! This module monitors interface state events from the Linux kernel using Netlink multicast,
//! handles interface renaming based on MAC address mapping to avoid conflicts, configures IP addresses,
//! and orchestrates starting/stopping dependent network services when links appear or disappear.

use crate::error::RouterError;
use crate::managers::{self, Service};
use crate::network;
use futures_util::{StreamExt, TryStreamExt};
use log::{error, info, warn};
use pnet::util::MacAddr;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use rtnetlink::{LinkUnspec, MulticastGroup};
use std::collections::{HashMap, HashSet};

/// Dynamic Router Service wrapper for execution management.
pub enum RouterService {
    /// WAN DHCP Client service.
    DhcpClient(managers::DhcpClient),
    /// SNTP Client time synchronization service.
    SntpClient(managers::SntpClient),
    /// LAN Manager service.
    LanManager(managers::LanManager),
}

impl Service for RouterService {
    /// Starts the encapsulated router service.
    async fn start(&mut self) -> Result<(), managers::ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.start().await,
            RouterService::SntpClient(s) => s.start().await,
            RouterService::LanManager(s) => s.start().await,
        }
    }

    /// Stops the encapsulated router service.
    async fn stop(&mut self) -> Result<(), managers::ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.stop().await,
            RouterService::SntpClient(s) => s.stop().await,
            RouterService::LanManager(s) => s.stop().await,
        }
    }
}

/// Representation of a managed network interface.
pub struct ManagedInterface {
    /// The target name of the interface (e.g., "wan", "lan").
    pub name: String,
    /// The target MAC address mapping to detect and identify the hardware interface.
    pub mac: MacAddr,
    /// Collection of active services bound to this interface.
    pub active_services: Vec<RouterService>,
    /// The resolved Linux kernel interface index, if currently detected and active.
    pub active_index: Option<u32>,
}

impl ManagedInterface {
    /// Creates a new managed interface description with its dependent services.
    pub fn new(name: String, mac: MacAddr, active_services: Vec<RouterService>) -> Self {
        Self {
            name,
            mac,
            active_services,
            active_index: None,
        }
    }

    /// Starts all instantiated services bound to this interface.
    pub async fn start_services(&mut self) {
        for service in &mut self.active_services {
            if let Err(e) = service.start().await {
                error!(
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
    }
}

fn get_link_speed(iface_name: &str) -> String {
    let path = format!("/sys/class/net/{}/speed", iface_name);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&mbps| mbps > 0)
        .map(|mbps| format!("{} Mbps", mbps))
        .unwrap_or_else(|| "unknown".to_string())
}

fn if_indextoname(index: u32) -> Option<String> {
    std::fs::read_dir("/sys/class/net").ok()?.find_map(|entry| {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let ifindex_path = format!("/sys/class/net/{}/ifindex", name);
        let ifindex = std::fs::read_to_string(ifindex_path)
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()?;
        (ifindex == index).then_some(name)
    })
}

/// Subscribes to Netlink link multicast groups and monitors the lifecycle of all managed interfaces.
///
/// Deduplicates dynamic hardware detection logs, handles interface renaming on match,
/// and manages dynamic service transitions.
pub async fn monitor_interfaces(mut interfaces: Vec<ManagedInterface>) {
    let (connection, handle, mut messages) =
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

    // Map of interface index -> (name, MAC, has_link)
    let mut link_states = HashMap::new();

    // Initial scan to populate current link states
    let mut links = handle.link().get().execute();
    while let Some(link_msg) = links.try_next().await.unwrap_or(None) {
        let index = link_msg.header.index;
        let (name, address) = parse_link_attributes(link_msg.attributes);
        if let (Some(n), Some(addr)) = (name, address)
            && n != "lo"
        {
            // Bring it UP administratively so carrier detection/negotiation can occur
            let _ = network::ensure_interface_up(&n).await;

            let has_link = link_msg.header.flags.contains(LinkFlags::LowerUp);
            link_states.insert(index, (n.clone(), addr, has_link));

            if has_link {
                let speed = get_link_speed(&n);
                info!(
                    "[interface] Interface {} (MAC: {}) got link (speed: {})",
                    n, addr, speed
                );
            }
        }
    }

    // Local set tracking discovered interfaces to deduplicate logs (no static globals needed)
    let mut detected_indices = HashSet::new();

    // Initial check (catch up on startup for all interfaces)
    for iface in &mut interfaces {
        if let Some((index, name)) = find_interface_by_mac(iface.mac).await {
            info!(
                "[interface] Interface {} (MAC: {}) detected at startup. Renaming and starting services...",
                iface.name, iface.mac
            );
            detected_indices.insert(index);
            if let Err(e) = activate_interface(iface, index, &name).await {
                panic!(
                    "CRITICAL: Failed to activate interface {} on startup: {}",
                    iface.name, e
                );
            }
        }
    }

    while let Some((message, _addr)) = messages.next().await {
        if let NetlinkPayload::InnerMessage(rtnl_msg) = message.payload {
            let res = process_netlink_message(
                rtnl_msg,
                &mut interfaces,
                &mut detected_indices,
                &mut link_states,
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
                address = managers::utils::mac_from_slice(&addr).ok();
            }
            _ => {}
        }
    }
    (name, address)
}

/// Formats and logs the newly detected network device's MAC address.
fn log_detected_device(name: &str, mac: MacAddr) {
    info!(
        "[interface] Detected network device: {} (MAC: {})",
        name, mac
    );
}

/// Helper function to route incoming Netlink route messages to their handlers.
async fn process_netlink_message(
    rtnl_msg: RouteNetlinkMessage,
    interfaces: &mut [ManagedInterface],
    detected_indices: &mut HashSet<u32>,
    link_states: &mut HashMap<u32, (String, MacAddr, bool)>,
) -> Result<(), RouterError> {
    match rtnl_msg {
        RouteNetlinkMessage::NewLink(link_msg) => {
            handle_new_link_event(link_msg, interfaces, detected_indices, link_states).await?;
        }
        RouteNetlinkMessage::DelLink(link_msg) => {
            handle_del_link_event(link_msg, interfaces, detected_indices, link_states).await;
        }
        _ => {}
    }
    Ok(())
}

/// Handles incoming NewLink netlink events by parsing attributes and routing to managed interfaces.
async fn handle_new_link_event(
    link_msg: LinkMessage,
    interfaces: &mut [ManagedInterface],
    detected_indices: &mut HashSet<u32>,
    link_states: &mut HashMap<u32, (String, MacAddr, bool)>,
) -> Result<(), RouterError> {
    let index = link_msg.header.index;
    let (name, address) = parse_link_attributes(link_msg.attributes);

    let (n, addr) = if let (Some(name_val), Some(addr_val)) = (name.clone(), address) {
        (name_val, addr_val)
    } else if let Some(cached) = link_states.get(&index) {
        let name_resolved = name.unwrap_or_else(|| cached.0.clone());
        let addr_resolved = address.unwrap_or(cached.1);
        (name_resolved, addr_resolved)
    } else {
        let Some(name_resolved) = name.or_else(|| if_indextoname(index)) else {
            return Ok(());
        };
        let addr_resolved = address.unwrap_or(MacAddr::new(0, 0, 0, 0, 0, 0));
        (name_resolved, addr_resolved)
    };

    if n == "lo" {
        return Ok(());
    }

    let has_link = link_msg.header.flags.contains(LinkFlags::LowerUp);
    let prev_link = link_states.get(&index).map(|s| s.2);
    if prev_link != Some(has_link) {
        if has_link {
            let speed = get_link_speed(&n);
            info!(
                "[interface] Interface {} (MAC: {}) got link (speed: {})",
                n, addr, speed
            );
        } else {
            warn!("[interface] Interface {} (MAC: {}) lost link", n, addr);
        }
        link_states.insert(index, (n.clone(), addr, has_link));
    }

    // 1. Dedup and log detection of any new physical/USB interface
    if detected_indices.insert(index) {
        log_detected_device(&n, addr);
        // Ensure the newly detected interface is administratively UP to enable link negotiation
        let _ = network::ensure_interface_up(&n).await;
    }

    // 2. Route hotplug matching to the respective managed interface
    for iface in interfaces {
        handle_new_link(iface, index, &n, addr).await?;
    }
    Ok(())
}

/// Handles incoming DelLink netlink events by removing from detected index and stopping active services.
async fn handle_del_link_event(
    link_msg: LinkMessage,
    interfaces: &mut [ManagedInterface],
    detected_indices: &mut HashSet<u32>,
    link_states: &mut HashMap<u32, (String, MacAddr, bool)>,
) {
    let index = link_msg.header.index;
    detected_indices.remove(&index);
    if let Some((n, addr, has_link)) = link_states.remove(&index)
        && has_link
    {
        warn!("[interface] Interface {} (MAC: {}) lost link", n, addr);
    }
    for iface in interfaces {
        handle_del_link(iface, index).await;
    }
}

/// Helper function to perform renaming, IP configuration, and start dependent services.
async fn activate_interface(
    iface: &mut ManagedInterface,
    index: u32,
    current_name: &str,
) -> Result<(), RouterError> {
    rename_and_up_interface(&iface.name, iface.mac, index, current_name).await?;
    network::ensure_interface_up(&iface.name).await?;
    iface.start_services().await;
    iface.active_index = Some(index);
    Ok(())
}

/// Handles interface appearance/hotplugging, name collisions, and acts as a watchdog.
async fn handle_new_link(
    iface: &mut ManagedInterface,
    index: u32,
    name: &str,
    mac: MacAddr,
) -> Result<(), RouterError> {
    if mac == iface.mac {
        if iface.active_index.is_none() {
            info!(
                "[interface] Interface {} (MAC: {}) appeared. Renaming and starting services...",
                iface.name, iface.mac
            );
            activate_interface(iface, index, name).await?;
        } else if iface.active_index == Some(index) {
            // Watchdog: keep configured
            network::ensure_interface_up(&iface.name).await?;
        }
    } else if name == iface.name {
        // Collision: another interface has our target name but different MAC.
        // Rename it out of the way.
        let temp_name = format!("{}_old_{}", iface.name, index);
        warn!(
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
        warn!(
            "[interface] Interface {} (MAC: {}) disappeared. Stopping and deleting services...",
            iface.name, iface.mac
        );
        iface.stop_services().await;
        iface.active_index = None;
    }
}

/// Finds the kernel interface index and current name matching the target MAC address.
pub async fn find_interface_by_mac(target_mac: MacAddr) -> Option<(u32, String)> {
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return None;
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let index = link.header.index;
        let (name, address) = parse_link_attributes(link.attributes);
        if let (Some(n), Some(addr)) = (name, address)
            && addr == target_mac
        {
            return Some((index, n));
        }
    }
    None
}

/// Renames the interface to its configured target name and brings it up.
pub async fn rename_and_up_interface(
    target_name: &str,
    mac: MacAddr,
    index: u32,
    current_name: &str,
) -> Result<(), RouterError> {
    if current_name == target_name {
        return Ok(());
    }

    info!(
        "[interface] Renaming interface {} (index {}) to {} based on MAC {}",
        current_name, index, target_name, mac
    );

    rename_interface_by_index(index, target_name).await?;
    info!(
        "[interface] Renamed interface from {} to {} (index {})",
        current_name, target_name, index
    );
    Ok(())
}

/// Utility function to rename an interface by kernel index via netlink.
async fn rename_interface_by_index(index: u32, new_name: &str) -> Result<(), RouterError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let msg_down = LinkUnspec::new_with_index(index).down().build();
    handle.link().change(msg_down).execute().await?;

    let msg_name = LinkUnspec::new_with_index(index)
        .name(new_name.to_string())
        .build();
    handle.link().change(msg_name).execute().await?;

    let msg_up = LinkUnspec::new_with_index(index).up().build();
    handle.link().change(msg_up).execute().await?;

    Ok(())
}
