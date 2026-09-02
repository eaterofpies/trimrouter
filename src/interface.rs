//! Dynamic interface lifecycle management and service dependency coordination.
//!
//! This module monitors interface state events from the Linux kernel using Netlink multicast,
//! handles interface renaming based on MAC address mapping to avoid conflicts, configures IP addresses,
//! and orchestrates starting/stopping dependent network services when links appear or disappear.

use crate::error::RouterError;
use crate::init::watchdog::{HeartbeatSender, MonitoredService, send_service_heartbeat};
use crate::network;
use crate::services::{self, Service};
use futures_util::{StreamExt, TryStreamExt};
use log::{debug, error, info, warn};
use pnet::util::MacAddr;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use rtnetlink::{LinkUnspec, MulticastGroup};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::time::sleep;

const INTERFACE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

/// Dynamic Router Service wrapper for execution management.
pub enum RouterService {
    /// WAN DHCP Client service.
    DhcpClient(services::DhcpClient),
    /// SNTP Client time synchronization service.
    SntpClient(services::SntpClient),
    /// LAN Manager service.
    LanManager(services::LanManager),
}

impl Service for RouterService {
    /// Starts the encapsulated router service.
    async fn start(&mut self) -> Result<(), services::ServiceError> {
        match self {
            RouterService::DhcpClient(s) => s.start().await,
            RouterService::SntpClient(s) => s.start().await,
            RouterService::LanManager(s) => s.start().await,
        }
    }

    /// Stops the encapsulated router service.
    async fn stop(&mut self) -> Result<(), services::ServiceError> {
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
            if let Err(e) = service.stop().await {
                error!(
                    "[interface] Failed to stop service on interface {}: {}",
                    self.name, e
                );
            }
        }
    }
}

fn read_sysfs_net_attr(iface_name: &str, attr: &str) -> Option<String> {
    let path = format!("/sys/class/net/{}/{}", iface_name, attr);
    std::fs::read_to_string(path).ok()
}

fn parse_link_speed_str(content: &str) -> String {
    content
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&mbps| mbps > 0)
        .map(|mbps| format!("{} Mbps", mbps))
        .unwrap_or_else(|| "unknown".to_string())
}

fn get_link_speed(iface_name: &str) -> String {
    read_sysfs_net_attr(iface_name, "speed")
        .map(|s| parse_link_speed_str(&s))
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_carrier_file_content(content: &str) -> Option<bool> {
    match content.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

fn parse_operstate_str(content: &str) -> Option<bool> {
    match content.trim() {
        "up" => Some(true),
        "down" | "lowerlayerdown" | "dormant" => Some(false),
        _ => None,
    }
}

fn get_interface_carrier(iface_name: &str) -> Option<bool> {
    if let Some(content) = read_sysfs_net_attr(iface_name, "carrier")
        && let Some(carrier) = parse_carrier_file_content(&content)
    {
        return Some(carrier);
    }
    read_sysfs_net_attr(iface_name, "operstate").and_then(|s| parse_operstate_str(&s))
}

fn poll_interface_carrier_states(
    interfaces: &[ManagedInterface],
    link_states: &mut HashMap<u32, (String, MacAddr, bool)>,
) {
    poll_interface_carrier_states_with_reader(interfaces, link_states, get_interface_carrier);
}

fn poll_interface_carrier_states_with_reader<F>(
    interfaces: &[ManagedInterface],
    link_states: &mut HashMap<u32, (String, MacAddr, bool)>,
    carrier_reader: F,
) where
    F: Fn(&str) -> Option<bool>,
{
    for iface in interfaces {
        let Some(index) = iface.active_index else {
            continue;
        };
        let Some(carrier) = carrier_reader(&iface.name) else {
            continue;
        };
        update_carrier_state(index, &iface.name, iface.mac, carrier, link_states);
    }
}

fn log_carrier_transition(name: &str, mac: MacAddr, carrier: bool) {
    if carrier {
        let speed = get_link_speed(name);
        info!(
            "[interface] Interface {} (MAC: {}) got link (speed: {})",
            name, mac, speed
        );
    } else {
        warn!("[interface] Interface {} (MAC: {}) lost link", name, mac);
    }
}

fn update_carrier_state(
    index: u32,
    name: &str,
    mac: MacAddr,
    carrier: bool,
    link_states: &mut HashMap<u32, (String, MacAddr, bool)>,
) {
    match link_states.get_mut(&index) {
        Some(state) => {
            if state.2 == carrier {
                return;
            }
            state.2 = carrier;
            log_carrier_transition(name, mac, carrier);
        }
        None => {
            link_states.insert(index, (name.to_string(), mac, carrier));
            if carrier {
                log_carrier_transition(name, mac, carrier);
            }
        }
    }
}

fn if_indextoname(index: u32) -> Option<String> {
    std::fs::read_dir("/sys/class/net").ok()?.find_map(|entry| {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let ifindex = read_sysfs_net_attr(&name, "ifindex")?
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
async fn initial_link_scan(handle: &rtnetlink::Handle) -> HashMap<u32, (String, MacAddr, bool)> {
    let mut link_states = HashMap::new();
    let mut links = handle.link().get().execute();

    while let Some(link_msg) = links.try_next().await.unwrap_or(None) {
        let index = link_msg.header.index;
        let (name, address) = parse_link_attributes(link_msg.attributes);
        if let (Some(n), Some(addr)) = (name, address)
            && n != "lo"
        {
            if let Err(e) = network::ensure_interface_up(&n).await {
                debug!("[interface] Failed to bring interface {} up: {}", n, e);
            }

            let has_link = link_msg.header.flags.contains(LinkFlags::LowerUp);
            update_carrier_state(index, &n, addr, has_link, &mut link_states);
        }
    }
    link_states
}

async fn activate_startup_interfaces(
    interfaces: &mut [ManagedInterface],
    detected_indices: &mut HashSet<u32>,
) {
    for iface in interfaces {
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
}

pub async fn monitor_interfaces(
    mut interfaces: Vec<ManagedInterface>,
    heartbeat_tx: Option<HeartbeatSender>,
) {
    send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::InterfaceMonitor);

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

    let mut link_states = initial_link_scan(&handle).await;
    let mut detected_indices = HashSet::new();

    activate_startup_interfaces(&mut interfaces, &mut detected_indices).await;

    loop {
        tokio::select! {
            _ = sleep(INTERFACE_HEARTBEAT_INTERVAL) => {
                send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::InterfaceMonitor);
                poll_interface_carrier_states(&interfaces, &mut link_states);
            }
            msg = messages.next() => {
                let Some((message, _addr)) = msg else { break; };
                send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::InterfaceMonitor);
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
    update_carrier_state(index, &n, addr, has_link, link_states);

    // 1. Dedup and log detection of any new physical/USB interface
    if detected_indices.insert(index) {
        log_detected_device(&n, addr);
        // Ensure the newly detected interface is administratively UP to enable link negotiation
        if let Err(e) = network::ensure_interface_up(&n).await {
            debug!("[interface] Failed to ensure interface {} up: {}", n, e);
        }
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

fn create_rtnetlink_handle() -> Result<rtnetlink::Handle, RouterError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    Ok(handle)
}

/// Finds the kernel interface index and current name matching the target MAC address.
pub async fn find_interface_by_mac(target_mac: MacAddr) -> Option<(u32, String)> {
    let handle = create_rtnetlink_handle().ok()?;

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
    let handle = create_rtnetlink_handle()?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_carrier_file_content() {
        assert_eq!(parse_carrier_file_content("1\n"), Some(true));
        assert_eq!(parse_carrier_file_content("1"), Some(true));
        assert_eq!(parse_carrier_file_content("0\n"), Some(false));
        assert_eq!(parse_carrier_file_content("0"), Some(false));
        assert_eq!(parse_carrier_file_content("invalid"), None);
        assert_eq!(parse_carrier_file_content(""), None);
    }

    #[test]
    fn test_parse_link_speed_str() {
        assert_eq!(parse_link_speed_str("1000\n"), "1000 Mbps");
        assert_eq!(parse_link_speed_str("100"), "100 Mbps");
        assert_eq!(parse_link_speed_str("0"), "unknown");
        assert_eq!(parse_link_speed_str("-1"), "unknown");
        assert_eq!(parse_link_speed_str("invalid"), "unknown");
    }

    #[test]
    fn test_update_carrier_state_transitions() {
        let mut link_states = HashMap::new();
        let mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);

        // Initial insertion with carrier = true
        update_carrier_state(10, "eth0", mac, true, &mut link_states);
        assert_eq!(link_states.get(&10), Some(&("eth0".to_string(), mac, true)));

        // No transition (carrier = true again) -> remains true
        update_carrier_state(10, "eth0", mac, true, &mut link_states);
        assert_eq!(link_states.get(&10), Some(&("eth0".to_string(), mac, true)));

        // Transition to carrier = false
        update_carrier_state(10, "eth0", mac, false, &mut link_states);
        assert_eq!(
            link_states.get(&10),
            Some(&("eth0".to_string(), mac, false))
        );

        // Transition back to carrier = true
        update_carrier_state(10, "eth0", mac, true, &mut link_states);
        assert_eq!(link_states.get(&10), Some(&("eth0".to_string(), mac, true)));
    }

    #[test]
    fn test_parse_operstate_str() {
        assert_eq!(parse_operstate_str("up\n"), Some(true));
        assert_eq!(parse_operstate_str("up"), Some(true));
        assert_eq!(parse_operstate_str("down\n"), Some(false));
        assert_eq!(parse_operstate_str("lowerlayerdown"), Some(false));
        assert_eq!(parse_operstate_str("dormant"), Some(false));
        assert_eq!(parse_operstate_str("unknown"), None);
        assert_eq!(parse_operstate_str(""), None);
    }

    #[test]
    fn test_poll_interface_carrier_states_mock_reader() {
        let mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
        let mut iface = ManagedInterface::new("wan".to_string(), mac, vec![]);
        iface.active_index = Some(5);
        let interfaces = vec![iface];

        let mut link_states = HashMap::new();
        link_states.insert(5, ("wan".to_string(), mac, true));

        // Poll with reader reporting carrier down (false)
        poll_interface_carrier_states_with_reader(&interfaces, &mut link_states, |_| Some(false));
        assert_eq!(link_states.get(&5), Some(&("wan".to_string(), mac, false)));

        // Poll with reader reporting carrier restored (true)
        poll_interface_carrier_states_with_reader(&interfaces, &mut link_states, |_| Some(true));
        assert_eq!(link_states.get(&5), Some(&("wan".to_string(), mac, true)));

        // Poll with reader reporting None (driver error/missing) -> state unchanged
        poll_interface_carrier_states_with_reader(&interfaces, &mut link_states, |_| None);
        assert_eq!(link_states.get(&5), Some(&("wan".to_string(), mac, true)));
    }

    #[test]
    fn test_parse_link_attributes() {
        let attributes = vec![
            LinkAttribute::IfName("wan".to_string()),
            LinkAttribute::Address(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ];
        let (name, mac) = parse_link_attributes(attributes);
        assert_eq!(name, Some("wan".to_string()));
        assert_eq!(mac, Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)));
    }

    #[test]
    fn test_read_sysfs_net_attr_nonexistent() {
        assert_eq!(
            read_sysfs_net_attr("non_existent_device_12345", "speed"),
            None
        );
    }

    #[tokio::test]
    async fn test_managed_interface_creation_and_lifecycle() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mut iface = ManagedInterface::new("wan".to_string(), mac, Vec::new());
        assert_eq!(iface.name, "wan");
        assert_eq!(iface.mac, mac);
        assert_eq!(iface.active_index, None);
        assert!(iface.active_services.is_empty());

        iface.start_services().await;
        iface.stop_services().await;
    }

    #[tokio::test]
    async fn test_handle_del_link_resets_active_index() {
        let mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let mut iface = ManagedInterface::new("wan".to_string(), mac, Vec::new());
        iface.active_index = Some(42);

        // Deleting non-matching index does nothing
        handle_del_link(&mut iface, 99).await;
        assert_eq!(iface.active_index, Some(42));

        // Deleting matching index stops services and resets active_index
        handle_del_link(&mut iface, 42).await;
        assert_eq!(iface.active_index, None);
    }

    #[test]
    fn test_if_indextoname_nonexistent() {
        assert_eq!(if_indextoname(999999), None);
    }

    #[test]
    fn test_log_carrier_transition() {
        let mac = MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56);
        log_carrier_transition("eth0", mac, true);
        log_carrier_transition("eth0", mac, false);
    }
}
