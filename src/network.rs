use pnet::util::MacAddr;
use rtnetlink::Handle;
use std::net::IpAddr;
use std::str::FromStr;

pub const WAN_INTERFACE: &str = "wan";
pub const LAN_INTERFACE: &str = "lan";

pub async fn configure_network(
    wan_iface: &str,
    lan_iface: &str,
    lan_ip_cidr: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Enable IPv4 Packet Forwarding
    println!("[network] Enabling IPv4 forwarding...");
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;

    // 2. Open rtnetlink connection
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // 3. Configure Loopback ('lo') (Link UP only, kernel auto-assigns 127.0.0.1/8)
    println!("[network] Configuring loopback interface (lo)...");
    if let Err(e) = configure_interface(&handle, "lo", None).await {
        eprintln!("[network] Warning: Failed to configure loopback: {}", e);
    }

    // 4. Configure LAN interface
    println!(
        "[network] Configuring LAN interface ({}) with IP {}...",
        lan_iface, lan_ip_cidr
    );
    configure_interface(&handle, lan_iface, Some(lan_ip_cidr)).await?;

    // 5. Configure WAN interface (Link UP only)
    println!(
        "[network] Configuring WAN interface ({}) link UP...",
        wan_iface
    );
    configure_interface(&handle, wan_iface, None).await?;

    Ok(())
}

async fn configure_interface(
    handle: &Handle,
    name: &str,
    ip_cidr: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get link index by name
    use futures_util::TryStreamExt;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Err(format!("Interface {} not found", name).into()),
        Err(e) => return Err(e.into()),
    };
    let index = link.header.index;

    // Set link state to UP
    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;

    // If an IP/CIDR is specified, assign it to the link index
    if let Some(cidr) = ip_cidr {
        let parts: Vec<&str> = cidr.split('/').collect();
        let ip_str = parts[0];
        let prefix = if parts.len() > 1 {
            parts[1].parse::<u8>()?
        } else {
            24
        };
        let ip = IpAddr::from_str(ip_str)?;

        // Attempt to assign the address. If it's already assigned (EEXIST), ignore the error.
        match handle.address().add(index, ip, prefix).execute().await {
            Ok(_) => println!("[network] Successfully assigned {} to {}", cidr, name),
            Err(rtnetlink::Error::NetlinkError(msg)) if msg.code.map(|c| c.get()) == Some(-17) => {
                // Address already exists (EEXIST), ignore silently
            }
            Err(e) => {
                println!(
                    "[network] Address assignment message for {} ({}): {}",
                    name, cidr, e
                );
            }
        }
    }

    Ok(())
}

fn extract_link_attribute(
    nla: rtnetlink::packet_route::link::LinkAttribute,
    name: &mut Option<String>,
    mac: &mut Option<Vec<u8>>,
) {
    match nla {
        rtnetlink::packet_route::link::LinkAttribute::IfName(n) => *name = Some(n),
        rtnetlink::packet_route::link::LinkAttribute::Address(addr) => *mac = Some(addr),
        _ => {}
    }
}

fn parse_link_info(
    link: rtnetlink::packet_route::link::LinkMessage,
) -> Option<(u32, String, Vec<u8>)> {
    let index = link.header.index;
    let mut name = None;
    let mut mac = None;
    for nla in link.attributes {
        extract_link_attribute(nla, &mut name, &mut mac);
    }
    let n = name?;
    let m = mac?;
    Some((index, n, m))
}

fn process_link_message(
    link: rtnetlink::packet_route::link::LinkMessage,
    wan_bytes: &[u8],
    lan_bytes: &[u8],
    interfaces: &mut Vec<(u32, String, Vec<u8>)>,
) -> (bool, bool) {
    let mut found_wan = false;
    let mut found_lan = false;
    if let Some((index, n, m)) = parse_link_info(link) {
        if m == wan_bytes[..] {
            found_wan = true;
        }
        if m == lan_bytes[..] {
            found_lan = true;
        }
        interfaces.push((index, n, m));
    }
    (found_wan, found_lan)
}

async fn collect_interfaces(
    handle: &rtnetlink::Handle,
    wan_bytes: &[u8],
    lan_bytes: &[u8],
    interfaces: &mut Vec<(u32, String, Vec<u8>)>,
) -> Result<(bool, bool), rtnetlink::Error> {
    use futures_util::TryStreamExt;
    let mut links = handle.link().get().execute();
    let mut found_wan = false;
    let mut found_lan = false;

    while let Some(link) = links.try_next().await? {
        let (wan, lan) = process_link_message(link, wan_bytes, lan_bytes, interfaces);
        found_wan |= wan;
        found_lan |= lan;
    }
    Ok((found_wan, found_lan))
}

async fn rename_interface_to_wan(
    interfaces: &[(u32, String, Vec<u8>)],
    chosen_index: u32,
    chosen_name: &str,
    wan_mac: &str,
    handle: &rtnetlink::Handle,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(other) = interfaces
        .iter()
        .find(|(idx, name, _)| name == WAN_INTERFACE && *idx != chosen_index)
    {
        let temp_name = format!("{}_old_{}", WAN_INTERFACE, other.0);
        println!(
            "[network] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
            WAN_INTERFACE, other.0, temp_name
        );
        let msg_down = rtnetlink::LinkUnspec::new_with_index(other.0).down().build();
        handle.link().change(msg_down).execute().await?;
        let msg_name = rtnetlink::LinkUnspec::new_with_index(other.0)
            .name(temp_name)
            .build();
        handle.link().change(msg_name).execute().await?;
        let msg_up = rtnetlink::LinkUnspec::new_with_index(other.0).up().build();
        handle.link().change(msg_up).execute().await?;
    }

    println!(
        "[network] Renaming interface {} (index {}) to {} based on MAC {}",
        chosen_name, chosen_index, WAN_INTERFACE, wan_mac
    );
    let msg_down = rtnetlink::LinkUnspec::new_with_index(chosen_index).down().build();
    handle.link().change(msg_down).execute().await?;
    let msg_name = rtnetlink::LinkUnspec::new_with_index(chosen_index)
        .name(WAN_INTERFACE.to_string())
        .build();
    handle.link().change(msg_name).execute().await?;
    let msg_up = rtnetlink::LinkUnspec::new_with_index(chosen_index).up().build();
    handle.link().change(msg_up).execute().await?;
    Ok(())
}

async fn resolve_and_rename_wan(
    interfaces: &[(u32, String, Vec<u8>)],
    wan_mac: &str,
    handle: &rtnetlink::Handle,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_mac = MacAddr::from_str(wan_mac)?;
    let target_bytes = target_mac.octets();

    let mut candidates: Vec<_> = interfaces
        .iter()
        .filter(|(_, _, m)| m == &target_bytes[..])
        .cloned()
        .collect();

    if candidates.is_empty() {
        return Ok(());
    }

    candidates.sort_by_key(|c| c.0);
    let chosen = match candidates.last() {
        Some(c) => c,
        None => return Ok(()),
    };
    let chosen_index = chosen.0;
    let chosen_name = &chosen.1;

    if candidates.len() > 1 {
        for old in &candidates[..candidates.len() - 1] {
            eprintln!(
                "[network] WARNING: Multiple interfaces found with MAC address {}! The newer interface {} (index {}) takes precedence over {} (index {}).",
                wan_mac, chosen_name, chosen_index, old.1, old.0
            );
        }
    }

    if chosen_name != WAN_INTERFACE {
        rename_interface_to_wan(interfaces, chosen_index, chosen_name, wan_mac, handle).await?;
    }

    Ok(())
}

async fn rename_interface_to_lan(
    interfaces: &[(u32, String, Vec<u8>)],
    chosen_index: u32,
    chosen_name: &str,
    lan_mac: &str,
    handle: &rtnetlink::Handle,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(other) = interfaces
        .iter()
        .find(|(idx, name, _)| name == LAN_INTERFACE && *idx != chosen_index)
    {
        let temp_name = format!("{}_old_{}", LAN_INTERFACE, other.0);
        println!(
            "[network] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
            LAN_INTERFACE, other.0, temp_name
        );
        let msg_down = rtnetlink::LinkUnspec::new_with_index(other.0).down().build();
        handle.link().change(msg_down).execute().await?;
        let msg_name = rtnetlink::LinkUnspec::new_with_index(other.0)
            .name(temp_name)
            .build();
        handle.link().change(msg_name).execute().await?;
        let msg_up = rtnetlink::LinkUnspec::new_with_index(other.0).up().build();
        handle.link().change(msg_up).execute().await?;
    }

    println!(
        "[network] Renaming interface {} (index {}) to {} based on MAC {}",
        chosen_name, chosen_index, LAN_INTERFACE, lan_mac
    );
    let msg_down = rtnetlink::LinkUnspec::new_with_index(chosen_index).down().build();
    handle.link().change(msg_down).execute().await?;
    let msg_name = rtnetlink::LinkUnspec::new_with_index(chosen_index)
        .name(LAN_INTERFACE.to_string())
        .build();
    handle.link().change(msg_name).execute().await?;
    let msg_up = rtnetlink::LinkUnspec::new_with_index(chosen_index).up().build();
    handle.link().change(msg_up).execute().await?;
    Ok(())
}

async fn resolve_and_rename_lan(
    interfaces: &[(u32, String, Vec<u8>)],
    lan_mac: &str,
    handle: &rtnetlink::Handle,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_mac = MacAddr::from_str(lan_mac)?;
    let target_bytes = target_mac.octets();

    let mut candidates: Vec<_> = interfaces
        .iter()
        .filter(|(_, _, m)| m == &target_bytes[..])
        .cloned()
        .collect();

    if candidates.is_empty() {
        return Ok(());
    }

    candidates.sort_by_key(|c| c.0);
    let chosen = match candidates.last() {
        Some(c) => c,
        None => return Ok(()),
    };
    let chosen_index = chosen.0;
    let chosen_name = &chosen.1;

    if candidates.len() > 1 {
        for old in &candidates[..candidates.len() - 1] {
            eprintln!(
                "[network] WARNING: Multiple interfaces found with MAC address {}! The newer interface {} (index {}) takes precedence over {} (index {}).",
                lan_mac, chosen_name, chosen_index, old.1, old.0
            );
        }
    }

    if chosen_name != LAN_INTERFACE {
        rename_interface_to_lan(interfaces, chosen_index, chosen_name, lan_mac, handle).await?;
    }

    Ok(())
}

pub async fn resolve_and_rename_interfaces(
    wan_mac: &str,
    lan_mac: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_wan_mac = MacAddr::from_str(wan_mac)
        .map_err(|_| format!("Invalid WAN MAC address format: {}", wan_mac))?;
    let target_lan_mac = MacAddr::from_str(lan_mac)
        .map_err(|_| format!("Invalid LAN MAC address format: {}", lan_mac))?;

    let wan_bytes = target_wan_mac.octets();
    let lan_bytes = target_lan_mac.octets();

    println!(
        "[network] Waiting for interfaces to appear via MAC addresses (WAN: {}, LAN: {})...",
        wan_mac, lan_mac
    );

    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(10);

    let mut interfaces = Vec::new();

    loop {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        interfaces.clear();
        let (found_wan, found_lan) = collect_interfaces(&handle, &wan_bytes[..], &lan_bytes[..], &mut interfaces).await?;

        if (found_wan && found_lan) || start_time.elapsed() >= timeout {
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // 2. Resolve WAN
    resolve_and_rename_wan(&interfaces, wan_mac, &handle).await?;

    // 3. Resolve LAN
    resolve_and_rename_lan(&interfaces, lan_mac, &handle).await?;

    Ok(())
}

pub async fn ensure_interface_up_and_configured(
    name: &str,
    ip_cidr: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    use futures_util::TryStreamExt;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Ok(false), // Link does not exist yet (e.g. unplugged)
        Err(e) => return Err(e.into()),
    };
    let index = link.header.index;

    // Check if the link is UP and already has the correct IP address
    let flags = link.header.flags;
    let is_up = flags.contains(rtnetlink::packet_route::link::LinkFlags::Up);

    let parts: Vec<&str> = ip_cidr.split('/').collect();
    let ip_str = parts[0];
    let expected_ip = std::net::IpAddr::from_str(ip_str)?;
    let expected_prefix = if parts.len() > 1 { parts[1].parse::<u8>()? } else { 24 };

    // Check if the address is already assigned
    let mut already_configured = false;
    let mut addrs = handle.address().get().execute();
    while let Some(addr_msg) = addrs.try_next().await? {
        if addr_msg.header.index == index {
            for attr in addr_msg.attributes {
                if let rtnetlink::packet_route::address::AddressAttribute::Local(ip) = attr
                    && ip == expected_ip
                    && addr_msg.header.prefix_len == expected_prefix
                {
                    already_configured = true;
                    break;
                }
            }
        }
    }

    if is_up && already_configured {
        return Ok(true); // Already fully configured and UP
    }

    // Set link state to UP
    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;

    // Attempt to assign the address. If it's already assigned (EEXIST), ignore the error.
    match handle.address().add(index, expected_ip, expected_prefix).execute().await {
        Ok(_) => println!("[network] Successfully assigned {} to {}", ip_cidr, name),
        Err(rtnetlink::Error::NetlinkError(msg)) if msg.code.map(|c| c.get()) == Some(-17) => {
            // Address already exists (EEXIST), ignore silently
        }
        Err(e) => {
            println!(
                "[network] Address assignment message for {} ({}): {}",
                name, ip_cidr, e
            );
        }
    }

    Ok(true)
}

pub async fn ensure_interface_up(
    name: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    use futures_util::TryStreamExt;
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Ok(false), // Link does not exist yet (e.g. unplugged)
        Err(e) => return Err(e.into()),
    };
    let index = link.header.index;
    let flags = link.header.flags;
    let is_up = flags.contains(rtnetlink::packet_route::link::LinkFlags::Up);

    if is_up {
        return Ok(true);
    }

    let message = rtnetlink::LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;
    println!("[network] Successfully set interface {} link state to UP", name);
    Ok(true)
}

