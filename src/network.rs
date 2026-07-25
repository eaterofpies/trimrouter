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

pub async fn resolve_and_rename_interfaces(
    wan_mac: &str,
    lan_mac: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // 1. Gather all interfaces
    use futures_util::TryStreamExt;
    let mut links = handle.link().get().execute();
    let mut interfaces = Vec::new();
    while let Some(link) = links.try_next().await? {
        let index = link.header.index;
        let mut name = None;
        let mut mac = None;
        for nla in link.attributes {
            match nla {
                rtnetlink::packet_route::link::LinkAttribute::IfName(n) => name = Some(n),
                rtnetlink::packet_route::link::LinkAttribute::Address(addr) => mac = Some(addr),
                _ => {}
            }
        }
        if let (Some(n), Some(m)) = (name, mac) {
            interfaces.push((index, n, m));
        }
    }

    // 2. Resolve WAN
    {
        let target_mac = match MacAddr::from_str(wan_mac) {
            Ok(m) => m,
            Err(_) => return Err(format!("Invalid MAC address format: {}", wan_mac).into()),
        };
        let target_bytes = target_mac.octets();

        let mut candidates: Vec<_> = interfaces
            .iter()
            .filter(|(_, _, m)| m == &target_bytes[..])
            .cloned()
            .collect();

        if !candidates.is_empty() {
            candidates.sort_by_key(|c| c.0);
            let chosen = candidates.last().unwrap();
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
                if let Some(other) = interfaces
                    .iter()
                    .find(|(idx, name, _)| name == WAN_INTERFACE && *idx != chosen_index)
                {
                    let temp_name = format!("{}_old_{}", WAN_INTERFACE, other.0);
                    println!(
                        "[network] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
                        WAN_INTERFACE, other.0, temp_name
                    );
                    let msg_down = rtnetlink::LinkUnspec::new_with_index(other.0)
                        .down()
                        .build();
                    let _ = handle.link().change(msg_down).execute().await;
                    let msg_name = rtnetlink::LinkUnspec::new_with_index(other.0)
                        .name(temp_name)
                        .build();
                    let _ = handle.link().change(msg_name).execute().await;
                    let msg_up = rtnetlink::LinkUnspec::new_with_index(other.0).up().build();
                    let _ = handle.link().change(msg_up).execute().await;
                }

                println!(
                    "[network] Renaming interface {} (index {}) to {} based on MAC {}",
                    chosen_name, chosen_index, WAN_INTERFACE, wan_mac
                );
                let msg_down = rtnetlink::LinkUnspec::new_with_index(chosen_index)
                    .down()
                    .build();
                handle.link().change(msg_down).execute().await?;
                let msg_name = rtnetlink::LinkUnspec::new_with_index(chosen_index)
                    .name(WAN_INTERFACE.to_string())
                    .build();
                handle.link().change(msg_name).execute().await?;
                let msg_up = rtnetlink::LinkUnspec::new_with_index(chosen_index)
                    .up()
                    .build();
                handle.link().change(msg_up).execute().await?;
            }
        }
    }

    // 3. Resolve LAN
    {
        let target_mac = match MacAddr::from_str(lan_mac) {
            Ok(m) => m,
            Err(_) => return Err(format!("Invalid MAC address format: {}", lan_mac).into()),
        };
        let target_bytes = target_mac.octets();

        let mut candidates: Vec<_> = interfaces
            .iter()
            .filter(|(_, _, m)| m == &target_bytes[..])
            .cloned()
            .collect();

        if !candidates.is_empty() {
            candidates.sort_by_key(|c| c.0);
            let chosen = candidates.last().unwrap();
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
                if let Some(other) = interfaces
                    .iter()
                    .find(|(idx, name, _)| name == LAN_INTERFACE && *idx != chosen_index)
                {
                    let temp_name = format!("{}_old_{}", LAN_INTERFACE, other.0);
                    println!(
                        "[network] Interface name collision: renaming existing interface {} (index {}) to {} to free up the name",
                        LAN_INTERFACE, other.0, temp_name
                    );
                    let msg_down = rtnetlink::LinkUnspec::new_with_index(other.0)
                        .down()
                        .build();
                    let _ = handle.link().change(msg_down).execute().await;
                    let msg_name = rtnetlink::LinkUnspec::new_with_index(other.0)
                        .name(temp_name)
                        .build();
                    let _ = handle.link().change(msg_name).execute().await;
                    let msg_up = rtnetlink::LinkUnspec::new_with_index(other.0).up().build();
                    let _ = handle.link().change(msg_up).execute().await;
                }

                println!(
                    "[network] Renaming interface {} (index {}) to {} based on MAC {}",
                    chosen_name, chosen_index, LAN_INTERFACE, lan_mac
                );
                let msg_down = rtnetlink::LinkUnspec::new_with_index(chosen_index)
                    .down()
                    .build();
                handle.link().change(msg_down).execute().await?;
                let msg_name = rtnetlink::LinkUnspec::new_with_index(chosen_index)
                    .name(LAN_INTERFACE.to_string())
                    .build();
                handle.link().change(msg_name).execute().await?;
                let msg_up = rtnetlink::LinkUnspec::new_with_index(chosen_index)
                    .up()
                    .build();
                handle.link().change(msg_up).execute().await?;
            }
        }
    }

    Ok(())
}
