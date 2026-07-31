use rtnetlink::Handle;
use std::net::IpAddr;
use std::str::FromStr;

pub const WAN_INTERFACE: &str = "wan";
pub const LAN_INTERFACE: &str = "lan";

pub async fn configure_network_init() -> Result<(), Box<dyn std::error::Error>> {
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
    let expected_prefix = if parts.len() > 1 {
        parts[1].parse::<u8>()?
    } else {
        24
    };

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
    match handle
        .address()
        .add(index, expected_ip, expected_prefix)
        .execute()
        .await
    {
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

pub async fn ensure_interface_up(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
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
    println!(
        "[network] Successfully set interface {} link state to UP",
        name
    );
    Ok(true)
}
