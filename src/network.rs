use crate::error::RouterError;
use futures_util::TryStreamExt;
use ipnet::Ipv4Net;
use log::{debug, info, warn};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::LinkFlags;
use rtnetlink::{Error as NetlinkError, Handle, LinkUnspec};
use std::fs;
use std::net::IpAddr;
use std::str::FromStr;

pub const WAN_INTERFACE: &str = "wan";
pub const LAN_INTERFACE: &str = "lan";

pub async fn configure_network_init() -> Result<(), RouterError> {
    // 1. Enable IPv4 Packet Forwarding
    debug!("[network] Enabling IPv4 forwarding...");
    fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;

    // 2. Open rtnetlink connection
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // 3. Configure Loopback ('lo') (Link UP only, kernel auto-assigns 127.0.0.1/8)
    debug!("[network] Configuring loopback interface (lo)...");
    if let Err(e) = configure_interface(&handle, "lo", None).await {
        warn!("[network] Warning: Failed to configure loopback: {}", e);
    }

    Ok(())
}

async fn configure_interface(
    handle: &Handle,
    name: &str,
    ip_cidr: Option<&str>,
) -> Result<(), RouterError> {
    // Get link index by name
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Err(RouterError::InterfaceNotFound(name.to_string())),
        Err(e) => return Err(e.into()),
    };
    let index = link.header.index;

    // Set link state to UP
    let message = LinkUnspec::new_with_index(index).up().build();
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
            Ok(_) => info!("[network] Successfully assigned {} to {}", cidr, name),
            Err(NetlinkError::NetlinkError(msg)) if msg.code.map(|c| c.get()) == Some(-17) => {
                // Address already exists (EEXIST), ignore silently
            }
            Err(e) => {
                warn!(
                    "[network] Address assignment message for {} ({}): {}",
                    name, cidr, e
                );
            }
        }
    }

    Ok(())
}

pub async fn configure_interface_ip(name: &str, ip_cidr: &str) -> Result<bool, RouterError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(link) = links.try_next().await? else {
        return Ok(false); // Link does not exist yet (e.g. unplugged)
    };
    let index = link.header.index;

    // Parse target IP/subnet
    let expected_net = ip_cidr.parse::<Ipv4Net>()?;
    let expected_ip = IpAddr::V4(expected_net.addr());
    let expected_prefix = expected_net.prefix_len();

    // Flush stale IPv4 addresses and check if the expected one is already set
    let mut already_configured = false;
    let mut addrs = handle.address().get().execute();
    while let Some(addr_msg) = addrs.try_next().await? {
        if addr_msg.header.index == index && matches!(addr_msg.header.family, AddressFamily::Inet) {
            let is_match = addr_msg.attributes.iter().any(|attr| {
                if let AddressAttribute::Local(ip) = attr {
                    *ip == expected_ip && addr_msg.header.prefix_len == expected_prefix
                } else {
                    false
                }
            });

            if is_match {
                already_configured = true;
            } else {
                debug!(
                    "[network] Deleting stale IP address from interface {}: prefix_len={}",
                    name, addr_msg.header.prefix_len
                );
                let _ = handle.address().del(addr_msg).execute().await;
            }
        }
    }

    if already_configured {
        return Ok(true); // Already fully configured
    }

    // Assign the address if not already present
    if !already_configured {
        match handle
            .address()
            .add(index, expected_ip, expected_prefix)
            .execute()
            .await
        {
            Ok(_) => info!("[network] Successfully assigned {} to {}", ip_cidr, name),
            Err(NetlinkError::NetlinkError(msg)) if msg.code.map(|c| c.get()) == Some(-17) => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(true)
}

pub async fn ensure_interface_up(name: &str) -> Result<bool, RouterError> {
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let Some(link) = links.try_next().await? else {
        return Ok(false); // Link does not exist yet (e.g. unplugged)
    };
    let index = link.header.index;
    let flags = link.header.flags;
    let is_up = flags.contains(LinkFlags::Up);

    if is_up {
        return Ok(true);
    }

    let message = LinkUnspec::new_with_index(index).up().build();
    handle.link().change(message).execute().await?;
    info!(
        "[network] Successfully set interface {} link state to UP",
        name
    );
    Ok(true)
}

pub async fn get_interface_index(name: &str) -> Option<u32> {
    let (connection, handle, _) = rtnetlink::new_connection().ok()?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = links.try_next().await.ok()??;
    Some(link.header.index)
}
