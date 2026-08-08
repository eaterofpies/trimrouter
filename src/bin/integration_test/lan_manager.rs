use futures_util::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::AddressAttribute;
use std::net::Ipv4Addr;
use std::time::Duration;
use trimrouter::network;
use trimrouter::services::utils::SharedWanLease;
use trimrouter::services::{LanManager, Service};

pub async fn test_lan_wan_conflict(lease_state: SharedWanLease) -> Result<(), String> {
    std::println!("[test] Starting LAN/WAN Subnet Overlap test...");

    // 1. Instantiate and start LanManager service
    // Default initial LAN IP is "192.168.1.1/24" and backup is "10.0.0.1/24"
    let mut lan_manager = LanManager::new(
        "lan".to_string(),
        "192.168.1.1/24".to_string(),
        "10.0.0.1/24".to_string(),
        lease_state.clone(),
    );

    if let Err(e) = lan_manager.start().await {
        return Err(format!("Failed to start LanManager: {}", e));
    }

    // Await initial configuration (lan gets 192.168.1.1)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify LAN IP is initially 192.168.1.1
    let initial_ips = get_interface_ips("lan").await?;
    if !initial_ips
        .iter()
        .any(|ip| ip == &Ipv4Addr::new(192, 168, 1, 1))
    {
        if let Err(e) = lan_manager.stop().await {
            return Err(format!(
                "LAN IP 192.168.1.1 not found, and failed to stop LanManager: {}",
                e
            ));
        }
        return Err(format!(
            "Initial LAN IP 192.168.1.1 not found. Active IPs: {:?}",
            initial_ips
        ));
    }

    // 2. Simulate conflict: Set the WAN IP lease state AND configure a conflicting WAN IP on the interface
    // to trigger the Netlink address update event.
    {
        let mut lease = lease_state.lock().unwrap();
        lease.ip = Some(Ipv4Addr::new(192, 168, 1, 50));
        lease.mask = Some(Ipv4Addr::new(255, 255, 255, 0));
    }

    std::println!(
        "[test] Triggering Netlink event by configuring conflicting IP 192.168.1.50/24 on wan..."
    );
    if let Err(e) = network::configure_interface_ip("wan", "192.168.1.50/24").await {
        if let Err(e) = lan_manager.stop().await {
            return Err(format!(
                "Failed to set conflicting IP on wan, and failed to stop LanManager: {}",
                e
            ));
        }
        return Err(format!("Failed to set conflicting IP on wan: {}", e));
    }

    // 3. Await LAN subnet shift to backup (10.0.0.1/24)
    let start = std::time::Instant::now();
    let mut shifted = false;
    while start.elapsed() < Duration::from_secs(10) {
        let current_ips = get_interface_ips("lan").await?;
        if current_ips
            .iter()
            .any(|ip| ip == &Ipv4Addr::new(10, 0, 0, 1))
            && !current_ips
                .iter()
                .any(|ip| ip == &Ipv4Addr::new(192, 168, 1, 1))
        {
            shifted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if let Err(e) = lan_manager.stop().await {
        return Err(format!("Failed to stop LanManager: {}", e));
    }

    if !shifted {
        let current_ips = get_interface_ips("lan").await?;
        return Err(format!(
            "Subnet shift failed. Lan interface IPs: {:?}",
            current_ips
        ));
    }

    std::println!("[test] Subnet overlap resolved successfully: LAN shifted to 10.0.0.1.");
    Ok(())
}

async fn get_interface_ips(name: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    tokio::spawn(connection);

    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let link = match links.try_next().await {
        Ok(Some(l)) => l,
        Ok(None) => return Err(format!("Interface {} not found", name)),
        Err(e) => return Err(e.to_string()),
    };
    let index = link.header.index;

    let mut ips = Vec::new();
    let mut addrs = handle.address().get().execute();
    while let Ok(Some(addr_msg)) = addrs.try_next().await {
        if addr_msg.header.index == index && matches!(addr_msg.header.family, AddressFamily::Inet) {
            for attr in addr_msg.attributes {
                if let AddressAttribute::Local(std::net::IpAddr::V4(ip)) = attr {
                    ips.push(ip);
                }
            }
        }
    }
    Ok(ips)
}
