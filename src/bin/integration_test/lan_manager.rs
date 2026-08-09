use futures_util::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::AddressAttribute;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
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

pub async fn test_lan_dhcp_handshake(lease_state: SharedWanLease) -> Result<LanManager, String> {
    std::println!("[test] Starting LAN DHCP Server Handshake test...");

    // 1. Start LanManager service on "lan" (which starts the LAN DHCP server)
    let mut lan_manager = LanManager::new(
        "lan".to_string(),
        "192.168.1.1/24".to_string(),
        "10.0.0.1/24".to_string(),
        lease_state.clone(),
    );
    if let Err(e) = lan_manager.start().await {
        return Err(format!("Failed to start LanManager: {}", e));
    }

    // Await server startup and IP configuration
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2. Tell the host coordinator to trigger the mock LAN client DHCP handshake
    std::println!("[test-control] TRIGGER_LAN_DHCP_HANDSHAKE");

    // 3. Open raw ICMP socket to ping the LAN client once it gets its IP (192.168.1.2)
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| format!("Failed to create ICMP socket: {}", e))?;
    let local_addr: SocketAddr = "192.168.1.1:0".parse().unwrap();
    socket
        .bind(&local_addr.into())
        .map_err(|e| format!("Failed to bind ICMP socket: {}", e))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;

    let target_ip = Ipv4Addr::new(192, 168, 1, 2);
    let id = 0x5432u16;
    let ping_data = build_icmp_echo_request(id, 1);
    let dest_addr: SocketAddr = format!("{}:0", target_ip).parse().unwrap();

    let mut success = false;
    let start_time = std::time::Instant::now();

    // Loop for up to 10 seconds trying to ping
    while start_time.elapsed() < Duration::from_secs(10) {
        // Send ping
        let _ = socket.send_to(&ping_data, &dest_addr.into());

        // Wait for pong
        let mut buf = [std::mem::MaybeUninit::new(0u8); 512];
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            // Safe because the first n bytes are guaranteed to be initialized by recv_from
            let slice =
                unsafe { std::mem::transmute::<&[std::mem::MaybeUninit<u8>], &[u8]>(&buf[..n]) };
            // Check both: with IP header (index 20) or without IP header (index 0)
            let (icmp_type, icmp_code, recv_id) = if n >= 28 && slice[20] == 0 && slice[21] == 0 {
                (
                    slice[20],
                    slice[21],
                    ((slice[24] as u16) << 8) | (slice[25] as u16),
                )
            } else if n >= 8 {
                (
                    slice[0],
                    slice[1],
                    ((slice[4] as u16) << 8) | (slice[5] as u16),
                )
            } else {
                (255, 255, 0)
            };

            if icmp_type == 0 && icmp_code == 0 && recv_id == id {
                success = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if !success {
        if let Err(e) = lan_manager.stop().await {
            std::eprintln!(
                "[test] Warning: Failed to stop LanManager during cleanup: {}",
                e
            );
        }
        return Err(
            "LAN DHCP handshake test failed: did not receive ICMP reply from leased client"
                .to_string(),
        );
    }

    std::println!("[test] LAN DHCP Server Handshake verified successfully.");
    Ok(lan_manager)
}

fn build_icmp_echo_request(id: u16, seq: u16) -> Vec<u8> {
    let mut header = vec![0u8; 8];
    header[0] = 8; // Type = 8 (Echo Request)
    header[1] = 0; // Code = 0
    header[4] = (id >> 8) as u8;
    header[5] = id as u8;
    header[6] = (seq >> 8) as u8;
    header[7] = seq as u8;

    // Checksum calculation
    let mut sum = 0u32;
    for i in (0..8).step_by(2) {
        let val = ((header[i] as u32) << 8) | (header[i + 1] as u32);
        sum += val;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    header[2] = (checksum >> 8) as u8;
    header[3] = checksum as u8;
    header
}
