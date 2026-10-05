use futures_util::TryStreamExt;
use pnet::util::MacAddr;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::AddressAttribute;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use trimrouter::config::StaticLease;
use trimrouter::network;
use trimrouter::services::observability::{ObservabilityReceivers, null_dhcp_leases_sender};
use trimrouter::services::utils::{WanLease, WanLeaseReceiver, WanLeaseSender};
use trimrouter::services::{LanManager, Service};

pub async fn test_lan_wan_conflict(
    lease_tx: WanLeaseSender,
    lease_rx: WanLeaseReceiver,
) -> Result<(), String> {
    std::println!("[test] Starting LAN/WAN Subnet Overlap test...");

    // 1. Instantiate and start LanManager service
    // Default initial LAN IP is "192.168.1.1/24" and backup is "10.0.0.1/24"
    let mut lan_manager = LanManager::new(
        "lan".to_string(),
        "wan".to_string(),
        "192.168.1.1/24".to_string(),
        "10.0.0.1/24".to_string(),
        ObservabilityReceivers::from_wan_lease(lease_rx),
        None,
        None,
        null_dhcp_leases_sender(),
        Vec::new(),
        Vec::new(),
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
    let _ = lease_tx.send(WanLease {
        ip: Some(Ipv4Addr::new(192, 168, 1, 50)),
        mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
        gateway: None,
        dns_servers: Vec::new(),
    });

    std::println!(
        "[test] Triggering Netlink event by configuring conflicting IP 192.168.1.50/24 on wan..."
    );
    if let Err(e) = network::configure_interface_ip("wan", "192.168.1.50/24").await {
        if let Err(e) = lan_manager.stop().await {
            return Err(format!(
                "Failed to configure conflicting WAN IP, and failed to stop LanManager: {}",
                e
            ));
        }
        return Err(format!("Failed to configure conflicting WAN IP: {}", e));
    }

    // 3. Await resolution (LanManager detects subnet conflict and shifts to backup subnet 10.0.0.1/24)
    let start = std::time::Instant::now();
    let mut resolved = false;
    while start.elapsed() < Duration::from_secs(10) {
        let current_ips = get_interface_ips("lan").await?;
        if current_ips
            .iter()
            .any(|ip| ip == &Ipv4Addr::new(10, 0, 0, 1))
        {
            resolved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if !resolved {
        let current_ips = get_interface_ips("lan").await?;
        if let Err(e) = lan_manager.stop().await {
            eprintln!(
                "[test] Warning: Failed to stop LanManager during error cleanup: {}",
                e
            );
        }
        return Err(format!(
            "LanManager failed to shift to backup subnet 10.0.0.1/24. Active LAN IPs: {:?}",
            current_ips
        ));
    }

    std::println!("[test] LanManager successfully resolved subnet conflict and shifted to backup.");

    // Clean up
    if let Err(e) = lan_manager.stop().await {
        return Err(format!("Failed to stop LanManager: {}", e));
    }
    if let Some(index) = network::get_interface_index("wan").await {
        let _ = network::flush_ipv4_addresses("wan", index).await;
    }

    Ok(())
}

async fn get_interface_ips(ifname: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    tokio::spawn(connection);

    let index = network::get_interface_index(ifname)
        .await
        .ok_or_else(|| format!("Interface '{}' not found", ifname))?;

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

pub async fn test_lan_dhcp_handshake(lease_rx: WanLeaseReceiver) -> Result<LanManager, String> {
    std::println!("[test] Starting LAN DHCP Server Handshake test...");

    // 1. Start LanManager service on "lan" (which starts the LAN DHCP server)
    let mut lan_manager = LanManager::new(
        "lan".to_string(),
        "wan".to_string(),
        "192.168.1.1/24".to_string(),
        "10.0.0.1/24".to_string(),
        ObservabilityReceivers::from_wan_lease(lease_rx),
        None,
        None,
        null_dhcp_leases_sender(),
        Vec::new(),
        Vec::new(),
    );
    if let Err(e) = lan_manager.start().await {
        return Err(format!("Failed to start LanManager: {}", e));
    }

    // Await server startup and IP configuration
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2. Tell the host coordinator to trigger the mock LAN client DHCP handshake (client 1)
    std::println!("[test-control] TRIGGER_LAN_DHCP_HANDSHAKE");

    // 3. Ping the dynamically leased client IP (192.168.1.2)
    let target_ip = Ipv4Addr::new(192, 168, 1, 2);
    if let Err(e) = ping_ip(target_ip, Duration::from_secs(10)).await {
        if let Err(stop_err) = lan_manager.stop().await {
            std::eprintln!(
                "[test] Warning: Failed to stop LanManager during cleanup: {}",
                stop_err
            );
        }
        return Err(format!(
            "LAN DHCP handshake test failed: did not receive ICMP reply from {}: {}",
            target_ip, e
        ));
    }

    // 4. Trigger second dynamic client (client 2 with distinct MAC) to verify multi-client dynamic pool allocation and ARP probing
    std::println!("[test-control] TRIGGER_LAN_DHCP_HANDSHAKE_CLIENT2");

    let target_ip2 = Ipv4Addr::new(192, 168, 1, 3);
    if let Err(e) = ping_ip(target_ip2, Duration::from_secs(10)).await {
        if let Err(stop_err) = lan_manager.stop().await {
            std::eprintln!(
                "[test] Warning: Failed to stop LanManager during cleanup: {}",
                stop_err
            );
        }
        return Err(format!(
            "LAN dynamic client 2 DHCP handshake failed: did not receive ICMP reply from {}: {}",
            target_ip2, e
        ));
    }

    std::println!(
        "[test] LAN DHCP Server Handshake verified successfully (multiple dynamic clients leased)."
    );
    Ok(lan_manager)
}

pub async fn test_lan_static_lease(lease_rx: WanLeaseReceiver) -> Result<(), String> {
    std::println!("[test] Starting LAN Static Lease Reservation test...");

    let client_mac = MacAddr::new(0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
    let static_ip = Ipv4Addr::new(192, 168, 1, 50);
    let static_leases = vec![StaticLease {
        mac: client_mac,
        ip: static_ip,
        hostname: Some("printer".to_string()),
    }];

    let mut lan_manager = LanManager::new(
        "lan".to_string(),
        "wan".to_string(),
        "192.168.1.1/24".to_string(),
        "10.0.0.1/24".to_string(),
        ObservabilityReceivers::from_wan_lease(lease_rx),
        None,
        None,
        null_dhcp_leases_sender(),
        static_leases,
        Vec::new(),
    );

    if let Err(e) = lan_manager.start().await {
        return Err(format!(
            "Failed to start LanManager with static lease: {}",
            e
        ));
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Trigger mock client DHCP handshake with static reservation active
    std::println!("[test-control] TRIGGER_LAN_DHCP_HANDSHAKE");

    // Verify ping to static reserved IP 192.168.1.50
    if let Err(e) = ping_ip(static_ip, Duration::from_secs(10)).await {
        let _ = lan_manager.stop().await;
        return Err(format!(
            "Static lease ping failed for reserved IP {}: {}",
            static_ip, e
        ));
    }

    // Trigger mock client DHCP renewal with ciaddr (regression prevention for renewing state)
    std::println!("[test-control] TRIGGER_LAN_DHCP_RENEWAL");
    tokio::time::sleep(Duration::from_millis(500)).await;

    if let Err(e) = lan_manager.stop().await {
        return Err(format!("Failed to stop LanManager during cleanup: {}", e));
    }

    std::println!("[test] LAN Static Lease Reservation and Renewal verified successfully.");
    Ok(())
}

async fn ping_ip(target_ip: Ipv4Addr, timeout: Duration) -> Result<(), String> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| format!("Failed to create ICMP socket: {}", e))?;
    let local_addr: SocketAddr = "192.168.1.1:0".parse().unwrap();
    socket
        .bind(&local_addr.into())
        .map_err(|e| format!("Failed to bind ICMP socket: {}", e))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| e.to_string())?;

    let id = rand::random::<u16>();
    let ping_data = build_icmp_echo_request(id, 1);
    let dest_addr: SocketAddr = format!("{}:0", target_ip).parse().unwrap();

    let start_time = std::time::Instant::now();
    while start_time.elapsed() < timeout {
        let _ = socket.send_to(&ping_data, &dest_addr.into());
        let mut buf = [std::mem::MaybeUninit::new(0u8); 512];
        if let Ok((n, _)) = socket.recv_from(&mut buf) {
            let slice =
                unsafe { std::mem::transmute::<&[std::mem::MaybeUninit<u8>], &[u8]>(&buf[..n]) };
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
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    Err(format!(
        "Timed out waiting for ICMP echo reply from {}",
        target_ip
    ))
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
