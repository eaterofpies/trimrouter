use std::net::UdpSocket;
use std::time::Duration;

pub async fn test_nat_routing() -> Result<(), String> {
    std::println!("[test] Starting Forwarded NAT Routing test...");

    // 1. Bind to UDP port 23457 to receive verification from the host
    let socket = UdpSocket::bind("192.168.1.1:23457").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;

    // 2. Trigger the host test coordinator
    std::println!("[test-control] TRIGGER_FORWARDED_NAT_TEST");

    // 3. Await verification packet from the host
    let mut buf = [0u8; 512];
    let (amt, _src) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("Timed out waiting for forwarded NAT verification: {}", e))?;

    if &buf[..amt] == b"FORWARDED_NAT_OK" {
        std::println!("[test] NAT Masquerading verified successfully.");
        Ok(())
    } else {
        Err(format!(
            "Received invalid forwarded NAT verification payload: {:?}",
            String::from_utf8_lossy(&buf[..amt])
        ))
    }
}

pub async fn test_firewall_wan_drop() -> Result<(), String> {
    std::println!("[test] Starting Firewall WAN Drop test...");

    // 1. Tell the host runner to trigger unsolicited WAN traffic to our WAN IP
    std::println!("[test-control] TRIGGER_UNSOLICITED_WAN_TRAFFIC");

    // 2. Sleep to allow the host to inject and check for a drop
    tokio::time::sleep(Duration::from_secs(2)).await;

    std::println!("[test] Firewall WAN drop check completed.");
    Ok(())
}

pub async fn test_dnat_port_forwarding() -> Result<(), String> {
    std::println!("[test] Starting DNAT Port Forwarding test...");

    // 1. Bind to UDP port 23458 to receive verification from the LAN mock
    let socket = UdpSocket::bind("192.168.1.1:23458").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;

    // 2. Trigger the host test coordinator to send an inbound packet on WAN port 28080
    std::println!("[test-control] TRIGGER_PORT_FORWARDING_TEST");

    // 3. Await verification packet from the LAN client
    let mut buf = [0u8; 512];
    let (amt, _src) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("Timed out waiting for port forwarding verification: {}", e))?;

    if &buf[..amt] == b"PORT_FORWARDING_OK" {
        std::println!("[test] Inbound DNAT port forwarding verified successfully.");
        Ok(())
    } else {
        Err(format!(
            "Received invalid port forwarding verification payload: {:?}",
            String::from_utf8_lossy(&buf[..amt])
        ))
    }
}

pub async fn test_conntrack_invalid_drop() -> Result<(), String> {
    std::println!("[test] Starting Firewall Conntrack Invalid Drop test...");

    // 1. Tell the host runner to trigger invalid conntrack packet injection
    std::println!("[test-control] TRIGGER_INVALID_CONNTRACK_TRAFFIC");

    // 2. Sleep to allow the host to inject and check for a drop
    tokio::time::sleep(Duration::from_secs(2)).await;

    std::println!("[test] Firewall conntrack invalid drop check completed.");
    Ok(())
}

const ANTI_SPOOFING_TEST_PORT: u16 = 23459;

pub async fn test_anti_spoofing_wan_drop() -> Result<(), String> {
    std::println!("[test] Starting Anti-Spoofing Reverse Path Filtering WAN Drop test...");

    // 1. Bind to UDP port 23459 on all interfaces to verify no spoofed packet arrives
    let bind_addr = format!("0.0.0.0:{}", ANTI_SPOOFING_TEST_PORT);
    let socket = UdpSocket::bind(&bind_addr).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .map_err(|e| e.to_string())?;

    // 2. Tell the host runner to inject a packet on WAN with a spoofed internal LAN source IP
    std::println!("[test-control] TRIGGER_SPOOFED_INTERNAL_WAN_TRAFFIC");

    // 3. Verify no packet is delivered (dropped by strict rp_filter in kernel)
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((amt, src)) => Err(format!(
            "Anti-spoofing failure: Received spoofed packet from {} ({} bytes: {:?})",
            src,
            amt,
            String::from_utf8_lossy(&buf[..amt])
        )),
        Err(ref e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            std::println!(
                "[test] Anti-spoofing check completed: Spoofed internal packet was dropped."
            );
            Ok(())
        }
        Err(e) => Err(format!(
            "Socket read error during anti-spoofing test: {}",
            e
        )),
    }
}
