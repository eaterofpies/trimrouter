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

pub async fn test_conntrack_invalid_drop() -> Result<(), String> {
    std::println!("[test] Starting Firewall Conntrack Invalid Drop test...");

    // 1. Tell the host runner to trigger invalid conntrack packet injection
    std::println!("[test-control] TRIGGER_INVALID_CONNTRACK_TRAFFIC");

    // 2. Sleep to allow the host to inject and check for a drop
    tokio::time::sleep(Duration::from_secs(2)).await;

    std::println!("[test] Firewall conntrack invalid drop check completed.");
    Ok(())
}
