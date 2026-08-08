use std::net::UdpSocket;
use std::time::Duration;

const NAT_TEST_PORT: u16 = 23456;

pub async fn test_nat_routing() -> Result<(), String> {
    std::println!("[test] Starting NAT Routing test...");

    // 1. Bind a UDP socket to the LAN IP address 192.168.1.1
    let bind_addr = format!("192.168.1.1:{}", NAT_TEST_PORT);
    let socket = UdpSocket::bind(&bind_addr).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    // 2. Send a UDP packet to an external WAN target 8.8.8.8
    // The kernel routing table will route this packet through "wan" (default gateway),
    // and Netfilter masquerading should translate its source IP from 192.168.1.1 to 10.0.2.15.
    let payload = b"NAT_PING_TEST";
    let mut resolved = false;
    let mut buf = [0u8; 512];
    let dest_addr = format!("8.8.8.8:{}", NAT_TEST_PORT);

    for _ in 0..5 {
        if socket.send_to(payload, &dest_addr).is_ok()
            && let Ok((amt, _src)) = socket.recv_from(&mut buf)
            && &buf[..amt] == b"NAT_PONG_TEST"
        {
            resolved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if !resolved {
        return Err(
            "NAT routing test failed: did not receive NAT_PONG_TEST reply from external target"
                .to_string(),
        );
    }

    std::println!("[test] NAT Masquerading verified successfully.");
    Ok(())
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
