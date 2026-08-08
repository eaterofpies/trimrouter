use std::net::UdpSocket;
use std::time::Duration;
use trimrouter::services::utils::SharedWanLease;
use trimrouter::services::{DnsForwarder, Service};

// Sample DNS query payload (google.com A record request)
const DNS_QUERY: &[u8] = &[
    0x1a, 0x1a, // Transaction ID
    0x01, 0x00, // Flags: Standard query
    0x00, 0x01, // Questions: 1
    0x00, 0x00, // Answer RRs: 0
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // google.com
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
];

// Sample DNS response payload (google.com A record response: 8.8.8.8)
const DNS_RESPONSE: &[u8] = &[
    0x1a, 0x1a, // Transaction ID
    0x81, 0x80, // Flags: Standard query response, No error
    0x00, 0x01, // Questions: 1
    0x00, 0x01, // Answer RRs: 1
    0x00, 0x00, // Authority RRs: 0
    0x00, 0x00, // Additional RRs: 0
    0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
    0x01, // Type: A
    0x00, 0x01, // Class: IN
    0xc0, 0x0c, // Pointer to name
    0x00, 0x01, // Type: A
    0x00, 0x01, // Class: IN
    0x00, 0x00, 0x00, 0x3c, // TTL: 60s
    0x00, 0x04, // Length: 4
    0x08, 0x08, 0x08, 0x08, // IP: 8.8.8.8
];

pub async fn test_dns_forwarding(lease_state: SharedWanLease) -> Result<DnsForwarder, String> {
    std::println!("[test] Starting DNS Forwarder test...");

    // 1. Start DNS Forwarder
    let mut dns_forwarder = DnsForwarder::new(lease_state);
    if let Err(e) = dns_forwarder.start().await {
        return Err(format!("Failed to start DNS Forwarder: {}", e));
    }

    // 2. Bind a client socket
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    // Send query to local DNS forwarder (which will be active on loopback/LAN interface)
    // Wait, let's send to 127.0.0.1:53
    let mut resolved = false;
    let mut buf = [0u8; 512];

    // Retry sending DNS query up to 5 times (DNS forwarder might take a moment to bind/ready)
    for _ in 0..5 {
        if socket.send_to(DNS_QUERY, "127.0.0.1:53").is_ok()
            && let Ok((amt, _src)) = socket.recv_from(&mut buf)
            && &buf[..amt] == DNS_RESPONSE
        {
            resolved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if !resolved {
        if let Err(e) = dns_forwarder.stop().await {
            return Err(format!(
                "DNS forwarder failed to resolve, and failed to stop forwarder: {}",
                e
            ));
        }
        return Err("DNS forwarder failed to resolve or forward query correctly".to_string());
    }

    std::println!("[test] DNS Forwarder successfully resolved query.");
    Ok(dns_forwarder)
}
