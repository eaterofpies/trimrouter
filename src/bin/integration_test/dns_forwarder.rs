use std::net::UdpSocket;
use std::time::Duration;
use trimrouter::services::utils::SharedWanLease;
use trimrouter::services::{DnsForwarder, Service};

pub async fn test_dns_forwarding(lease_state: SharedWanLease) -> Result<DnsForwarder, String> {
    std::println!("[test] Starting DNS Forwarder test...");

    // 1. Start DNS Forwarder
    let mut dns_forwarder = DnsForwarder::new(lease_state);
    if let Err(e) = dns_forwarder.start().await {
        return Err(format!("Failed to start DNS Forwarder: {}", e));
    }

    // 2. Bind to UDP port 23457 to receive verification from the host
    let socket = UdpSocket::bind("192.168.1.1:23457").map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    // 3. Trigger the host test coordinator
    std::println!("[test-control] TRIGGER_DNS_CLIENT_TEST");

    // 4. Await verification packet from the host
    let mut buf = [0u8; 512];
    let (amt, _src) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("Timed out waiting for DNS caching verification: {}", e))?;

    if &buf[..amt] == b"DNS_CACHE_OK" {
        std::println!("[test] DNS Forwarder successfully resolved and cached query.");
        Ok(dns_forwarder)
    } else {
        if let Err(e) = dns_forwarder.stop().await {
            std::eprintln!("[test] Warning: Failed to stop DNS forwarder: {}", e);
        }
        Err(format!(
            "Received invalid DNS verification payload: {:?}",
            String::from_utf8_lossy(&buf[..amt])
        ))
    }
}
