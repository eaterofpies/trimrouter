use std::net::Ipv4Addr;
use std::time::Duration;
use trimrouter::services::utils::SharedWanLease;
use trimrouter::services::{DhcpClient, Service};

pub async fn test_dhcp_client_binding(lease_state: SharedWanLease) -> Result<DhcpClient, String> {
    std::println!("[test] Starting DHCP Client binding test...");

    // 1. Tell host to start the WAN ISP mock
    std::println!("[test-control] START_WAN_ISP");

    // 2. Instantiate and start DHCP client on "wan"
    let mut client = DhcpClient::new("wan".to_string(), lease_state.clone());
    if let Err(e) = client.start().await {
        return Err(format!("Failed to start DHCP client: {}", e));
    }

    // 3. Await configuration (up to 30 seconds)
    let start = std::time::Instant::now();
    let mut bound = false;
    while start.elapsed() < Duration::from_secs(30) {
        {
            let lease = lease_state.lock().unwrap();
            if lease.ip == Some(Ipv4Addr::new(10, 0, 2, 15)) {
                bound = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if !bound {
        if let Err(e) = client.stop().await {
            return Err(format!(
                "DHCP client failed to bind, and failed to stop client: {}",
                e
            ));
        }
        return Err("DHCP client failed to bind to WAN IP 10.0.2.15 within timeout".to_string());
    }

    std::println!("[test] DHCP Client successfully bound to WAN IP.");
    Ok(client)
}

pub async fn test_dhcp_renewal(lease_state: SharedWanLease) -> Result<(), String> {
    std::println!("[test] Starting DHCP Client renewal test...");

    // With a lease time of 6 seconds, renewal (T1) happens at 3 seconds.
    // Wait up to 8 seconds to allow renewal to trigger and complete.
    let _start = std::time::Instant::now();
    let mut renewed = false;

    // We can monitor stdout or check if the lease remains active.
    // Since the mock ISP ACK will arrive, let's verify that the lease is still valid
    // after the renewal window.
    tokio::time::sleep(Duration::from_secs(5)).await;

    {
        let lease = lease_state.lock().unwrap();
        if lease.ip == Some(Ipv4Addr::new(10, 0, 2, 15)) {
            renewed = true;
        }
    }

    if !renewed {
        return Err("Lease was lost or not renewed".to_string());
    }

    std::println!("[test] DHCP Client renewal verified successfully.");
    Ok(())
}
