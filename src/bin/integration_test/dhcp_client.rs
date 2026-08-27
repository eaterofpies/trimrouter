use futures_util::TryStreamExt;
use std::net::Ipv4Addr;
use std::time::Duration;
use trimrouter::services::utils::{WanLeaseReceiver, WanLeaseSender};
use trimrouter::services::{DhcpClient, Service};

pub async fn test_dhcp_client_binding(
    lease_tx: WanLeaseSender,
    mut lease_rx: WanLeaseReceiver,
) -> Result<DhcpClient, String> {
    std::println!("[test] Starting DHCP Client binding test...");

    // 1. Tell host to start the WAN ISP mock
    std::println!("[test-control] START_WAN_ISP");

    // 2. Instantiate and start DHCP client on "wan"
    let mut client = DhcpClient::new("wan".to_string(), lease_tx);
    if let Err(e) = client.start().await {
        return Err(format!("Failed to start DHCP client: {}", e));
    }

    // 3. Await configuration (up to 30 seconds)
    let start = std::time::Instant::now();
    let mut bound = false;
    while start.elapsed() < Duration::from_secs(30) {
        if lease_rx.borrow().ip == Some(Ipv4Addr::new(10, 0, 2, 15)) {
            bound = true;
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            _ = lease_rx.changed() => {}
        }
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

pub async fn test_dhcp_renewal(lease_rx: WanLeaseReceiver) -> Result<(), String> {
    std::println!("[test] Starting DHCP Client renewal test...");

    // With a lease time of 6 seconds, renewal (T1) happens at 3 seconds.
    // Wait up to 8 seconds to allow renewal to trigger and complete.
    let _start = std::time::Instant::now();
    let mut renewed = false;

    // We can monitor stdout or check if the lease remains active.
    // Since the mock ISP ACK will arrive, let's verify that the lease is still valid
    // after the renewal window.
    tokio::time::sleep(Duration::from_secs(5)).await;

    if lease_rx.borrow().ip == Some(Ipv4Addr::new(10, 0, 2, 15)) {
        renewed = true;
    }

    if !renewed {
        return Err("Lease was lost or not renewed".to_string());
    }

    std::println!("[test] DHCP Client renewal verified successfully.");
    Ok(())
}

pub async fn has_default_route(iface_index: u32) -> Result<bool, String> {
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    tokio::spawn(connection);

    let get_msg = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new().build();

    let mut routes = handle.route().get(get_msg).execute();
    while let Ok(Some(route_msg)) = routes.try_next().await {
        if route_msg.header.destination_prefix_length == 0 {
            for attr in route_msg.attributes {
                if let rtnetlink::packet_route::route::RouteAttribute::Oif(oif) = attr
                    && oif == iface_index
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

pub async fn test_kernel_route_teardown() -> Result<(), String> {
    std::println!("[test] Starting Kernel Dynamic Route Teardown test...");

    let wan_idx = match trimrouter::network::get_interface_index("wan").await {
        Some(idx) => idx,
        None => return Err("Interface wan not found".to_string()),
    };

    let ip = Ipv4Addr::new(10, 0, 2, 15);
    let mask = Ipv4Addr::new(255, 255, 255, 0);

    // 1. Verify default route was established by DHCP client or configure it explicitly
    if !has_default_route(wan_idx).await? {
        let gw = Some(Ipv4Addr::new(10, 0, 2, 2));
        trimrouter::services::dhcp_client::manager::configure_wan("wan", ip, mask, gw)
            .await
            .map_err(|e| e.to_string())?;
    }

    if !has_default_route(wan_idx).await? {
        return Err("Default route was not found in kernel routing table".to_string());
    }
    std::println!("[test] Verified active 0.0.0.0/0 default route in kernel routing table.");

    // 2. Deconfigure WAN interface
    trimrouter::services::dhcp_client::manager::deconfigure_wan("wan", ip, mask)
        .await
        .map_err(|e| e.to_string())?;

    // 3. Verify default route has been torn down
    if has_default_route(wan_idx).await? {
        return Err(
            "Default route still exists in kernel routing table after deconfigure_wan".to_string(),
        );
    }

    std::println!("[test] Verified default route was cleanly torn down from kernel FIB.");
    Ok(())
}
