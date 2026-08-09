use nix::unistd::Pid;
use std::sync::Arc;
use std::time::Duration;
use trimrouter::kmod;
use trimrouter::netfilter;
use trimrouter::network;
use trimrouter::services::{Service, WanLease};
use trimrouter::system::{RealSystem, SystemOps, mount_boot_partition, mount_virtual_filesystems};

mod dhcp_client;
mod dns_forwarder;
mod firewall;
mod lan_manager;
mod sntp;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_modprobe = args.first().is_some_and(|arg0| arg0.contains("modprobe"))
        || args.get(1).is_some_and(|arg1| arg1 == "modprobe");

    if is_modprobe {
        if let Err(e) = kmod::run_as_modprobe(args) {
            std::eprintln!("[modprobe] ERROR: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    // 1. Redirect console output for PID 1
    let sys = Arc::new(RealSystem);
    if sys.getpid() == Pid::from_raw(1)
        && let Ok(console) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/console")
    {
        use std::os::unix::io::AsRawFd;
        let fd = console.as_raw_fd();
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }

    std::println!("====================================================");
    std::println!("Starting trimrouter Integration Test Suite (PID 1)");
    std::println!("====================================================");

    let mut passed = 0;
    let mut failed = 0;

    // 2. Initialize guest environment (similar to early_boot)
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) = mount_virtual_filesystems(sys.as_ref()) {
            std::eprintln!("[test] FATAL: Failed to mount VFS: {}", e);
            std::process::exit(1);
        }
        kmod::start_uevent_listener();
        kmod::load_required_modules();
        if let Err(e) = mount_boot_partition(sys.as_ref()) {
            std::eprintln!("[test] FATAL: Failed to mount boot: {}", e);
            std::process::exit(1);
        }
        let config = match trimrouter::config::RouterConfig::parse(sys.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                std::eprintln!("[test] FATAL: Failed to parse configuration: {}", e);
                std::process::exit(1);
            }
        };

        // Test 0: Network Device Discovery (Waiting for interfaces to appear via MAC)
        std::println!("[test] Starting Network Device Discovery test...");
        let mut devices_ready = false;
        let discovery_timeout = Duration::from_secs(15);
        let wan_mac = config.wan_mac;
        let lan_mac = config.lan_mac;
        let mut wan_info = None;
        let mut lan_info = None;
        let start = std::time::Instant::now();

        while start.elapsed() < discovery_timeout {
            if wan_info.is_none() {
                wan_info = trimrouter::interface::find_interface_by_mac(wan_mac).await;
            }
            if lan_info.is_none() {
                lan_info = trimrouter::interface::find_interface_by_mac(lan_mac).await;
            }
            if wan_info.is_some() && lan_info.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if let (Some((wan_idx, wan_name)), Some((lan_idx, lan_name))) = (wan_info, lan_info) {
            let wan_rename =
                trimrouter::interface::rename_and_up_interface("wan", wan_mac, wan_idx, &wan_name)
                    .await;
            let lan_rename =
                trimrouter::interface::rename_and_up_interface("lan", lan_mac, lan_idx, &lan_name)
                    .await;
            if wan_rename.is_ok() && lan_rename.is_ok() {
                devices_ready = true;
            } else {
                std::eprintln!(
                    "[test] Failed to rename network devices: wan={:?}, lan={:?}",
                    wan_rename,
                    lan_rename
                );
            }
        }

        if devices_ready {
            std::println!("[test-control] TEST_PASSED network_discovery");
            passed += 1;
        } else {
            std::println!(
                "[test-control] TEST_FAILED network_discovery Network devices failed to appear or be renamed"
            );
            std::process::exit(1);
        }

        if let Err(e) = network::configure_network_init().await {
            std::eprintln!("[test] FATAL: Failed to init loopback: {}", e);
            std::process::exit(1);
        }
        if let Err(e) =
            netfilter::configure_firewall(network::WAN_INTERFACE, network::LAN_INTERFACE)
        {
            std::eprintln!("[test] FATAL: Failed to configure firewall: {}", e);
            std::process::exit(1);
        }
    }

    // Pre-configure the lan IP to 192.168.1.1/24 so local/NAT tests can bind/route
    if let Err(e) = network::configure_interface_ip("lan", "192.168.1.1/24").await {
        std::eprintln!(
            "[test] FATAL: Failed to pre-configure lan interface IP: {}",
            e
        );
        std::process::exit(1);
    }
    if let Err(e) = network::ensure_interface_up("lan").await {
        std::eprintln!("[test] FATAL: Failed to bring lan interface UP: {}", e);
        std::process::exit(1);
    }

    std::println!("[test] Running integration tests...");

    // Shared state for the DHCP lease obtained on WAN
    let lease_state = Arc::new(std::sync::Mutex::new(WanLease::default()));

    // Test 1: DHCP Client Binding
    let mut dhcp_client = match dhcp_client::test_dhcp_client_binding(lease_state.clone()).await {
        Ok(client) => {
            std::println!("[test-control] TEST_PASSED dhcp_client_binding");
            passed += 1;
            Some(client)
        }
        Err(e) => {
            std::println!("[test-control] TEST_FAILED dhcp_client_binding {}", e);
            failed += 1;
            None
        }
    };
    // Test 8: LAN DHCP Server Handshake
    let mut lan_manager = None;
    match lan_manager::test_lan_dhcp_handshake(lease_state.clone()).await {
        Ok(manager) => {
            std::println!("[test-control] TEST_PASSED lan_dhcp_handshake");
            passed += 1;
            lan_manager = Some(manager);
        }
        Err(e) => {
            std::println!("[test-control] TEST_FAILED lan_dhcp_handshake {}", e);
            failed += 1;
        }
    }

    // Test 2: DNS Forwarding (Only run if client bound successfully)
    let mut dns_forwarder = None;
    if dhcp_client.is_some() {
        match dns_forwarder::test_dns_forwarding(lease_state.clone()).await {
            Ok(forwarder) => {
                std::println!("[test-control] TEST_PASSED dns_forwarding");
                passed += 1;
                dns_forwarder = Some(forwarder);
            }
            Err(e) => {
                std::println!("[test-control] TEST_FAILED dns_forwarding {}", e);
                failed += 1;
            }
        }
    } else {
        std::println!("[test] Skipping DNS Forwarding test (DHCP Client binding failed).");
    }

    // Test 3: SNTP Client Time Sync (Only run if DNS forwarding is available)
    let mut sntp_client = None;
    if dns_forwarder.is_some() {
        match sntp::test_sntp_sync(lease_state.clone()).await {
            Ok(client) => {
                std::println!("[test-control] TEST_PASSED sntp_sync");
                passed += 1;
                sntp_client = Some(client);
            }
            Err(e) => {
                std::println!("[test-control] TEST_FAILED sntp_sync {}", e);
                failed += 1;
            }
        }
    } else {
        std::println!("[test] Skipping SNTP Client test (DNS Forwarding not available).");
    }

    // Test 4: NAT Routing (Only run if client bound successfully)
    if dhcp_client.is_some() {
        match firewall::test_nat_routing().await {
            Ok(_) => {
                std::println!("[test-control] TEST_PASSED nat_routing");
                passed += 1;
            }
            Err(e) => {
                std::println!("[test-control] TEST_FAILED nat_routing {}", e);
                failed += 1;
            }
        }
    } else {
        std::println!("[test] Skipping NAT Routing test (DHCP Client binding failed).");
    }

    // Test 5: Firewall Drop (Only run if client bound successfully)
    if dhcp_client.is_some() {
        match firewall::test_firewall_wan_drop().await {
            Ok(_) => {
                std::println!("[test-control] TEST_PASSED firewall_wan_drop");
                passed += 1;
            }
            Err(e) => {
                std::println!("[test-control] TEST_FAILED firewall_wan_drop {}", e);
                failed += 1;
            }
        }
    } else {
        std::println!("[test] Skipping Firewall Drop test (DHCP Client binding failed).");
    }

    // Test 6: DHCP Renewal (Only run if client bound successfully)
    if dhcp_client.is_some() {
        match dhcp_client::test_dhcp_renewal(lease_state.clone()).await {
            Ok(_) => {
                std::println!("[test-control] TEST_PASSED dhcp_renewal");
                passed += 1;
            }
            Err(e) => {
                std::println!("[test-control] TEST_FAILED dhcp_renewal {}", e);
                failed += 1;
            }
        }
    } else {
        std::println!("[test] Skipping DHCP Renewal test (DHCP Client binding failed).");
    }

    // Clean up current running services before overlap test
    if let Some(mut client) = dhcp_client.take()
        && let Err(e) = client.stop().await
    {
        std::println!("[test-control] TEST_FAILED stop_dhcp_client {}", e);
        failed += 1;
    }
    if let Some(mut forwarder) = dns_forwarder.take()
        && let Err(e) = forwarder.stop().await
    {
        std::println!("[test-control] TEST_FAILED stop_dns_forwarder {}", e);
        failed += 1;
    }
    if let Some(mut sntp) = sntp_client.take()
        && let Err(e) = sntp.stop().await
    {
        std::println!("[test-control] TEST_FAILED stop_sntp_client {}", e);
        failed += 1;
    }
    if let Some(mut lan) = lan_manager.take()
        && let Err(e) = lan.stop().await
    {
        std::println!("[test-control] TEST_FAILED stop_lan_manager {}", e);
        failed += 1;
    }

    // Clean WAN IP configuration
    if let Some(index) = get_interface_index("wan").await
        && let Err(e) = flush_ipv4_addresses("wan", index).await
    {
        std::eprintln!(
            "[test] Warning: Failed to flush WAN IP addresses during cleanup: {}",
            e
        );
    }

    // Test 7: LAN/WAN Subnet Overlap
    let conflict_lease_state = Arc::new(std::sync::Mutex::new(WanLease::default()));
    match lan_manager::test_lan_wan_conflict(conflict_lease_state).await {
        Ok(_) => {
            std::println!("[test-control] TEST_PASSED lan_wan_conflict");
            passed += 1;
        }
        Err(e) => {
            std::println!("[test-control] TEST_FAILED lan_wan_conflict {}", e);
            failed += 1;
        }
    }

    std::println!("[test] Finished. Passed: {}, Failed: {}", passed, failed);

    // Write a special exit tag so host can know we completed cleanly
    if failed > 0 {
        std::println!("[test-control] SUITE_FAILED");
    } else {
        std::println!("[test-control] SUITE_PASSED");
    }

    // Sleep briefly to allow log flushes
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Power off the VM since we are done testing
    if sys.getpid() == Pid::from_raw(1) {
        std::println!("[test] Powering off guest VM...");
        if let Err(e) = sys.reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF) {
            std::eprintln!("[test] Warning: Failed to power off guest VM: {}", e);
        }
    }
}

async fn get_interface_index(name: &str) -> Option<u32> {
    use futures_util::TryStreamExt;
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return None;
    };
    tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let index = link.header.index;
        for nla in link.attributes {
            if let rtnetlink::packet_route::link::LinkAttribute::IfName(n) = nla
                && n == name
            {
                return Some(index);
            }
        }
    }
    None
}

async fn flush_ipv4_addresses(name: &str, index: u32) -> Result<(), String> {
    use futures_util::TryStreamExt;
    use rtnetlink::packet_route::AddressFamily;
    let (connection, handle, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    tokio::spawn(connection);

    let mut addrs = handle.address().get().execute();
    while let Ok(Some(addr_msg)) = addrs.try_next().await {
        if addr_msg.header.index == index && matches!(addr_msg.header.family, AddressFamily::Inet) {
            std::println!(
                "[test] Cleaning up address on interface {} (prefix_len={})",
                name,
                addr_msg.header.prefix_len
            );
            if let Err(e) = handle.address().del(addr_msg).execute().await {
                std::println!("[test] WARNING: Failed to delete address: {}", e);
            }
        }
    }
    Ok(())
}
