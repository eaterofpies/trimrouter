#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        std::print!("{}", $crate::services::utils::get_timestamp_prefix());
        std::println!($($arg)*);
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        std::eprint!("{}", $crate::services::utils::get_timestamp_prefix());
        std::eprintln!($($arg)*);
    }};
}

mod config;
mod kmod;
mod netfilter;
mod network;
mod packet;
mod reaper;
mod services;
mod signal;
mod system;

use config::RouterConfig;
use nix::sys::reboot::RebootMode;
use nix::unistd::Pid;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use system::{RealSystem, SystemOps, mount_virtual_filesystems, register_panic_handler};

async fn start_power_button_monitor<S: SystemOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    println!("[init] Starting ACPI power button monitor...");
    for i in 0..5 {
        let path = format!("/dev/input/event{}", i);
        if let Ok(device) = evdev::Device::open(&path) {
            println!("[init] Monitoring power button input device: {}", path);
            let sys_clone = sys.clone();
            let shutdown_clone = shutdown_flag.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = device.into_event_stream() {
                    use futures_util::StreamExt;
                    while let Some(Ok(event)) = stream.next().await {
                        if event.event_type() == evdev::EventType::KEY
                            && event.code() == evdev::KeyCode::KEY_POWER.code()
                            && event.value() == 1
                        {
                            println!(
                                "\n[acpi] Power button pressed. Triggering system shutdown..."
                            );
                            shutdown_clone.store(true, std::sync::atomic::Ordering::Relaxed);
                            let _ = sys_clone.reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF);
                            break;
                        }
                    }
                }
            });
        }
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let is_modprobe = args.first().is_some_and(|arg0| arg0.contains("modprobe"))
        || args.get(1).is_some_and(|arg1| arg1 == "modprobe");

    if is_modprobe {
        if let Err(e) = kmod::run_as_modprobe(args) {
            eprintln!("[modprobe] ERROR: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let sys = Arc::new(RealSystem);
    run_as_init(sys).await;
}

async fn run_as_init(sys: Arc<RealSystem>) {
    // For PID 1, redirect standard descriptors (0, 1, 2) to /dev/console
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

    println!("====================================================");
    println!("Starting rustyrouter (PID 1 Init Daemon)");
    println!("====================================================");

    // 1. Register Panic Hook (Emergency Reboot)
    register_panic_handler(sys.clone());

    // Spawn netlink uevent listener to handle module autoloading for hardware discovery
    kmod::start_uevent_listener();

    // 2. Mount Filesystems if running as PID 1
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) = mount_virtual_filesystems(sys.as_ref()) {
            eprintln!("[init] FATAL: {}", e);
            let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
            return;
        }
        kmod::load_required_modules();
    } else {
        println!(
            "[init] Running in standard user environment (PID {}). Skipping VFS mounts.",
            sys.getpid()
        );
    }

    // 3. Load Configuration
    let config = RouterConfig::parse(sys.as_ref());
    println!("[init] Configuration loaded: {:?}", config);

    // 4. Configure Network Interfaces (lo, LAN, WAN)
    if sys.getpid() == Pid::from_raw(1) {
        let rename_res =
            network::resolve_and_rename_interfaces(&config.wan_mac, &config.lan_mac).await;
        if let Err(e) = rename_res {
            eprintln!(
                "[init] ERROR: Failed to rename interfaces based on MAC: {}",
                e
            );
        }

        if let Err(e) = network::configure_network(
            network::WAN_INTERFACE,
            network::LAN_INTERFACE,
            &config.lan_ip,
        )
        .await
        {
            eprintln!(
                "[init] ERROR: Failed to configure network interfaces: {}",
                e
            );
        }

        // Spawn background watchdog tasks to monitor and configure LAN/WAN interfaces if added/re-added (e.g. hotplug)
        let lan_iface_monitor = network::LAN_INTERFACE.to_string();
        let lan_ip_monitor = config.lan_ip.clone();
        tokio::spawn(monitor_lan_watchdog(lan_iface_monitor, lan_ip_monitor));

        let wan_iface_monitor = network::WAN_INTERFACE.to_string();
        tokio::spawn(monitor_wan_watchdog(wan_iface_monitor));
        if let Err(e) =
            netfilter::configure_firewall(network::WAN_INTERFACE, network::LAN_INTERFACE)
        {
            eprintln!("[init] FATAL: Failed to configure firewall: {}", e);
            let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
            return;
        }
    }

    // 5. Lifecycle coordination flag
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // 5. Spawn Core Tasks
    let reaper_sys = sys.clone();
    let reaper_shutdown = shutdown_flag.clone();
    tokio::spawn(async move {
        reaper::start_orphan_reaper(reaper_sys, reaper_shutdown).await;
    });

    let sig_sys = sys.clone();
    let sig_shutdown = shutdown_flag.clone();
    let sig_handle = tokio::spawn(async move {
        signal::start_signal_monitor(sig_sys, sig_shutdown).await;
    });

    // Spawn ACPI Power Button Monitor
    let power_sys = sys.clone();
    let power_shutdown = shutdown_flag.clone();
    tokio::spawn(async move {
        start_power_button_monitor(power_sys, power_shutdown).await;
    });

    // Shared state for the DHCP lease obtained on WAN
    let lease_state = Arc::new(std::sync::Mutex::new(services::WanLease::default()));

    use services::Service;

    // Instantiate services
    let mut dhcp_client = services::DhcpClient::new(network::WAN_INTERFACE.to_string(), lease_state.clone());
    let mut dhcp_server = services::DhcpServer::new(network::LAN_INTERFACE.to_string(), config.lan_ip.clone());
    let mut dns_forwarder = services::DnsForwarder::new(lease_state.clone());
    let mut sntp_client = services::SntpClient::new(lease_state.clone());

    // Start services using Service trait
    if let Err(e) = dhcp_client.start().await {
        eprintln!("[init] Failed to start WAN DHCP client: {}", e);
    }
    if let Err(e) = dhcp_server.start().await {
        eprintln!("[init] Failed to start LAN DHCP server: {}", e);
    }
    if let Err(e) = dns_forwarder.start().await {
        eprintln!("[init] Failed to start DNS forwarder: {}", e);
    }
    if let Err(e) = sntp_client.start().await {
        eprintln!("[init] Failed to start SNTP client: {}", e);
    }

    println!("[init] System startup completed successfully. Entering main event loop.");

    // Keep the main thread alive waiting for the signal handler to finish
    let _ = sig_handle.await;

    // Perform clean shutdown of services on exit
    println!("[init] Stopping services...");
    let _ = dhcp_client.stop().await;
    let _ = dhcp_server.stop().await;
    let _ = dns_forwarder.stop().await;
    let _ = sntp_client.stop().await;
}

async fn monitor_lan_watchdog(iface: String, ip: String) {
    loop {
        let _ = network::ensure_interface_up_and_configured(&iface, &ip).await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn monitor_wan_watchdog(iface: String) {
    loop {
        let _ = network::ensure_interface_up(&iface).await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

