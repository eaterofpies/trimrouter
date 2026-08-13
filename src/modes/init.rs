use crate::config::RouterConfig;
use crate::managers::CHROOT_JAIL_PATH;
use crate::system::{
    RealSystem, SystemOps, mount_boot_partition, mount_virtual_filesystems, register_panic_handler,
};
use crate::{interface, kmod, managers, netfilter, network, reaper, signal, system};
use nix::unistd::Pid;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub async fn run_as_init(sys: Arc<RealSystem>) {
    let config = early_boot(sys.clone());

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let sig_handle = start_system_services(sys.clone(), shutdown_flag.clone());

    let mut dns_forwarder =
        configure_networking_and_services(sys, config, shutdown_flag.clone()).await;

    // Keep the main thread alive waiting for the signal handler to finish
    let _ = sig_handle.await;

    println!("[init] Stopping services...");
    use crate::managers::Service;
    let _ = dns_forwarder.stop().await;
}

fn early_boot(sys: Arc<RealSystem>) -> RouterConfig {
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
    println!("Starting trimrouter (PID 1 Init Daemon)");
    println!("====================================================");

    // 1. Register Panic Hook (Emergency Reboot)
    register_panic_handler(sys.clone());

    // Spawn netlink uevent listener to handle module autoloading for hardware discovery
    kmod::start_uevent_listener();

    // 2. Mount Filesystems if running as PID 1
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) = mount_virtual_filesystems(sys.as_ref()) {
            panic!("FATAL: Failed to mount virtual filesystems: {}", e);
        }
        kmod::load_required_modules();
        if let Err(e) = mount_boot_partition(sys.as_ref()) {
            panic!("FATAL: Failed to mount boot partition: {}", e);
        }

        // Create chroot jail directory if it doesn't exist
        std::fs::create_dir_all(CHROOT_JAIL_PATH).expect("Failed to create chroot jail directory");
        if let Ok(metadata) = std::fs::metadata(CHROOT_JAIL_PATH) {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = metadata.permissions();
            perms.set_mode(0o555); // rx-rx-rx
            std::fs::set_permissions(CHROOT_JAIL_PATH, perms)
                .expect("Failed to set chroot jail permissions");
        }
    } else {
        println!(
            "[init] Running in standard user environment (PID {}). Skipping VFS mounts.",
            sys.getpid()
        );
        // Ensure jail directory exists for local tests as well
        std::fs::create_dir_all(CHROOT_JAIL_PATH).expect("Failed to create chroot jail directory");
    }

    // 3. Load Configuration
    let config = match RouterConfig::parse(sys.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            panic!("FATAL: Failed to parse configuration: {}", e);
        }
    };
    let delay_val = match config.reboot_delay {
        None => -1,
        Some(d) => d as i32,
    };
    system::REBOOT_DELAY.store(delay_val, std::sync::atomic::Ordering::Relaxed);
    println!("[init] Configuration loaded: {:?}", config);

    config
}

fn start_system_services(
    sys: Arc<RealSystem>,
    shutdown_flag: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    // Spawn orphan process reaper
    let reaper_sys = sys.clone();
    let reaper_shutdown = shutdown_flag.clone();
    tokio::spawn(async move {
        reaper::start_orphan_reaper(reaper_sys, reaper_shutdown).await;
    });

    // Spawn ACPI Power Button Monitor
    let power_sys = sys.clone();
    let power_shutdown = shutdown_flag.clone();
    tokio::spawn(async move {
        start_power_button_monitor(power_sys, power_shutdown).await;
    });

    // Spawn system signal monitor
    let sig_sys = sys.clone();
    let sig_shutdown = shutdown_flag;
    tokio::spawn(async move {
        signal::start_signal_monitor(sig_sys, sig_shutdown).await;
    })
}

async fn configure_networking_and_services(
    sys: Arc<RealSystem>,
    config: RouterConfig,
    _shutdown_flag: Arc<AtomicBool>,
) -> managers::DnsForwarder {
    // 4. Configure Network (Loopback only)
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) = network::configure_network_init().await {
            panic!("FATAL: Failed to initialize network: {}", e);
        }

        if let Err(e) =
            netfilter::configure_firewall(network::WAN_INTERFACE, network::LAN_INTERFACE)
        {
            panic!("FATAL: Failed to configure firewall: {}", e);
        }
    }

    // Shared state for the DHCP lease obtained on WAN
    let lease_state = Arc::new(std::sync::Mutex::new(managers::WanLease::default()));

    // Start DNS Forwarder as a global service
    use crate::managers::Service;
    let mut dns_forwarder = managers::DnsForwarder::new(lease_state.clone());
    if let Err(e) = dns_forwarder.start().await {
        eprintln!("[init] ERROR: Failed to start DNS forwarder: {}", e);
    }

    // Create and monitor interfaces via the unified ManagedInterface structure
    let wan_services = vec![
        interface::RouterService::DhcpClient(managers::DhcpClient::new(
            network::WAN_INTERFACE.to_string(),
            lease_state.clone(),
        )),
        interface::RouterService::SntpClient(managers::SntpClient::new(lease_state.clone())),
    ];
    let wan_iface = interface::ManagedInterface::new(
        network::WAN_INTERFACE.to_string(),
        config.wan_mac,
        wan_services,
    );

    let lan_services = vec![interface::RouterService::LanManager(
        managers::LanManager::new(
            network::LAN_INTERFACE.to_string(),
            config.lan_ip.clone(),
            config.backup_lan_ip.clone(),
            lease_state.clone(),
        ),
    )];
    let lan_iface = interface::ManagedInterface::new(
        network::LAN_INTERFACE.to_string(),
        config.lan_mac,
        lan_services,
    );

    tokio::spawn(interface::monitor_interfaces(vec![wan_iface, lan_iface]));

    println!("[init] System startup completed successfully. Entering main event loop.");

    dns_forwarder
}

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
