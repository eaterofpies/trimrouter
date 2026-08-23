use crate::config::RouterConfig;
use crate::interface;
use crate::kmod;
use crate::managers::{self, CHROOT_JAIL_PATH, Service};
use crate::netfilter;
use crate::network;
use crate::partition::{
    ensure_log_partition_in_mbr, mount_boot_partition, setup_log_partition, wait_for_boot_partition,
};
use crate::reaper;
use crate::signal;
use crate::system::{
    self, RealSystem, SystemOps, mount_virtual_filesystems, register_panic_handler,
};
use futures_util::StreamExt;
use log::{debug, error, info, warn};
use nix::unistd::Pid;
use std::fs::{self, OpenOptions, metadata, set_permissions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task::JoinHandle;

pub async fn run_as_init(sys: Arc<RealSystem>) {
    let config = early_boot(sys.clone());

    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let sig_handle = start_system_services(sys.clone(), shutdown_flag.clone());

    let mut dns_forwarder =
        configure_networking_and_services(sys, config, shutdown_flag.clone()).await;

    // Keep the main thread alive waiting for the signal handler to finish
    let _ = sig_handle.await;

    info!("[init] Stopping services...");
    let _ = dns_forwarder.stop().await;
}

fn early_boot(sys: Arc<RealSystem>) -> RouterConfig {
    // For PID 1, redirect standard descriptors (0, 1, 2) to /dev/console
    if sys.getpid() == Pid::from_raw(1)
        && let Ok(console) = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/console")
    {
        let fd = console.as_raw_fd();
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }

    info!("====================================================");
    info!("Starting trimrouter (PID 1 Init Daemon)");
    info!("====================================================");

    // 1. Register Panic Hook (Emergency Reboot)
    register_panic_handler(sys.clone());

    // Spawn netlink uevent listener to handle module autoloading for hardware discovery
    kmod::start_uevent_listener();

    // 2. Mount Filesystems if running as PID 1
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) = mount_virtual_filesystems(sys.as_ref()) {
            panic!("FATAL: Failed to mount virtual filesystems: {}", e);
        }
        kmod::trigger_uevents();
        kmod::load_required_modules();
        let (boot_dev, parent_disk) = match wait_for_boot_partition() {
            Ok(res) => res,
            Err(e) => panic!("FATAL: Failed to find boot partition: {}", e),
        };

        if let Err(e) = ensure_log_partition_in_mbr(&boot_dev, &parent_disk) {
            warn!("[init] Warning: failed to ensure partition 2: {}", e);
        }

        if let Err(e) = mount_boot_partition(sys.as_ref(), &boot_dev) {
            panic!("FATAL: Failed to mount boot partition: {}", e);
        }

        // Make full module tree available via EROFS mount
        kmod::activate_boot_modules();

        if let Err(e) = setup_log_partition(sys.as_ref(), &boot_dev, &parent_disk) {
            warn!("[init] Warning: Failed to setup log partition: {}", e);
        }

        // Create chroot jail directory if it doesn't exist
        fs::create_dir_all(CHROOT_JAIL_PATH).expect("Failed to create chroot jail directory");
        if let Ok(meta) = metadata(CHROOT_JAIL_PATH) {
            let mut perms = meta.permissions();
            perms.set_mode(0o555); // rx-rx-rx
            set_permissions(CHROOT_JAIL_PATH, perms)
                .expect("Failed to set chroot jail permissions");
        }
    } else {
        info!(
            "[init] Running in standard user environment (PID {}). Skipping VFS mounts.",
            sys.getpid()
        );
        // Ensure jail directory exists for local tests as well
        fs::create_dir_all(CHROOT_JAIL_PATH).expect("Failed to create chroot jail directory");
    }

    // 3. Load Configuration
    let config = match RouterConfig::parse(sys.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            panic!("FATAL: Failed to parse configuration: {}", e);
        }
    };
    crate::logging::init_logging(config.logging.max_log_size_mb, config.logging.level);
    let delay_val = match config.reboot_delay {
        None => -1,
        Some(d) => d as i32,
    };
    system::REBOOT_DELAY.store(delay_val, Ordering::Relaxed);
    info!("[init] Configuration loaded: {:?}", config);

    config
}

fn start_system_services(sys: Arc<RealSystem>, shutdown_flag: Arc<AtomicBool>) -> JoinHandle<()> {
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
    let mut dns_forwarder = managers::DnsForwarder::new(lease_state.clone());
    if let Err(e) = dns_forwarder.start().await {
        error!("[init] Failed to start DNS forwarder: {}", e);
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

    info!("[init] System startup completed successfully. Entering main event loop.");

    dns_forwarder
}

async fn start_power_button_monitor<S: SystemOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    debug!("[init] Starting ACPI power button monitor...");
    for i in 0..5 {
        let path = format!("/dev/input/event{}", i);
        if let Ok(device) = evdev::Device::open(&path) {
            debug!("[init] Monitoring power button input device: {}", path);
            let sys_clone = sys.clone();
            let shutdown_clone = shutdown_flag.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = device.into_event_stream() {
                    while let Some(Ok(event)) = stream.next().await {
                        if event.event_type() == evdev::EventType::KEY
                            && event.code() == evdev::KeyCode::KEY_POWER.code()
                            && event.value() == 1
                        {
                            info!("[acpi] Power button pressed. Triggering system shutdown...");
                            shutdown_clone.store(true, Ordering::Relaxed);
                            let _ = sys_clone.reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF);
                            break;
                        }
                    }
                }
            });
        }
    }
}
