pub mod firewall;
pub mod kmod;
pub mod power;
pub mod reaper;
pub mod storage;
pub mod system;

use crate::config::RouterConfig;
use crate::interface;
use crate::network;
use crate::services::{self, CHROOT_JAIL_PATH, Service};
use futures_util::StreamExt;
use log::{debug, error, info, warn};
use nix::unistd::Pid;
use std::fs::{self, OpenOptions, metadata, set_permissions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use storage::{
    ensure_log_partition_in_mbr, mount_boot_partition, setup_log_partition, wait_for_boot_partition,
};
use system::{ProcessOps, RealSystem, mount_virtual_filesystems, register_panic_handler};
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
    if let Err(e) = dns_forwarder.stop().await {
        error!("[init] Failed to stop DNS forwarder: {}", e);
    }
}

fn early_boot(sys: Arc<RealSystem>) -> RouterConfig {
    setup_console_io(sys.as_ref());

    info!("====================================================");
    info!("Starting trimrouter (PID 1 Init Daemon)");
    info!("====================================================");

    register_panic_handler(sys.clone());
    kmod::start_uevent_listener();

    mount_storage_and_modules(sys.as_ref());
    load_and_apply_config(sys.as_ref())
}

fn setup_console_io(sys: &RealSystem) {
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
}

fn setup_chroot_jail() {
    if let Err(e) = fs::create_dir_all(CHROOT_JAIL_PATH) {
        warn!(
            "[init] Warning: Failed to create chroot jail directory: {}",
            e
        );
        return;
    }
    if let Ok(meta) = metadata(CHROOT_JAIL_PATH) {
        let mut perms = meta.permissions();
        perms.set_mode(0o555); // rx-rx-rx
        if let Err(e) = set_permissions(CHROOT_JAIL_PATH, perms) {
            warn!(
                "[init] Warning: Failed to set chroot jail permissions: {}",
                e
            );
        }
    }
}

fn mount_storage_and_modules(sys: &RealSystem) {
    if sys.getpid() != Pid::from_raw(1) {
        info!(
            "[init] Running in standard user environment (PID {}). Skipping VFS mounts.",
            sys.getpid()
        );
        setup_chroot_jail();
        return;
    }

    if let Err(e) = mount_virtual_filesystems(sys) {
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

    if let Err(e) = mount_boot_partition(sys, &boot_dev) {
        panic!("FATAL: Failed to mount boot partition: {}", e);
    }

    // Make full module tree available via EROFS mount
    kmod::activate_boot_modules();

    if let Err(e) = setup_log_partition(sys, &boot_dev, &parent_disk) {
        warn!("[init] Warning: Failed to setup log partition: {}", e);
    }

    setup_chroot_jail();
}

fn load_and_apply_config(sys: &RealSystem) -> RouterConfig {
    let config = match RouterConfig::parse(sys) {
        Ok(c) => c,
        Err(e) => {
            panic!("FATAL: Failed to parse configuration: {}", e);
        }
    };
    crate::logging::init_logging(config.logging.max_log_size_mb, config.logging.level);
    info!(
        "[init] trimrouter starting (git: {}, built: {})",
        env!("VERGEN_GIT_SHA"),
        env!("VERGEN_BUILD_TIMESTAMP")
    );
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
        power::start_signal_monitor(sig_sys, sig_shutdown).await;
    })
}

async fn configure_networking_and_services(
    sys: Arc<RealSystem>,
    config: RouterConfig,
    _shutdown_flag: Arc<AtomicBool>,
) -> services::DnsForwarder {
    setup_loopback_and_firewall(sys.as_ref()).await;

    let (lease_tx, lease_rx) = tokio::sync::watch::channel(services::WanLease::default());

    let mut dns_forwarder = services::DnsForwarder::new(lease_rx.clone());
    if let Err(e) = dns_forwarder.start().await {
        error!("[init] Failed to start DNS forwarder: {}", e);
    }

    let managed_ifaces = build_managed_interfaces(&config, lease_tx, lease_rx);
    tokio::spawn(interface::monitor_interfaces(managed_ifaces));

    info!("[init] System startup completed successfully. Entering main event loop.");

    dns_forwarder
}

async fn setup_loopback_and_firewall(sys: &RealSystem) {
    if sys.getpid() == Pid::from_raw(1) {
        if let Err(e) = network::configure_network_init().await {
            panic!("FATAL: Failed to initialize network: {}", e);
        }

        if let Err(e) = firewall::configure_firewall(network::WAN_INTERFACE, network::LAN_INTERFACE)
        {
            panic!("FATAL: Failed to configure firewall: {}", e);
        }
    }
}

fn build_managed_interfaces(
    config: &RouterConfig,
    lease_tx: services::WanLeaseSender,
    lease_rx: services::WanLeaseReceiver,
) -> Vec<interface::ManagedInterface> {
    let wan_services = vec![
        interface::RouterService::DhcpClient(services::DhcpClient::new(
            network::WAN_INTERFACE.to_string(),
            lease_tx,
        )),
        interface::RouterService::SntpClient(services::SntpClient::new(lease_rx.clone())),
    ];
    let wan_iface = interface::ManagedInterface::new(
        network::WAN_INTERFACE.to_string(),
        config.wan_mac,
        wan_services,
    );

    let lan_services = vec![interface::RouterService::LanManager(
        services::LanManager::new(
            network::LAN_INTERFACE.to_string(),
            config.lan_ip.clone(),
            config.backup_lan_ip.clone(),
            lease_rx,
        ),
    )];
    let lan_iface = interface::ManagedInterface::new(
        network::LAN_INTERFACE.to_string(),
        config.lan_mac,
        lan_services,
    );

    vec![wan_iface, lan_iface]
}

async fn start_power_button_monitor<S: system::PowerOps + 'static>(
    sys: Arc<S>,
    shutdown_flag: Arc<AtomicBool>,
) {
    debug!("[init] Starting ACPI power button monitor loop...");
    let mut opened_devices = std::collections::HashSet::new();

    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            break;
        }

        for i in 0..32 {
            let path = format!("/dev/input/event{}", i);
            if !opened_devices.contains(&path)
                && let Ok(device) = evdev::Device::open(&path)
            {
                info!(
                    "[init] Monitoring power button input device: {} ({})",
                    path,
                    device.name().unwrap_or("Unknown")
                );
                opened_devices.insert(path);
                tokio::spawn(monitor_single_power_device(
                    device,
                    sys.clone(),
                    shutdown_flag.clone(),
                ));
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn monitor_single_power_device<S: system::PowerOps>(
    device: evdev::Device,
    sys: Arc<S>,
    shutdown_flag: Arc<AtomicBool>,
) {
    let Ok(mut stream) = device.into_event_stream() else {
        return;
    };
    while let Some(Ok(event)) = stream.next().await {
        let is_power_key = event.event_type() == evdev::EventType::KEY
            && (event.code() == evdev::KeyCode::KEY_POWER.code()
                || event.code() == evdev::KeyCode::KEY_POWER2.code()
                || event.code() == evdev::KeyCode::KEY_SLEEP.code());

        if is_power_key && event.value() == 1 {
            info!(
                "[acpi] Power button pressed (event code: {}). Triggering system shutdown...",
                event.code()
            );
            shutdown_flag.store(true, Ordering::Relaxed);
            let _ = sys.reboot(nix::sys::reboot::RebootMode::RB_POWER_OFF);
            break;
        }
    }
}
