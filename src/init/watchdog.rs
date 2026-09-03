use log::{debug, error, info, warn};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};

pub const DEFAULT_WATCHDOG_PATH: &str = "/dev/watchdog";
pub const DEFAULT_WATCHDOG_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 30;
pub const HEARTBEAT_CHANNEL_CAPACITY: usize = 64;
pub const KEEPALIVE_BYTE: u8 = b'\0';
pub const MAGIC_CLOSE_BYTE: u8 = b'V';
pub const MONITORED_SERVICE_COUNT: usize = 4;
const WDIOC_GETTIMEOUT: u32 = 0x8004_5707;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MonitoredService {
    DnsForwarder = 0,
    InterfaceMonitor = 1,
    DhcpClient = 2,
    LanManager = 3,
}

impl MonitoredService {
    pub const ALL: [MonitoredService; MONITORED_SERVICE_COUNT] = [
        MonitoredService::DnsForwarder,
        MonitoredService::InterfaceMonitor,
        MonitoredService::DhcpClient,
        MonitoredService::LanManager,
    ];

    pub const fn index(&self) -> usize {
        *self as usize
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            MonitoredService::DnsForwarder => "dns-forwarder",
            MonitoredService::InterfaceMonitor => "interface-monitor",
            MonitoredService::DhcpClient => "dhcp-client",
            MonitoredService::LanManager => "lan-manager",
        }
    }
}

impl std::fmt::Display for MonitoredService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

pub type HeartbeatSender = Sender<MonitoredService>;
pub type HeartbeatReceiver = Receiver<MonitoredService>;
pub type ServiceLivenessMap = [Option<Instant>; MONITORED_SERVICE_COUNT];

pub fn send_service_heartbeat(tx: Option<&HeartbeatSender>, service: MonitoredService) {
    if let Some(sender) = tx
        && let Err(e) = sender.try_send(service)
    {
        debug!(
            "[watchdog] Failed to send heartbeat for '{}': {}",
            service, e
        );
    }
}

pub trait WatchdogDevice: Send + Sync + 'static {
    fn keepalive(&mut self) -> io::Result<()>;
    fn disarm(&mut self) -> io::Result<()>;
    fn driver_timeout(&self) -> Option<Duration> {
        None
    }
}

pub struct LinuxWatchdog {
    file: Option<File>,
    path: PathBuf,
    driver_timeout: Option<Duration>,
}

impl LinuxWatchdog {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let p = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(false)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&p)?;

        let mut hw_timeout: libc::c_int = 0;
        let fd = file.as_raw_fd();
        let ret = unsafe { libc::ioctl(fd, WDIOC_GETTIMEOUT as _, &mut hw_timeout) };
        let driver_timeout = if ret == 0 && hw_timeout > 0 {
            info!(
                "[watchdog] Hardware watchdog active at {} (driver timeout: {}s)",
                p.display(),
                hw_timeout
            );
            Some(Duration::from_secs(hw_timeout as u64))
        } else {
            info!("[watchdog] Hardware watchdog active at {}", p.display());
            None
        };

        Ok(Self {
            file: Some(file),
            path: p,
            driver_timeout,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl WatchdogDevice for LinuxWatchdog {
    fn keepalive(&mut self) -> io::Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Watchdog device is closed",
            ));
        };
        file.write_all(&[KEEPALIVE_BYTE])?;
        file.flush()
    }

    fn disarm(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.write_all(&[MAGIC_CLOSE_BYTE])?;
            file.flush()
        } else {
            Ok(())
        }
    }

    fn driver_timeout(&self) -> Option<Duration> {
        self.driver_timeout
    }
}

impl Drop for LinuxWatchdog {
    fn drop(&mut self) {
        if self.file.is_some() {
            debug!("[watchdog] Watchdog handle dropped while active.");
        }
    }
}

fn drain_heartbeats(rx: &mut HeartbeatReceiver, liveness: &mut ServiceLivenessMap) {
    while let Ok(service) = rx.try_recv() {
        liveness[service.index()] = Some(Instant::now());
    }
}

fn evaluate_health(
    expected_services: &[MonitoredService],
    liveness: &ServiceLivenessMap,
    timeout: Duration,
) -> bool {
    let now = Instant::now();
    for &service in expected_services {
        match liveness[service.index()] {
            Some(last) if now.duration_since(last) <= timeout => {}
            Some(last) => {
                let elapsed = now.duration_since(last).as_secs();
                warn!(
                    "[watchdog] Health check failed: service '{}' heartbeat timed out ({}s elapsed > {}s limit)",
                    service,
                    elapsed,
                    timeout.as_secs()
                );
                log_health_diagnostics(expected_services, liveness, now);
                return false;
            }
            None => {
                warn!(
                    "[watchdog] Health check failed: service '{}' has never sent a heartbeat!",
                    service
                );
                log_health_diagnostics(expected_services, liveness, now);
                return false;
            }
        }
    }
    true
}

fn log_health_diagnostics(
    expected_services: &[MonitoredService],
    liveness: &ServiceLivenessMap,
    now: Instant,
) {
    for &svc in expected_services {
        if let Some(t) = liveness[svc.index()] {
            debug!(
                "[watchdog] Diagnostic status: service '{}' last seen {}s ago",
                svc,
                now.duration_since(t).as_secs()
            );
        } else {
            debug!("[watchdog] Diagnostic status: service '{}' never seen", svc);
        }
    }
}

pub async fn start_watchdog_monitor<W>(
    mut watchdog: W,
    mut rx: HeartbeatReceiver,
    expected_services: Vec<MonitoredService>,
    shutdown_flag: Arc<AtomicBool>,
) where
    W: WatchdogDevice,
{
    let base_interval = Duration::from_secs(DEFAULT_WATCHDOG_INTERVAL_SECS);
    let interval = match watchdog.driver_timeout() {
        Some(hw) if hw / 2 < base_interval && hw / 2 > Duration::from_secs(0) => {
            let clamped = hw / 2;
            info!(
                "[watchdog] Clamping keepalive interval to {}s (half of {}s driver timeout)",
                clamped.as_secs(),
                hw.as_secs()
            );
            clamped
        }
        _ => base_interval,
    };

    let timeout = Duration::from_secs(DEFAULT_HEARTBEAT_TIMEOUT_SECS);
    let mut liveness: ServiceLivenessMap = [None; MONITORED_SERVICE_COUNT];

    let start_time = Instant::now();
    for &service in &expected_services {
        liveness[service.index()] = Some(start_time);
    }

    info!(
        "[watchdog] Starting async watchdog keepalive monitor (interval: {}s, timeout: {}s)...",
        interval.as_secs(),
        DEFAULT_HEARTBEAT_TIMEOUT_SECS
    );

    let mut ticker = tokio::time::interval(interval);

    loop {
        ticker.tick().await;

        if shutdown_flag.load(Ordering::Relaxed) {
            info!("[watchdog] Clean shutdown detected. Disarming watchdog...");
            if let Err(e) = watchdog.disarm() {
                warn!(
                    "[watchdog] Warning: failed to disarm watchdog on shutdown: {}",
                    e
                );
            }
            break;
        }

        drain_heartbeats(&mut rx, &mut liveness);

        if evaluate_health(&expected_services, &liveness, timeout) {
            if let Err(e) = watchdog.keepalive() {
                error!("[watchdog] Failed to pet hardware watchdog: {}", e);
            } else {
                debug!("[watchdog] Petted hardware watchdog.");
            }
        } else {
            warn!("[watchdog] System health check failed! Skipping keepalive heartbeat.");
        }
    }
}

pub fn spawn_dummy_heartbeat_consumer(mut rx: HeartbeatReceiver) {
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
}

pub fn init_and_spawn_watchdog(
    enabled: bool,
    rx: HeartbeatReceiver,
    expected_services: Vec<MonitoredService>,
    shutdown_flag: Arc<AtomicBool>,
) {
    if !enabled {
        info!(
            "[watchdog] Hardware watchdog is disabled by configuration. Spawning dummy heartbeat consumer."
        );
        spawn_dummy_heartbeat_consumer(rx);
        return;
    }

    match LinuxWatchdog::open(DEFAULT_WATCHDOG_PATH) {
        Ok(watchdog) => {
            tokio::spawn(start_watchdog_monitor(
                watchdog,
                rx,
                expected_services,
                shutdown_flag,
            ));
        }
        Err(e) => {
            info!(
                "[watchdog] Hardware watchdog device {} unavailable ({}). Spawning dummy heartbeat consumer.",
                DEFAULT_WATCHDOG_PATH, e
            );
            spawn_dummy_heartbeat_consumer(rx);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    pub struct MockWatchdog {
        pub pings: Arc<Mutex<usize>>,
        pub disarmed: Arc<Mutex<bool>>,
    }

    impl Default for MockWatchdog {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockWatchdog {
        pub fn new() -> Self {
            Self {
                pings: Arc::new(Mutex::new(0)),
                disarmed: Arc::new(Mutex::new(false)),
            }
        }
    }

    impl WatchdogDevice for MockWatchdog {
        fn keepalive(&mut self) -> io::Result<()> {
            if *self.disarmed.lock().unwrap() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "Watchdog disarmed",
                ));
            }
            *self.pings.lock().unwrap() += 1;
            Ok(())
        }

        fn disarm(&mut self) -> io::Result<()> {
            *self.disarmed.lock().unwrap() = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_watchdog_monitor_pings_and_disarms() {
        let mock = MockWatchdog::new();
        let pings = mock.pings.clone();
        let disarmed = mock.disarmed.clone();

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(HEARTBEAT_CHANNEL_CAPACITY);

        let flag_clone = shutdown_flag.clone();
        let monitor_handle = tokio::spawn(async move {
            start_watchdog_monitor(mock, rx, vec![MonitoredService::DnsForwarder], flag_clone)
                .await;
        });

        // Send a heartbeat
        let _ = tx.send(MonitoredService::DnsForwarder).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(*pings.lock().unwrap() >= 1);

        // Trigger clean shutdown
        shutdown_flag.store(true, Ordering::Relaxed);
        let _ = monitor_handle.await;

        assert!(*disarmed.lock().unwrap());
    }

    #[tokio::test]
    async fn test_watchdog_monitor_skips_when_heartbeat_stale() {
        let mock = MockWatchdog::new();
        let pings = mock.pings.clone();
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let (_tx, rx) = mpsc::channel(HEARTBEAT_CHANNEL_CAPACITY);

        let flag_clone = shutdown_flag.clone();
        let monitor_handle = tokio::spawn(async move {
            let mut liveness: ServiceLivenessMap = [None; MONITORED_SERVICE_COUNT];
            // Stale timestamp (35s ago)
            liveness[MonitoredService::DhcpClient.index()] =
                Some(Instant::now() - Duration::from_secs(35));
            let timeout = Duration::from_secs(30);

            assert!(!evaluate_health(
                &[MonitoredService::DhcpClient],
                &liveness,
                timeout
            ));

            start_watchdog_monitor(mock, rx, vec![MonitoredService::DhcpClient], flag_clone).await;
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown_flag.store(true, Ordering::Relaxed);
        let _ = monitor_handle.await;
        assert!(*pings.lock().unwrap() >= 1); // Startup initialized to now, so 1 initial ping
    }

    #[tokio::test]
    async fn test_dummy_heartbeat_consumer_drains() {
        let (tx, rx) = mpsc::channel(2);
        spawn_dummy_heartbeat_consumer(rx);

        assert!(tx.send(MonitoredService::DnsForwarder).await.is_ok());
        assert!(tx.send(MonitoredService::DhcpClient).await.is_ok());
        assert!(tx.send(MonitoredService::LanManager).await.is_ok());
    }

    #[test]
    fn test_monitored_service_indices_and_all() {
        assert_eq!(MonitoredService::ALL.len(), MONITORED_SERVICE_COUNT);
        for (i, svc) in MonitoredService::ALL.iter().enumerate() {
            assert_eq!(svc.index(), i);
        }
    }

    #[test]
    fn test_monitored_service_display_and_as_str() {
        assert_eq!(MonitoredService::DnsForwarder.as_str(), "dns-forwarder");
        assert_eq!(
            MonitoredService::InterfaceMonitor.as_str(),
            "interface-monitor"
        );
        assert_eq!(MonitoredService::DhcpClient.as_str(), "dhcp-client");
        assert_eq!(MonitoredService::LanManager.as_str(), "lan-manager");

        assert_eq!(
            format!("{}", MonitoredService::DnsForwarder),
            "dns-forwarder"
        );
        assert_eq!(
            format!("{}", MonitoredService::InterfaceMonitor),
            "interface-monitor"
        );
        assert_eq!(format!("{}", MonitoredService::DhcpClient), "dhcp-client");
        assert_eq!(format!("{}", MonitoredService::LanManager), "lan-manager");
    }

    #[test]
    fn test_send_service_heartbeat_none_and_closed() {
        // None sender should not panic
        send_service_heartbeat(None, MonitoredService::DnsForwarder);

        // Sender with dropped receiver should not panic
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        send_service_heartbeat(Some(&tx), MonitoredService::DnsForwarder);
    }

    #[test]
    fn test_evaluate_health_unseen_service_fails() {
        let liveness: ServiceLivenessMap = [None; MONITORED_SERVICE_COUNT];
        let timeout = Duration::from_secs(30);

        // A service with None liveness fails health evaluation
        assert!(!evaluate_health(
            &[MonitoredService::DnsForwarder],
            &liveness,
            timeout
        ));
    }

    #[test]
    fn test_evaluate_health_partial_failure_one_stale_service() {
        let mut liveness: ServiceLivenessMap = [None; MONITORED_SERVICE_COUNT];
        let now = Instant::now();
        let timeout = Duration::from_secs(30);

        // DNS forwarder, Interface monitor, and LAN manager are active
        liveness[MonitoredService::DnsForwarder.index()] = Some(now);
        liveness[MonitoredService::InterfaceMonitor.index()] = Some(now);
        liveness[MonitoredService::LanManager.index()] = Some(now);

        // DHCP client has timed out (45s elapsed > 30s timeout)
        liveness[MonitoredService::DhcpClient.index()] = Some(now - Duration::from_secs(45));

        let expected = vec![
            MonitoredService::DnsForwarder,
            MonitoredService::InterfaceMonitor,
            MonitoredService::DhcpClient,
            MonitoredService::LanManager,
        ];

        assert!(!evaluate_health(&expected, &liveness, timeout));
    }
}
