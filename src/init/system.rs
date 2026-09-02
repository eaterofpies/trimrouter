use crate::error::RouterError;
use log::{error, info, warn};
use nix::mount::MsFlags;
use nix::sys::reboot::RebootMode;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::fs;
use std::panic;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::Duration;

pub trait MountOps: Send + Sync + 'static {
    fn mount(
        &self,
        source: Option<&str>,
        target: &str,
        fstype: &str,
        flags: MsFlags,
        data: Option<&str>,
    ) -> Result<(), nix::Error>;
}

pub trait PowerOps: Send + Sync + 'static {
    fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error>;
    fn sync(&self);
}

pub trait ProcessOps: Send + Sync + 'static {
    fn waitpid(
        &self,
        pid: Option<Pid>,
        options: Option<WaitPidFlag>,
    ) -> Result<WaitStatus, nix::Error>;

    fn getpid(&self) -> Pid;
}

pub trait ConfigReaderOps: Send + Sync + 'static {
    fn read_config_file(&self) -> Result<String, std::io::Error>;
}

pub trait SystemOps: MountOps + PowerOps + ProcessOps + ConfigReaderOps {}
impl<T: MountOps + PowerOps + ProcessOps + ConfigReaderOps + ?Sized> SystemOps for T {}

pub struct RealSystem;

impl MountOps for RealSystem {
    fn mount(
        &self,
        source: Option<&str>,
        target: &str,
        fstype: &str,
        flags: MsFlags,
        data: Option<&str>,
    ) -> Result<(), nix::Error> {
        if self.getpid() != Pid::from_raw(1) {
            println!(
                "[sys] Skipping mount of {} -> {} (not PID 1)",
                fstype, target
            );
            return Ok(());
        }
        let _ = fs::create_dir_all(target);
        nix::mount::mount(source, target, Some(fstype), flags, data)
    }
}

impl PowerOps for RealSystem {
    fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error> {
        nix::sys::reboot::reboot(mode).map(|_| ())
    }

    fn sync(&self) {
        unsafe {
            libc::sync();
        }
    }
}

impl ProcessOps for RealSystem {
    fn waitpid(
        &self,
        pid: Option<Pid>,
        options: Option<WaitPidFlag>,
    ) -> Result<WaitStatus, nix::Error> {
        nix::sys::wait::waitpid(pid, options)
    }

    fn getpid(&self) -> Pid {
        nix::unistd::getpid()
    }
}

impl ConfigReaderOps for RealSystem {
    fn read_config_file(&self) -> Result<String, std::io::Error> {
        fs::read_to_string("/boot/config/trimrouter.toml")
    }
}

pub const RUN_TMPFS_DATA: &str = "size=8M,mode=0755";
pub const TMP_TMPFS_DATA: &str = "size=16M,mode=1777";

pub fn mount_virtual_filesystems<S: MountOps>(sys: &S) -> Result<(), RouterError> {
    info!("[init] Mounting virtual filesystems...");

    sys.mount(None, "/proc", "proc", MsFlags::empty(), None)
        .map_err(|e| RouterError::Generic(format!("Failed to mount /proc: {}", e)))?;
    info!("[init] Mounted /proc successfully.");

    sys.mount(None, "/sys", "sysfs", MsFlags::empty(), None)
        .map_err(|e| RouterError::Generic(format!("Failed to mount /sys: {}", e)))?;
    info!("[init] Mounted /sys successfully.");

    sys.mount(None, "/dev", "devtmpfs", MsFlags::empty(), None)
        .map_err(|e| RouterError::Generic(format!("Failed to mount /dev: {}", e)))?;
    info!("[init] Mounted /dev successfully.");

    sys.mount(
        None,
        "/run",
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(RUN_TMPFS_DATA),
    )
    .map_err(|e| RouterError::Generic(format!("Failed to mount /run: {}", e)))?;
    info!(
        "[init] Mounted /run successfully (tmpfs quota: {}).",
        RUN_TMPFS_DATA
    );

    sys.mount(
        None,
        "/tmp",
        "tmpfs",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(TMP_TMPFS_DATA),
    )
    .map_err(|e| RouterError::Generic(format!("Failed to mount /tmp: {}", e)))?;
    info!(
        "[init] Mounted /tmp successfully (tmpfs quota: {}).",
        TMP_TMPFS_DATA
    );

    // Set kernel modprobe helper path to trigger lazy loading
    if let Err(e) = fs::write("/proc/sys/kernel/modprobe", "/sbin/modprobe") {
        warn!(
            "[init] Warning: Failed to set /proc/sys/kernel/modprobe: {}",
            e
        );
    } else {
        info!("[init] Configured kernel modprobe path to /sbin/modprobe.");
    }

    Ok(())
}

pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
pub const RESOLV_CONF_CONTENT: &str = "nameserver 127.0.0.1\n";

pub fn setup_resolv_conf_at_path(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, RESOLV_CONF_CONTENT)?;
    fs::rename(&tmp_path, path)
}

pub fn setup_resolv_conf<S: ProcessOps>(sys: &S) -> Result<(), std::io::Error> {
    if sys.getpid() != Pid::from_raw(1) {
        info!("[init] Skipping /etc/resolv.conf setup (not PID 1)");
        return Ok(());
    }
    info!(
        "[init] Configuring {} with local DNS forwarder...",
        RESOLV_CONF_PATH
    );
    setup_resolv_conf_at_path(Path::new(RESOLV_CONF_PATH))
}

// -1 = infinite (default), >=0 = delay in seconds
pub static REBOOT_DELAY: AtomicI32 = AtomicI32::new(-1);

fn log_panic_info(info: &std::panic::PanicHookInfo<'_>) {
    error!("====================================================");
    error!("CRITICAL: TRIMROUTER PANICKED!");
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        error!("Panic Cause: {}", s);
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        error!("Panic Cause: {}", s);
    } else {
        error!("Panic Cause: Unknown");
    }
    if let Some(loc) = info.location() {
        error!("Location: {}:{}:{}", loc.file(), loc.line(), loc.column());
    }
    error!("====================================================");
    crate::logging::flush();
}

fn halt_on_panic<S: PowerOps + ProcessOps>(sys: &S) {
    if sys.getpid() != Pid::from_raw(1) {
        return;
    }
    crate::logging::flush();
    sys.sync();

    let delay = REBOOT_DELAY.load(Ordering::Relaxed);
    if delay >= 0 {
        error!("[init] Rebooting in {} seconds...", delay);
        crate::logging::flush();
        sys.sync();
        thread::sleep(Duration::from_secs(delay as u64));
        error!("[init] Rebooting system now...");
        crate::logging::flush();
        sys.sync();
        let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
    } else {
        error!("[init] System halted. Hanging indefinitely on panic...");
        crate::logging::flush();
        sys.sync();
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }
}

pub fn register_panic_handler<S: PowerOps + ProcessOps>(sys: Arc<S>) {
    panic::set_hook(Box::new(move |info| {
        log_panic_info(info);
        halt_on_panic(sys.as_ref());
    }));
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MountCall {
        pub source: Option<String>,
        pub target: String,
        pub fstype: String,
        pub flags: MsFlags,
        pub data: Option<String>,
    }

    pub struct MockSystem {
        pub pid: Pid,
        pub config_content: String,
        pub mount_calls: Mutex<Vec<MountCall>>,
        pub reboot_call: Mutex<Option<RebootMode>>,
        pub sync_calls: Mutex<usize>,
        pub waitpid_results: Mutex<Vec<Result<WaitStatus, nix::Error>>>,
    }

    impl Default for MockSystem {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockSystem {
        pub fn new() -> Self {
            MockSystem {
                pid: Pid::from_raw(1),
                config_content: "".to_string(),
                mount_calls: Mutex::new(Vec::new()),
                reboot_call: Mutex::new(None),
                sync_calls: Mutex::new(0),
                waitpid_results: Mutex::new(Vec::new()),
            }
        }
    }

    impl MountOps for MockSystem {
        fn mount(
            &self,
            source: Option<&str>,
            target: &str,
            fstype: &str,
            flags: MsFlags,
            data: Option<&str>,
        ) -> Result<(), nix::Error> {
            self.mount_calls.lock().unwrap().push(MountCall {
                source: source.map(|s| s.to_string()),
                target: target.to_string(),
                fstype: fstype.to_string(),
                flags,
                data: data.map(|d| d.to_string()),
            });
            Ok(())
        }
    }

    impl PowerOps for MockSystem {
        fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error> {
            *self.reboot_call.lock().unwrap() = Some(mode);
            Ok(())
        }

        fn sync(&self) {
            *self.sync_calls.lock().unwrap() += 1;
        }
    }

    impl ProcessOps for MockSystem {
        fn waitpid(
            &self,
            _pid: Option<Pid>,
            _options: Option<WaitPidFlag>,
        ) -> Result<WaitStatus, nix::Error> {
            let mut list = self.waitpid_results.lock().unwrap();
            if list.is_empty() {
                Ok(WaitStatus::StillAlive)
            } else {
                list.remove(0)
            }
        }

        fn getpid(&self) -> Pid {
            self.pid
        }
    }

    impl ConfigReaderOps for MockSystem {
        fn read_config_file(&self) -> Result<String, std::io::Error> {
            if self.config_content.is_empty() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No config mock",
                ))
            } else {
                Ok(self.config_content.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockSystem;
    use super::*;
    #[test]
    fn test_vfs_mounting() {
        let sys = MockSystem::new();
        let result = mount_virtual_filesystems(&sys);

        assert!(result.is_ok());
        let calls = sys.mount_calls.lock().unwrap();
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[0].target, "/proc");
        assert_eq!(calls[0].fstype, "proc");
        assert_eq!(calls[1].target, "/sys");
        assert_eq!(calls[1].fstype, "sysfs");
        assert_eq!(calls[2].target, "/dev");
        assert_eq!(calls[2].fstype, "devtmpfs");
        assert_eq!(calls[3].target, "/run");
        assert_eq!(calls[3].fstype, "tmpfs");
        assert_eq!(calls[3].data.as_deref(), Some(RUN_TMPFS_DATA));
        assert!(calls[3].flags.contains(MsFlags::MS_NOSUID));
        assert!(calls[3].flags.contains(MsFlags::MS_NODEV));
        assert_eq!(calls[4].target, "/tmp");
        assert_eq!(calls[4].fstype, "tmpfs");
        assert_eq!(calls[4].data.as_deref(), Some(TMP_TMPFS_DATA));
        assert!(calls[4].flags.contains(MsFlags::MS_NOSUID));
        assert!(calls[4].flags.contains(MsFlags::MS_NODEV));
    }

    #[test]
    fn test_hang_on_panic() {
        let mut sys = MockSystem::new();
        // Set PID to non-1 so it returns from panic hook without infinite sleeping
        sys.pid = Pid::from_raw(99);
        let sys = Arc::new(sys);

        register_panic_handler(sys.clone());

        let handle = std::thread::spawn(move || {
            panic!("Test panic exception");
        });

        let _ = handle.join(); // This will return immediately now

        let reboot_called = sys.reboot_call.lock().unwrap();
        assert_eq!(*reboot_called, None);
    }

    #[test]
    fn test_setup_resolv_conf_skipped_when_not_pid1() {
        let mut sys = MockSystem::new();
        sys.pid = Pid::from_raw(42);
        let res = setup_resolv_conf(&sys);
        assert!(res.is_ok());
    }

    #[test]
    fn test_setup_resolv_conf_at_path() {
        let temp_dir = std::env::temp_dir().join(format!(
            "trimrouter_test_resolv_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let resolv_path = temp_dir.join("resolv.conf");
        let res = setup_resolv_conf_at_path(&resolv_path);
        assert!(res.is_ok());
        let content = fs::read_to_string(&resolv_path).unwrap();
        assert_eq!(content, RESOLV_CONF_CONTENT);
        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_real_system_basic_methods() {
        let sys = RealSystem;
        let pid = sys.getpid();
        assert!(pid.as_raw() > 0);
        sys.sync();
    }

    #[test]
    fn test_mock_system_read_config_empty_returns_err() {
        let sys = MockSystem::new();
        assert!(sys.read_config_file().is_err());
    }
}
