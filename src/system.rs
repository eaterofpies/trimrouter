use crate::error::RouterError;
use nix::mount::MsFlags;
use nix::sys::reboot::RebootMode;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::fs;
use std::panic;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub trait SystemOps: Send + Sync + 'static {
    fn mount(
        &self,
        source: Option<&str>,
        target: &str,
        fstype: &str,
        flags: MsFlags,
        data: Option<&str>,
    ) -> Result<(), nix::Error>;

    fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error>;

    fn waitpid(
        &self,
        pid: Option<Pid>,
        options: Option<WaitPidFlag>,
    ) -> Result<WaitStatus, nix::Error>;

    fn read_cmdline(&self) -> Result<String, std::io::Error>;

    fn getpid(&self) -> Pid;
}

pub struct RealSystem;

impl SystemOps for RealSystem {
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
        nix::mount::mount(source, target, Some(fstype), flags, data)
    }

    fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error> {
        nix::sys::reboot::reboot(mode).map(|_| ())
    }

    fn waitpid(
        &self,
        pid: Option<Pid>,
        options: Option<WaitPidFlag>,
    ) -> Result<WaitStatus, nix::Error> {
        nix::sys::wait::waitpid(pid, options)
    }

    fn read_cmdline(&self) -> Result<String, std::io::Error> {
        fs::read_to_string("/proc/cmdline")
    }

    fn getpid(&self) -> Pid {
        nix::unistd::getpid()
    }
}

pub fn mount_virtual_filesystems<S: SystemOps>(sys: &S) -> Result<(), RouterError> {
    println!("[init] Mounting virtual filesystems...");

    sys.mount(None, "/proc", "proc", MsFlags::empty(), None)
        .map_err(|e| RouterError::Generic(format!("Failed to mount /proc: {}", e)))?;
    println!("[init] Mounted /proc successfully.");

    sys.mount(None, "/sys", "sysfs", MsFlags::empty(), None)
        .map_err(|e| RouterError::Generic(format!("Failed to mount /sys: {}", e)))?;
    println!("[init] Mounted /sys successfully.");

    sys.mount(None, "/dev", "devtmpfs", MsFlags::empty(), None)
        .map_err(|e| RouterError::Generic(format!("Failed to mount /dev: {}", e)))?;
    println!("[init] Mounted /dev successfully.");

    sys.mount(None, "/run", "tmpfs", MsFlags::empty(), None)
        .map_err(|e| RouterError::Generic(format!("Failed to mount /run: {}", e)))?;
    println!("[init] Mounted /run successfully.");

    // Set kernel modprobe helper path to trigger lazy loading
    if let Err(e) = fs::write("/proc/sys/kernel/modprobe", "/sbin/modprobe") {
        println!(
            "[init] Warning: Failed to set /proc/sys/kernel/modprobe: {}",
            e
        );
    } else {
        println!("[init] Configured kernel modprobe path to /sbin/modprobe.");
    }

    Ok(())
}

const BOOT_MOUNT_POINT: &str = "/boot";
const BOOT_DEVICE_CANDIDATES: &[&str] = &["/dev/vda1", "/dev/mmcblk0p1", "/dev/sda1"];
const BOOT_MOUNT_TIMEOUT: Duration = Duration::from_secs(15);
const BOOT_MOUNT_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn try_mount_candidates<S: SystemOps>(sys: &S) -> Option<String> {
    for dev in BOOT_DEVICE_CANDIDATES {
        if Path::new(dev).exists()
            && sys
                .mount(
                    Some(*dev),
                    BOOT_MOUNT_POINT,
                    "vfat",
                    MsFlags::MS_RDONLY,
                    None,
                )
                .is_ok()
        {
            return Some((*dev).to_string());
        }
    }
    None
}

pub fn mount_boot_partition<S: SystemOps>(sys: &S) -> Result<(), RouterError> {
    if sys.getpid() != Pid::from_raw(1) {
        return Ok(());
    }

    if let Err(e) = fs::create_dir_all(BOOT_MOUNT_POINT) {
        println!(
            "[init] Warning: failed to create {} directory: {}",
            BOOT_MOUNT_POINT, e
        );
        return Ok(());
    }

    let start = Instant::now();
    let mut mounted_device = None;

    println!("[init] Waiting for boot partition to become available...");

    while start.elapsed() < BOOT_MOUNT_TIMEOUT {
        if let Some(dev) = try_mount_candidates(sys) {
            mounted_device = Some(dev);
            break;
        }
        thread::sleep(BOOT_MOUNT_POLL_INTERVAL);
    }

    let Some(dev) = mounted_device else {
        return Err(RouterError::from(
            "Timeout reached. Could not find or mount boot partition from any candidate device.",
        ));
    };

    println!(
        "[init] Successfully mounted {} on {} as read-only.",
        dev, BOOT_MOUNT_POINT
    );

    Ok(())
}

use std::sync::atomic::AtomicI32;

// -1 = infinite (default), >=0 = delay in seconds
pub static REBOOT_DELAY: AtomicI32 = AtomicI32::new(-1);

fn log_panic_info(info: &std::panic::PanicHookInfo<'_>) {
    eprintln!("====================================================");
    eprintln!("CRITICAL: TRIMROUTER PANICKED!");
    if let Some(s) = info.payload().downcast_ref::<&str>() {
        eprintln!("Panic Cause: {}", s);
    } else if let Some(s) = info.payload().downcast_ref::<String>() {
        eprintln!("Panic Cause: {}", s);
    } else {
        eprintln!("Panic Cause: Unknown");
    }
    if let Some(loc) = info.location() {
        eprintln!("Location: {}:{}:{}", loc.file(), loc.line(), loc.column());
    }
    eprintln!("====================================================");
}

fn halt_on_panic<S: SystemOps>(sys: &S) {
    if sys.getpid() != Pid::from_raw(1) {
        return;
    }
    let delay = REBOOT_DELAY.load(std::sync::atomic::Ordering::Relaxed);

    if delay >= 0 {
        eprintln!("[init] Rebooting in {} seconds...", delay);
        std::thread::sleep(Duration::from_secs(delay as u64));
        eprintln!("[init] Rebooting system now...");
        let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
    } else {
        eprintln!("[init] System halted. Hanging indefinitely on panic...");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

pub fn register_panic_handler<S: SystemOps>(sys: Arc<S>) {
    panic::set_hook(Box::new(move |info| {
        log_panic_info(info);
        halt_on_panic(sys.as_ref());
    }));
}

#[cfg(test)]
pub mod mock {
    use super::*;
    use std::sync::Mutex;

    type MountCall = (Option<String>, String, String, MsFlags);

    pub struct MockSystem {
        pub pid: Pid,
        pub cmdline_content: String,
        pub mount_calls: Mutex<Vec<MountCall>>,
        pub reboot_call: Mutex<Option<RebootMode>>,
        pub waitpid_results: Mutex<Vec<Result<WaitStatus, nix::Error>>>,
    }

    impl MockSystem {
        pub fn new() -> Self {
            MockSystem {
                pid: Pid::from_raw(1),
                cmdline_content: "".to_string(),
                mount_calls: Mutex::new(Vec::new()),
                reboot_call: Mutex::new(None),
                waitpid_results: Mutex::new(Vec::new()),
            }
        }
    }

    impl SystemOps for MockSystem {
        fn mount(
            &self,
            source: Option<&str>,
            target: &str,
            fstype: &str,
            flags: MsFlags,
            _data: Option<&str>,
        ) -> Result<(), nix::Error> {
            self.mount_calls.lock().unwrap().push((
                source.map(|s| s.to_string()),
                target.to_string(),
                fstype.to_string(),
                flags,
            ));
            Ok(())
        }

        fn reboot(&self, mode: RebootMode) -> Result<(), nix::Error> {
            *self.reboot_call.lock().unwrap() = Some(mode);
            Ok(())
        }

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

        fn read_cmdline(&self) -> Result<String, std::io::Error> {
            if self.cmdline_content.is_empty() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "No cmdline mock",
                ))
            } else {
                Ok(self.cmdline_content.clone())
            }
        }

        fn getpid(&self) -> Pid {
            self.pid
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
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[0].1, "/proc");
        assert_eq!(calls[0].2, "proc");
        assert_eq!(calls[1].1, "/sys");
        assert_eq!(calls[1].2, "sysfs");
        assert_eq!(calls[2].1, "/dev");
        assert_eq!(calls[2].2, "devtmpfs");
        assert_eq!(calls[3].1, "/run");
        assert_eq!(calls[3].2, "tmpfs");
    }

    #[test]
    fn test_mount_boot_partition_failure() {
        let sys = MockSystem::new();
        let result = mount_boot_partition(&sys);
        assert!(result.is_err());
        let calls = sys.mount_calls.lock().unwrap();
        assert!(calls.is_empty());
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
}
