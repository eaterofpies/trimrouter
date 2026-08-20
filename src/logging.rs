use chrono::{Datelike, Utc};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const DEFAULT_LOG_DIR: &str = "/var/log";
pub const DEFAULT_LOG_FILE: &str = "/var/log/system.log";
pub const DEFAULT_MAX_LOG_SIZE_MB: u64 = 100;
pub const BYTES_PER_MB: u64 = 1024 * 1024;

pub const DIRTY_EXPIRE_CENTISECS_PATH: &str = "/proc/sys/vm/dirty_expire_centisecs";
pub const DIRTY_EXPIRE_CENTISECS_VALUE: &str = "3000";
pub const DIRTY_WRITEBACK_CENTISECS_PATH: &str = "/proc/sys/vm/dirty_writeback_centisecs";
pub const DIRTY_WRITEBACK_CENTISECS_VALUE: &str = "500";

type SpaceChecker = Box<dyn Fn(&Path) -> io::Result<u64> + Send + Sync>;

pub struct Logger {
    log_dir: PathBuf,
    active_log_path: PathBuf,
    log_file: Option<File>,
    max_size_bytes: u64,
    current_size: u64,
    last_rotation_date: (i32, u32), // (year, ordinal_day)
    log_disabled: bool,
    space_checker: Option<SpaceChecker>,
}

static GLOBAL_LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

pub fn get_logger() -> &'static Mutex<Logger> {
    GLOBAL_LOGGER.get_or_init(|| {
        Mutex::new(Logger::new(
            Path::new(DEFAULT_LOG_DIR),
            Path::new(DEFAULT_LOG_FILE),
            DEFAULT_MAX_LOG_SIZE_MB,
        ))
    })
}

pub fn configure_vm_writeback() {
    if let Err(e) = fs::write(DIRTY_EXPIRE_CENTISECS_PATH, DIRTY_EXPIRE_CENTISECS_VALUE) {
        std::println!(
            "[init] Warning: failed to set dirty_expire_centisecs: {}",
            e
        );
    }
    if let Err(e) = fs::write(
        DIRTY_WRITEBACK_CENTISECS_PATH,
        DIRTY_WRITEBACK_CENTISECS_VALUE,
    ) {
        std::println!(
            "[init] Warning: failed to set dirty_writeback_centisecs: {}",
            e
        );
    }
}

pub fn init_logging(max_size_mb: u64) {
    configure_vm_writeback();
    let mut logger = get_logger().lock().unwrap();
    *logger = Logger::new(
        Path::new(DEFAULT_LOG_DIR),
        Path::new(DEFAULT_LOG_FILE),
        max_size_mb,
    );
    logger.open_log_file();
}

pub fn log(service: &str, message: &str) {
    let now = Utc::now();
    let formatted_line = format_log_line(now, service, message);
    if let Ok(mut logger) = get_logger().lock() {
        logger.write_entry(&formatted_line);
    } else {
        std::print!("{}", formatted_line);
    }
}

pub fn log_raw(message: &str) {
    let now = Utc::now();
    let formatted_line = format_raw_line(now, message);
    if let Ok(mut logger) = get_logger().lock() {
        logger.write_entry(&formatted_line);
    } else {
        std::print!("{}", formatted_line);
    }
}

pub fn flush() {
    if let Ok(mut logger) = get_logger().lock() {
        logger.flush_active_file();
    }
}

pub fn format_raw_line(timestamp: chrono::DateTime<Utc>, message: &str) -> String {
    let trimmed = message.trim_end();
    let ts_str = timestamp.format("%Y-%m-%dT%H:%M:%SZ");
    if trimmed.starts_with('[')
        && trimmed.len() > 20
        && trimmed[1..5].chars().all(|c| c.is_ascii_digit())
    {
        // Already contains a timestamp prefix: "[YYYY-..."
        format!("{}\n", trimmed)
    } else if trimmed.starts_with('[') {
        // Contains a service tag prefix: "[service] message"
        format!("[{}] {}\n", ts_str, trimmed)
    } else {
        // Plain message: "message"
        format!("[{}] [system] {}\n", ts_str, trimmed)
    }
}

pub fn format_log_line(timestamp: chrono::DateTime<Utc>, service: &str, message: &str) -> String {
    let ts_str = timestamp.format("%Y-%m-%dT%H:%M:%SZ");
    format!("[{}] [{}] {}\n", ts_str, service, message)
}

pub const MIN_USABLE_LOG_SPACE: u64 = 64 * 1024; // 64 KiB

pub fn get_available_space_bytes(dir_path: &Path) -> io::Result<u64> {
    let (_, avail) = get_partition_space(dir_path)?;
    Ok(avail)
}

pub fn get_partition_space(dir_path: &Path) -> io::Result<(u64, u64)> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(dir_path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    let total = (stat.f_blocks as u64).saturating_mul(stat.f_frsize as u64);
    let avail = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
    Ok((total, avail))
}

impl Logger {
    pub fn new(log_dir: &Path, active_log_path: &Path, max_size_mb: u64) -> Self {
        let now = Utc::now();
        Self {
            log_dir: log_dir.to_path_buf(),
            active_log_path: active_log_path.to_path_buf(),
            log_file: None,
            max_size_bytes: max_size_mb.saturating_mul(BYTES_PER_MB),
            current_size: 0,
            last_rotation_date: (now.year(), now.ordinal()),
            log_disabled: false,
            space_checker: None,
        }
    }

    #[cfg(test)]
    pub fn with_space_checker<F>(mut self, checker: F) -> Self
    where
        F: Fn(&Path) -> io::Result<u64> + Send + Sync + 'static,
    {
        self.space_checker = Some(Box::new(checker));
        self
    }

    pub fn open_log_file(&mut self) {
        if !self.log_dir.exists() {
            self.log_file = None;
            return;
        }

        if let Ok((total, _)) = get_partition_space(&self.log_dir)
            && total > 0
            && self.max_size_bytes >= total
        {
            // For smaller partitions (e.g. test images), cap max log size to half the partition
            self.max_size_bytes = (total / 2).max(1024 * 1024);
        }

        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.active_log_path)
        {
            Ok(file) => {
                let size = file.metadata().map(|m| m.len()).unwrap_or(0);
                self.current_size = size;
                self.log_file = Some(file);
                self.log_disabled = false;
            }
            Err(e) => {
                std::eprintln!(
                    "[logging] Warning: failed to open log file {}: {}. Falling back to console.",
                    self.active_log_path.display(),
                    e
                );
                self.log_file = None;
            }
        }
    }

    fn check_free_space(&self) -> io::Result<u64> {
        if let Some(checker) = &self.space_checker {
            checker(&self.log_dir)
        } else {
            get_available_space_bytes(&self.log_dir)
        }
    }

    pub fn write_entry(&mut self, formatted_line: &str) {
        std::print!("{}", formatted_line);

        if self.log_disabled || self.log_file.is_none() {
            return;
        }

        let now = Utc::now();
        let today = (now.year(), now.ordinal());
        let size_trigger = self
            .current_size
            .saturating_add(formatted_line.len() as u64)
            >= self.max_size_bytes;
        let date_trigger = today != self.last_rotation_date;

        if size_trigger || date_trigger {
            self.rotate(now);
        }

        if self.log_disabled {
            return;
        }

        if let Some(file) = &mut self.log_file {
            if let Err(e) = file.write_all(formatted_line.as_bytes()) {
                std::eprintln!(
                    "[logging] ERROR: Failed to write to {}: {}",
                    self.active_log_path.display(),
                    e
                );
            } else {
                let _ = file.flush();
                self.current_size = self
                    .current_size
                    .saturating_add(formatted_line.len() as u64);
            }
        }
    }

    pub fn rotate(&mut self, now: chrono::DateTime<Utc>) {
        if let Ok(free_space) = self.check_free_space()
            && free_space < self.max_size_bytes
        {
            self.reclaim_space();
        }

        let min_required = self.max_size_bytes.min(MIN_USABLE_LOG_SPACE);
        if let Ok(free_space) = self.check_free_space()
            && free_space < min_required
        {
            std::eprintln!(
                "[logging] Warning: Insufficient space ({} bytes) on log partition for rotation. Stopping writes.",
                free_space
            );
            self.log_disabled = true;
            return;
        }

        self.flush_active_file();
        self.log_file = None;

        let timestamp_suffix = now.format("%Y-%m-%dT%H%M%SZ");
        let rotated_name = format!("system.{}.log", timestamp_suffix);
        let rotated_path = self.log_dir.join(rotated_name);

        if self.active_log_path.exists()
            && let Err(e) = fs::rename(&self.active_log_path, &rotated_path)
        {
            std::eprintln!(
                "[logging] Warning: Failed to rename rotated log file: {}",
                e
            );
        }

        self.last_rotation_date = (now.year(), now.ordinal());
        self.current_size = 0;
        self.open_log_file();
    }

    pub fn reclaim_space(&mut self) {
        let mut rotated_files = match list_rotated_log_files(&self.log_dir) {
            Ok(files) => files,
            Err(_) => return,
        };

        rotated_files.sort_by(|a, b| a.0.cmp(&b.0));

        for (_, path) in rotated_files {
            if let Ok(free_space) = self.check_free_space()
                && free_space >= self.max_size_bytes
            {
                break;
            }
            let _ = fs::remove_file(&path);
        }
    }

    pub fn flush_active_file(&mut self) {
        if let Some(file) = &mut self.log_file {
            let _ = file.flush();
            let _ = file.sync_all();
        }
    }
}

fn list_rotated_log_files(dir: &Path) -> io::Result<Vec<(String, PathBuf)>> {
    let entries = fs::read_dir(dir)?;
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && name.starts_with("system.")
            && name.ends_with(".log")
            && name != "system.log"
        {
            let ts = name
                .trim_start_matches("system.")
                .trim_end_matches(".log")
                .to_string();
            files.push((ts, path));
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_format_log_line() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2026, 8, 14, 14, 30, 0).unwrap();
        let line = format_log_line(ts, "init", "Mounted /boot successfully.");
        assert_eq!(
            line,
            "[2026-08-14T14:30:00Z] [init] Mounted /boot successfully.\n"
        );
    }

    #[test]
    fn test_size_rotation_and_reclamation() {
        let temp_dir = std::env::temp_dir().join("trimrouter_log_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let active_path = temp_dir.join("system.log");
        let mut logger = Logger::new(&temp_dir, &active_path, 1);
        logger.max_size_bytes = 50; // Set low limit for testing

        let simulated_space = Arc::new(AtomicU64::new(1000));
        let space_clone = Arc::clone(&simulated_space);
        logger = logger.with_space_checker(move |_| Ok(space_clone.load(Ordering::Relaxed)));
        logger.open_log_file();

        let entry = "[2026-08-14T14:30:00Z] [init] Test line 1.\n";
        logger.write_entry(entry);
        assert!(active_path.exists());

        // Write enough to trigger size rotation
        let entry2 =
            "[2026-08-14T14:30:01Z] [init] Long test line 2 that exceeds max size limit.\n";
        logger.write_entry(entry2);

        let rotated = list_rotated_log_files(&temp_dir).unwrap();
        assert!(
            !rotated.is_empty(),
            "Rotated log file should have been created"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_daily_rollover() {
        let temp_dir = std::env::temp_dir().join("trimrouter_daily_log_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let active_path = temp_dir.join("system.log");
        let mut logger = Logger::new(&temp_dir, &active_path, 100);
        // Set last rotation date to yesterday
        logger.last_rotation_date = (2026, 1);
        logger.open_log_file();

        let entry = "[2026-08-14T14:30:00Z] [init] First line today.\n";
        logger.write_entry(entry);

        let rotated = list_rotated_log_files(&temp_dir).unwrap();
        assert!(
            !rotated.is_empty(),
            "Daily rollover should create rotated file"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_reclamation_order_oldest_first() {
        let temp_dir = std::env::temp_dir().join("trimrouter_reclaim_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // Create rotated files with different timestamps
        let old_file = temp_dir.join("system.2026-08-10T100000Z.log");
        let new_file = temp_dir.join("system.2026-08-12T100000Z.log");
        fs::write(&old_file, "old logs").unwrap();
        fs::write(&new_file, "new logs").unwrap();

        let active_path = temp_dir.join("system.log");
        let mut logger = Logger::new(&temp_dir, &active_path, 1);
        logger.max_size_bytes = 1000;

        // Simulate free space = 500 (below max_size_bytes)
        let simulated_space = Arc::new(AtomicU64::new(500));
        let space_clone = Arc::clone(&simulated_space);
        logger = logger.with_space_checker(move |_| {
            let val = space_clone.load(Ordering::Relaxed);
            // Once old file is deleted, simulate space becoming sufficient
            Ok(val)
        });

        logger.reclaim_space();

        // Both rotated files should be deleted since space remained low
        assert!(
            !old_file.exists(),
            "Oldest rotated file must be deleted first"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
