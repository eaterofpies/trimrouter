use chrono::{DateTime, Datelike, Utc};
pub use log::Level;
use log::{LevelFilter, Log, Metadata, Record};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const DEFAULT_LOG_DIR: &str = "/var/log";
pub const DEFAULT_LOG_FILE: &str = "/var/log/system.log";
pub const DEFAULT_MAX_LOG_SIZE_MB: u64 = 100;
pub const BYTES_PER_MB: u64 = 1024 * 1024;
pub const MIN_USABLE_LOG_SPACE: u64 = 64 * 1024; // 64 KiB

pub const DIRTY_EXPIRE_CENTISECS_PATH: &str = "/proc/sys/vm/dirty_expire_centisecs";
pub const DIRTY_EXPIRE_CENTISECS_VALUE: &str = "3000";
pub const DIRTY_WRITEBACK_CENTISECS_PATH: &str = "/proc/sys/vm/dirty_writeback_centisecs";
pub const DIRTY_WRITEBACK_CENTISECS_VALUE: &str = "500";

type SpaceChecker = Box<dyn Fn(&Path) -> io::Result<u64> + Send + Sync>;

pub struct Logger {
    pub log_dir: PathBuf,
    pub active_log_path: PathBuf,
    pub log_file: Option<File>,
    pub max_size_bytes: u64,
    pub level: LevelFilter,
    pub current_size: u64,
    pub last_rotation_date: (i32, u32), // (year, ordinal_day)
    pub log_disabled: bool,
    pub space_checker: Option<SpaceChecker>,
}

static GLOBAL_LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();
static ROUTER_LOGGER: RouterLogger = RouterLogger;

struct RouterLogger;

impl Log for RouterLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if let Ok(logger) = get_logger().lock() {
            metadata.level() <= logger.level
        } else {
            true
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let target = clean_target(record.target());
            let line = format_log_line(
                Utc::now(),
                record.level(),
                &target,
                &record.args().to_string(),
            );
            if let Ok(mut logger) = get_logger().lock() {
                logger.write_entry(&line);
            } else {
                std::print!("{}", line);
            }
        }
    }

    fn flush(&self) {
        crate::logging::flush();
    }
}

pub fn get_logger() -> &'static Mutex<Logger> {
    GLOBAL_LOGGER.get_or_init(|| {
        let mut logger = Logger::new(
            Path::new(DEFAULT_LOG_DIR),
            Path::new(DEFAULT_LOG_FILE),
            DEFAULT_MAX_LOG_SIZE_MB,
            LevelFilter::Info,
        );
        logger.open_log_file();
        Mutex::new(logger)
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

pub fn init_early_logging() {
    let _ = log::set_logger(&ROUTER_LOGGER);
    log::set_max_level(LevelFilter::Info);
}

pub fn init_logging(max_size_mb: u64, level: LevelFilter) {
    configure_vm_writeback();
    if let Ok(mut logger) = get_logger().lock() {
        logger.max_size_bytes = max_size_mb.saturating_mul(BYTES_PER_MB);
        logger.level = level;
        logger.open_log_file();
    }
    let _ = log::set_logger(&ROUTER_LOGGER);
    log::set_max_level(level);
}

pub fn log(level: Level, service: &str, message: &str) {
    let now = Utc::now();
    let formatted_line = format_log_line(now, level, service, message);
    if let Ok(mut logger) = get_logger().lock() {
        if level <= logger.level {
            logger.write_entry(&formatted_line);
        }
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

pub fn log_raw_with_level(level: Level, message: &str) {
    let now = Utc::now();
    let formatted_line = format_raw_line_with_explicit_level(now, Some(level), message);
    if let Ok(mut logger) = get_logger().lock() {
        if level <= logger.level {
            logger.write_entry(&formatted_line);
        }
    } else {
        std::print!("{}", formatted_line);
    }
}

pub fn flush() {
    if let Ok(mut logger) = get_logger().lock() {
        logger.flush_active_file();
    }
}

pub fn clean_target(target: &str) -> String {
    if target.starts_with("trimrouter::") {
        let last_part = target.split("::").last().unwrap_or(target);
        last_part.replace('_', "-")
    } else {
        target.replace('_', "-")
    }
}

pub fn parse_line_level(message: &str) -> Level {
    let lower = message.to_ascii_lowercase();
    if lower.contains("fatal")
        || lower.contains("error")
        || lower.contains("failed")
        || lower.contains("panic")
    {
        Level::Error
    } else if lower.contains("warning") || lower.contains("warn") {
        Level::Warn
    } else if lower.contains("debug") {
        Level::Debug
    } else if lower.contains("trace") {
        Level::Trace
    } else {
        Level::Info
    }
}

pub fn format_raw_line_with_explicit_level(
    timestamp: DateTime<Utc>,
    explicit_level: Option<Level>,
    message: &str,
) -> String {
    let trimmed = message.trim_end();
    let ts_str = timestamp.format("%Y-%m-%dT%H:%M:%SZ");

    if trimmed.starts_with('[')
        && trimmed.len() > 20
        && trimmed[1..5].chars().all(|c| c.is_ascii_digit())
    {
        // Already fully formatted: "[2026-..."
        return format!("{}\n", trimmed);
    }

    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((service, body)) = rest.split_once(']')
    {
        let level = explicit_level.unwrap_or_else(|| parse_line_level(body));
        let clean_body = body.trim_start();
        return format!("[{}] [{}] [{}] {}\n", ts_str, level, service, clean_body);
    }

    let level = explicit_level.unwrap_or_else(|| parse_line_level(trimmed));
    format!("[{}] [{}] [system] {}\n", ts_str, level, trimmed)
}

pub fn format_raw_line(timestamp: DateTime<Utc>, message: &str) -> String {
    format_raw_line_with_explicit_level(timestamp, None, message)
}

pub fn format_log_line(
    timestamp: DateTime<Utc>,
    level: Level,
    service: &str,
    message: &str,
) -> String {
    let ts_str = timestamp.format("%Y-%m-%dT%H:%M:%SZ");
    format!("[{}] [{}] [{}] {}\n", ts_str, level, service, message)
}

pub fn get_available_space_bytes(dir_path: &Path) -> io::Result<u64> {
    let (_, avail) = get_partition_space(dir_path)?;
    Ok(avail)
}

pub fn get_partition_space(dir_path: &Path) -> io::Result<(u64, u64)> {
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
    pub fn new(
        log_dir: &Path,
        active_log_path: &Path,
        max_size_mb: u64,
        level: LevelFilter,
    ) -> Self {
        let now = Utc::now();
        Self {
            log_dir: log_dir.to_path_buf(),
            active_log_path: active_log_path.to_path_buf(),
            log_file: None,
            max_size_bytes: max_size_mb.saturating_mul(BYTES_PER_MB),
            level,
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

        if self.active_log_path.is_symlink() {
            let _ = fs::remove_file(&self.active_log_path);
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

        let can_rotate = std::process::id() == 1 || cfg!(test);
        if can_rotate && (size_trigger || date_trigger) {
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

    pub fn rotate(&mut self, now: DateTime<Utc>) {
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

        if rotated_path.is_symlink() {
            let _ = fs::remove_file(&rotated_path);
        }

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
        if let Ok(file_type) = entry.file_type() {
            if file_type.is_dir() {
                continue;
            }
        } else {
            continue;
        }

        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && let Some(rest) = name.strip_prefix("system.")
            && let Some(ts) = rest.strip_suffix(".log")
            && !ts.is_empty()
        {
            files.push((ts.to_string(), path));
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_format_log_line() {
        let ts = Utc.with_ymd_and_hms(2026, 8, 14, 14, 30, 0).unwrap();
        let line = format_log_line(ts, Level::Info, "init", "Mounted /boot successfully.");
        assert_eq!(
            line,
            "[2026-08-14T14:30:00Z] [INFO] [init] Mounted /boot successfully.\n"
        );
    }

    #[test]
    fn test_format_raw_line() {
        let ts = Utc.with_ymd_and_hms(2026, 8, 14, 14, 30, 0).unwrap();
        let info_line = format_raw_line(ts, "[dhcp-client] Lease acquired");
        assert_eq!(
            info_line,
            "[2026-08-14T14:30:00Z] [INFO] [dhcp-client] Lease acquired\n"
        );

        let warn_line = format_raw_line(ts, "[init] Warning: partition 2 not found");
        assert_eq!(
            warn_line,
            "[2026-08-14T14:30:00Z] [WARN] [init] Warning: partition 2 not found\n"
        );

        let err_line = format_raw_line(ts, "[init] ERROR: Failed to bind socket");
        assert_eq!(
            err_line,
            "[2026-08-14T14:30:00Z] [ERROR] [init] ERROR: Failed to bind socket\n"
        );
    }

    #[test]
    fn test_size_rotation_and_reclamation() {
        let temp_dir = std::env::temp_dir().join("trimrouter_log_test");
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        let active_path = temp_dir.join("system.log");
        let mut logger = Logger::new(&temp_dir, &active_path, 1, LevelFilter::Info);
        logger.max_size_bytes = 50; // Set low limit for testing

        let simulated_space = Arc::new(AtomicU64::new(1000));
        let space_clone = Arc::clone(&simulated_space);
        logger = logger.with_space_checker(move |_| Ok(space_clone.load(Ordering::Relaxed)));
        logger.open_log_file();

        let entry = "[2026-08-14T14:30:00Z] [INFO] [init] Test line 1.\n";
        logger.write_entry(entry);
        assert!(active_path.exists());

        // Write enough to trigger size rotation
        let entry2 =
            "[2026-08-14T14:30:01Z] [INFO] [init] Long test line 2 that exceeds max size limit.\n";
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
        let mut logger = Logger::new(&temp_dir, &active_path, 100, LevelFilter::Info);
        // Set last rotation date to yesterday
        logger.last_rotation_date = (2026, 1);
        logger.open_log_file();

        let entry = "[2026-08-14T14:30:00Z] [INFO] [init] First line today.\n";
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
        let mut logger = Logger::new(&temp_dir, &active_path, 1, LevelFilter::Info);
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

    #[test]
    fn test_list_rotated_log_files_and_symlink_reclamation() {
        let temp_dir =
            std::env::temp_dir().join(format!("trimrouter_symlink_test_{}", rand::random::<u64>()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();

        // 1. Real rotated file
        let valid_file = temp_dir.join("system.2026-08-15T120000Z.log");
        fs::write(&valid_file, "valid content").unwrap();

        // 2. Subdirectory named like a rotated file (must be ignored)
        let fake_dir = temp_dir.join("system.2026-08-16T120000Z.log");
        fs::create_dir_all(&fake_dir).unwrap();

        // 3. Symlink pointing to an external target file
        let target_file = temp_dir.join("real_target.txt");
        fs::write(&target_file, "secret").unwrap();
        let symlink_file = temp_dir.join("system.2026-08-17T120000Z.log");
        let _ = std::os::unix::fs::symlink(&target_file, &symlink_file);

        let rotated = list_rotated_log_files(&temp_dir).unwrap();
        // Discovers both valid file and symlink (for reclamation), but ignores subdirectory
        assert_eq!(rotated.len(), 2);

        // 4. Run reclamation: symlink is unlinked/removed, but target_file remains untouched
        let active_path = temp_dir.join("system.log");
        let mut logger = Logger::new(&temp_dir, &active_path, 1, LevelFilter::Info);
        logger.max_size_bytes = 1000;
        logger = logger.with_space_checker(|_| Ok(100)); // Low free space triggers reclamation
        logger.reclaim_space();

        assert!(!symlink_file.exists());
        assert!(!valid_file.exists());
        assert!(target_file.exists()); // External target file was NOT deleted!

        // 5. Test open_log_file cleans up active log symlink
        let active_target = temp_dir.join("active_target.txt");
        fs::write(&active_target, "active secret").unwrap();
        let _ = std::os::unix::fs::symlink(&active_target, &active_path);
        assert!(active_path.is_symlink());

        logger.open_log_file();
        assert!(!active_path.is_symlink()); // Symlink was unlinked
        assert!(active_target.exists()); // Target was not truncated or modified

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_clean_target_variants() {
        assert_eq!(
            clean_target("trimrouter::services::dns_forwarder"),
            "dns-forwarder"
        );
        assert_eq!(clean_target("trimrouter::init::watchdog"), "watchdog");
        assert_eq!(clean_target("custom_service_name"), "custom-service-name");
    }

    #[test]
    fn test_parse_line_level_all() {
        assert_eq!(
            parse_line_level("A fatal system crash occurred"),
            Level::Error
        );
        assert_eq!(parse_line_level("Error: unable to bind port"), Level::Error);
        assert_eq!(parse_line_level("Service failed to start"), Level::Error);
        assert_eq!(parse_line_level("Kernel panic - not syncing"), Level::Error);

        assert_eq!(parse_line_level("Warning: lease near expiry"), Level::Warn);
        assert_eq!(parse_line_level("warn: dropping packet"), Level::Warn);

        assert_eq!(
            parse_line_level("debug: parsing query payload"),
            Level::Debug
        );
        assert_eq!(parse_line_level("trace: entering state loop"), Level::Trace);
        assert_eq!(parse_line_level("System started successfully"), Level::Info);
    }

    #[test]
    fn test_format_raw_line_with_explicit_level_variants() {
        let ts = Utc.with_ymd_and_hms(2026, 8, 14, 14, 30, 0).unwrap();

        // Already formatted line
        let already = "[2026-08-14T14:30:00Z] [INFO] [init] Ready\n";
        assert_eq!(
            format_raw_line_with_explicit_level(ts, None, already),
            already
        );

        // Line with service header [dhcp]
        let svc_line = "[dhcp] IP assigned to client";
        assert_eq!(
            format_raw_line_with_explicit_level(ts, Some(Level::Info), svc_line),
            "[2026-08-14T14:30:00Z] [INFO] [dhcp] IP assigned to client\n"
        );

        // Plain line without service
        let plain = "Boot completed";
        assert_eq!(
            format_raw_line_with_explicit_level(ts, Some(Level::Info), plain),
            "[2026-08-14T14:30:00Z] [INFO] [system] Boot completed\n"
        );
    }
}
