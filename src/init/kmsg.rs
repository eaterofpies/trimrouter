use crate::logging::Level;
use log::debug;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::task;

pub const KMSG_DEVICE_PATH: &str = "/dev/kmsg";
pub const KMSG_READ_BUFFER_SIZE: usize = 4096;
pub const KERNEL_LOG_TAG: &str = "kernel";

/// Syslog severity levels (lower 3 bits of kmsg priority prefix)
const KLOG_SEV_MASK: u32 = 7;
const KLOG_SEV_ERR_MAX: u32 = 3;
const KLOG_SEV_WARN: u32 = 4;
const KLOG_SEV_DEBUG: u32 = 7;

/// Parses a raw kernel log buffer record from `/dev/kmsg`.
///
/// Linux `/dev/kmsg` records follow the format:
/// `<prio>,<seq>,<timestamp_us>,<flags>;<message>\n[optional key-value metadata...]`
pub fn parse_kmsg_record(raw: &[u8]) -> Option<(Level, String)> {
    let text = std::str::from_utf8(raw).ok()?;
    let (header, rest) = text.split_once(';')?;
    let prio_str = header.split(',').next()?;
    let prio: u32 = prio_str.parse().ok()?;

    let level = match prio & KLOG_SEV_MASK {
        0..=KLOG_SEV_ERR_MAX => Level::Error,
        KLOG_SEV_WARN => Level::Warn,
        KLOG_SEV_DEBUG => Level::Debug,
        _ => Level::Info,
    };

    let msg_line = rest.lines().next()?.trim();
    if msg_line.is_empty() {
        return None;
    }

    Some((level, msg_line.to_string()))
}

/// Spawns the kernel message stream reader task.
pub fn start_kmsg_logger(shutdown_flag: Arc<AtomicBool>) -> task::JoinHandle<()> {
    task::spawn_blocking(move || {
        run_kmsg_reader(Path::new(KMSG_DEVICE_PATH), shutdown_flag);
    })
}

fn run_kmsg_reader(kmsg_path: &Path, shutdown_flag: Arc<AtomicBool>) {
    let mut file = match File::open(kmsg_path) {
        Ok(f) => f,
        Err(e) => {
            debug!(
                "[kmsg] Kernel message device {} unavailable: {}",
                kmsg_path.display(),
                e
            );
            return;
        }
    };

    let mut buf = [0u8; KMSG_READ_BUFFER_SIZE];
    while !shutdown_flag.load(Ordering::Relaxed) {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Some((level, msg)) = parse_kmsg_record(&buf[..n]) {
                    let formatted = format!("[{}] {}", KERNEL_LOG_TAG, msg);
                    crate::logging::log_raw_with_level(level, &formatted);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                debug!("[kmsg] Kernel log streaming stopped: {}", e);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_kmsg_record_info_with_metadata() {
        let raw = b"6,339,5140900,-;eth0: Link is Up - 1000Mbps/Full - flow control off\n SUBSYSTEM=net\n DEVICE=+net:eth0\n";
        let (level, msg) = parse_kmsg_record(raw).unwrap();
        assert_eq!(level, Level::Info);
        assert_eq!(msg, "eth0: Link is Up - 1000Mbps/Full - flow control off");
    }

    #[test]
    fn test_parse_kmsg_record_warning() {
        let raw = b"4,512,1234567,-;ACPI: thermal zone warning threshold reached\n";
        let (level, msg) = parse_kmsg_record(raw).unwrap();
        assert_eq!(level, Level::Warn);
        assert_eq!(msg, "ACPI: thermal zone warning threshold reached");
    }

    #[test]
    fn test_parse_kmsg_record_error_severities() {
        // Priority 0 (Emergency), 1 (Alert), 2 (Critical), 3 (Error)
        for prio in 0..=3 {
            let raw = format!("{},10,999,-;Kernel filesystem error\n", prio);
            let (level, msg) = parse_kmsg_record(raw.as_bytes()).unwrap();
            assert_eq!(level, Level::Error);
            assert_eq!(msg, "Kernel filesystem error");
        }
    }

    #[test]
    fn test_parse_kmsg_record_debug() {
        let raw = b"7,12,88888,-;pci 0000:00:01.0: reg 0x10: [io 0x1000-0x101f]\n";
        let (level, msg) = parse_kmsg_record(raw).unwrap();
        assert_eq!(level, Level::Debug);
        assert_eq!(msg, "pci 0000:00:01.0: reg 0x10: [io 0x1000-0x101f]");
    }

    #[test]
    fn test_parse_kmsg_record_malformed_and_empty() {
        assert!(parse_kmsg_record(b"").is_none());
        assert!(parse_kmsg_record(b"invalid format without semicolon").is_none());
        assert!(parse_kmsg_record(b"not_a_number,123,456,-;Message").is_none());
        assert!(parse_kmsg_record(b"6,123,456,-;   \n").is_none());
    }

    #[test]
    fn test_kmsg_reader_graceful_exit_when_device_missing() {
        let nonexistent = Path::new("/tmp/nonexistent_kmsg_test");
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        run_kmsg_reader(nonexistent, shutdown_flag);
    }

    #[test]
    fn test_kmsg_reader_processes_records_from_file() {
        let temp_dir =
            std::env::temp_dir().join(format!("trimrouter_kmsg_test_{}", rand::random::<u64>()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mock_kmsg = temp_dir.join("kmsg");
        let unique_id = rand::random::<u64>();
        let record = format!("6,100,12345,-;e1000: Link is Up (test {})\n", unique_id);
        std::fs::write(&mock_kmsg, record).unwrap();

        crate::logging::init_early_logging();
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        run_kmsg_reader(&mock_kmsg, shutdown_flag);

        let logs = crate::logging::get_recent_logs(20, None);
        assert!(
            logs.iter()
                .any(|l| l.contains("[kernel]") && l.contains(&unique_id.to_string())),
            "Expected parsed kmsg record logged with [kernel] tag in ring buffer"
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
