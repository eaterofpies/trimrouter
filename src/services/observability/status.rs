use crate::services::ipc::{DhcpLeaseInfo, DnsStatsInfo};
use crate::services::utils::{WanLease, mask_to_prefix_len};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::sync::{OnceLock, RwLock};

pub const DEFAULT_WAN_INTERFACE: &str = "wan";
pub const DEFAULT_LAN_INTERFACE: &str = "lan";
const PROC_UPTIME_PATH: &str = "/proc/uptime";
const PROC_LOADAVG_PATH: &str = "/proc/loadavg";
const PROC_MEMINFO_PATH: &str = "/proc/meminfo";
const SYS_CLASS_NET_PATH: &str = "/sys/class/net";

pub const LOG_PARTITION_PATH: &str = "/var/log";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StatusResponse {
    pub system: SystemStatus,
    pub network: NetworkStatus,
    pub dhcp_server: DhcpServerStatus,
    pub dns_forwarder: DnsForwarderStatus,
    pub sntp: SntpStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SystemStatus {
    pub version: String,
    pub git_sha: String,
    pub uptime_seconds: u64,
    pub memory: MemoryStatus,
    pub storage: StorageStatus,
    pub load_average: [f64; 3],
    pub watchdog_active: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MemoryStatus {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct StorageStatus {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NetworkStatus {
    pub wan: WanStatus,
    pub lan: LanStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct WanStatus {
    pub interface: String,
    pub mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expiry_seconds: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LanStatus {
    pub interface: String,
    pub mac: String,
    pub ip: String,
    pub prefix_len: u8,
    pub mode: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DhcpServerStatus {
    pub active_leases_count: usize,
    pub leases: Vec<DhcpLeaseEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DhcpLeaseEntry {
    pub mac: String,
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub expires_in_seconds: u64,
    pub is_static: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DnsForwarderStatus {
    pub queries_total: u64,
    pub cache_hits_total: u64,
    pub cache_hit_ratio: f64,
    pub cached_entries_count: usize,
    pub rate_limited_drops_total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SntpStatus {
    pub synchronized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sync_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stratum: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LogsResponse {
    pub total_lines_available: usize,
    pub lines: Vec<String>,
}

#[derive(Default)]
pub struct ObservabilityTracker {
    pub dns_stats: RwLock<DnsStatsInfo>,
    pub dhcp_leases: RwLock<Vec<DhcpLeaseInfo>>,
    pub sntp_state: RwLock<SntpStatus>,
    pub lan_interface: RwLock<String>,
    pub lan_ip: RwLock<String>,
    pub initial_lan_ip: RwLock<String>,
}

static OBSERVABILITY_TRACKER: OnceLock<ObservabilityTracker> = OnceLock::new();

pub fn get_tracker() -> &'static ObservabilityTracker {
    OBSERVABILITY_TRACKER.get_or_init(|| ObservabilityTracker {
        dns_stats: RwLock::new(DnsStatsInfo::default()),
        dhcp_leases: RwLock::new(Vec::new()),
        sntp_state: RwLock::new(SntpStatus {
            synchronized: false,
            last_sync_timestamp: None,
            stratum: None,
            server: None,
        }),
        lan_interface: RwLock::new(DEFAULT_LAN_INTERFACE.to_string()),
        lan_ip: RwLock::new("192.168.1.1/24".to_string()),
        initial_lan_ip: RwLock::new("192.168.1.1/24".to_string()),
    })
}

pub fn update_dns_stats(stats: DnsStatsInfo) {
    if let Ok(mut lock) = get_tracker().dns_stats.write() {
        *lock = stats;
    }
}

pub fn update_dhcp_leases(leases: Vec<DhcpLeaseInfo>) {
    if let Ok(mut lock) = get_tracker().dhcp_leases.write() {
        *lock = leases;
    }
}

pub fn update_sntp_sync(server: &str, stratum: u8) {
    if let Ok(mut lock) = get_tracker().sntp_state.write() {
        lock.synchronized = true;
        lock.last_sync_timestamp = Some(Utc::now().to_rfc3339());
        lock.stratum = Some(stratum);
        lock.server = Some(server.to_string());
    }
}

pub fn set_lan_info(interface: &str, initial_lan_ip: &str) {
    let tracker = get_tracker();
    if let Ok(mut lock) = tracker.lan_interface.write() {
        *lock = interface.to_string();
    }
    if let Ok(mut lock) = tracker.initial_lan_ip.write() {
        *lock = initial_lan_ip.to_string();
    }
    if let Ok(mut lock) = tracker.lan_ip.write() {
        *lock = initial_lan_ip.to_string();
    }
}

pub fn update_current_lan_ip(current_lan_ip: &str) {
    if let Ok(mut lock) = get_tracker().lan_ip.write() {
        *lock = current_lan_ip.to_string();
    }
}

pub fn parse_uptime_str(content: &str) -> u64 {
    content
        .split_whitespace()
        .next()
        .and_then(|val| val.parse::<f64>().ok())
        .map(|f| f.max(0.0) as u64)
        .unwrap_or(0)
}

pub fn parse_loadavg_str(content: &str) -> [f64; 3] {
    let mut iter = content.split_whitespace();
    let l1 = iter
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let l2 = iter
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    let l3 = iter
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(0.0);
    [l1, l2, l3]
}

pub fn parse_meminfo_str(content: &str) -> MemoryStatus {
    let mut total_kb = 0u64;
    let mut avail_kb = 0u64;
    let mut free_kb = 0u64;
    let mut buffers_kb = 0u64;
    let mut cached_kb = 0u64;
    let mut has_avail = false;

    for line in content.lines() {
        let Some((key, val_str)) = line.split_once(':') else {
            continue;
        };
        let kb = val_str
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        match key.trim() {
            "MemTotal" => total_kb = kb,
            "MemAvailable" => {
                avail_kb = kb;
                has_avail = true;
            }
            "MemFree" => free_kb = kb,
            "Buffers" => buffers_kb = kb,
            "Cached" => cached_kb = kb,
            _ => {}
        }
    }

    let effective_avail_kb = if has_avail {
        avail_kb
    } else {
        free_kb.saturating_add(buffers_kb).saturating_add(cached_kb)
    };

    let total_bytes = total_kb.saturating_mul(1024);
    let free_bytes = effective_avail_kb.saturating_mul(1024);
    let used_bytes = total_bytes.saturating_sub(free_bytes);

    MemoryStatus {
        total_bytes,
        used_bytes,
        free_bytes,
    }
}

pub fn read_storage_stats(path: &str) -> StorageStatus {
    let c_path = match CString::new(path) {
        Ok(p) => p,
        Err(_) => {
            return StorageStatus {
                total_bytes: 0,
                used_bytes: 0,
                free_bytes: 0,
            };
        }
    };

    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if res != 0 {
        return StorageStatus {
            total_bytes: 0,
            used_bytes: 0,
            free_bytes: 0,
        };
    }

    let block_size = stat.f_frsize as u64;
    let total_bytes = (stat.f_blocks as u64).saturating_mul(block_size);
    let free_bytes = (stat.f_bavail as u64).saturating_mul(block_size);
    let used_bytes = total_bytes.saturating_sub(free_bytes);

    StorageStatus {
        total_bytes,
        used_bytes,
        free_bytes,
    }
}

pub fn read_sysfs_u64(path: &Path) -> u64 {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

pub fn read_interface_mac(iface_name: &str) -> String {
    let path = format!("{}/{}/address", SYS_CLASS_NET_PATH, iface_name);
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "00:00:00:00:00:00".to_string())
}

pub fn read_interface_traffic(iface_name: &str) -> (u64, u64, u64, u64) {
    let stats_dir = Path::new(SYS_CLASS_NET_PATH)
        .join(iface_name)
        .join("statistics");
    let rx_bytes = read_sysfs_u64(&stats_dir.join("rx_bytes"));
    let tx_bytes = read_sysfs_u64(&stats_dir.join("tx_bytes"));
    let rx_packets = read_sysfs_u64(&stats_dir.join("rx_packets"));
    let tx_packets = read_sysfs_u64(&stats_dir.join("tx_packets"));
    (rx_bytes, tx_bytes, rx_packets, tx_packets)
}

pub fn collect_system_status(watchdog_active: bool) -> SystemStatus {
    let version = match option_env!("VERGEN_GIT_DESCRIBE") {
        Some(desc)
            if desc.starts_with('v') || desc.chars().next().is_some_and(|c| c.is_ascii_digit()) =>
        {
            desc.strip_prefix('v').unwrap_or(desc).to_string()
        }
        _ => env!("CARGO_PKG_VERSION").to_string(),
    };
    let git_sha = option_env!("VERGEN_GIT_SHA")
        .unwrap_or("unknown")
        .to_string();

    let uptime_str = fs::read_to_string(PROC_UPTIME_PATH).unwrap_or_default();
    let uptime_seconds = parse_uptime_str(&uptime_str);

    let loadavg_str = fs::read_to_string(PROC_LOADAVG_PATH).unwrap_or_default();
    let load_average = parse_loadavg_str(&loadavg_str);

    let meminfo_str = fs::read_to_string(PROC_MEMINFO_PATH).unwrap_or_default();
    let memory = parse_meminfo_str(&meminfo_str);
    let storage = read_storage_stats(LOG_PARTITION_PATH);

    SystemStatus {
        version,
        git_sha,
        uptime_seconds,
        memory,
        storage,
        load_average,
        watchdog_active,
    }
}

pub fn collect_network_status(
    wan_lease: &WanLease,
    wan_iface: &str,
    lan_iface: &str,
    current_lan_ip_str: &str,
    initial_lan_ip_str: &str,
) -> NetworkStatus {
    let wan_mac = read_interface_mac(wan_iface);
    let (wan_rx_bytes, wan_tx_bytes, wan_rx_packets, wan_tx_packets) =
        read_interface_traffic(wan_iface);

    let wan_prefix_len = wan_lease.mask.and_then(|m| mask_to_prefix_len(m).ok());
    let wan = WanStatus {
        interface: wan_iface.to_string(),
        mac: wan_mac,
        ip: wan_lease.ip.map(|ip| ip.to_string()),
        prefix_len: wan_prefix_len,
        gateway: wan_lease.gateway.map(|gw| gw.to_string()),
        dns_servers: wan_lease
            .dns_servers
            .iter()
            .map(|ip| ip.to_string())
            .collect(),
        lease_expiry_seconds: None,
        rx_bytes: wan_rx_bytes,
        tx_bytes: wan_tx_bytes,
        rx_packets: wan_rx_packets,
        tx_packets: wan_tx_packets,
    };

    let lan_mac = read_interface_mac(lan_iface);
    let (lan_rx_bytes, lan_tx_bytes, lan_rx_packets, lan_tx_packets) =
        read_interface_traffic(lan_iface);

    let lan_net = current_lan_ip_str
        .parse::<ipnet::Ipv4Net>()
        .unwrap_or_else(|_| "192.168.1.1/24".parse().unwrap());
    let lan_mode = if current_lan_ip_str == initial_lan_ip_str {
        "primary".to_string()
    } else {
        "backup".to_string()
    };

    let lan = LanStatus {
        interface: lan_iface.to_string(),
        mac: lan_mac,
        ip: lan_net.addr().to_string(),
        prefix_len: lan_net.prefix_len(),
        mode: lan_mode,
        rx_bytes: lan_rx_bytes,
        tx_bytes: lan_tx_bytes,
        rx_packets: lan_rx_packets,
        tx_packets: lan_tx_packets,
    };

    NetworkStatus { wan, lan }
}

pub fn collect_dhcp_status() -> DhcpServerStatus {
    let leases_raw = get_tracker()
        .dhcp_leases
        .read()
        .map(|l| l.clone())
        .unwrap_or_default();

    let leases: Vec<DhcpLeaseEntry> = leases_raw
        .into_iter()
        .map(|l| DhcpLeaseEntry {
            mac: l.mac.to_string(),
            ip: l.ip.to_string(),
            hostname: l.hostname,
            expires_in_seconds: l.expires_in_seconds,
            is_static: l.is_static,
        })
        .collect();

    DhcpServerStatus {
        active_leases_count: leases.len(),
        leases,
    }
}

pub fn collect_dns_status() -> DnsForwarderStatus {
    let stats = get_tracker()
        .dns_stats
        .read()
        .map(|s| s.clone())
        .unwrap_or_default();

    let cache_hit_ratio = if stats.queries_total > 0 {
        (stats.cache_hits_total as f64 / stats.queries_total as f64 * 1000.0).round() / 1000.0
    } else {
        0.0
    };

    DnsForwarderStatus {
        queries_total: stats.queries_total,
        cache_hits_total: stats.cache_hits_total,
        cache_hit_ratio,
        cached_entries_count: stats.cached_entries_count,
        rate_limited_drops_total: stats.rate_limited_drops_total,
    }
}

pub fn collect_sntp_status() -> SntpStatus {
    get_tracker()
        .sntp_state
        .read()
        .map(|s| s.clone())
        .unwrap_or_else(|_| SntpStatus {
            synchronized: false,
            last_sync_timestamp: None,
            stratum: None,
            server: None,
        })
}

pub fn collect_status_response(wan_lease: &WanLease, watchdog_active: bool) -> StatusResponse {
    let tracker = get_tracker();
    let lan_iface = tracker
        .lan_interface
        .read()
        .map(|s| s.clone())
        .unwrap_or_else(|_| DEFAULT_LAN_INTERFACE.to_string());
    let current_lan_ip = tracker
        .lan_ip
        .read()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "192.168.1.1/24".to_string());
    let initial_lan_ip = tracker
        .initial_lan_ip
        .read()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "192.168.1.1/24".to_string());

    let system = collect_system_status(watchdog_active);
    let network = collect_network_status(
        wan_lease,
        DEFAULT_WAN_INTERFACE,
        &lan_iface,
        &current_lan_ip,
        &initial_lan_ip,
    );
    let dhcp_server = collect_dhcp_status();
    let dns_forwarder = collect_dns_status();
    let sntp = collect_sntp_status();

    StatusResponse {
        system,
        network,
        dhcp_server,
        dns_forwarder,
        sntp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_uptime_str() {
        assert_eq!(parse_uptime_str("86400.45 172800.90"), 86400);
        assert_eq!(parse_uptime_str("123.00 456.00"), 123);
        assert_eq!(parse_uptime_str("invalid"), 0);
        assert_eq!(parse_uptime_str(""), 0);
    }

    #[test]
    fn test_parse_loadavg_str() {
        let load = parse_loadavg_str("0.05 0.02 0.00 1/120 12345");
        assert_eq!(load, [0.05, 0.02, 0.00]);

        let load_fallback = parse_loadavg_str("invalid");
        assert_eq!(load_fallback, [0.0, 0.0, 0.0]);
    }

    #[test]
    fn test_parse_meminfo_str_with_available() {
        let meminfo = r#"
MemTotal:         131072 kB
MemFree:           10240 kB
MemAvailable:     116736 kB
Buffers:            4096 kB
Cached:            65536 kB
"#;
        let mem = parse_meminfo_str(meminfo);
        assert_eq!(mem.total_bytes, 131072 * 1024);
        assert_eq!(mem.free_bytes, 116736 * 1024);
        assert_eq!(mem.used_bytes, (131072 - 116736) * 1024);
    }

    #[test]
    fn test_parse_meminfo_str_fallback_free_buffers_cached() {
        let meminfo = r#"
MemTotal:         131072 kB
MemFree:           10240 kB
Buffers:            4096 kB
Cached:            65536 kB
"#;
        let mem = parse_meminfo_str(meminfo);
        assert_eq!(mem.total_bytes, 131072 * 1024);
        let avail = 10240 + 4096 + 65536;
        assert_eq!(mem.free_bytes, avail * 1024);
        assert_eq!(mem.used_bytes, (131072 - avail) * 1024);
    }

    #[test]
    fn test_read_storage_stats_root_or_nonexistent() {
        let storage = read_storage_stats("/");
        assert!(storage.total_bytes > 0);
        assert!(storage.free_bytes > 0);

        let invalid = read_storage_stats("/nonexistent_path_xyz_123");
        assert_eq!(invalid.total_bytes, 0);
        assert_eq!(invalid.used_bytes, 0);
        assert_eq!(invalid.free_bytes, 0);
    }

    #[test]
    fn test_collect_status_response_serialization() {
        let wan_lease = WanLease {
            ip: Some(Ipv4Addr::new(192, 0, 2, 100)),
            mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        };

        update_dns_stats(DnsStatsInfo {
            queries_total: 100,
            cache_hits_total: 75,
            cached_entries_count: 10,
            rate_limited_drops_total: 0,
        });

        update_dhcp_leases(vec![DhcpLeaseInfo {
            mac: MacAddr::new(0x52, 0x54, 0x00, 0xaa, 0xbb, 0x01),
            ip: Ipv4Addr::new(192, 168, 1, 100),
            hostname: Some("workstation-1".to_string()),
            expires_in_seconds: 3600,
            is_static: false,
        }]);

        update_sntp_sync("time.google.com", 2);

        let status = collect_status_response(&wan_lease, true);
        assert_eq!(status.dns_forwarder.queries_total, 100);
        assert_eq!(status.dns_forwarder.cache_hits_total, 75);
        assert_eq!(status.dns_forwarder.cache_hit_ratio, 0.75);
        assert_eq!(status.dhcp_server.active_leases_count, 1);
        assert!(status.sntp.synchronized);
        assert_eq!(status.network.wan.ip, Some("192.0.2.100".to_string()));
        assert_eq!(status.network.wan.prefix_len, Some(24));

        let json = serde_json::to_string_pretty(&status).unwrap();
        assert!(json.contains("\"queries_total\": 100"));
        assert!(json.contains("\"workstation-1\""));
        assert!(json.contains("\"time.google.com\""));
        assert!(json.contains("\"free_bytes\""));
        assert!(json.contains("\"storage\""));
    }
}
