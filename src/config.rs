use crate::error::RouterError;
use crate::init::system::ConfigReaderOps;
use crate::services::utils::CleanOption;
use pnet::util::MacAddr;
use serde::Deserialize;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LoggingConfig {
    pub max_log_size_mb: u64,
    pub level: log::LevelFilter,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            max_log_size_mb: 100,
            level: log::LevelFilter::Info,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub lan_ip: String,
    pub backup_lan_ip: String,
    pub wan_mac: MacAddr,
    pub lan_mac: MacAddr,
    pub reboot_delay: Option<u32>, // Some(N) = N seconds, None = infinite
    pub logging: LoggingConfig,
    pub watchdog: bool,
    pub dns_servers: Vec<Ipv4Addr>,
}

impl std::fmt::Debug for RouterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterConfig")
            .field("lan_ip", &self.lan_ip)
            .field("backup_lan_ip", &self.backup_lan_ip)
            .field("wan_mac", &self.wan_mac)
            .field("lan_mac", &self.lan_mac)
            .field("reboot_delay", &CleanOption(&self.reboot_delay))
            .field("logging", &self.logging)
            .field("watchdog", &self.watchdog)
            .field("dns_servers", &self.dns_servers)
            .finish()
    }
}

#[derive(Deserialize)]
struct ConfigToml {
    network: NetworkSection,
    system: Option<SystemSection>,
    logging: Option<LoggingSection>,
    dns: Option<DnsSection>,
}

#[derive(Deserialize)]
struct NetworkSection {
    lan_ip: Option<String>,
    backup_lan_ip: Option<String>,
    wan_mac: String,
    lan_mac: String,
    dns_servers: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct DnsSection {
    servers: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct SystemSection {
    reboot_delay: Option<u32>,
    watchdog: Option<bool>,
}

#[derive(Deserialize)]
struct LoggingSection {
    max_log_size_mb: Option<u64>,
    level: Option<String>,
}

fn is_valid_unicast_mac(mac: &MacAddr) -> bool {
    if mac.is_zero() || mac.is_broadcast() {
        return false;
    }
    (mac.0 & 0x01) == 0
}

fn parse_mac_addresses(net: &NetworkSection) -> Result<(MacAddr, MacAddr), RouterError> {
    let wan_mac = MacAddr::from_str(&net.wan_mac)
        .map_err(|_| RouterError::Generic("wan_mac must be a valid MAC address".to_string()))?;
    if !is_valid_unicast_mac(&wan_mac) {
        return Err(RouterError::Generic(format!(
            "wan_mac {} must be a valid non-zero, non-multicast unicast MAC address",
            wan_mac
        )));
    }

    let lan_mac = MacAddr::from_str(&net.lan_mac)
        .map_err(|_| RouterError::Generic("lan_mac must be a valid MAC address".to_string()))?;
    if !is_valid_unicast_mac(&lan_mac) {
        return Err(RouterError::Generic(format!(
            "lan_mac {} must be a valid non-zero, non-multicast unicast MAC address",
            lan_mac
        )));
    }

    if wan_mac == lan_mac {
        return Err(RouterError::Generic(
            "wan_mac and lan_mac must be distinct MAC addresses".to_string(),
        ));
    }

    Ok((wan_mac, lan_mac))
}

fn validate_lan_subnet(name: &str, cidr: &str) -> Result<ipnet::Ipv4Net, RouterError> {
    let net = ipnet::Ipv4Net::from_str(cidr)
        .map_err(|e| RouterError::Generic(format!("Invalid {} CIDR '{}': {}", name, cidr, e)))?;
    if net.prefix_len() < 8 || net.prefix_len() > 30 {
        return Err(RouterError::Generic(format!(
            "Invalid {} prefix length /{} (must be between /8 and /30)",
            name,
            net.prefix_len()
        )));
    }
    if net.addr() == net.network() {
        return Err(RouterError::Generic(format!(
            "{} '{}' cannot use the network address as the router host IP",
            name, cidr
        )));
    }
    if net.addr() == net.broadcast() {
        return Err(RouterError::Generic(format!(
            "{} '{}' cannot use the broadcast address as the router host IP",
            name, cidr
        )));
    }
    Ok(net)
}

fn parse_logging_config(logging: Option<&LoggingSection>) -> Result<LoggingConfig, RouterError> {
    let max_log_size_mb = logging
        .and_then(|l| l.max_log_size_mb)
        .unwrap_or(100)
        .max(1);

    let level = match logging.and_then(|l| l.level.as_deref()) {
        Some(lvl_str) => log::LevelFilter::from_str(lvl_str).map_err(|_| {
            RouterError::Generic(format!(
                "Invalid logging level '{}'. Must be one of: error, warn, info, debug, trace",
                lvl_str
            ))
        })?,
        None => log::LevelFilter::Info,
    };

    Ok(LoggingConfig {
        max_log_size_mb,
        level,
    })
}

fn parse_dns_servers(
    net: &NetworkSection,
    dns: Option<&DnsSection>,
) -> Result<Vec<Ipv4Addr>, RouterError> {
    let raw_list = net
        .dns_servers
        .as_deref()
        .or_else(|| dns.and_then(|d| d.servers.as_deref()));

    let Some(raw_list) = raw_list else {
        return Ok(Vec::new());
    };

    let mut parsed_ips = Vec::new();
    for ip_str in raw_list {
        let ip = Ipv4Addr::from_str(ip_str.trim()).map_err(|e| {
            RouterError::Generic(format!(
                "Invalid custom DNS resolver IP address '{}': {}",
                ip_str, e
            ))
        })?;
        if !crate::services::utils::is_valid_upstream_resolver(ip) {
            return Err(RouterError::Generic(format!(
                "Invalid custom DNS resolver '{}': cannot be loopback, broadcast, multicast, link-local, documentation, or unspecified",
                ip_str
            )));
        }
        if !parsed_ips.contains(&ip) {
            parsed_ips.push(ip);
        }
    }
    Ok(parsed_ips)
}

impl RouterConfig {
    pub fn parse<S: ConfigReaderOps>(sys: &S) -> Result<Self, RouterError> {
        let content = sys.read_config_file().map_err(|e| {
            RouterError::Generic(format!(
                "Failed to read trimrouter.toml configuration file: {}",
                e
            ))
        })?;

        let parsed: ConfigToml = toml::from_str(&content).map_err(|e| {
            RouterError::Generic(format!(
                "Failed to parse trimrouter.toml TOML syntax: {}",
                e
            ))
        })?;

        let (wan_mac, lan_mac) = parse_mac_addresses(&parsed.network)?;
        let dns_servers = parse_dns_servers(&parsed.network, parsed.dns.as_ref())?;
        let lan_ip = parsed
            .network
            .lan_ip
            .unwrap_or_else(|| "192.168.1.1/24".to_string());
        let backup_lan_ip = parsed
            .network
            .backup_lan_ip
            .unwrap_or_else(|| "10.0.0.1/24".to_string());

        let lan_net = validate_lan_subnet("lan_ip", &lan_ip)?;
        let backup_net = validate_lan_subnet("backup_lan_ip", &backup_lan_ip)?;

        if lan_net.contains(&backup_net.network()) || backup_net.contains(&lan_net.network()) {
            return Err(RouterError::Generic(format!(
                "lan_ip ({}) and backup_lan_ip ({}) must not overlap with each other",
                lan_ip, backup_lan_ip
            )));
        }

        let reboot_delay = parsed.system.as_ref().and_then(|s| s.reboot_delay);
        let logging = parse_logging_config(parsed.logging.as_ref())?;
        let watchdog = parsed
            .system
            .as_ref()
            .and_then(|s| s.watchdog)
            .unwrap_or(true);

        Ok(RouterConfig {
            lan_ip,
            backup_lan_ip,
            wan_mac,
            lan_mac,
            reboot_delay,
            logging,
            watchdog,
            dns_servers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::system::mock::MockSystem;

    #[test]
    fn test_config_parsing_missing_wan_mac() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            lan_mac = "52:54:00:12:34:57"
            backup_lan_ip = "10.0.0.1/24"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("missing field `wan_mac`")
        );
    }

    #[test]
    fn test_config_parsing_missing_lan_mac() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            backup_lan_ip = "10.0.0.1/24"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("missing field `lan_mac`")
        );
    }

    #[test]
    fn test_config_parsing_missing_backup_lan_ip() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
        "#
        .to_string();
        let config = RouterConfig::parse(&sys).unwrap();
        assert_eq!(config.lan_ip, "192.168.1.1/24");
        assert_eq!(config.backup_lan_ip, "10.0.0.1/24");
    }

    #[test]
    fn test_config_parsing_with_mac() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "10.0.0.1/24"
            backup_lan_ip = "172.16.0.1/24"
        "#
        .to_string();

        let config = RouterConfig::parse(&sys).unwrap();
        assert_eq!(config.lan_ip, "10.0.0.1/24");
        assert_eq!(config.backup_lan_ip, "172.16.0.1/24");
        assert_eq!(
            config.wan_mac,
            MacAddr::from_str("52:54:00:12:34:56").unwrap()
        );
        assert_eq!(
            config.lan_mac,
            MacAddr::from_str("52:54:00:12:34:57").unwrap()
        );
        assert_eq!(config.reboot_delay, None);
    }

    #[test]
    fn test_config_parsing_with_backup_lan_ip() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"
            backup_lan_ip = "172.16.0.1/24"
        "#
        .to_string();

        let config = RouterConfig::parse(&sys).unwrap();
        assert_eq!(config.lan_ip, "192.168.1.1/24");
        assert_eq!(config.backup_lan_ip, "172.16.0.1/24");
    }

    #[test]
    fn test_config_parsing_zero_mac_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "00:00:00:00:00:00"
            lan_mac = "52:54:00:12:34:57"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("must be a valid non-zero")
        );
    }

    #[test]
    fn test_config_parsing_broadcast_mac_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "FF:FF:FF:FF:FF:FF"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("must be a valid non-zero")
        );
    }

    #[test]
    fn test_config_parsing_multicast_mac_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "01:00:5E:00:00:01"
            lan_mac = "52:54:00:12:34:57"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("non-multicast"));
    }

    #[test]
    fn test_config_parsing_identical_macs_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:56"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("distinct MAC"));
    }

    #[test]
    fn test_config_parsing_invalid_cidr_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/invalid"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_prefix_out_of_bounds_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/32"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("must be between /8 and /30")
        );
    }

    #[test]
    fn test_config_parsing_network_or_broadcast_lan_ip_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.0/24"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("cannot use the network address")
        );

        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.255/24"
        "#
        .to_string();
        let res2 = RouterConfig::parse(&sys);
        assert!(res2.is_err());
        assert!(
            res2.unwrap_err()
                .to_string()
                .contains("cannot use the broadcast address")
        );
    }

    #[test]
    fn test_config_parsing_overlapping_lan_and_backup_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"
            backup_lan_ip = "192.168.1.100/24"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("must not overlap"));
    }

    #[test]
    fn test_config_parsing_reboot_delay() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            backup_lan_ip = "10.0.0.1/24"
            [system]
            reboot_delay = 5
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.reboot_delay, Some(5));
    }

    #[test]
    fn test_config_parsing_logging_custom() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            [logging]
            max_log_size_mb = 50
            level = "debug"
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.logging.max_log_size_mb, 50);
        assert_eq!(cfg.logging.level, log::LevelFilter::Debug);
    }

    #[test]
    fn test_config_parsing_logging_default() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.logging.max_log_size_mb, 100);
        assert_eq!(cfg.logging.level, log::LevelFilter::Info);
    }

    #[test]
    fn test_config_parsing_logging_invalid_level() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            [logging]
            level = "super_verbose"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_watchdog_default() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert!(cfg.watchdog);
    }

    #[test]
    fn test_config_parsing_watchdog_disabled() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            [system]
            watchdog = false
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert!(!cfg.watchdog);
    }

    #[test]
    fn test_config_parsing_custom_dns_network_section() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            dns_servers = ["1.1.1.1", "1.0.0.1"]
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(
            cfg.dns_servers,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1),]
        );
    }

    #[test]
    fn test_config_parsing_custom_dns_dedicated_section() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            [dns]
            servers = ["8.8.8.8", "8.8.4.4"]
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(
            cfg.dns_servers,
            vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4),]
        );
    }

    #[test]
    fn test_config_parsing_custom_dns_invalid_ip() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            dns_servers = ["not.an.ip.address"]
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_custom_dns_rejects_loopback() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            dns_servers = ["127.0.0.1"]
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }
}
