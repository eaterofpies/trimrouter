use crate::error::RouterError;
use crate::init::system::ConfigReaderOps;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardProtocol {
    Tcp,
    Udp,
    Both,
}

impl std::fmt::Display for ForwardProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Both => write!(f, "both"),
        }
    }
}

impl FromStr for ForwardProtocol {
    type Err = RouterError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(ForwardProtocol::Tcp),
            "udp" => Ok(ForwardProtocol::Udp),
            "both" | "tcp+udp" | "tcp,udp" | "all" => Ok(ForwardProtocol::Both),
            _ => Err(RouterError::Generic(format!(
                "Invalid port forwarding protocol '{}': expected 'tcp', 'udp', or 'both'",
                s
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PortForwardRule {
    pub protocol: ForwardProtocol,
    pub external_port: u16,
    pub internal_ip: Ipv4Addr,
    pub internal_port: u16,
    pub description: Option<String>,
}

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
    pub logging: LoggingConfig,
    pub watchdog: bool,
    pub dns_servers: Vec<Ipv4Addr>,
    pub static_leases: HashMap<MacAddr, Ipv4Addr>,
    pub port_forwards: Vec<PortForwardRule>,
}

impl std::fmt::Debug for RouterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterConfig")
            .field("lan_ip", &self.lan_ip)
            .field("backup_lan_ip", &self.backup_lan_ip)
            .field("wan_mac", &self.wan_mac)
            .field("lan_mac", &self.lan_mac)
            .field("logging", &self.logging)
            .field("watchdog", &self.watchdog)
            .field("dns_servers", &self.dns_servers)
            .field("static_leases", &self.static_leases)
            .field("port_forwards", &self.port_forwards)
            .finish()
    }
}

#[derive(Deserialize)]
struct ConfigToml {
    network: NetworkSection,
    dhcp: Option<DhcpSection>,
    system: Option<SystemSection>,
    logging: Option<LoggingSection>,
    dns: Option<DnsSection>,
    port_forwarding: Option<Vec<PortForwardToml>>,
    port_forwards: Option<Vec<PortForwardToml>>,
    firewall: Option<FirewallSection>,
}

#[derive(Deserialize)]
struct FirewallSection {
    port_forwarding: Option<Vec<PortForwardToml>>,
    port_forwards: Option<Vec<PortForwardToml>>,
}

#[derive(Deserialize)]
struct PortForwardToml {
    proto: Option<String>,
    protocol: Option<String>,
    external_port: Option<u16>,
    ext_port: Option<u16>,
    port: Option<u16>,
    internal_ip: Option<String>,
    int_ip: Option<String>,
    ip: Option<String>,
    internal_port: Option<u16>,
    int_port: Option<u16>,
    description: Option<String>,
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
struct DhcpSection {
    reservations: Option<Vec<DhcpReservationToml>>,
}

#[derive(Deserialize)]
struct DhcpReservationToml {
    mac: String,
    ip: String,
}

#[derive(Deserialize)]
struct DnsSection {
    servers: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct SystemSection {
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

fn parse_dhcp_reservations(
    dhcp: Option<&DhcpSection>,
    lan_net: &ipnet::Ipv4Net,
) -> Result<HashMap<MacAddr, Ipv4Addr>, RouterError> {
    let mut static_leases = HashMap::new();
    let mut seen_ips = HashSet::new();

    let Some(dhcp_sec) = dhcp else {
        return Ok(static_leases);
    };
    let Some(ref reservations) = dhcp_sec.reservations else {
        return Ok(static_leases);
    };

    for res in reservations {
        let mac = MacAddr::from_str(&res.mac).map_err(|_| {
            RouterError::Generic(format!(
                "DHCP reservation MAC '{}' must be a valid MAC address",
                res.mac
            ))
        })?;
        if !is_valid_unicast_mac(&mac) {
            return Err(RouterError::Generic(format!(
                "DHCP reservation MAC '{}' must be a valid non-zero, non-multicast unicast MAC address",
                mac
            )));
        }

        let ip: Ipv4Addr = res.ip.parse().map_err(|_| {
            RouterError::Generic(format!(
                "DHCP reservation IP '{}' must be a valid IPv4 address",
                res.ip
            ))
        })?;

        if !lan_net.contains(&ip)
            || ip == lan_net.network()
            || ip == lan_net.broadcast()
            || ip == lan_net.addr()
        {
            return Err(RouterError::Generic(format!(
                "DHCP reservation IP '{}' must be a valid host IP within LAN subnet '{}' and not the router's gateway IP",
                ip, lan_net
            )));
        }

        if static_leases.insert(mac, ip).is_some() {
            return Err(RouterError::Generic(format!(
                "Duplicate MAC address '{}' in DHCP reservations",
                mac
            )));
        }

        if !seen_ips.insert(ip) {
            return Err(RouterError::Generic(format!(
                "Duplicate IP address '{}' in DHCP reservations",
                ip
            )));
        }
    }

    Ok(static_leases)
}

fn collect_raw_port_forward_rules(config: &ConfigToml) -> Vec<&PortForwardToml> {
    let mut list = Vec::new();
    if let Some(ref rules) = config.port_forwarding {
        list.extend(rules.iter());
    }
    if let Some(ref rules) = config.port_forwards {
        list.extend(rules.iter());
    }
    if let Some(ref fw) = config.firewall {
        if let Some(ref rules) = fw.port_forwarding {
            list.extend(rules.iter());
        }
        if let Some(ref rules) = fw.port_forwards {
            list.extend(rules.iter());
        }
    }
    list
}

fn validate_and_build_port_forward_rule(
    raw: &PortForwardToml,
    lan_net: &ipnet::Ipv4Net,
) -> Result<PortForwardRule, RouterError> {
    let proto_str = raw
        .proto
        .as_deref()
        .or(raw.protocol.as_deref())
        .unwrap_or("tcp");
    let protocol = ForwardProtocol::from_str(proto_str)?;

    let external_port = raw
        .external_port
        .or(raw.ext_port)
        .or(raw.port)
        .ok_or_else(|| {
            RouterError::Generic(
                "Port forwarding rule is missing 'external_port' (or 'ext_port' / 'port')"
                    .to_string(),
            )
        })?;
    if external_port == 0 {
        return Err(RouterError::Generic(
            "Port forwarding 'external_port' must be between 1 and 65535 (cannot be 0)".to_string(),
        ));
    }

    let ip_str = raw
        .internal_ip
        .as_deref()
        .or(raw.int_ip.as_deref())
        .or(raw.ip.as_deref())
        .ok_or_else(|| {
            RouterError::Generic(
                "Port forwarding rule is missing 'internal_ip' (or 'int_ip' / 'ip')".to_string(),
            )
        })?;
    let internal_ip: Ipv4Addr = ip_str.parse().map_err(|_| {
        RouterError::Generic(format!(
            "Port forwarding target IP '{}' must be a valid IPv4 address",
            ip_str
        ))
    })?;

    if !lan_net.contains(&internal_ip)
        || internal_ip == lan_net.network()
        || internal_ip == lan_net.broadcast()
        || internal_ip == lan_net.addr()
    {
        return Err(RouterError::Generic(format!(
            "Port forwarding target IP '{}' must be a valid host IP within LAN subnet '{}' and not the router's gateway IP",
            internal_ip, lan_net
        )));
    }

    let internal_port = raw.internal_port.or(raw.int_port).unwrap_or(external_port);
    if internal_port == 0 {
        return Err(RouterError::Generic(
            "Port forwarding 'internal_port' must be between 1 and 65535 (cannot be 0)".to_string(),
        ));
    }

    Ok(PortForwardRule {
        protocol,
        external_port,
        internal_ip,
        internal_port,
        description: raw.description.clone(),
    })
}

fn check_port_forward_conflicts(
    rule: &PortForwardRule,
    bound_tcp_ports: &mut HashSet<u16>,
    bound_udp_ports: &mut HashSet<u16>,
) -> Result<(), RouterError> {
    if (rule.protocol == ForwardProtocol::Udp || rule.protocol == ForwardProtocol::Both)
        && rule.external_port == dhcproto::v4::CLIENT_PORT
    {
        return Err(RouterError::Generic(format!(
            "Port forwarding external UDP port {} conflicts with WAN DHCP client",
            dhcproto::v4::CLIENT_PORT
        )));
    }

    if (rule.protocol == ForwardProtocol::Tcp || rule.protocol == ForwardProtocol::Both)
        && !bound_tcp_ports.insert(rule.external_port)
    {
        return Err(RouterError::Generic(format!(
            "Duplicate port forwarding binding for TCP port {}",
            rule.external_port
        )));
    }

    if (rule.protocol == ForwardProtocol::Udp || rule.protocol == ForwardProtocol::Both)
        && !bound_udp_ports.insert(rule.external_port)
    {
        return Err(RouterError::Generic(format!(
            "Duplicate port forwarding binding for UDP port {}",
            rule.external_port
        )));
    }

    Ok(())
}

fn parse_port_forward_rules(
    config_toml: &ConfigToml,
    lan_net: &ipnet::Ipv4Net,
) -> Result<Vec<PortForwardRule>, RouterError> {
    let mut rules = Vec::new();
    let mut bound_tcp_ports = HashSet::new();
    let mut bound_udp_ports = HashSet::new();

    let raw_rules = collect_raw_port_forward_rules(config_toml);
    for raw in raw_rules {
        let rule = validate_and_build_port_forward_rule(raw, lan_net)?;
        check_port_forward_conflicts(&rule, &mut bound_tcp_ports, &mut bound_udp_ports)?;
        rules.push(rule);
    }

    Ok(rules)
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
            .as_deref()
            .unwrap_or("192.168.1.1/24")
            .to_string();
        let backup_lan_ip = parsed
            .network
            .backup_lan_ip
            .as_deref()
            .unwrap_or("10.0.0.1/24")
            .to_string();

        let lan_net = validate_lan_subnet("lan_ip", &lan_ip)?;
        let backup_net = validate_lan_subnet("backup_lan_ip", &backup_lan_ip)?;

        if lan_net.contains(&backup_net.network()) || backup_net.contains(&lan_net.network()) {
            return Err(RouterError::Generic(format!(
                "lan_ip ({}) and backup_lan_ip ({}) must not overlap with each other",
                lan_ip, backup_lan_ip
            )));
        }

        let static_leases = parse_dhcp_reservations(parsed.dhcp.as_ref(), &lan_net)?;
        let port_forwards = parse_port_forward_rules(&parsed, &lan_net)?;
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
            logging,
            watchdog,
            dns_servers,
            static_leases,
            port_forwards,
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
    fn test_config_parsing_system_watchdog_toggle() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            backup_lan_ip = "10.0.0.1/24"
            [system]
            watchdog = false
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert!(!cfg.watchdog);
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

    #[test]
    fn test_config_parsing_custom_dns_deduplication_and_whitespace() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            dns_servers = [" 1.1.1.1 ", "8.8.8.8", "1.1.1.1"]
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(
            cfg.dns_servers,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
    }

    #[test]
    fn test_config_parsing_custom_dns_empty_list() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            dns_servers = []
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert!(cfg.dns_servers.is_empty());
    }

    #[test]
    fn test_config_parsing_custom_dns_rejects_special_addresses() {
        let invalid_addrs = [
            "0.0.0.0",         // Unspecified
            "255.255.255.255", // Broadcast
            "224.0.0.1",       // Multicast
            "169.254.1.1",     // Link-local
            "192.0.2.1",       // TEST-NET-1 documentation
            "198.51.100.1",    // TEST-NET-2 documentation
            "203.0.113.1",     // TEST-NET-3 documentation
        ];

        for addr in invalid_addrs {
            let mut sys = MockSystem::new();
            sys.config_content = format!(
                r#"
                [network]
                wan_mac = "52:54:00:12:34:56"
                lan_mac = "52:54:00:12:34:57"
                dns_servers = ["{}"]
                "#,
                addr
            );
            assert!(
                RouterConfig::parse(&sys).is_err(),
                "Expected address {} to be rejected",
                addr
            );
        }
    }

    #[test]
    fn test_config_parsing_dhcp_reservations_valid() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:58"
            ip = "192.168.1.50"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:59"
            ip = "192.168.1.60"
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.static_leases.len(), 2);
        assert_eq!(
            cfg.static_leases
                .get(&MacAddr(0x52, 0x54, 0x00, 0x12, 0x34, 0x58)),
            Some(&Ipv4Addr::new(192, 168, 1, 50))
        );
        assert_eq!(
            cfg.static_leases
                .get(&MacAddr(0x52, 0x54, 0x00, 0x12, 0x34, 0x59)),
            Some(&Ipv4Addr::new(192, 168, 1, 60))
        );
    }

    #[test]
    fn test_config_parsing_dhcp_reservations_rejects_gateway_ip() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:58"
            ip = "192.168.1.1"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_dhcp_reservations_rejects_out_of_subnet() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:58"
            ip = "10.0.0.50"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_dhcp_reservations_rejects_duplicate_mac() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:58"
            ip = "192.168.1.50"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:58"
            ip = "192.168.1.51"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_dhcp_reservations_rejects_duplicate_ip() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:58"
            ip = "192.168.1.50"

            [[dhcp.reservations]]
            mac = "52:54:00:12:34:59"
            ip = "192.168.1.50"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_port_forwarding_valid() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[port_forwarding]]
            proto = "tcp"
            external_port = 8080
            internal_ip = "192.168.1.50"
            internal_port = 80
            description = "Web Server"

            [[port_forwarding]]
            proto = "udp"
            external_port = 9000
            internal_ip = "192.168.1.50"
            internal_port = 9000
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.port_forwards.len(), 2);
        assert_eq!(cfg.port_forwards[0].protocol, ForwardProtocol::Tcp);
        assert_eq!(cfg.port_forwards[0].external_port, 8080);
        assert_eq!(
            cfg.port_forwards[0].internal_ip,
            Ipv4Addr::new(192, 168, 1, 50)
        );
        assert_eq!(cfg.port_forwards[0].internal_port, 80);
        assert_eq!(
            cfg.port_forwards[0].description.as_deref(),
            Some("Web Server")
        );

        assert_eq!(cfg.port_forwards[1].protocol, ForwardProtocol::Udp);
        assert_eq!(cfg.port_forwards[1].external_port, 9000);
        assert_eq!(
            cfg.port_forwards[1].internal_ip,
            Ipv4Addr::new(192, 168, 1, 50)
        );
        assert_eq!(cfg.port_forwards[1].internal_port, 9000);
    }

    #[test]
    fn test_config_parsing_port_forwarding_both_and_omitted_internal_port() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[port_forwards]]
            proto = "both"
            ext_port = 2222
            int_ip = "192.168.1.100"
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.port_forwards.len(), 1);
        assert_eq!(cfg.port_forwards[0].protocol, ForwardProtocol::Both);
        assert_eq!(cfg.port_forwards[0].external_port, 2222);
        assert_eq!(
            cfg.port_forwards[0].internal_ip,
            Ipv4Addr::new(192, 168, 1, 100)
        );
        assert_eq!(cfg.port_forwards[0].internal_port, 2222);
    }

    #[test]
    fn test_config_parsing_port_forwarding_invalid_proto_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"

            [[port_forwarding]]
            proto = "icmp"
            external_port = 80
            internal_ip = "192.168.1.50"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_port_forwarding_zero_port_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"

            [[port_forwarding]]
            proto = "tcp"
            external_port = 0
            internal_ip = "192.168.1.50"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_port_forwarding_gateway_ip_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[port_forwarding]]
            proto = "tcp"
            external_port = 8080
            internal_ip = "192.168.1.1"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_port_forwarding_duplicate_external_port_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[port_forwarding]]
            proto = "tcp"
            external_port = 8080
            internal_ip = "192.168.1.50"

            [[port_forwarding]]
            proto = "tcp"
            external_port = 8080
            internal_ip = "192.168.1.60"
        "#
        .to_string();
        assert!(RouterConfig::parse(&sys).is_err());
    }

    #[test]
    fn test_config_parsing_port_forwarding_dhcp_port_rejected() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "192.168.1.1/24"

            [[port_forwarding]]
            proto = "udp"
            external_port = 68
            internal_ip = "192.168.1.50"
        "#
        .to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("conflicts with WAN DHCP client")
        );
    }
}
