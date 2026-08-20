use crate::error::RouterError;
use crate::system::SystemOps;
use pnet::util::MacAddr;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoggingConfig {
    pub max_log_size_mb: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            max_log_size_mb: 100,
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
}

impl std::fmt::Debug for RouterConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterConfig")
            .field("lan_ip", &self.lan_ip)
            .field("backup_lan_ip", &self.backup_lan_ip)
            .field("wan_mac", &self.wan_mac)
            .field("lan_mac", &self.lan_mac)
            .field(
                "reboot_delay",
                &crate::managers::utils::CleanOption(&self.reboot_delay),
            )
            .field("logging", &self.logging)
            .finish()
    }
}

#[derive(Deserialize)]
struct ConfigToml {
    network: NetworkSection,
    system: Option<SystemSection>,
    logging: Option<LoggingSection>,
}

#[derive(Deserialize)]
struct NetworkSection {
    lan_ip: Option<String>,
    backup_lan_ip: Option<String>,
    wan_mac: String,
    lan_mac: String,
}

#[derive(Deserialize)]
struct SystemSection {
    reboot_delay: Option<u32>,
}

#[derive(Deserialize)]
struct LoggingSection {
    max_log_size_mb: Option<u64>,
}

impl RouterConfig {
    pub fn parse<S: SystemOps>(sys: &S) -> Result<Self, RouterError> {
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

        let wan_mac = MacAddr::from_str(&parsed.network.wan_mac)
            .map_err(|_| RouterError::Generic("wan_mac must be a valid MAC address".to_string()))?;
        let lan_mac = MacAddr::from_str(&parsed.network.lan_mac)
            .map_err(|_| RouterError::Generic("lan_mac must be a valid MAC address".to_string()))?;

        let lan_ip = parsed
            .network
            .lan_ip
            .unwrap_or_else(|| "192.168.1.1/24".to_string());

        let backup_lan_ip = parsed
            .network
            .backup_lan_ip
            .clone()
            .unwrap_or_else(|| "10.0.0.1/24".to_string());

        let reboot_delay = parsed
            .system
            .as_ref()
            .and_then(|sys_sec| sys_sec.reboot_delay);

        let logging = LoggingConfig {
            max_log_size_mb: parsed
                .logging
                .as_ref()
                .and_then(|l| l.max_log_size_mb)
                .unwrap_or(100),
        };

        Ok(RouterConfig {
            lan_ip,
            backup_lan_ip,
            wan_mac,
            lan_mac,
            reboot_delay,
            logging,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::mock::MockSystem;

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
            backup_lan_ip = "10.0.0.1/24"
        "#
        .to_string();

        let config = RouterConfig::parse(&sys).unwrap();
        assert_eq!(config.lan_ip, "10.0.0.1/24");
        assert_eq!(config.backup_lan_ip, "10.0.0.1/24");
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
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.logging.max_log_size_mb, 50);
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
    }
}
