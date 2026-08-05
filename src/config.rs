use crate::error::RouterError;
use crate::system::SystemOps;
use pnet::util::MacAddr;
use serde::Deserialize;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub lan_ip: String,
    pub wan_mac: MacAddr,
    pub lan_mac: MacAddr,
    pub reboot_delay: Option<u32>, // Some(N) = N seconds, None = infinite
}

#[derive(Deserialize)]
struct ConfigToml {
    network: NetworkSection,
    system: Option<SystemSection>,
}

#[derive(Deserialize)]
struct NetworkSection {
    lan_ip: Option<String>,
    wan_mac: String,
    lan_mac: String,
}

#[derive(Deserialize)]
struct SystemSection {
    reboot_delay: Option<u32>,
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

        let reboot_delay = parsed
            .system
            .as_ref()
            .and_then(|sys_sec| sys_sec.reboot_delay);

        Ok(RouterConfig {
            lan_ip,
            wan_mac,
            lan_mac,
            reboot_delay,
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
    fn test_config_parsing_with_mac() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            lan_ip = "10.0.0.1/24"
        "#
        .to_string();

        let config = RouterConfig::parse(&sys).unwrap();
        assert_eq!(config.lan_ip, "10.0.0.1/24");
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
    fn test_config_parsing_reboot_delay() {
        let mut sys = MockSystem::new();
        sys.config_content = r#"
            [network]
            wan_mac = "52:54:00:12:34:56"
            lan_mac = "52:54:00:12:34:57"
            [system]
            reboot_delay = 5
        "#
        .to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.reboot_delay, Some(5));
    }
}
