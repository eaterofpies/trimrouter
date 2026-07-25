use crate::system::SystemOps;
use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub lan_ip: String,
    pub wan_mac: String,
    pub lan_mac: String,
}

impl RouterConfig {
    pub fn parse<S: SystemOps>(sys: &S) -> Self {
        // 1. Check environment variable overrides first (useful for testing/dev namespaces)
        let mut lan_ip = env::var("RUSTYROUTER_LAN_IP").ok();
        let mut wan_mac = env::var("RUSTYROUTER_WAN_MAC").ok();
        let mut lan_mac = env::var("RUSTYROUTER_LAN_MAC").ok();

        let env_override = lan_ip.is_some() || wan_mac.is_some() || lan_mac.is_some();

        // 2. Parse from /proc/cmdline if env variables are not fully set
        if !env_override {
            if let Ok(cmdline) = sys.read_cmdline() {
                println!("[config] Read /proc/cmdline: {}", cmdline.trim());
                for arg in cmdline.split_whitespace() {
                    if let Some(val) = arg.strip_prefix("rustyrouter.lan_ip=") {
                        lan_ip = Some(val.to_string());
                    } else if let Some(val) = arg.strip_prefix("rustyrouter.wan_mac=") {
                        wan_mac = Some(val.to_string());
                    } else if let Some(val) = arg.strip_prefix("rustyrouter.lan_mac=") {
                        lan_mac = Some(val.to_string());
                    }
                }
            } else {
                println!("[config] Failed to read /proc/cmdline, using automatic fallback");
            }
        } else {
            println!("[config] Using environment variable overrides");
        }

        // 3. Apply parsed config or panic if required MAC parameters are missing
        let wan_mac = wan_mac.expect("rustyrouter.wan_mac configuration parameter is required");
        let lan_mac = lan_mac.expect("rustyrouter.lan_mac configuration parameter is required");

        RouterConfig {
            lan_ip: lan_ip.unwrap_or_else(|| "192.168.1.1/24".to_string()),
            wan_mac,
            lan_mac,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::mock::MockSystem;

    #[test]
    #[should_panic(expected = "rustyrouter.wan_mac configuration parameter is required")]
    fn test_config_parsing_missing_wan_mac() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "rustyrouter.lan_mac=52:54:00:12:34:57".to_string();
        RouterConfig::parse(&sys);
    }

    #[test]
    #[should_panic(expected = "rustyrouter.lan_mac configuration parameter is required")]
    fn test_config_parsing_missing_lan_mac() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "rustyrouter.wan_mac=52:54:00:12:34:56".to_string();
        RouterConfig::parse(&sys);
    }

    #[test]
    fn test_config_parsing_with_mac() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "rustyrouter.wan_mac=52:54:00:12:34:56 rustyrouter.lan_mac=52:54:00:12:34:57 rustyrouter.lan_ip=10.0.0.1/24".to_string();

        let config = RouterConfig::parse(&sys);
        assert_eq!(config.lan_ip, "10.0.0.1/24");
        assert_eq!(config.wan_mac, "52:54:00:12:34:56");
        assert_eq!(config.lan_mac, "52:54:00:12:34:57");
    }
}
