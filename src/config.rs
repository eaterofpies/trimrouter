use crate::system::SystemOps;
use std::env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub lan_ip: String,
    pub wan_mac: String,
    pub lan_mac: String,
}

fn parse_env() -> (Option<String>, Option<String>, Option<String>) {
    let lan_ip = env::var("RUSTYROUTER_LAN_IP").ok();
    let wan_mac = env::var("RUSTYROUTER_WAN_MAC").ok();
    let lan_mac = env::var("RUSTYROUTER_LAN_MAC").ok();
    if lan_ip.is_some() || wan_mac.is_some() || lan_mac.is_some() {
        println!("[config] Using environment variable overrides");
    }
    (lan_ip, wan_mac, lan_mac)
}

fn extract_cmdline_arg(
    arg: &str,
    lan_ip: &mut Option<String>,
    wan_mac: &mut Option<String>,
    lan_mac: &mut Option<String>,
) {
    if let Some(val) = arg.strip_prefix("rustyrouter.lan_ip=") {
        *lan_ip = Some(val.to_string());
    } else if let Some(val) = arg.strip_prefix("rustyrouter.wan_mac=") {
        *wan_mac = Some(val.to_string());
    } else if let Some(val) = arg.strip_prefix("rustyrouter.lan_mac=") {
        *lan_mac = Some(val.to_string());
    }
}

fn parse_cmdline<S: SystemOps>(sys: &S) -> (Option<String>, Option<String>, Option<String>) {
    let Ok(cmdline) = sys.read_cmdline() else {
        println!("[config] Failed to read /proc/cmdline, using automatic fallback");
        return (None, None, None);
    };

    println!("[config] Read /proc/cmdline: {}", cmdline.trim());
    let mut lan_ip = None;
    let mut wan_mac = None;
    let mut lan_mac = None;

    for arg in cmdline.split_whitespace() {
        extract_cmdline_arg(arg, &mut lan_ip, &mut wan_mac, &mut lan_mac);
    }
    (lan_ip, wan_mac, lan_mac)
}

impl RouterConfig {
    pub fn parse<S: SystemOps>(sys: &S) -> Self {
        let (lan_ip_env, wan_mac_env, lan_mac_env) = parse_env();
        let (lan_ip_cmd, wan_mac_cmd, lan_mac_cmd) =
            if lan_ip_env.is_none() && wan_mac_env.is_none() && lan_mac_env.is_none() {
                parse_cmdline(sys)
            } else {
                (None, None, None)
            };

        let wan_mac = wan_mac_env
            .or(wan_mac_cmd)
            .expect("rustyrouter.wan_mac configuration parameter is required");
        let lan_mac = lan_mac_env
            .or(lan_mac_cmd)
            .expect("rustyrouter.lan_mac configuration parameter is required");
        let lan_ip = lan_ip_env
            .or(lan_ip_cmd)
            .unwrap_or_else(|| "192.168.1.1/24".to_string());

        RouterConfig {
            lan_ip,
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
