use crate::system::SystemOps;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub lan_ip: String,
    pub wan_mac: String,
    pub lan_mac: String,
    pub reboot_delay: Option<u32>, // Some(N) = N seconds, None = infinite
}

fn extract_cmdline_arg(
    arg: &str,
    lan_ip: &mut Option<String>,
    wan_mac: &mut Option<String>,
    lan_mac: &mut Option<String>,
    reboot_delay: &mut Option<String>,
) {
    if let Some(val) = arg.strip_prefix("rustyrouter.lan_ip=") {
        *lan_ip = Some(val.to_string());
    } else if let Some(val) = arg.strip_prefix("rustyrouter.wan_mac=") {
        *wan_mac = Some(val.to_string());
    } else if let Some(val) = arg.strip_prefix("rustyrouter.lan_mac=") {
        *lan_mac = Some(val.to_string());
    } else if arg == "rustyrouter.reboot_delay" {
        *reboot_delay = Some("10".to_string());
    } else if let Some(val) = arg.strip_prefix("rustyrouter.reboot_delay=") {
        *reboot_delay = Some(val.to_string());
    }
}

fn parse_cmdline<S: SystemOps>(sys: &S) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let Ok(cmdline) = sys.read_cmdline() else {
        println!("[config] Failed to read /proc/cmdline, using automatic fallback");
        return (None, None, None, None);
    };

    println!("[config] Read /proc/cmdline: {}", cmdline.trim());
    let mut lan_ip = None;
    let mut wan_mac = None;
    let mut lan_mac = None;
    let mut reboot_delay = None;

    for arg in cmdline.split_whitespace() {
        extract_cmdline_arg(arg, &mut lan_ip, &mut wan_mac, &mut lan_mac, &mut reboot_delay);
    }
    (lan_ip, wan_mac, lan_mac, reboot_delay)
}

impl RouterConfig {
    pub fn parse<S: SystemOps>(sys: &S) -> Self {
        let (lan_ip, wan_mac, lan_mac, reboot_delay_str) = parse_cmdline(sys);

        let wan_mac = wan_mac.expect("rustyrouter.wan_mac configuration parameter is required");
        let lan_mac = lan_mac.expect("rustyrouter.lan_mac configuration parameter is required");
        let lan_ip = lan_ip.unwrap_or_else(|| "192.168.1.1/24".to_string());

        let reboot_delay = match reboot_delay_str {
            Some(ref s) => s.parse::<u32>().ok().or(Some(10)),
            None => None, // unset = infinite if not specified at all
        };

        RouterConfig {
            lan_ip,
            wan_mac,
            lan_mac,
            reboot_delay,
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
        assert_eq!(config.reboot_delay, None); // unspecified is infinite
    }

    #[test]
    fn test_config_parsing_reboot_delay() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "rustyrouter.wan_mac=52:54:00:12:34:56 rustyrouter.lan_mac=52:54:00:12:34:57 rustyrouter.reboot_delay=5".to_string();
        let cfg = RouterConfig::parse(&sys);
        assert_eq!(cfg.reboot_delay, Some(5));

        sys.cmdline_content = "rustyrouter.wan_mac=52:54:00:12:34:56 rustyrouter.lan_mac=52:54:00:12:34:57 rustyrouter.reboot_delay".to_string();
        let cfg = RouterConfig::parse(&sys);
        assert_eq!(cfg.reboot_delay, Some(10)); // standalone flag is 10
    }
}
