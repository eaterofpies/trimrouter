use crate::error::RouterError;
use crate::system::SystemOps;
use pnet::util::MacAddr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterConfig {
    pub lan_ip: String,
    pub wan_mac: MacAddr,
    pub lan_mac: MacAddr,
    pub reboot_delay: Option<u32>, // Some(N) = N seconds, None = infinite
}

fn extract_cmdline_arg(
    arg: &str,
    lan_ip: &mut Option<String>,
    wan_mac: &mut Option<String>,
    lan_mac: &mut Option<String>,
    reboot_delay: &mut Option<String>,
) {
    if let Some(val) = arg.strip_prefix("trimrouter.lan_ip=") {
        *lan_ip = Some(val.to_string());
    } else if let Some(val) = arg.strip_prefix("trimrouter.wan_mac=") {
        *wan_mac = Some(val.to_string());
    } else if let Some(val) = arg.strip_prefix("trimrouter.lan_mac=") {
        *lan_mac = Some(val.to_string());
    } else if arg == "trimrouter.reboot_delay" {
        *reboot_delay = Some("10".to_string());
    } else if let Some(val) = arg.strip_prefix("trimrouter.reboot_delay=") {
        *reboot_delay = Some(val.to_string());
    }
}

fn parse_cmdline<S: SystemOps>(
    sys: &S,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
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
        extract_cmdline_arg(
            arg,
            &mut lan_ip,
            &mut wan_mac,
            &mut lan_mac,
            &mut reboot_delay,
        );
    }
    (lan_ip, wan_mac, lan_mac, reboot_delay)
}

impl RouterConfig {
    pub fn parse<S: SystemOps>(sys: &S) -> Result<Self, RouterError> {
        let (lan_ip, wan_mac_str, lan_mac_str, reboot_delay_str) = parse_cmdline(sys);

        let wan_mac_raw = wan_mac_str.ok_or_else(|| {
            RouterError::Generic(
                "trimrouter.wan_mac configuration parameter is required".to_string(),
            )
        })?;
        let lan_mac_raw = lan_mac_str.ok_or_else(|| {
            RouterError::Generic(
                "trimrouter.lan_mac configuration parameter is required".to_string(),
            )
        })?;

        let wan_mac = MacAddr::from_str(&wan_mac_raw).map_err(|_| {
            RouterError::Generic("trimrouter.wan_mac must be a valid MAC address".to_string())
        })?;
        let lan_mac = MacAddr::from_str(&lan_mac_raw).map_err(|_| {
            RouterError::Generic("trimrouter.lan_mac must be a valid MAC address".to_string())
        })?;

        let lan_ip = lan_ip.unwrap_or_else(|| "192.168.1.1/24".to_string());

        let reboot_delay = match reboot_delay_str {
            Some(ref s) => s.parse::<u32>().ok().or(Some(10)),
            None => None, // unset = infinite if not specified at all
        };

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
        sys.cmdline_content = "trimrouter.lan_mac=52:54:00:12:34:57".to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            "Router error: trimrouter.wan_mac configuration parameter is required"
        );
    }

    #[test]
    fn test_config_parsing_missing_lan_mac() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "trimrouter.wan_mac=52:54:00:12:34:56".to_string();
        let res = RouterConfig::parse(&sys);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            "Router error: trimrouter.lan_mac configuration parameter is required"
        );
    }

    #[test]
    fn test_config_parsing_with_mac() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "trimrouter.wan_mac=52:54:00:12:34:56 trimrouter.lan_mac=52:54:00:12:34:57 trimrouter.lan_ip=10.0.0.1/24".to_string();

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
        assert_eq!(config.reboot_delay, None); // unspecified is infinite
    }

    #[test]
    fn test_config_parsing_reboot_delay() {
        let mut sys = MockSystem::new();
        sys.cmdline_content = "trimrouter.wan_mac=52:54:00:12:34:56 trimrouter.lan_mac=52:54:00:12:34:57 trimrouter.reboot_delay=5".to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.reboot_delay, Some(5));

        sys.cmdline_content = "trimrouter.wan_mac=52:54:00:12:34:56 trimrouter.lan_mac=52:54:00:12:34:57 trimrouter.reboot_delay".to_string();
        let cfg = RouterConfig::parse(&sys).unwrap();
        assert_eq!(cfg.reboot_delay, Some(10)); // standalone flag is 10
    }
}
