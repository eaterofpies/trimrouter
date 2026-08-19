use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "trimrouter-multicall", multicall = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(
        name = "init",
        ignore_errors = true,
        disable_help_flag = true,
        disable_version_flag = true
    )]
    Init {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        _args: Vec<String>,
    },
    #[command(
        name = "modprobe",
        ignore_errors = true,
        disable_help_flag = true,
        disable_version_flag = true
    )]
    Modprobe {
        #[arg(short = 'q')]
        quiet: bool,

        #[arg(short = 's')]
        syslog: bool,

        #[arg(short = 'b')]
        use_blacklist: bool,

        module_name: String,

        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
    Worker {
        #[command(subcommand)]
        service: WorkerService,
    },
    #[command(name = "trimrouter", alias = "exe")]
    Trimrouter {
        #[command(subcommand)]
        sub: Option<TrimrouterSubcommands>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrimrouterSubcommands {
    #[command(
        name = "modprobe",
        ignore_errors = true,
        disable_help_flag = true,
        disable_version_flag = true
    )]
    Modprobe {
        #[arg(short = 'q')]
        quiet: bool,

        #[arg(short = 's')]
        syslog: bool,

        #[arg(short = 'b')]
        use_blacklist: bool,

        module_name: String,

        #[arg(trailing_var_arg = true)]
        params: Vec<String>,
    },
    Worker {
        #[command(subcommand)]
        service: WorkerService,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum WorkerService {
    #[command(name = "sntp-client")]
    SntpClient { ipc_fd: i32 },
    #[command(name = "dhcp-client")]
    DhcpClient {
        ipc_fd: i32,
        raw_socket_fd: i32,
        wan_interface: String,
    },
    #[command(name = "dhcp-server")]
    DhcpServer {
        ipc_fd: i32,
        raw_socket_fd: i32,
        wan_interface: String,
        lan_ip: String,
    },
    #[command(name = "dns-forwarder")]
    DnsForwarder {
        ipc_fd: i32,
        dns_socket_fd: i32,
        upstream_socket_fd: i32,
    },
}

impl WorkerService {
    pub fn to_args_and_child_fds(&self) -> (Vec<String>, Vec<std::os::unix::io::RawFd>) {
        match self {
            Self::SntpClient { ipc_fd } => (vec![ipc_fd.to_string()], vec![*ipc_fd]),
            Self::DhcpClient {
                ipc_fd,
                raw_socket_fd,
                wan_interface,
            } => (
                vec![
                    ipc_fd.to_string(),
                    raw_socket_fd.to_string(),
                    wan_interface.clone(),
                ],
                vec![*ipc_fd, *raw_socket_fd],
            ),
            Self::DhcpServer {
                ipc_fd,
                raw_socket_fd,
                wan_interface,
                lan_ip,
            } => (
                vec![
                    ipc_fd.to_string(),
                    raw_socket_fd.to_string(),
                    wan_interface.clone(),
                    lan_ip.clone(),
                ],
                vec![*ipc_fd, *raw_socket_fd],
            ),
            Self::DnsForwarder {
                ipc_fd,
                dns_socket_fd,
                upstream_socket_fd,
            } => (
                vec![
                    ipc_fd.to_string(),
                    dns_socket_fd.to_string(),
                    upstream_socket_fd.to_string(),
                ],
                vec![*ipc_fd, *dns_socket_fd, *upstream_socket_fd],
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multicall_parsing() {
        let args1 = vec![
            "trimrouter".to_string(),
            "worker".to_string(),
            "dhcp-client".to_string(),
            "3".to_string(),
            "4".to_string(),
            "eth0".to_string(),
        ];
        assert!(Cli::try_parse_from(&args1).is_ok());

        let args2 = vec![
            "/bin/trimrouter".to_string(),
            "worker".to_string(),
            "dhcp-client".to_string(),
            "3".to_string(),
            "4".to_string(),
            "eth0".to_string(),
        ];
        assert!(Cli::try_parse_from(&args2).is_ok());

        let args3 = vec!["modprobe".to_string(), "net-pf-10".to_string()];
        assert!(Cli::try_parse_from(&args3).is_ok());

        // Test PID 1 init invocation (e.g. /init from kernel)
        let init_args1 = vec!["init".to_string()];
        let cli_init1 = Cli::try_parse_from(&init_args1).expect("Failed to parse init");
        assert!(matches!(cli_init1.command, Some(Commands::Init { .. })));

        let init_args2 = vec!["/init".to_string(), "--flag".to_string()];
        let cli_init2 = Cli::try_parse_from(&init_args2).expect("Failed to parse /init with flags");
        assert!(matches!(cli_init2.command, Some(Commands::Init { .. })));

        // Test worker spawned via /proc/self/exe
        let exe_worker_args = vec![
            "/proc/self/exe".to_string(),
            "worker".to_string(),
            "sntp-client".to_string(),
            "5".to_string(),
        ];
        assert!(Cli::try_parse_from(&exe_worker_args).is_ok());

        let exe_short_args = vec![
            "exe".to_string(),
            "worker".to_string(),
            "dns-forwarder".to_string(),
            "3".to_string(),
            "4".to_string(),
            "5".to_string(),
        ];
        assert!(Cli::try_parse_from(&exe_short_args).is_ok());
    }
}
