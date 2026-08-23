use clap::{Parser, Subcommand};
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

#[derive(Debug)]
pub struct CliFd(pub OwnedFd);

impl Clone for CliFd {
    fn clone(&self) -> Self {
        Self(
            self.0
                .try_clone()
                .expect("failed to duplicate file descriptor"),
        )
    }
}

impl From<OwnedFd> for CliFd {
    fn from(fd: OwnedFd) -> Self {
        Self(fd)
    }
}

impl From<std::net::UdpSocket> for CliFd {
    fn from(sock: std::net::UdpSocket) -> Self {
        Self(sock.into())
    }
}

impl From<CliFd> for OwnedFd {
    fn from(cli_fd: CliFd) -> Self {
        cli_fd.0
    }
}

impl AsRawFd for CliFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsFd for CliFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

fn parse_cli_fd(s: &str) -> Result<CliFd, String> {
    let fd_num = s.parse::<RawFd>().map_err(|e| e.to_string())?;
    Ok(CliFd(unsafe { OwnedFd::from_raw_fd(fd_num) }))
}

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
    SntpClient {
        #[arg(value_parser = parse_cli_fd)]
        ipc_fd: CliFd,
    },
    #[command(name = "dhcp-client")]
    DhcpClient {
        #[arg(value_parser = parse_cli_fd)]
        ipc_fd: CliFd,
        #[arg(value_parser = parse_cli_fd)]
        raw_socket_fd: CliFd,
        wan_interface: String,
    },
    #[command(name = "dhcp-server")]
    DhcpServer {
        #[arg(value_parser = parse_cli_fd)]
        ipc_fd: CliFd,
        #[arg(value_parser = parse_cli_fd)]
        raw_socket_fd: CliFd,
        wan_interface: String,
        lan_ip: String,
    },
    #[command(name = "dns-forwarder")]
    DnsForwarder {
        #[arg(value_parser = parse_cli_fd)]
        ipc_fd: CliFd,
        #[arg(value_parser = parse_cli_fd)]
        dns_socket_fd: CliFd,
        #[arg(value_parser = parse_cli_fd)]
        upstream_socket_fd: CliFd,
    },
}

impl WorkerService {
    pub fn to_args(&self) -> Vec<String> {
        match self {
            Self::SntpClient { ipc_fd } => {
                vec![ipc_fd.as_raw_fd().to_string()]
            }
            Self::DhcpClient {
                ipc_fd,
                raw_socket_fd,
                wan_interface,
            } => {
                vec![
                    ipc_fd.as_raw_fd().to_string(),
                    raw_socket_fd.as_raw_fd().to_string(),
                    wan_interface.clone(),
                ]
            }
            Self::DhcpServer {
                ipc_fd,
                raw_socket_fd,
                wan_interface,
                lan_ip,
            } => {
                vec![
                    ipc_fd.as_raw_fd().to_string(),
                    raw_socket_fd.as_raw_fd().to_string(),
                    wan_interface.clone(),
                    lan_ip.clone(),
                ]
            }
            Self::DnsForwarder {
                ipc_fd,
                dns_socket_fd,
                upstream_socket_fd,
            } => {
                vec![
                    ipc_fd.as_raw_fd().to_string(),
                    dns_socket_fd.as_raw_fd().to_string(),
                    upstream_socket_fd.as_raw_fd().to_string(),
                ]
            }
        }
    }

    pub fn child_fds(&self) -> Vec<BorrowedFd<'_>> {
        match self {
            Self::SntpClient { ipc_fd } => vec![ipc_fd.as_fd()],
            Self::DhcpClient {
                ipc_fd,
                raw_socket_fd,
                ..
            } => vec![ipc_fd.as_fd(), raw_socket_fd.as_fd()],
            Self::DhcpServer {
                ipc_fd,
                raw_socket_fd,
                ..
            } => vec![ipc_fd.as_fd(), raw_socket_fd.as_fd()],
            Self::DnsForwarder {
                ipc_fd,
                dns_socket_fd,
                upstream_socket_fd,
            } => vec![
                ipc_fd.as_fd(),
                dns_socket_fd.as_fd(),
                upstream_socket_fd.as_fd(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::IntoRawFd;

    #[test]
    fn test_worker_multicall_parsing() {
        let (s1, s2) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd1 = s1.into_raw_fd();
        let fd2 = s2.into_raw_fd();

        let args1 = vec![
            "trimrouter".to_string(),
            "worker".to_string(),
            "dhcp-client".to_string(),
            fd1.to_string(),
            fd2.to_string(),
            "eth0".to_string(),
        ];
        assert!(Cli::try_parse_from(&args1).is_ok());

        let (s3, s4) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd3 = s3.into_raw_fd();
        let fd4 = s4.into_raw_fd();

        let args2 = vec![
            "/bin/trimrouter".to_string(),
            "worker".to_string(),
            "dhcp-client".to_string(),
            fd3.to_string(),
            fd4.to_string(),
            "eth0".to_string(),
        ];
        assert!(Cli::try_parse_from(&args2).is_ok());

        let args3 = vec!["modprobe".to_string(), "net-pf-10".to_string()];
        assert!(Cli::try_parse_from(&args3).is_ok());
    }

    #[test]
    fn test_init_multicall_parsing() {
        let init_args1 = vec!["init".to_string()];
        let cli_init1 = Cli::try_parse_from(&init_args1).expect("Failed to parse init");
        assert!(matches!(cli_init1.command, Some(Commands::Init { .. })));

        let init_args2 = vec!["/init".to_string(), "--flag".to_string()];
        let cli_init2 = Cli::try_parse_from(&init_args2).expect("Failed to parse /init with flags");
        assert!(matches!(cli_init2.command, Some(Commands::Init { .. })));
    }

    #[test]
    fn test_proc_self_exe_worker_parsing() {
        let (s5, _s6) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd5 = s5.into_raw_fd();
        let exe_worker_args = vec![
            "/proc/self/exe".to_string(),
            "worker".to_string(),
            "sntp-client".to_string(),
            fd5.to_string(),
        ];
        assert!(Cli::try_parse_from(&exe_worker_args).is_ok());

        let (s7, s8) = std::os::unix::net::UnixStream::pair().unwrap();
        let (s9, _s10) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd7 = s7.into_raw_fd();
        let fd8 = s8.into_raw_fd();
        let fd9 = s9.into_raw_fd();
        let exe_short_args = vec![
            "exe".to_string(),
            "worker".to_string(),
            "dns-forwarder".to_string(),
            fd7.to_string(),
            fd8.to_string(),
            fd9.to_string(),
        ];
        assert!(Cli::try_parse_from(&exe_short_args).is_ok());
    }
}
