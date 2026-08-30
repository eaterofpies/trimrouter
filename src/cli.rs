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
        #[arg(value_parser = parse_cli_fd)]
        ntp_socket_fd: CliFd,
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
            Self::SntpClient {
                ipc_fd,
                ntp_socket_fd,
            } => {
                vec![
                    ipc_fd.as_raw_fd().to_string(),
                    ntp_socket_fd.as_raw_fd().to_string(),
                ]
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
            Self::SntpClient {
                ipc_fd,
                ntp_socket_fd,
            } => vec![ipc_fd.as_fd(), ntp_socket_fd.as_fd()],
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
        let (s5b, _s6b) = std::os::unix::net::UnixStream::pair().unwrap();
        let fd5 = s5.into_raw_fd();
        let fd5b = s5b.into_raw_fd();
        let exe_worker_args = vec![
            "/proc/self/exe".to_string(),
            "worker".to_string(),
            "sntp-client".to_string(),
            fd5.to_string(),
            fd5b.to_string(),
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

    #[test]
    fn test_worker_service_arg_strings_and_child_fds() {
        let (s1, _s2) = std::os::unix::net::UnixStream::pair().unwrap();
        let (s3, _s4) = std::os::unix::net::UnixStream::pair().unwrap();
        let (s5, _s6) = std::os::unix::net::UnixStream::pair().unwrap();

        let fd1 = CliFd(s1.into());
        let fd2 = CliFd(s3.into());
        let fd3 = CliFd(s5.into());

        let raw1 = fd1.as_raw_fd().to_string();
        let raw2 = fd2.as_raw_fd().to_string();
        let raw3 = fd3.as_raw_fd().to_string();

        // SntpClient
        let (sntp_sock, _sntp_sock_peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let sntp_fd = CliFd(sntp_sock.into());
        let sntp_raw = sntp_fd.as_raw_fd().to_string();
        let sntp = WorkerService::SntpClient {
            ipc_fd: fd1,
            ntp_socket_fd: sntp_fd,
        };
        assert_eq!(sntp.to_args(), vec![raw1, sntp_raw]);
        assert_eq!(sntp.child_fds().len(), 2);

        // DhcpClient
        let (dc1, dc2) = std::os::unix::net::UnixStream::pair().unwrap();
        let (dc_raw1, dc_raw2) = (dc1.as_raw_fd().to_string(), dc2.as_raw_fd().to_string());
        let dhcp_cli = WorkerService::DhcpClient {
            ipc_fd: CliFd(dc1.into()),
            raw_socket_fd: CliFd(dc2.into()),
            wan_interface: "wan0".to_string(),
        };
        assert_eq!(
            dhcp_cli.to_args(),
            vec![dc_raw1, dc_raw2, "wan0".to_string()]
        );
        assert_eq!(dhcp_cli.child_fds().len(), 2);

        // DhcpServer
        let (ds1, ds2) = std::os::unix::net::UnixStream::pair().unwrap();
        let (ds_raw1, ds_raw2) = (ds1.as_raw_fd().to_string(), ds2.as_raw_fd().to_string());
        let dhcp_srv = WorkerService::DhcpServer {
            ipc_fd: CliFd(ds1.into()),
            raw_socket_fd: CliFd(ds2.into()),
            wan_interface: "lan0".to_string(),
            lan_ip: "192.168.1.1/24".to_string(),
        };
        assert_eq!(
            dhcp_srv.to_args(),
            vec![
                ds_raw1,
                ds_raw2,
                "lan0".to_string(),
                "192.168.1.1/24".to_string()
            ]
        );
        assert_eq!(dhcp_srv.child_fds().len(), 2);

        // DnsForwarder
        let dns = WorkerService::DnsForwarder {
            ipc_fd: CliFd(std::os::unix::net::UnixStream::pair().unwrap().0.into()),
            dns_socket_fd: fd2,
            upstream_socket_fd: fd3,
        };
        assert_eq!(dns.child_fds().len(), 3);
        assert_eq!(dns.to_args()[1], raw2);
        assert_eq!(dns.to_args()[2], raw3);
    }

    #[test]
    fn test_parse_cli_fd_invalid() {
        assert!(parse_cli_fd("not-a-number").is_err());
    }
}
