use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Worker {
        #[command(subcommand)]
        service: WorkerService,
    },
}

#[derive(Subcommand, Debug)]
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
