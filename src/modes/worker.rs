use crate::cli::WorkerService;
use crate::workers::{dhcp_client, dhcp_server, dns_forwarder, sntp_client};
use log::error;
use std::process::exit;

pub async fn run_worker(service: WorkerService) {
    match service {
        WorkerService::SntpClient { ipc_fd } => {
            if let Err(e) = sntp_client::run_sntp_client_worker(ipc_fd).await {
                error!("[sntp-client-worker] ERROR: {}", e);
                exit(1);
            }
            exit(0);
        }
        WorkerService::DhcpClient {
            ipc_fd,
            raw_socket_fd,
            wan_interface,
        } => {
            if let Err(e) =
                dhcp_client::run_dhcp_client_worker(ipc_fd, raw_socket_fd, wan_interface).await
            {
                error!("[dhcp-client-worker] ERROR: {}", e);
                exit(1);
            }
            exit(0);
        }
        WorkerService::DhcpServer {
            ipc_fd,
            raw_socket_fd,
            wan_interface,
            lan_ip,
        } => {
            if let Err(e) =
                dhcp_server::run_dhcp_server_worker(ipc_fd, raw_socket_fd, wan_interface, lan_ip)
                    .await
            {
                error!("[dhcp-server-worker] ERROR: {}", e);
                exit(1);
            }
            exit(0);
        }
        WorkerService::DnsForwarder {
            ipc_fd,
            dns_socket_fd,
            upstream_socket_fd,
        } => {
            if let Err(e) =
                dns_forwarder::run_dns_forwarder_worker(ipc_fd, dns_socket_fd, upstream_socket_fd)
                    .await
            {
                error!("[dns-forwarder-worker] ERROR: {}", e);
                exit(1);
            }
            exit(0);
        }
    }
}
