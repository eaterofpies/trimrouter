use crate::cli::WorkerService;
use crate::services::{dhcp_client, dhcp_server, dns_forwarder, sntp_client};
use log::error;
use std::process::exit;

async fn dispatch_worker(service: WorkerService) -> Result<(), (&'static str, std::io::Error)> {
    match service {
        WorkerService::SntpClient { ipc_fd } => sntp_client::run_sntp_client_worker(ipc_fd.into())
            .await
            .map_err(|e| ("sntp-client", e)),
        WorkerService::DhcpClient {
            ipc_fd,
            raw_socket_fd,
            wan_interface,
        } => {
            dhcp_client::run_dhcp_client_worker(ipc_fd.into(), raw_socket_fd.into(), wan_interface)
                .await
                .map_err(|e| ("dhcp-client", e))
        }
        WorkerService::DhcpServer {
            ipc_fd,
            raw_socket_fd,
            wan_interface,
            lan_ip,
        } => dhcp_server::run_dhcp_server_worker(
            ipc_fd.into(),
            raw_socket_fd.into(),
            wan_interface,
            lan_ip,
        )
        .await
        .map_err(|e| ("dhcp-server", e)),
        WorkerService::DnsForwarder {
            ipc_fd,
            dns_socket_fd,
            upstream_socket_fd,
        } => dns_forwarder::run_dns_forwarder_worker(
            ipc_fd.into(),
            dns_socket_fd.into(),
            upstream_socket_fd.into(),
        )
        .await
        .map_err(|e| ("dns-forwarder", e)),
    }
}

pub async fn run_worker(service: WorkerService) {
    if let Err((name, e)) = dispatch_worker(service).await {
        error!("[{}-worker] ERROR: {}", name, e);
        exit(1);
    }
    exit(0);
}
