use crate::cli::WorkerService;
use crate::services::{
    DHCP_CLIENT_SERVICE_NAME, DHCP_SERVER_SERVICE_NAME, DNS_FORWARDER_SERVICE_NAME,
    SNTP_CLIENT_SERVICE_NAME, dhcp_client, dhcp_server, dns_forwarder, sntp_client,
};
use log::error;
use std::process::exit;

async fn dispatch_worker(service: WorkerService) -> Result<(), (&'static str, std::io::Error)> {
    match service {
        WorkerService::SntpClient {
            ipc_fd,
            ntp_socket_fd,
        } => sntp_client::run_sntp_client_worker(ipc_fd.into(), ntp_socket_fd.into())
            .await
            .map_err(|e| (SNTP_CLIENT_SERVICE_NAME, e)),
        WorkerService::DhcpClient {
            ipc_fd,
            raw_socket_fd,
            wan_interface,
        } => {
            dhcp_client::run_dhcp_client_worker(ipc_fd.into(), raw_socket_fd.into(), wan_interface)
                .await
                .map_err(|e| (DHCP_CLIENT_SERVICE_NAME, e))
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
        .map_err(|e| (DHCP_SERVER_SERVICE_NAME, e)),
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
        .map_err(|e| (DNS_FORWARDER_SERVICE_NAME, e)),
    }
}

pub async fn run_worker(service: WorkerService) {
    if let Err((name, e)) = dispatch_worker(service).await {
        error!("[{}-worker] ERROR: {}", name, e);
        exit(1);
    }
    exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CliFd;

    #[test]
    fn test_worker_service_properties() {
        let (s1, _s2) = std::os::unix::net::UnixStream::pair().unwrap();
        let udp_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        let service = WorkerService::SntpClient {
            ipc_fd: CliFd(s1.into()),
            ntp_socket_fd: CliFd(udp_sock.into()),
        };

        let fds = service.child_fds();
        assert_eq!(fds.len(), 2);
        let args = service.to_args();
        assert_eq!(args.len(), 2);
    }
}
