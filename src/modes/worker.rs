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
    fn test_worker_service_properties_all_variants() {
        let (s1, _s2) = std::os::unix::net::UnixStream::pair().unwrap();
        let (s3, _s4) = std::os::unix::net::UnixStream::pair().unwrap();
        let udp_sock1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp_sock2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        // 1. SntpClient
        let sntp = WorkerService::SntpClient {
            ipc_fd: CliFd(s1.into()),
            ntp_socket_fd: CliFd(udp_sock1.into()),
        };
        assert_eq!(sntp.child_fds().len(), 2);
        assert_eq!(sntp.to_args().len(), 2);

        // 2. DnsForwarder
        let dns = WorkerService::DnsForwarder {
            ipc_fd: CliFd(s3.into()),
            dns_socket_fd: CliFd(udp_sock2.into()),
            upstream_socket_fd: CliFd(std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into()),
        };
        assert_eq!(dns.child_fds().len(), 3);
        assert_eq!(dns.to_args().len(), 3);

        // 3. DhcpClient
        let (s5, _s6) = std::os::unix::net::UnixStream::pair().unwrap();
        let dhcp_cli = WorkerService::DhcpClient {
            ipc_fd: CliFd(s5.into()),
            raw_socket_fd: CliFd(std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into()),
            wan_interface: "wan".to_string(),
        };
        assert_eq!(dhcp_cli.child_fds().len(), 2);
        assert_eq!(dhcp_cli.to_args().len(), 3);

        // 4. DhcpServer
        let (s7, _s8) = std::os::unix::net::UnixStream::pair().unwrap();
        let dhcp_srv = WorkerService::DhcpServer {
            ipc_fd: CliFd(s7.into()),
            raw_socket_fd: CliFd(std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into()),
            wan_interface: "lan".to_string(),
            lan_ip: "192.168.1.1/24".to_string(),
        };
        assert_eq!(dhcp_srv.child_fds().len(), 2);
        assert_eq!(dhcp_srv.to_args().len(), 4);
    }
}
