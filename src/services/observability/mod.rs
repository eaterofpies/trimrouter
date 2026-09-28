pub mod html;
pub mod server;
pub mod status;

pub use html::DASHBOARD_HTML;
pub use server::{HTTP_PORT, HttpServer, LogFilterParam};
pub use status::{
    ArpEntry, DEFAULT_LAN_INTERFACE, DEFAULT_WAN_INTERFACE, DhcpLeasesReceiver, DhcpLeasesSender,
    DnsStatsReceiver, DnsStatsSender, ObservabilityReceivers, SntpStatus, SntpStatusReceiver,
    SntpStatusSender, StatusResponse, WatchdogActiveReceiver, WatchdogActiveSender,
    null_dhcp_leases_sender, null_dns_stats_sender, null_sntp_status_sender,
    null_watchdog_active_sender,
};

use crate::services::supervisor::{Service, ServiceController, ServiceError};
use log::{debug, info};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpListener;

pub const OBSERVABILITY_SERVICE_NAME: &str = "observability";
pub const TCP_LISTEN_BACKLOG: i32 = 128;

pub struct ObservabilityService {
    lan_interface: String,
    lan_ip: String,
    receivers: ObservabilityReceivers,
    port: u16,
    controller: ServiceController,
}

impl ObservabilityService {
    pub fn new(
        lan_interface: String,
        lan_ip: String,
        receivers: ObservabilityReceivers,
        port: u16,
    ) -> Self {
        Self {
            lan_interface,
            lan_ip,
            receivers,
            port,
            controller: ServiceController::new(),
        }
    }
}

fn resolve_bind_socket_addr(lan_ip: &str, port: u16) -> SocketAddr {
    let ip_str = lan_ip.split('/').next().unwrap_or("0.0.0.0");
    let ip_addr = ip_str.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED);
    SocketAddr::new(IpAddr::V4(ip_addr), port)
}

fn configure_socket_binding(
    socket: &Socket,
    lan_interface: &str,
    lan_ip: &str,
    port: u16,
) -> Result<(), ServiceError> {
    let _ = socket.set_reuse_address(true);
    let _ = socket.set_nonblocking(true);

    if !lan_interface.is_empty()
        && let Err(e) = socket.bind_device(Some(lan_interface.as_bytes()))
    {
        debug!(
            "[observability] SO_BINDTODEVICE on '{}' failed ({}), continuing with standard bind",
            lan_interface, e
        );
    }

    let bind_addr = resolve_bind_socket_addr(lan_ip, port);
    if let Err(e) = socket.bind(&bind_addr.into()) {
        debug!(
            "[observability] Binding to {} failed ({}), falling back to 0.0.0.0:{}",
            bind_addr, e, port
        );
        let fallback_addr = SocketAddr::from(([0, 0, 0, 0], port));
        socket
            .bind(&fallback_addr.into())
            .map_err(ServiceError::Io)?;
    }

    socket
        .listen(TCP_LISTEN_BACKLOG)
        .map_err(ServiceError::Io)?;
    Ok(())
}

async fn create_bound_tcp_listener(
    lan_interface: &str,
    lan_ip: &str,
    port: u16,
) -> Result<TcpListener, ServiceError> {
    let socket =
        Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).map_err(ServiceError::Io)?;

    configure_socket_binding(&socket, lan_interface, lan_ip, port)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener).map_err(ServiceError::Io)
}

impl Service for ObservabilityService {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let listener =
            create_bound_tcp_listener(&self.lan_interface, &self.lan_ip, self.port).await?;
        let bind_addr = listener.local_addr().map_err(ServiceError::Io)?;

        info!(
            "[observability] Observability service listening on {} (interface: {})",
            bind_addr, self.lan_interface
        );

        let lan_interface = self.lan_interface.clone();
        let lan_ip = self.lan_ip.clone();
        let receivers = self.receivers.clone();

        self.controller.start(|shutdown_rx| async move {
            let server = HttpServer::new(listener, lan_interface, lan_ip, receivers);
            server.run(shutdown_rx).await;
            info!("[observability] Observability service stopped.");
        })
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.controller.stop().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_observability_service_lifecycle() {
        let (_lease_tx, lease_rx) = watch::channel(crate::services::WanLease::default());
        let (_dhcp_tx, dhcp_rx) = watch::channel(Vec::new());
        let (_dns_tx, dns_rx) = watch::channel(crate::services::ipc::DnsStatsInfo::default());
        let (_sntp_tx, sntp_rx) = watch::channel(SntpStatus::default());
        let (_watchdog_tx, watchdog_rx) = watch::channel(false);

        let receivers =
            ObservabilityReceivers::new(lease_rx, dhcp_rx, dns_rx, sntp_rx, watchdog_rx);

        let mut svc = ObservabilityService::new(
            "lan".to_string(),
            "192.168.1.1/24".to_string(),
            receivers,
            0, // Bind to random ephemeral port for testing
        );

        assert!(svc.start().await.is_ok());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(svc.stop().await.is_ok());
    }
}
