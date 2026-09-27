pub mod html;
pub mod server;
pub mod status;

pub use html::DASHBOARD_HTML;
pub use server::{HTTP_PORT, HttpServer};
pub use status::{
    DEFAULT_LAN_INTERFACE, DEFAULT_WAN_INTERFACE, ObservabilityTracker, StatusResponse,
    get_tracker, set_lan_info, update_current_lan_ip, update_dhcp_leases, update_dns_stats,
    update_sntp_sync,
};

use crate::services::supervisor::{Service, ServiceController, ServiceError};
use crate::services::utils::WanLeaseReceiver;
use log::{error, info};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub const OBSERVABILITY_SERVICE_NAME: &str = "observability";

pub struct ObservabilityService {
    lan_interface: String,
    lan_ip: String,
    lease_rx: WanLeaseReceiver,
    watchdog_active: bool,
    port: u16,
    controller: ServiceController,
}

impl ObservabilityService {
    pub fn new(
        lan_interface: String,
        lan_ip: String,
        lease_rx: WanLeaseReceiver,
        watchdog_active: bool,
        port: u16,
    ) -> Self {
        set_lan_info(&lan_interface, &lan_ip);
        Self {
            lan_interface,
            lan_ip,
            lease_rx,
            watchdog_active,
            port,
            controller: ServiceController::new(),
        }
    }

    pub fn reconfigure_lan_ip(&mut self, new_ip: &str) {
        self.lan_ip = new_ip.to_string();
        update_current_lan_ip(new_ip);
    }
}

impl Service for ObservabilityService {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
            error!(
                "[observability] Failed to bind HTTP listener to {}: {}",
                bind_addr, e
            );
            ServiceError::Io(e)
        })?;

        info!(
            "[observability] Observability service listening on {} (interface: {})",
            bind_addr, self.lan_interface
        );

        let lease_rx = self.lease_rx.clone();
        let watchdog_active = self.watchdog_active;

        self.controller.start(|shutdown_rx| async move {
            let server = HttpServer::new(listener, lease_rx, watchdog_active);
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
        let mut svc = ObservabilityService::new(
            "lan".to_string(),
            "192.168.1.1/24".to_string(),
            lease_rx,
            true,
            0, // Bind to random ephemeral port for testing
        );

        assert!(svc.start().await.is_ok());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(svc.stop().await.is_ok());
    }
}
