pub mod dhcp_client;
pub mod dhcp_server;
pub mod dns_forwarder;
pub mod ipc;
pub mod lan;
pub mod sntp_client;
pub mod supervisor;
pub mod utils;

pub use dhcp_client::{DhcpClient, run_dhcp_client_worker};
pub use dhcp_server::{DhcpServer, run_dhcp_server_worker};
pub use dns_forwarder::{DnsForwarder, run_dns_forwarder_worker};
pub use ipc::{LocalHostEvent, LocalHostReceiver, LocalHostSender};
pub use lan::LanManager;
pub use sntp_client::{SntpClient, run_sntp_client_worker};
pub use supervisor::{
    DHCP_CLIENT_SERVICE_NAME, DHCP_SERVER_SERVICE_NAME, DNS_FORWARDER_SERVICE_NAME, ExternalWorker,
    INTERFACE_MONITOR_SERVICE_NAME, LAN_MANAGER_SERVICE_NAME, SNTP_CLIENT_SERVICE_NAME, Service,
    ServiceController, ServiceError,
};
pub use utils::{CHROOT_JAIL_PATH, CleanOption, WanLease, WanLeaseReceiver, WanLeaseSender};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_service_instantiation_matrix() {
        let (lease_tx, lease_rx) = tokio::sync::watch::channel(WanLease::default());
        let (hb_tx, _hb_rx) = tokio::sync::mpsc::channel(1);
        let (lh_tx, _lh_rx) = tokio::sync::mpsc::channel(1);

        let dhcp_client = DhcpClient::with_heartbeat("wan".to_string(), lease_tx, hb_tx.clone());
        assert_eq!(dhcp_client.get_worker_pid(), 0);

        let dhcp_server = DhcpServer::new(
            "lan".to_string(),
            "192.168.1.1/24".to_string(),
            Some(hb_tx.clone()),
            Some(lh_tx.clone()),
            std::collections::HashMap::new(),
        );
        assert_eq!(dhcp_server.get_worker_pid(), 0);

        let dns_forwarder = DnsForwarder::with_custom_dns(
            lease_rx.clone(),
            vec![Ipv4Addr::new(1, 1, 1, 1)],
            Some(hb_tx.clone()),
            None,
        );
        assert_eq!(dns_forwarder.get_worker_pid(), 0);

        let _lan_manager = LanManager::new(
            "lan".to_string(),
            "192.168.1.1/24".to_string(),
            "10.0.0.1/24".to_string(),
            lease_rx.clone(),
            Some(hb_tx),
            Some(lh_tx),
            std::collections::HashMap::new(),
        );

        let _sntp_client = SntpClient::new(lease_rx);
    }
}
