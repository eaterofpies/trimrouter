pub mod dhcp_client;
pub mod dhcp_server;
pub mod dns_forwarder;
pub mod sntp_client;
pub mod utils;

pub use dhcp_client::DhcpClient;
pub use dhcp_server::DhcpServer;
pub use dns_forwarder::DnsForwarder;
pub use sntp_client::SntpClient;
pub use utils::WanLease;

#[derive(Debug)]
pub enum ServiceError {
    AlreadyRunning,
    NotRunning,
    Io(std::io::Error),
    FailedToStart(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::AlreadyRunning => write!(f, "Service is already running"),
            ServiceError::NotRunning => write!(f, "Service is not running"),
            ServiceError::Io(e) => write!(f, "IO error: {}", e),
            ServiceError::FailedToStart(msg) => write!(f, "Failed to start: {}", msg),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<std::io::Error> for ServiceError {
    fn from(e: std::io::Error) -> Self {
        ServiceError::Io(e)
    }
}

pub trait Service: Send + Sync {
    async fn start(&mut self) -> Result<(), ServiceError>;
    async fn stop(&mut self) -> Result<(), ServiceError>;
}

