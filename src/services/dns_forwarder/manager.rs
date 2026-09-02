use crate::init::watchdog::{HeartbeatSender, MonitoredService, send_service_heartbeat};
use crate::services::DNS_FORWARDER_SERVICE_NAME;
use crate::services::ipc::{
    DnsParentToWorkerMsg, DnsWorkerToParentMsg, async_unix_stream, recv_msg, send_msg,
};
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{DNS_PORT, WanLeaseReceiver, create_ipc_fds, terminate_worker};
use log::{error, info};
use std::io::Error as IoError;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::OwnedFd;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;

pub struct DnsForwarder {
    lease_rx: WanLeaseReceiver,
    state: ExternalWorker,
    heartbeat_tx: Option<HeartbeatSender>,
}

impl DnsForwarder {
    pub fn new(lease_rx: WanLeaseReceiver) -> Self {
        Self {
            lease_rx,
            state: ExternalWorker::new(DNS_FORWARDER_SERVICE_NAME),
            heartbeat_tx: None,
        }
    }

    pub fn with_heartbeat(lease_rx: WanLeaseReceiver, heartbeat_tx: HeartbeatSender) -> Self {
        Self {
            lease_rx,
            state: ExternalWorker::new(DNS_FORWARDER_SERVICE_NAME),
            heartbeat_tx: Some(heartbeat_tx),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
}

async fn run_parent_dns_monitor(
    mut ipc_reader: OwnedReadHalf,
    mut ipc_writer: OwnedWriteHalf,
    child_pid: u32,
    mut lease_rx: WanLeaseReceiver,
    mut shutdown_rx: Receiver<bool>,
    heartbeat_tx: Option<HeartbeatSender>,
) {
    info!(
        "[dns-forwarder-parent] Supervising DNS forwarder worker (PID {})",
        child_pid
    );

    let mut last_dns_servers: Vec<Ipv4Addr> = Vec::new();

    // 1. Initial sync on startup (marks version as seen)
    {
        let initial_servers = lease_rx.borrow_and_update().dns_servers.clone();
        if !initial_servers.is_empty() {
            if let Err(e) = update_upstream_resolvers(&mut ipc_writer, &initial_servers).await {
                error!(
                    "[dns-forwarder-parent] Failed to send initial upstream resolvers: {}",
                    e
                );
            }
            last_dns_servers = initial_servers;
        }
    }

    // 2. Reactive loop: receive worker heartbeats and update upstream resolvers
    while !*shutdown_rx.borrow() {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            ipc_msg = recv_msg::<DnsWorkerToParentMsg, _>(&mut ipc_reader) => {
                match ipc_msg {
                    Ok(Some(DnsWorkerToParentMsg::Heartbeat)) => {
                        send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::DnsForwarder);
                    }
                    Ok(None) | Err(_) => {
                        info!("[dns-forwarder-parent] Worker closed IPC. Shutting down monitor.");
                        break;
                    }
                }
            }
            res = lease_rx.changed() => {
                if res.is_err() {
                    break;
                }
                let current_servers = lease_rx.borrow_and_update().dns_servers.clone();
                if current_servers != last_dns_servers {
                    if update_upstream_resolvers(&mut ipc_writer, &current_servers).await.is_err() {
                        break;
                    }
                    last_dns_servers = current_servers;
                }
            }
        }
    }

    terminate_worker(child_pid).await;
}

async fn update_upstream_resolvers(
    ipc_writer: &mut OwnedWriteHalf,
    servers: &[Ipv4Addr],
) -> Result<(), IoError> {
    info!(
        "[dns-forwarder-parent] Upstream DNS servers updated: {:?}",
        servers
    );
    let msg = DnsParentToWorkerMsg::SetUpstreamResolvers {
        servers: servers.to_vec(),
    };
    send_msg(ipc_writer, &msg).await
}

fn start_parent_dns_monitor(
    parent_ipc_fd: OwnedFd,
    child_pid: u32,
    lease_rx: WanLeaseReceiver,
    shutdown_rx: Receiver<bool>,
    heartbeat_tx: Option<HeartbeatSender>,
) -> Result<JoinHandle<()>, ServiceError> {
    let ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();

    let handle = tokio::spawn(run_parent_dns_monitor(
        ipc_reader,
        ipc_writer,
        child_pid,
        lease_rx,
        shutdown_rx,
        heartbeat_tx,
    ));

    Ok(handle)
}

fn setup_dns_forwarder_attempt() -> Result<(crate::cli::WorkerService, OwnedFd), ServiceError> {
    let (parent_ipc, child_ipc) = create_ipc_fds()?;
    let dns_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, DNS_PORT))?;
    let upstream_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;

    Ok((
        crate::cli::WorkerService::DnsForwarder {
            ipc_fd: child_ipc.into(),
            dns_socket_fd: dns_socket.into(),
            upstream_socket_fd: upstream_socket.into(),
        },
        parent_ipc,
    ))
}

impl Service for DnsForwarder {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let lease_rx = self.lease_rx.clone();
        let heartbeat_tx = self.heartbeat_tx.clone();

        self.state.start_supervised(
            setup_dns_forwarder_attempt,
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                start_parent_dns_monitor(
                    parent_ipc_fd,
                    child_pid,
                    lease_rx.clone(),
                    shutdown_rx,
                    heartbeat_tx.clone(),
                )
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}
