use crate::init::watchdog::{HeartbeatSender, MonitoredService, send_service_heartbeat};
use crate::services::DNS_FORWARDER_SERVICE_NAME;
use crate::services::ipc::{
    DnsParentToWorkerMsg, DnsWorkerToParentMsg, LocalHostEvent, LocalHostReceiver,
    async_unix_stream, recv_msg, send_msg,
};
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{DNS_PORT, WanLeaseReceiver, create_ipc_fds, terminate_worker};
use log::{error, info};
use std::collections::HashMap;
use std::io::Error as IoError;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;

#[derive(Clone)]
struct LocalHostsState {
    rx: Arc<Mutex<Option<LocalHostReceiver>>>,
    cache: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
}

pub struct DnsForwarder {
    lease_rx: WanLeaseReceiver,
    state: ExternalWorker,
    heartbeat_tx: Option<HeartbeatSender>,
    local_hosts: LocalHostsState,
}

impl DnsForwarder {
    pub fn new(lease_rx: WanLeaseReceiver) -> Self {
        Self {
            lease_rx,
            state: ExternalWorker::new(DNS_FORWARDER_SERVICE_NAME),
            heartbeat_tx: None,
            local_hosts: LocalHostsState {
                rx: Arc::new(Mutex::new(None)),
                cache: Arc::new(Mutex::new(HashMap::new())),
            },
        }
    }

    pub fn with_heartbeat(lease_rx: WanLeaseReceiver, heartbeat_tx: HeartbeatSender) -> Self {
        Self {
            lease_rx,
            state: ExternalWorker::new(DNS_FORWARDER_SERVICE_NAME),
            heartbeat_tx: Some(heartbeat_tx),
            local_hosts: LocalHostsState {
                rx: Arc::new(Mutex::new(None)),
                cache: Arc::new(Mutex::new(HashMap::new())),
            },
        }
    }

    pub fn with_local_hosts(
        lease_rx: WanLeaseReceiver,
        heartbeat_tx: Option<HeartbeatSender>,
        local_hosts_rx: Option<LocalHostReceiver>,
    ) -> Self {
        Self {
            lease_rx,
            state: ExternalWorker::new(DNS_FORWARDER_SERVICE_NAME),
            heartbeat_tx,
            local_hosts: LocalHostsState {
                rx: Arc::new(Mutex::new(local_hosts_rx)),
                cache: Arc::new(Mutex::new(HashMap::new())),
            },
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
    local_hosts: LocalHostsState,
) {
    info!(
        "[dns-forwarder-parent] Supervising DNS forwarder worker (PID {})",
        child_pid
    );

    let mut last_dns_servers: Vec<Ipv4Addr> = Vec::new();

    // 1. Initial sync of upstream resolvers on startup
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

    // 2. Initial sync of cached local hostnames to worker
    {
        let cached = local_hosts.cache.lock().await.clone();
        for (name, ip) in cached {
            let msg = DnsParentToWorkerMsg::RegisterLocalHost { name, ip };
            if let Err(e) = send_msg(&mut ipc_writer, &msg).await {
                error!(
                    "[dns-forwarder-parent] Failed to send cached host to worker: {}",
                    e
                );
            }
        }
    }

    // 3. Reactive supervisor loop
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
            Some(event) = async {
                let mut guard = local_hosts.rx.lock().await;
                if let Some(ref mut rx) = *guard {
                    rx.recv().await
                } else {
                    futures_util::future::pending().await
                }
            } => {
                match event {
                    LocalHostEvent::Register { name, ip } => {
                        local_hosts.cache.lock().await.insert(name.clone(), ip);
                        let msg = DnsParentToWorkerMsg::RegisterLocalHost { name, ip };
                        if let Err(e) = send_msg(&mut ipc_writer, &msg).await {
                            error!("[dns-forwarder-parent] Failed to send RegisterLocalHost: {}", e);
                        }
                    }
                    LocalHostEvent::Deregister { name } => {
                        local_hosts.cache.lock().await.remove(&name);
                        let msg = DnsParentToWorkerMsg::DeregisterLocalHost { name };
                        if let Err(e) = send_msg(&mut ipc_writer, &msg).await {
                            error!("[dns-forwarder-parent] Failed to send DeregisterLocalHost: {}", e);
                        }
                    }
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
    local_hosts: LocalHostsState,
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
        local_hosts,
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
        let local_hosts = self.local_hosts.clone();

        self.state.start_supervised(
            setup_dns_forwarder_attempt,
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                start_parent_dns_monitor(
                    parent_ipc_fd,
                    child_pid,
                    lease_rx.clone(),
                    shutdown_rx,
                    heartbeat_tx.clone(),
                    local_hosts.clone(),
                )
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}
