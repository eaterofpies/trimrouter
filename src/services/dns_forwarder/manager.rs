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
    custom_dns: Vec<Ipv4Addr>,
    state: ExternalWorker,
    heartbeat_tx: Option<HeartbeatSender>,
    local_hosts: LocalHostsState,
}

impl DnsForwarder {
    pub fn new(lease_rx: WanLeaseReceiver) -> Self {
        Self::with_custom_dns(lease_rx, Vec::new(), None, None)
    }

    pub fn with_heartbeat(lease_rx: WanLeaseReceiver, heartbeat_tx: HeartbeatSender) -> Self {
        Self::with_custom_dns(lease_rx, Vec::new(), Some(heartbeat_tx), None)
    }

    pub fn with_local_hosts(
        lease_rx: WanLeaseReceiver,
        heartbeat_tx: Option<HeartbeatSender>,
        local_hosts_rx: Option<LocalHostReceiver>,
    ) -> Self {
        Self::with_custom_dns(lease_rx, Vec::new(), heartbeat_tx, local_hosts_rx)
    }

    pub fn with_custom_dns(
        lease_rx: WanLeaseReceiver,
        custom_dns: Vec<Ipv4Addr>,
        heartbeat_tx: Option<HeartbeatSender>,
        local_hosts_rx: Option<LocalHostReceiver>,
    ) -> Self {
        Self {
            lease_rx,
            custom_dns,
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

struct DnsMonitorParams {
    child_pid: u32,
    lease_rx: WanLeaseReceiver,
    custom_dns: Vec<Ipv4Addr>,
    shutdown_rx: Receiver<bool>,
    heartbeat_tx: Option<HeartbeatSender>,
    local_hosts: LocalHostsState,
}

async fn run_parent_dns_monitor(
    mut ipc_reader: OwnedReadHalf,
    mut ipc_writer: OwnedWriteHalf,
    mut params: DnsMonitorParams,
) {
    info!(
        "[dns-forwarder-parent] Supervising DNS forwarder worker (PID {})",
        params.child_pid
    );

    let mut last_dns_servers: Vec<Ipv4Addr> = Vec::new();

    // 1. Initial sync of upstream resolvers on startup (custom DNS takes priority)
    {
        let initial_servers = if !params.custom_dns.is_empty() {
            params.custom_dns.clone()
        } else {
            params.lease_rx.borrow_and_update().dns_servers.clone()
        };

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
        let cached = params.local_hosts.cache.lock().await.clone();
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
    while !*params.shutdown_rx.borrow() {
        tokio::select! {
            _ = params.shutdown_rx.changed() => break,
            ipc_msg = recv_msg::<DnsWorkerToParentMsg, _>(&mut ipc_reader) => {
                match ipc_msg {
                    Ok(Some(DnsWorkerToParentMsg::Heartbeat)) => {
                        send_service_heartbeat(params.heartbeat_tx.as_ref(), MonitoredService::DnsForwarder);
                    }
                    Ok(None) | Err(_) => {
                        info!("[dns-forwarder-parent] Worker closed IPC. Shutting down monitor.");
                        break;
                    }
                }
            }
            res = params.lease_rx.changed() => {
                if res.is_err() {
                    break;
                }
                if params.custom_dns.is_empty() {
                    let current_servers = params.lease_rx.borrow_and_update().dns_servers.clone();
                    if current_servers != last_dns_servers {
                        if update_upstream_resolvers(&mut ipc_writer, &current_servers).await.is_err() {
                            break;
                        }
                        last_dns_servers = current_servers;
                    }
                }
            }
            Some(event) = async {
                let mut guard = params.local_hosts.rx.lock().await;
                if let Some(ref mut rx) = *guard {
                    rx.recv().await
                } else {
                    futures_util::future::pending().await
                }
            } => {
                match event {
                    LocalHostEvent::Register { name, ip } => {
                        params.local_hosts.cache.lock().await.insert(name.clone(), ip);
                        let msg = DnsParentToWorkerMsg::RegisterLocalHost { name, ip };
                        if let Err(e) = send_msg(&mut ipc_writer, &msg).await {
                            error!("[dns-forwarder-parent] Failed to send RegisterLocalHost: {}", e);
                        }
                    }
                    LocalHostEvent::Deregister { name } => {
                        params.local_hosts.cache.lock().await.remove(&name);
                        let msg = DnsParentToWorkerMsg::DeregisterLocalHost { name };
                        if let Err(e) = send_msg(&mut ipc_writer, &msg).await {
                            error!("[dns-forwarder-parent] Failed to send DeregisterLocalHost: {}", e);
                        }
                    }
                }
            }
        }
    }

    terminate_worker(params.child_pid).await;
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
    params: DnsMonitorParams,
) -> Result<JoinHandle<()>, ServiceError> {
    let ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();

    let handle = tokio::spawn(run_parent_dns_monitor(ipc_reader, ipc_writer, params));

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
        let custom_dns = self.custom_dns.clone();
        let heartbeat_tx = self.heartbeat_tx.clone();
        let local_hosts = self.local_hosts.clone();

        self.state.start_supervised(
            setup_dns_forwarder_attempt,
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                let params = DnsMonitorParams {
                    child_pid,
                    lease_rx: lease_rx.clone(),
                    custom_dns: custom_dns.clone(),
                    shutdown_rx,
                    heartbeat_tx: heartbeat_tx.clone(),
                    local_hosts: local_hosts.clone(),
                };
                start_parent_dns_monitor(parent_ipc_fd, params)
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::WanLease;
    use tokio::net::UnixStream;

    #[test]
    fn test_dns_forwarder_constructors_and_pid() {
        let (_tx, lease_rx) = tokio::sync::watch::channel(WanLease::default());
        let fwd = DnsForwarder::new(lease_rx.clone());
        assert_eq!(fwd.get_worker_pid(), 0);

        let (hb_tx, _hb_rx) = tokio::sync::mpsc::channel(1);
        let fwd_hb = DnsForwarder::with_heartbeat(lease_rx.clone(), hb_tx);
        assert_eq!(fwd_hb.get_worker_pid(), 0);

        let (_lh_tx, lh_rx) = tokio::sync::mpsc::channel(1);
        let fwd_lh = DnsForwarder::with_local_hosts(lease_rx.clone(), None, Some(lh_rx));
        assert_eq!(fwd_lh.get_worker_pid(), 0);

        let custom = vec![Ipv4Addr::new(1, 1, 1, 1)];
        let fwd_custom = DnsForwarder::with_custom_dns(lease_rx, custom, None, None);
        assert_eq!(fwd_custom.get_worker_pid(), 0);
    }

    #[tokio::test]
    async fn test_update_upstream_resolvers_ipc_message() {
        let (s1, s2) = UnixStream::pair().unwrap();
        let (_r1, mut w1) = s1.into_split();
        let (mut r2, _w2) = s2.into_split();

        let servers = vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)];
        let res = update_upstream_resolvers(&mut w1, &servers).await;
        assert!(res.is_ok());

        let received: Option<DnsParentToWorkerMsg> = recv_msg(&mut r2).await.unwrap();
        assert_eq!(
            received,
            Some(DnsParentToWorkerMsg::SetUpstreamResolvers { servers })
        );
    }
}
