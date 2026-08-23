use super::ipc::{DnsParentToWorkerMsg, async_unix_stream, send_msg};
use super::utils::{SharedWanLease, create_ipc_fds, terminate_worker};
use super::{ExternalWorker, Service, ServiceError};
use log::info;
use std::io::{Error as IoError, ErrorKind};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;
use tokio::time::interval;

const DNS_PORT: u16 = 53;

pub struct DnsForwarder {
    lease_state: SharedWanLease,
    state: ExternalWorker,
}

impl DnsForwarder {
    pub fn new(lease_state: SharedWanLease) -> Self {
        Self {
            lease_state,
            state: ExternalWorker::new("dns-forwarder"),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
}

async fn run_parent_dns_monitor(
    ipc_reader: OwnedReadHalf,
    shared_ipc_writer: Arc<Mutex<OwnedWriteHalf>>,
    child_pid: u32,
    lease_state: SharedWanLease,
    mut shutdown_rx: Receiver<bool>,
) {
    info!(
        "[dns-forwarder-parent] Supervising DNS forwarder worker (PID {})",
        child_pid
    );

    let mut last_dns_servers: Vec<Ipv4Addr> = Vec::new();
    let mut interval_timer = interval(Duration::from_secs(1));
    let mut eof_buf = [0u8; 1];

    while !*shutdown_rx.borrow() {
        tokio::select! {
            _ = shutdown_rx.changed() => {}
            read_res = ipc_reader.readable() => {
                if read_res.is_err() {
                    break;
                }
                match ipc_reader.try_read(&mut eof_buf) {
                    Ok(0) => {
                        info!("[dns-forwarder-parent] Worker closed IPC. Shutting down monitor.");
                        break;
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                        // Not EOF, just woke up
                    }
                    _ => {
                        break;
                    }
                }
            }
            _ = interval_timer.tick() => {
                let current_servers = {
                    let lease = lease_state.lock().unwrap();
                    lease.dns_servers.clone()
                };

                if current_servers != last_dns_servers {
                    if update_upstream_resolvers(&shared_ipc_writer, &current_servers).await.is_err() {
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
    shared_ipc_writer: &Arc<Mutex<OwnedWriteHalf>>,
    servers: &[Ipv4Addr],
) -> Result<(), IoError> {
    info!(
        "[dns-forwarder-parent] Upstream DNS servers updated: {:?}",
        servers
    );
    let msg = DnsParentToWorkerMsg::SetUpstreamResolvers {
        servers: servers.to_vec(),
    };
    let mut writer = shared_ipc_writer.lock().await;
    send_msg(&mut *writer, &msg).await
}

fn start_parent_dns_monitor(
    parent_ipc_fd: OwnedFd,
    child_pid: u32,
    lease_state: SharedWanLease,
    shutdown_rx: Receiver<bool>,
) -> Result<JoinHandle<()>, ServiceError> {
    let ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(Mutex::new(ipc_writer));

    let handle = tokio::spawn(run_parent_dns_monitor(
        ipc_reader,
        shared_ipc_writer,
        child_pid,
        lease_state,
        shutdown_rx,
    ));

    Ok(handle)
}

fn setup_dns_forwarder_attempt() -> Result<(crate::cli::WorkerService, OwnedFd), ServiceError> {
    let (parent_ipc, child_ipc) = create_ipc_fds()?;
    let dns_socket = UdpSocket::bind(format!("0.0.0.0:{}", DNS_PORT))?;
    let upstream_socket = UdpSocket::bind("0.0.0.0:0")?;

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
        let lease_state = self.lease_state.clone();

        self.state.start_supervised(
            setup_dns_forwarder_attempt,
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                start_parent_dns_monitor(parent_ipc_fd, child_pid, lease_state.clone(), shutdown_rx)
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}
