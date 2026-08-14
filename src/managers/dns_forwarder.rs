use super::ipc::{DnsParentToWorkerMsg, send_msg};
use super::utils::{SharedWanLease, create_ipc_fds};
use super::{ExternalWorker, Service, ServiceError};
use std::net::Ipv4Addr;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::sync::Arc;

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
    ipc_reader: tokio::net::unix::OwnedReadHalf,
    shared_ipc_writer: Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    child_pid: u32,
    lease_state: SharedWanLease,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    println!(
        "[dns-forwarder-parent] Supervising DNS forwarder worker (PID {})",
        child_pid
    );

    let mut last_dns_servers: Vec<Ipv4Addr> = Vec::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
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
                        println!("[dns-forwarder-parent] Worker closed IPC. Shutting down monitor.");
                        break;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // Not EOF, just woke up
                    }
                    _ => {
                        break;
                    }
                }
            }
            _ = interval.tick() => {
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

    let pid = nix::unistd::Pid::from_raw(child_pid as i32);
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
}

async fn update_upstream_resolvers(
    shared_ipc_writer: &Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    servers: &[Ipv4Addr],
) -> Result<(), std::io::Error> {
    println!(
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
    parent_ipc_fd: RawFd,
    child_pid: u32,
    lease_state: SharedWanLease,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>, ServiceError> {
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    let std_stream = unsafe { StdUnixStream::from_raw_fd(parent_ipc_fd) };
    std_stream.set_nonblocking(true).map_err(ServiceError::Io)?;
    let ipc_stream = tokio::net::UnixStream::from_std(std_stream).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(tokio::sync::Mutex::new(ipc_writer));

    let handle = tokio::spawn(run_parent_dns_monitor(
        ipc_reader,
        shared_ipc_writer,
        child_pid,
        lease_state,
        shutdown_rx,
    ));

    Ok(handle)
}

fn setup_dns_forwarder_attempt()
-> Result<(crate::cli::WorkerService, std::os::unix::io::RawFd), ServiceError> {
    let (parent_ipc_fd, child_ipc_fd) = create_ipc_fds()?;
    let dns_socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", DNS_PORT))?;
    let dns_socket_fd = dns_socket.into_raw_fd();
    let upstream_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let upstream_socket_fd = upstream_socket.into_raw_fd();

    Ok((
        crate::cli::WorkerService::DnsForwarder {
            ipc_fd: child_ipc_fd,
            dns_socket_fd,
            upstream_socket_fd,
        },
        parent_ipc_fd,
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
