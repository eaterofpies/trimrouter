use super::ipc::{DnsParentToWorkerMsg, send_msg};
use super::utils::{
    SharedWanLease, create_ipc_fds, handle_supervisor_restart_delay, spawn_worker, terminate_worker,
};
use super::{DNS_FORWARDER_SERVICE_NAME, Service, ServiceError};
use std::net::Ipv4Addr;
use std::os::unix::io::{IntoRawFd, RawFd};
use std::process::Child;
use std::sync::Arc;

const DNS_PORT: u16 = 53;

pub struct DnsForwarder {
    lease_state: SharedWanLease,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    child_pid: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl DnsForwarder {
    pub fn new(lease_state: SharedWanLease) -> Self {
        Self {
            lease_state,
            shutdown_tx: None,
            task_handle: None,
            child_pid: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.child_pid.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn spawn_dns_worker_process(
    child_ipc_fd: RawFd,
    dns_socket_fd: RawFd,
    upstream_socket_fd: RawFd,
) -> Result<Child, ServiceError> {
    let child_ipc_str = child_ipc_fd.to_string();
    let dns_socket_str = dns_socket_fd.to_string();
    let upstream_socket_str = upstream_socket_fd.to_string();
    let args = &[
        child_ipc_str.as_str(),
        dns_socket_str.as_str(),
        upstream_socket_str.as_str(),
    ];
    spawn_worker(
        DNS_FORWARDER_SERVICE_NAME,
        args,
        &[child_ipc_fd, dns_socket_fd, upstream_socket_fd],
    )
    .map_err(|e| ServiceError::FailedToStart(format!("spawn failed: {}", e)))
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

impl Service for DnsForwarder {
    async fn start(&mut self) -> Result<(), ServiceError> {
        if self.task_handle.is_some() {
            return Err(ServiceError::AlreadyRunning);
        }

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let lease_state = self.lease_state.clone();
        let child_pid_atomic = self.child_pid.clone();

        let handle = tokio::spawn(async move {
            let mut attempt = 0;
            while !*shutdown_rx.borrow() {
                if !handle_supervisor_restart_delay("dns-forwarder", &mut attempt, &mut shutdown_rx)
                    .await
                {
                    break;
                }

                let (parent_ipc_fd, child_ipc_fd) = match create_ipc_fds() {
                    Ok(fds) => fds,
                    Err(e) => {
                        eprintln!(
                            "[dns-forwarder-parent] Failed to create IPC socketpair: {}",
                            e
                        );
                        continue;
                    }
                };

                // 2. Bind port 53 socket (requires root)
                let dns_socket = match std::net::UdpSocket::bind(format!("0.0.0.0:{}", DNS_PORT)) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("[dns-forwarder-parent] Failed to bind DNS port 53: {}", e);
                        unsafe {
                            libc::close(child_ipc_fd);
                            libc::close(parent_ipc_fd);
                        }
                        continue;
                    }
                };
                let dns_socket_fd = dns_socket.into_raw_fd();

                // 3. Bind upstream socket
                let upstream_socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(
                            "[dns-forwarder-parent] Failed to bind upstream DNS client socket: {}",
                            e
                        );
                        unsafe {
                            libc::close(child_ipc_fd);
                            libc::close(parent_ipc_fd);
                            libc::close(dns_socket_fd);
                        }
                        continue;
                    }
                };
                let upstream_socket_fd = upstream_socket.into_raw_fd();

                let child =
                    match spawn_dns_worker_process(child_ipc_fd, dns_socket_fd, upstream_socket_fd)
                    {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("[dns-forwarder-parent] Failed to spawn worker: {}", e);
                            unsafe {
                                libc::close(child_ipc_fd);
                                libc::close(parent_ipc_fd);
                                libc::close(dns_socket_fd);
                                libc::close(upstream_socket_fd);
                            }
                            continue;
                        }
                    };

                unsafe {
                    libc::close(child_ipc_fd);
                    libc::close(dns_socket_fd);
                    libc::close(upstream_socket_fd);
                }

                let child_pid = child.id();
                child_pid_atomic.store(child_pid, std::sync::atomic::Ordering::SeqCst);

                let monitor_handle = start_parent_dns_monitor(
                    parent_ipc_fd,
                    child_pid,
                    lease_state.clone(),
                    shutdown_rx.clone(),
                );

                match monitor_handle {
                    Ok(h) => {
                        let _ = h.await;
                    }
                    Err(e) => {
                        eprintln!("[dns-forwarder-parent] Failed to start monitor task: {}", e);
                        let pid = nix::unistd::Pid::from_raw(child_pid as i32);
                        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                        unsafe {
                            libc::close(parent_ipc_fd);
                        }
                    }
                }
            }
        });

        self.task_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;
        let child_pid = self.child_pid.swap(0, std::sync::atomic::Ordering::SeqCst);

        let _ = tx.send(true);
        if child_pid != 0 {
            println!(
                "[dns-forwarder-parent] Stopping DNS worker process PID {}",
                child_pid
            );
            terminate_worker(child_pid).await;
        }

        let _ = handle.await;
        Ok(())
    }
}
