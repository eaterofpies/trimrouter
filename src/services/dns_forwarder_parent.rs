use super::ipc::{ParentToWorkerMsg, send_msg};
use super::utils::{SharedWanLease, terminate_worker};
use super::{Service, ServiceError};
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::Arc;

const DNS_PORT: u16 = 53;

pub struct DnsForwarder {
    lease_state: SharedWanLease,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    child_pid: Option<u32>,
}

impl DnsForwarder {
    pub fn new(lease_state: SharedWanLease) -> Self {
        Self {
            lease_state,
            shutdown_tx: None,
            task_handle: None,
            child_pid: None,
        }
    }
}

fn spawn_dns_worker_process(
    child_ipc_fd: RawFd,
    dns_socket_fd: RawFd,
    upstream_socket_fd: RawFd,
) -> Result<std::process::Child, ServiceError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let binary_path = if std::path::Path::new("/bin/trimrouter").exists() {
        "/bin/trimrouter"
    } else {
        "/proc/self/exe"
    };

    let mut cmd = Command::new(binary_path);
    cmd.arg("worker");
    cmd.arg("dns-forwarder");
    cmd.arg(child_ipc_fd.to_string());
    cmd.arg(dns_socket_fd.to_string());
    cmd.arg(upstream_socket_fd.to_string());

    unsafe {
        cmd.pre_exec(move || {
            libc::fcntl(child_ipc_fd, libc::F_SETFD, 0);
            libc::fcntl(dns_socket_fd, libc::F_SETFD, 0);
            libc::fcntl(upstream_socket_fd, libc::F_SETFD, 0);
            Ok(())
        });
    }

    cmd.spawn()
        .map_err(|e| ServiceError::FailedToStart(format!("spawn failed: {}", e)))
}

fn start_parent_dns_monitor(
    parent_ipc_fd: RawFd,
    child_pid: u32,
    lease_state: SharedWanLease,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>, ServiceError> {
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    let std_stream = unsafe { StdUnixStream::from_raw_fd(parent_ipc_fd) };
    std_stream.set_nonblocking(true).map_err(ServiceError::Io)?;
    let ipc_stream = tokio::net::UnixStream::from_std(std_stream).map_err(ServiceError::Io)?;
    let (_, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(tokio::sync::Mutex::new(ipc_writer));

    let handle = tokio::spawn(async move {
        println!(
            "[dns-forwarder-parent] Supervising DNS forwarder worker (PID {})",
            child_pid
        );

        let mut last_dns_servers: Vec<Ipv4Addr> = Vec::new();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = interval.tick() => {
                    let current_servers = {
                        let lease = lease_state.lock().unwrap();
                        lease.dns_servers.clone()
                    };

                    if current_servers != last_dns_servers {
                        println!(
                            "[dns-forwarder-parent] Upstream DNS servers updated: {:?}",
                            current_servers
                        );
                        let msg = ParentToWorkerMsg::SetUpstreamResolvers {
                            servers: current_servers.clone(),
                        };
                        let mut writer = shared_ipc_writer.lock().await;
                        if send_msg(&mut *writer, &msg).await.is_err() {
                            break;
                        }
                        last_dns_servers = current_servers;
                    }
                }
            }
        }

        let pid = nix::unistd::Pid::from_raw(child_pid as i32);
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    });

    Ok(handle)
}

impl Service for DnsForwarder {
    async fn start(&mut self) -> Result<(), ServiceError> {
        if self.task_handle.is_some() {
            return Err(ServiceError::AlreadyRunning);
        }

        // 1. Create socketpair for IPC
        let (parent_ipc_socket, child_ipc_socket) = match tokio::net::UnixStream::pair() {
            Ok(pair) => pair,
            Err(e) => {
                return Err(ServiceError::FailedToStart(format!(
                    "Failed to create IPC socketpair: {}",
                    e
                )));
            }
        };

        // Convert child_ipc_socket to raw fd and disable CLOEXEC so it stays open in the child process
        use std::os::unix::io::IntoRawFd;
        let child_ipc_fd = child_ipc_socket
            .into_std()
            .map_err(ServiceError::Io)?
            .into_raw_fd();
        let parent_ipc_fd = parent_ipc_socket
            .into_std()
            .map_err(ServiceError::Io)?
            .into_raw_fd();

        // 2. Bind port 53 socket (requires root)
        let dns_socket = match std::net::UdpSocket::bind(format!("0.0.0.0:{}", DNS_PORT)) {
            Ok(s) => s,
            Err(e) => {
                unsafe {
                    libc::close(child_ipc_fd);
                    libc::close(parent_ipc_fd);
                }
                return Err(ServiceError::FailedToStart(format!(
                    "Failed to bind DNS port 53: {}",
                    e
                )));
            }
        };
        let dns_socket_fd = dns_socket.into_raw_fd();

        // 3. Bind upstream socket
        let upstream_socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                unsafe {
                    libc::close(child_ipc_fd);
                    libc::close(parent_ipc_fd);
                    libc::close(dns_socket_fd);
                }
                return Err(ServiceError::FailedToStart(format!(
                    "Failed to bind upstream DNS client socket: {}",
                    e
                )));
            }
        };
        let upstream_socket_fd = upstream_socket.into_raw_fd();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let child = match spawn_dns_worker_process(child_ipc_fd, dns_socket_fd, upstream_socket_fd)
        {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    libc::close(child_ipc_fd);
                    libc::close(parent_ipc_fd);
                    libc::close(dns_socket_fd);
                    libc::close(upstream_socket_fd);
                }
                return Err(e);
            }
        };

        unsafe {
            libc::close(child_ipc_fd);
            libc::close(dns_socket_fd);
            libc::close(upstream_socket_fd);
        }

        let child_pid = child.id();
        let handle = start_parent_dns_monitor(
            parent_ipc_fd,
            child_pid,
            self.lease_state.clone(),
            shutdown_rx,
        )?;

        self.child_pid = Some(child_pid);
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        let child_pid = self.child_pid.take().ok_or(ServiceError::NotRunning)?;
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;

        println!(
            "[dns-forwarder-parent] Stopping DNS worker process PID {}",
            child_pid
        );
        let _ = tx.send(true);
        terminate_worker(child_pid).await;

        let _ = handle.await;
        Ok(())
    }
}
