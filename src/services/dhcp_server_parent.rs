use super::ipc::{ParentToWorkerMsg, send_msg};
use super::utils::{setup_worker_sockets, terminate_worker};
use super::{Service, ServiceError};
use futures_util::StreamExt;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use std::os::unix::io::RawFd;
use std::sync::Arc;

pub struct DhcpServer {
    lan_interface: String,
    lan_ip: String,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    child_pid: Option<u32>,
}

impl DhcpServer {
    pub fn new(lan_interface: String, lan_ip: String) -> Self {
        Self {
            lan_interface,
            lan_ip,
            shutdown_tx: None,
            task_handle: None,
            child_pid: None,
        }
    }
}

fn spawn_server_worker_process(
    child_ipc_fd: RawFd,
    raw_socket_fd: RawFd,
    lan_interface: &str,
    lan_ip: &str,
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
    cmd.arg("dhcp-server");
    cmd.arg(child_ipc_fd.to_string());
    cmd.arg(raw_socket_fd.to_string());
    cmd.arg(lan_interface);
    cmd.arg(lan_ip);

    unsafe {
        cmd.pre_exec(move || {
            libc::fcntl(child_ipc_fd, libc::F_SETFD, 0);
            libc::fcntl(raw_socket_fd, libc::F_SETFD, 0);
            Ok(())
        });
    }

    cmd.spawn()
        .map_err(|e| ServiceError::FailedToStart(format!("spawn failed: {}", e)))
}

fn start_parent_arp_listener(
    parent_ipc_fd: RawFd,
    child_pid: u32,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>, ServiceError> {
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    let std_stream = unsafe { StdUnixStream::from_raw_fd(parent_ipc_fd) };
    std_stream.set_nonblocking(true).map_err(ServiceError::Io)?;
    let ipc_stream = tokio::net::UnixStream::from_std(std_stream).map_err(ServiceError::Io)?;
    let (_, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(tokio::sync::Mutex::new(ipc_writer));

    let connection_fut = rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh]);
    let (connection, _handle, mut messages) = match connection_fut {
        Ok(res) => res,
        Err(e) => {
            return Err(ServiceError::FailedToStart(format!(
                "Failed to start Netlink ARP listener connection: {}",
                e
            )));
        }
    };
    tokio::spawn(connection);

    let handle = tokio::spawn(async move {
        println!(
            "[dhcp-server-parent] Supervising DHCP server worker (PID {})",
            child_pid
        );
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                Some((message, _addr)) = messages.next() => {
                    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg)) = message.payload {
                        let mut ip_opt = None;
                        let mut mac_opt = None;
                        for nla in msg.attributes {
                            match nla {
                                NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)) => {
                                    ip_opt = Some(ip);
                                }
                                NeighbourAttribute::LinkLayerAddress(mac_bytes) if mac_bytes.len() == 6 => {
                                    let bytes: [u8; 6] = mac_bytes.try_into().unwrap();
                                    mac_opt = Some(bytes);
                                }
                                _ => {}
                            }
                        }
                        if let (Some(ip), Some(mac)) = (ip_opt, mac_opt) {
                            let ipc_msg = ParentToWorkerMsg::AddNeighbor {
                                ip_address: ip,
                                mac_address: mac,
                            };
                            let mut writer = shared_ipc_writer.lock().await;
                            let _ = send_msg(&mut *writer, &ipc_msg).await;
                        }
                    }
                }
            }
        }

        let pid = nix::unistd::Pid::from_raw(child_pid as i32);
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
    });

    Ok(handle)
}

impl Service for DhcpServer {
    async fn start(&mut self) -> Result<(), ServiceError> {
        if self.task_handle.is_some() {
            return Err(ServiceError::AlreadyRunning);
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let (raw_socket_fd, parent_ipc_fd, child_ipc_fd) =
            setup_worker_sockets(&self.lan_interface)
                .map_err(|e| ServiceError::FailedToStart(format!("Socket setup failed: {}", e)))?;

        let child = match spawn_server_worker_process(
            child_ipc_fd,
            raw_socket_fd,
            &self.lan_interface,
            &self.lan_ip,
        ) {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    libc::close(raw_socket_fd);
                    libc::close(parent_ipc_fd);
                    libc::close(child_ipc_fd);
                }
                return Err(e);
            }
        };

        unsafe {
            libc::close(child_ipc_fd);
            libc::close(raw_socket_fd);
        }

        let child_pid = child.id();
        let handle = start_parent_arp_listener(parent_ipc_fd, child_pid, shutdown_rx)?;

        self.child_pid = Some(child_pid);
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        let child_pid = self.child_pid.take().ok_or(ServiceError::NotRunning)?;
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;

        println!(
            "[dhcp-server-parent] Stopping worker process PID {}",
            child_pid
        );
        let _ = tx.send(true);
        terminate_worker(child_pid).await;

        let _ = handle.await;
        Ok(())
    }
}
