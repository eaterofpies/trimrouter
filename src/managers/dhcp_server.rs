use super::ipc::{DhcpServerParentToWorkerMsg, send_msg};
use super::utils::{
    handle_supervisor_restart_delay, setup_worker_sockets, spawn_worker, terminate_worker,
};
use super::{DHCP_SERVER_SERVICE_NAME, Service, ServiceError};
use futures_util::StreamExt;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use std::os::unix::io::RawFd;
use std::process::Child;
use std::sync::Arc;

pub struct DhcpServer {
    lan_interface: String,
    lan_ip: String,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    child_pid: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl DhcpServer {
    pub fn new(lan_interface: String, lan_ip: String) -> Self {
        Self {
            lan_interface,
            lan_ip,
            shutdown_tx: None,
            task_handle: None,
            child_pid: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.child_pid.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn spawn_server_worker_process(
    child_ipc_fd: RawFd,
    raw_socket_fd: RawFd,
    lan_interface: &str,
    lan_ip: &str,
) -> Result<Child, ServiceError> {
    let child_ipc_str = child_ipc_fd.to_string();
    let raw_socket_str = raw_socket_fd.to_string();
    let args = &[
        child_ipc_str.as_str(),
        raw_socket_str.as_str(),
        lan_interface,
        lan_ip,
    ];
    spawn_worker(
        DHCP_SERVER_SERVICE_NAME,
        args,
        &[child_ipc_fd, raw_socket_fd],
    )
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
                            let ipc_msg = DhcpServerParentToWorkerMsg::AddNeighbor {
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

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let lan_interface = self.lan_interface.clone();
        let lan_ip = self.lan_ip.clone();
        let child_pid_atomic = self.child_pid.clone();

        let handle = tokio::spawn(async move {
            let mut attempt = 0;
            while !*shutdown_rx.borrow() {
                if !handle_supervisor_restart_delay("dhcp-server", &mut attempt, &mut shutdown_rx)
                    .await
                {
                    break;
                }

                let (raw_socket_fd, parent_ipc_fd, child_ipc_fd) =
                    match setup_worker_sockets(&lan_interface) {
                        Ok(res) => res,
                        Err(e) => {
                            eprintln!("[dhcp-server-parent] Socket setup failed: {}", e);
                            continue;
                        }
                    };

                let child = match spawn_server_worker_process(
                    child_ipc_fd,
                    raw_socket_fd,
                    &lan_interface,
                    &lan_ip,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[dhcp-server-parent] Spawn failed: {}", e);
                        unsafe {
                            libc::close(raw_socket_fd);
                            libc::close(parent_ipc_fd);
                            libc::close(child_ipc_fd);
                        }
                        continue;
                    }
                };

                unsafe {
                    libc::close(child_ipc_fd);
                    libc::close(raw_socket_fd);
                }

                let child_pid = child.id();
                child_pid_atomic.store(child_pid, std::sync::atomic::Ordering::SeqCst);

                let listener_handle =
                    start_parent_arp_listener(parent_ipc_fd, child_pid, shutdown_rx.clone());

                match listener_handle {
                    Ok(h) => {
                        let _ = h.await;
                    }
                    Err(e) => {
                        eprintln!(
                            "[dhcp-server-parent] Failed to start ARP listener task: {}",
                            e
                        );
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
                "[dhcp-server-parent] Stopping worker process PID {}",
                child_pid
            );
            terminate_worker(child_pid).await;
        }

        let _ = handle.await;
        Ok(())
    }
}
