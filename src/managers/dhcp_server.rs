use super::ipc::{DhcpServerParentToWorkerMsg, async_unix_stream, send_msg};
use super::utils::{setup_worker_sockets, terminate_worker};
use super::{ExternalWorker, Service, ServiceError};
use futures_util::{Stream, StreamExt};
use log::info;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::Mutex;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;

pub struct DhcpServer {
    lan_interface: String,
    lan_ip: String,
    state: ExternalWorker,
}

impl DhcpServer {
    pub fn new(lan_interface: String, lan_ip: String) -> Self {
        Self {
            lan_interface,
            lan_ip,
            state: ExternalWorker::new("dhcp-server"),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
}

fn start_parent_arp_listener(
    parent_ipc_fd: OwnedFd,
    child_pid: u32,
    shutdown_rx: Receiver<bool>,
) -> Result<JoinHandle<()>, ServiceError> {
    let ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;
    let (_, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(Mutex::new(ipc_writer));

    let connection_fut = rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh]);
    let (connection, _handle, messages) = match connection_fut {
        Ok(res) => res,
        Err(e) => {
            return Err(ServiceError::FailedToStart(format!(
                "Failed to start Netlink ARP listener connection: {}",
                e
            )));
        }
    };
    tokio::spawn(connection);

    let handle = tokio::spawn(run_parent_dhcp_server_monitor(
        child_pid,
        messages,
        shared_ipc_writer,
        shutdown_rx,
    ));

    Ok(handle)
}

async fn run_parent_dhcp_server_monitor<S, A>(
    child_pid: u32,
    mut messages: S,
    shared_ipc_writer: Arc<Mutex<OwnedWriteHalf>>,
    mut shutdown_rx: Receiver<bool>,
) where
    S: Stream<Item = (NetlinkMessage<RouteNetlinkMessage>, A)> + Unpin + Send + 'static,
    A: Send + 'static,
{
    info!(
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

    terminate_worker(child_pid).await;
}

fn setup_dhcp_server_attempt(
    lan_interface: &str,
    lan_ip: &str,
) -> Result<(crate::cli::WorkerService, OwnedFd), ServiceError> {
    let (raw_socket_fd, parent_ipc, child_ipc) = setup_worker_sockets(lan_interface)
        .map_err(|e| ServiceError::FailedToStart(format!("Socket setup failed: {}", e)))?;
    Ok((
        crate::cli::WorkerService::DhcpServer {
            ipc_fd: child_ipc.into(),
            raw_socket_fd: raw_socket_fd.into(),
            wan_interface: lan_interface.to_string(),
            lan_ip: lan_ip.to_string(),
        },
        parent_ipc,
    ))
}

impl Service for DhcpServer {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let lan_interface = self.lan_interface.clone();
        let lan_ip = self.lan_ip.clone();

        self.state.start_supervised(
            move || setup_dhcp_server_attempt(&lan_interface, &lan_ip),
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                start_parent_arp_listener(parent_ipc_fd, child_pid, shutdown_rx)
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}
