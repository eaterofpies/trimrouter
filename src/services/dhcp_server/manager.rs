use crate::init::watchdog::{HeartbeatSender, MonitoredService, send_service_heartbeat};
use crate::services::DHCP_SERVER_SERVICE_NAME;
use crate::services::ipc::{
    DhcpServerParentToWorkerMsg, DhcpServerWorkerToParentMsg, async_unix_stream, recv_msg, send_msg,
};
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{setup_worker_sockets, terminate_worker};
use futures_util::StreamExt;
use log::{error, info};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use std::net::Ipv4Addr;
use std::os::unix::io::OwnedFd;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;

pub struct DhcpServer {
    lan_interface: String,
    lan_ip: String,
    state: ExternalWorker,
    heartbeat_tx: Option<HeartbeatSender>,
}

impl DhcpServer {
    pub fn new(lan_interface: String, lan_ip: String) -> Self {
        Self {
            lan_interface,
            lan_ip,
            state: ExternalWorker::new(DHCP_SERVER_SERVICE_NAME),
            heartbeat_tx: None,
        }
    }

    pub fn with_heartbeat(
        lan_interface: String,
        lan_ip: String,
        heartbeat_tx: HeartbeatSender,
    ) -> Self {
        Self {
            lan_interface,
            lan_ip,
            state: ExternalWorker::new(DHCP_SERVER_SERVICE_NAME),
            heartbeat_tx: Some(heartbeat_tx),
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
    heartbeat_tx: Option<HeartbeatSender>,
) -> Result<JoinHandle<()>, ServiceError> {
    let ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();

    let handle = tokio::spawn(run_parent_dhcp_server_monitor(
        child_pid,
        ipc_writer,
        ipc_reader,
        shutdown_rx,
        heartbeat_tx,
    ));

    Ok(handle)
}

async fn run_parent_dhcp_server_monitor(
    child_pid: u32,
    mut ipc_writer: OwnedWriteHalf,
    mut ipc_reader: OwnedReadHalf,
    mut shutdown_rx: Receiver<bool>,
    heartbeat_tx: Option<HeartbeatSender>,
) {
    let (connection, _handle, mut messages) =
        match rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh]) {
            Ok(res) => res,
            Err(e) => {
                error!(
                    "[dhcp-server-parent] Failed to start Netlink ARP listener: {}",
                    e
                );
                terminate_worker(child_pid).await;
                return;
            }
        };
    tokio::spawn(connection);

    info!(
        "[dhcp-server-parent] Supervising DHCP server worker (PID {})",
        child_pid
    );
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            ipc_msg = recv_msg::<DhcpServerWorkerToParentMsg, _>(&mut ipc_reader) => {
                match ipc_msg {
                    Ok(Some(DhcpServerWorkerToParentMsg::Heartbeat)) => {
                        send_service_heartbeat(heartbeat_tx.as_ref(), MonitoredService::LanManager);
                    }
                    Ok(None) | Err(_) => {
                        info!("[dhcp-server-parent] Worker closed IPC. Shutting down monitor.");
                        break;
                    }
                }
            }
            Some((message, _addr)) = messages.next() => {
                if let Some((ip, mac)) = parse_neighbor_update(&message.payload) {
                    let ipc_msg = DhcpServerParentToWorkerMsg::AddNeighbor {
                        ip_address: ip,
                        mac_address: mac,
                    };
                    if let Err(e) = send_msg(&mut ipc_writer, &ipc_msg).await {
                        error!(
                            "[dhcp-server-parent] Failed to send neighbor update over IPC: {}",
                            e
                        );
                        break;
                    }
                }
            }
        }
    }

    terminate_worker(child_pid).await;
}

fn parse_neighbor_update(
    payload: &NetlinkPayload<RouteNetlinkMessage>,
) -> Option<(Ipv4Addr, [u8; 6])> {
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg)) = payload else {
        return None;
    };
    let mut ip_opt = None;
    let mut mac_opt = None;
    for nla in &msg.attributes {
        match nla {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)) => {
                ip_opt = Some(*ip);
            }
            NeighbourAttribute::LinkLayerAddress(mac_bytes) => {
                if let Ok(bytes) = mac_bytes.as_slice().try_into() {
                    mac_opt = Some(bytes);
                }
            }
            _ => {}
        }
    }
    ip_opt.zip(mac_opt)
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
        let heartbeat_tx = self.heartbeat_tx.clone();

        self.state.start_supervised(
            move || setup_dhcp_server_attempt(&lan_interface, &lan_ip),
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                start_parent_arp_listener(
                    parent_ipc_fd,
                    child_pid,
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
