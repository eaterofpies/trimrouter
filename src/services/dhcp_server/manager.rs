use crate::config::StaticLease;
use crate::init::watchdog::{HeartbeatSender, MonitoredService, send_service_heartbeat};
use crate::services::DHCP_SERVER_SERVICE_NAME;
use crate::services::ipc::{
    DhcpServerParentToWorkerMsg, DhcpServerWorkerToParentMsg, IpcEndpoint, LocalHostEvent,
    LocalHostSender,
};
use crate::services::observability::DhcpLeasesSender;
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{setup_worker_sockets, terminate_worker};
use futures_util::StreamExt;
use ipnet::Ipv4Net;
use log::{error, info};
use pnet::util::MacAddr;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute};
use std::net::Ipv4Addr;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;

pub struct DhcpServer {
    lan_interface: String,
    lan_ip: String,
    state: ExternalWorker,
    heartbeat_tx: Option<HeartbeatSender>,
    local_hosts_tx: Option<LocalHostSender>,
    leases_tx: DhcpLeasesSender,
    static_leases: Vec<StaticLease>,
}

impl DhcpServer {
    pub fn new(
        lan_interface: String,
        lan_ip: String,
        heartbeat_tx: Option<HeartbeatSender>,
        local_hosts_tx: Option<LocalHostSender>,
        leases_tx: DhcpLeasesSender,
        static_leases: Vec<StaticLease>,
    ) -> Self {
        Self {
            lan_interface,
            lan_ip,
            state: ExternalWorker::new(DHCP_SERVER_SERVICE_NAME),
            heartbeat_tx,
            local_hosts_tx,
            leases_tx,
            static_leases,
        }
    }

    pub fn reconfigure_lan_ip(&mut self, new_ip: String) {
        self.lan_ip = new_ip;
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
}

fn start_parent_arp_listener(
    parent_ipc: IpcEndpoint<DhcpServerWorkerToParentMsg>,
    params: DhcpMonitorParams,
) -> Result<JoinHandle<()>, ServiceError> {
    let handle = tokio::spawn(run_parent_dhcp_server_monitor(parent_ipc, params));
    Ok(handle)
}

struct DhcpMonitorParams {
    child_pid: u32,
    shutdown_rx: Receiver<bool>,
    heartbeat_tx: Option<HeartbeatSender>,
    local_hosts_tx: Option<LocalHostSender>,
    leases_tx: DhcpLeasesSender,
    static_leases: Vec<StaticLease>,
    lan_interface: String,
    lan_ip: String,
}

fn read_lan_ifindex(lan_interface: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", lan_interface))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

async fn handle_worker_ipc_msg(
    ipc_msg: Result<Option<DhcpServerWorkerToParentMsg>, std::io::Error>,
    params: &DhcpMonitorParams,
) -> bool {
    match ipc_msg {
        Ok(Some(DhcpServerWorkerToParentMsg::Heartbeat { leases })) => {
            send_service_heartbeat(params.heartbeat_tx.as_ref(), MonitoredService::LanManager);
            let _ = params.leases_tx.send(leases);
            true
        }
        Ok(Some(DhcpServerWorkerToParentMsg::RegisterLocalHost { name, ip })) => {
            if let Some(ref tx) = params.local_hosts_tx {
                let _ = tx.send(LocalHostEvent::Register { name, ip }).await;
            }
            true
        }
        Ok(Some(DhcpServerWorkerToParentMsg::DeregisterLocalHost { name })) => {
            if let Some(ref tx) = params.local_hosts_tx {
                let _ = tx.send(LocalHostEvent::Deregister { name }).await;
            }
            true
        }
        Ok(None) | Err(_) => {
            info!("[dhcp-server-parent] Worker closed IPC. Shutting down monitor.");
            false
        }
    }
}

async fn run_parent_dhcp_server_monitor(
    ipc: IpcEndpoint<DhcpServerWorkerToParentMsg>,
    mut params: DhcpMonitorParams,
) {
    let msg = DhcpServerParentToWorkerMsg::SetStaticLeases {
        leases: params.static_leases.clone(),
    };
    if let Err(e) = ipc.send(&msg).await {
        error!(
            "[dhcp-server-parent] Failed to send static leases to worker: {}",
            e
        );
    }

    let (connection, _handle, mut messages) =
        match rtnetlink::new_multicast_connection(&[MulticastGroup::Neigh]) {
            Ok(res) => res,
            Err(e) => {
                error!(
                    "[dhcp-server-parent] Failed to start Netlink ARP listener: {}",
                    e
                );
                terminate_worker(params.child_pid).await;
                return;
            }
        };
    tokio::spawn(connection);

    let lan_net: Option<Ipv4Net> = params.lan_ip.parse().ok();
    let lan_gateway_ip = lan_net.as_ref().map(|n| n.addr());
    let lan_ifindex = read_lan_ifindex(&params.lan_interface);

    info!(
        "[dhcp-server-parent] Supervising DHCP server worker (PID {})",
        params.child_pid
    );
    loop {
        tokio::select! {
            _ = params.shutdown_rx.changed() => break,
            ipc_msg = ipc.recv() => {
                if !handle_worker_ipc_msg(ipc_msg, &params).await {
                    break;
                }
            }
            Some((message, _addr)) = messages.next() => {
                if let Some((ip, mac)) = parse_neighbor_update(
                    &message.payload,
                    lan_ifindex,
                    lan_net.as_ref(),
                    lan_gateway_ip,
                ) {
                    let ipc_msg = DhcpServerParentToWorkerMsg::AddNeighbor {
                        ip_address: ip,
                        mac_address: mac,
                    };
                    if let Err(e) = ipc.send(&ipc_msg).await {
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

    terminate_worker(params.child_pid).await;
}

pub fn parse_neighbor_update(
    payload: &NetlinkPayload<RouteNetlinkMessage>,
    lan_ifindex: Option<u32>,
    lan_net: Option<&Ipv4Net>,
    lan_gateway_ip: Option<Ipv4Addr>,
) -> Option<(Ipv4Addr, MacAddr)> {
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg)) = payload else {
        return None;
    };
    if let Some(target_idx) = lan_ifindex
        && msg.header.ifindex != target_idx
    {
        return None;
    }
    let mut ip_opt = None;
    let mut mac_opt = None;
    for nla in &msg.attributes {
        match nla {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)) => {
                ip_opt = Some(*ip);
            }
            NeighbourAttribute::LinkLayerAddress(mac_bytes) => {
                if let Ok(bytes) = mac_bytes.as_slice().try_into() {
                    let [b0, b1, b2, b3, b4, b5] = bytes;
                    mac_opt = Some(MacAddr::new(b0, b1, b2, b3, b4, b5));
                }
            }
            _ => {}
        }
    }
    let (ip, mac) = ip_opt.zip(mac_opt)?;
    if let (Some(net), Some(gw)) = (lan_net, lan_gateway_ip)
        && (!net.contains(&ip) || ip == gw)
    {
        return None;
    }
    Some((ip, mac))
}

fn setup_dhcp_server_attempt(
    lan_interface: &str,
    lan_ip: &str,
) -> Result<
    (
        crate::cli::WorkerService,
        IpcEndpoint<DhcpServerWorkerToParentMsg>,
    ),
    ServiceError,
> {
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
        let lan_interface_spawn = self.lan_interface.clone();
        let lan_ip_spawn = self.lan_ip.clone();
        let heartbeat_tx = self.heartbeat_tx.clone();
        let local_hosts_tx = self.local_hosts_tx.clone();
        let leases_tx = self.leases_tx.clone();
        let static_leases = self.static_leases.clone();

        self.state.start_supervised(
            move || setup_dhcp_server_attempt(&lan_interface, &lan_ip),
            move |parent_ipc, child_pid, shutdown_rx| {
                let params = DhcpMonitorParams {
                    child_pid,
                    shutdown_rx,
                    heartbeat_tx: heartbeat_tx.clone(),
                    local_hosts_tx: local_hosts_tx.clone(),
                    leases_tx: leases_tx.clone(),
                    static_leases: static_leases.clone(),
                    lan_interface: lan_interface_spawn.clone(),
                    lan_ip: lan_ip_spawn.clone(),
                };
                start_parent_arp_listener(parent_ipc, params)
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
    use rtnetlink::packet_route::neighbour::NeighbourMessage;

    #[test]
    fn test_dhcp_server_constructors_and_pid() {
        let (hb_tx, _hb_rx) = tokio::sync::mpsc::channel(1);
        let (lh_tx, _lh_rx) = tokio::sync::mpsc::channel(1);
        let srv = DhcpServer::new(
            "lan".to_string(),
            "192.168.1.1/24".to_string(),
            Some(hb_tx),
            Some(lh_tx),
            crate::services::observability::null_dhcp_leases_sender(),
            Vec::new(),
        );
        assert_eq!(srv.get_worker_pid(), 0);
    }

    #[test]
    fn test_parse_neighbor_update_valid_and_invalid() {
        let lan_net: Ipv4Net = "192.168.1.0/24".parse().unwrap();
        let lan_gw = Ipv4Addr::new(192, 168, 1, 1);
        let target_ifindex = Some(2);

        // Non-NewNeighbour payload
        let non_neigh = NetlinkPayload::Noop;
        assert_eq!(
            parse_neighbor_update(&non_neigh, target_ifindex, Some(&lan_net), Some(lan_gw)),
            None
        );

        // Valid NewNeighbour message with IP and MAC on matching interface and inside LAN subnet
        let mut msg = NeighbourMessage::default();
        msg.header.ifindex = 2;
        msg.attributes
            .push(NeighbourAttribute::Destination(NeighbourAddress::Inet(
                Ipv4Addr::new(192, 168, 1, 50),
            )));
        msg.attributes
            .push(NeighbourAttribute::LinkLayerAddress(vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ]));

        let payload = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg));
        let parsed = parse_neighbor_update(&payload, target_ifindex, Some(&lan_net), Some(lan_gw));
        assert_eq!(
            parsed,
            Some((
                Ipv4Addr::new(192, 168, 1, 50),
                MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)
            ))
        );

        // Rejects mismatched interface index (e.g. WAN interface 3)
        let parsed_wrong_if =
            parse_neighbor_update(&payload, Some(3), Some(&lan_net), Some(lan_gw));
        assert_eq!(parsed_wrong_if, None);

        // Rejects off-subnet WAN neighbor (e.g. 100.66.208.1)
        let mut wan_msg = NeighbourMessage::default();
        wan_msg.header.ifindex = 2;
        wan_msg
            .attributes
            .push(NeighbourAttribute::Destination(NeighbourAddress::Inet(
                Ipv4Addr::new(100, 66, 208, 1),
            )));
        wan_msg
            .attributes
            .push(NeighbourAttribute::LinkLayerAddress(vec![
                0x1c, 0x90, 0xbe, 0xda, 0x13, 0xc2,
            ]));
        let wan_payload = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(wan_msg));
        let parsed_wan =
            parse_neighbor_update(&wan_payload, target_ifindex, Some(&lan_net), Some(lan_gw));
        assert_eq!(parsed_wan, None);

        // Rejects router's own gateway IP (192.168.1.1)
        let mut gw_msg = NeighbourMessage::default();
        gw_msg.header.ifindex = 2;
        gw_msg
            .attributes
            .push(NeighbourAttribute::Destination(NeighbourAddress::Inet(
                Ipv4Addr::new(192, 168, 1, 1),
            )));
        gw_msg
            .attributes
            .push(NeighbourAttribute::LinkLayerAddress(vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ]));
        let gw_payload = NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(gw_msg));
        let parsed_gw =
            parse_neighbor_update(&gw_payload, target_ifindex, Some(&lan_net), Some(lan_gw));
        assert_eq!(parsed_gw, None);

        // Missing MAC attribute
        let mut msg_no_mac = NeighbourMessage::default();
        msg_no_mac.header.ifindex = 2;
        msg_no_mac
            .attributes
            .push(NeighbourAttribute::Destination(NeighbourAddress::Inet(
                Ipv4Addr::new(192, 168, 1, 50),
            )));
        let payload_no_mac =
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg_no_mac));
        assert_eq!(
            parse_neighbor_update(
                &payload_no_mac,
                target_ifindex,
                Some(&lan_net),
                Some(lan_gw)
            ),
            None
        );
    }
}
