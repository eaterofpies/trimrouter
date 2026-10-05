use crate::config::StaticLease;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::os::unix::io::{FromRawFd, OwnedFd};
use tokio_seqpacket::UnixSeqpacket;

/// Represents a strongly-typed bidirectional Unix domain SEQPACKET IPC channel.
///
/// Features native datagram message boundaries with connection lifecycle & EOF detection.
pub struct IpcEndpoint<InMsg> {
    pub socket: UnixSeqpacket,
    _phantom: PhantomData<fn() -> InMsg>,
}

impl<InMsg: for<'a> Deserialize<'a>> IpcEndpoint<InMsg> {
    pub fn new(socket: UnixSeqpacket) -> Self {
        Self {
            socket,
            _phantom: PhantomData,
        }
    }

    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, std::io::Error> {
        let socket = UnixSeqpacket::try_from(fd)?;
        Ok(Self::new(socket))
    }

    pub async fn recv(&self) -> Result<Option<InMsg>, std::io::Error> {
        let mut buf = [0u8; MAX_IPC_MSG_LEN];
        let info = self.socket.recv(&mut buf).await?;
        if info.bytes_read() == 0 {
            return Ok(None);
        }
        let msg = postcard::from_bytes(&buf[..info.bytes_read()])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Some(msg))
    }

    pub async fn send<OutMsg: Serialize>(&self, msg: &OutMsg) -> Result<(), std::io::Error> {
        let serialized = postcard::to_stdvec(msg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if serialized.len() > MAX_IPC_MSG_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Serialized IPC message length {} exceeds maximum limit of {}",
                    serialized.len(),
                    MAX_IPC_MSG_LEN
                ),
            ));
        }
        self.socket.send(&serialized).await?;
        Ok(())
    }
}

pub fn create_ipc_channel<InMsg: for<'a> Deserialize<'a>>()
-> Result<(IpcEndpoint<InMsg>, OwnedFd), std::io::Error> {
    let (s1, s2) = UnixSeqpacket::pair()?;
    let child_fd = unsafe { OwnedFd::from_raw_fd(s2.into_raw_fd()) };
    Ok((IpcEndpoint::new(s1), child_fd))
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LocalHostEvent {
    Register { name: String, ip: Ipv4Addr },
    Deregister { name: String },
}

pub type LocalHostSender = tokio::sync::mpsc::Sender<LocalHostEvent>;
pub type LocalHostReceiver = tokio::sync::mpsc::Receiver<LocalHostEvent>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsStatsInfo {
    pub queries_total: u64,
    pub cache_hits_total: u64,
    pub cached_entries_count: usize,
    pub rate_limited_drops_total: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DnsParentToWorkerMsg {
    SetUpstreamResolvers { servers: Vec<Ipv4Addr> },
    RegisterLocalHost { name: String, ip: Ipv4Addr },
    DeregisterLocalHost { name: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DnsWorkerToParentMsg {
    Heartbeat { stats: DnsStatsInfo },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DhcpLeaseInfo {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    pub hostname: Option<String>,
    pub expires_in_seconds: u64,
    pub is_static: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpServerParentToWorkerMsg {
    AddNeighbor {
        ip_address: Ipv4Addr,
        mac_address: MacAddr,
    },
    SetStaticLeases {
        leases: Vec<StaticLease>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpServerWorkerToParentMsg {
    Heartbeat { leases: Vec<DhcpLeaseInfo> },
    RegisterLocalHost { name: String, ip: Ipv4Addr },
    DeregisterLocalHost { name: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpClientToParentMsg {
    ApplyWanLease {
        ip_address: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        dns_servers: Vec<Ipv4Addr>,
    },
    ClearWanLease,
    Heartbeat,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SntpClientToParentMsg {
    SetSystemTime { seconds: i64, nanoseconds: i64 },
    ResolveTimeServer,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SntpParentToClientMsg {
    TimeServerResolved { result: Result<Ipv4Addr, String> },
}

pub const MAX_IPC_MSG_LEN: usize = 65536; // 64 KB maximum message size

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipc_roundtrip_all_message_types() {
        let (parent_ipc, child_fd) = create_ipc_channel::<DhcpClientToParentMsg>().unwrap();
        let child_ipc: IpcEndpoint<DhcpClientToParentMsg> =
            IpcEndpoint::from_owned_fd(child_fd).unwrap();

        // 1. DhcpClientToParentMsg::ApplyWanLease
        let client_msg = DhcpClientToParentMsg::ApplyWanLease {
            ip_address: Ipv4Addr::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        };
        child_ipc.send(&client_msg).await.unwrap();
        let received = parent_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, client_msg);

        // 2. DhcpClientToParentMsg::ClearWanLease
        let clear_msg = DhcpClientToParentMsg::ClearWanLease;
        child_ipc.send(&clear_msg).await.unwrap();
        let received = parent_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, clear_msg);

        // 3. DhcpServerParentToWorkerMsg
        let (parent_server_ipc, child_server_fd) =
            create_ipc_channel::<DhcpServerWorkerToParentMsg>().unwrap();
        let child_server_ipc: IpcEndpoint<DhcpServerParentToWorkerMsg> =
            IpcEndpoint::from_owned_fd(child_server_fd).unwrap();

        let server_msg = DhcpServerParentToWorkerMsg::AddNeighbor {
            ip_address: Ipv4Addr::new(192, 168, 1, 10),
            mac_address: MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
        };
        parent_server_ipc.send(&server_msg).await.unwrap();
        let received: DhcpServerParentToWorkerMsg = child_server_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, server_msg);

        // 3b. DhcpServerParentToWorkerMsg::SetStaticLeases
        let static_leases_msg = DhcpServerParentToWorkerMsg::SetStaticLeases {
            leases: vec![StaticLease {
                mac: MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
                ip: Ipv4Addr::new(192, 168, 1, 50),
                hostname: Some("nas".to_string()),
            }],
        };
        parent_server_ipc.send(&static_leases_msg).await.unwrap();
        let received: DhcpServerParentToWorkerMsg = child_server_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, static_leases_msg);

        // 4. DnsParentToWorkerMsg::SetUpstreamResolvers
        let (parent_dns_ipc, child_dns_fd) = create_ipc_channel::<DnsWorkerToParentMsg>().unwrap();
        let child_dns_ipc: IpcEndpoint<DnsParentToWorkerMsg> =
            IpcEndpoint::from_owned_fd(child_dns_fd).unwrap();

        let dns_msg = DnsParentToWorkerMsg::SetUpstreamResolvers {
            servers: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        };
        parent_dns_ipc.send(&dns_msg).await.unwrap();
        let received: DnsParentToWorkerMsg = child_dns_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, dns_msg);

        // 5. SntpClientToParentMsg::SetSystemTime
        let (parent_sntp_ipc, child_sntp_fd) =
            create_ipc_channel::<SntpClientToParentMsg>().unwrap();
        let child_sntp_ipc: IpcEndpoint<SntpParentToClientMsg> =
            IpcEndpoint::from_owned_fd(child_sntp_fd).unwrap();

        let sntp_msg = SntpClientToParentMsg::SetSystemTime {
            seconds: 1724515200,
            nanoseconds: 500_000,
        };
        child_sntp_ipc.send(&sntp_msg).await.unwrap();
        let received: SntpClientToParentMsg = parent_sntp_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, sntp_msg);

        // 6. SntpClientToParentMsg::ResolveTimeServer
        let resolve_msg = SntpClientToParentMsg::ResolveTimeServer;
        child_sntp_ipc.send(&resolve_msg).await.unwrap();
        let received: SntpClientToParentMsg = parent_sntp_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, resolve_msg);

        // 7. SntpParentToClientMsg::TimeServerResolved
        let resolved_msg = SntpParentToClientMsg::TimeServerResolved {
            result: Ok(Ipv4Addr::new(216, 239, 35, 0)),
        };
        parent_sntp_ipc.send(&resolved_msg).await.unwrap();
        let received: SntpParentToClientMsg = child_sntp_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, resolved_msg);

        // 8. Heartbeat messages
        let dns_heartbeat = DnsWorkerToParentMsg::Heartbeat {
            stats: DnsStatsInfo {
                queries_total: 10,
                cache_hits_total: 5,
                cached_entries_count: 2,
                rate_limited_drops_total: 0,
            },
        };
        child_dns_ipc.send(&dns_heartbeat).await.unwrap();
        let received: DnsWorkerToParentMsg = parent_dns_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, dns_heartbeat);

        let dhcp_heartbeat = DhcpServerWorkerToParentMsg::Heartbeat {
            leases: vec![DhcpLeaseInfo {
                mac: MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
                ip: Ipv4Addr::new(192, 168, 1, 100),
                hostname: Some("test-client".to_string()),
                expires_in_seconds: 3600,
                is_static: false,
            }],
        };
        child_server_ipc.send(&dhcp_heartbeat).await.unwrap();
        let received: DhcpServerWorkerToParentMsg =
            parent_server_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, dhcp_heartbeat);

        child_ipc
            .send(&DhcpClientToParentMsg::Heartbeat)
            .await
            .unwrap();
        let received: DhcpClientToParentMsg = parent_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, DhcpClientToParentMsg::Heartbeat);
    }

    #[tokio::test]
    async fn test_ipc_endpoint_cancellation_safety() {
        let (parent_ipc, child_fd) = create_ipc_channel::<DhcpClientToParentMsg>().unwrap();
        let child_ipc: IpcEndpoint<DhcpClientToParentMsg> =
            IpcEndpoint::from_owned_fd(child_fd).unwrap();

        // 1. Poll recv() inside select with immediate timeout: must cancel cleanly without hanging
        tokio::select! {
            _ = parent_ipc.recv() => panic!("Should not complete before message sent"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }

        // 2. Send message
        let msg = DhcpClientToParentMsg::ApplyWanLease {
            ip_address: Ipv4Addr::new(192, 168, 1, 100),
            prefix_len: 24,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
        };
        child_ipc.send(&msg).await.unwrap();

        // 3. Next recv() must successfully receive the datagram
        let received = parent_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, msg);
    }

    #[tokio::test]
    async fn test_ipc_recv_eof_returns_none() {
        let (parent_ipc, child_fd) = create_ipc_channel::<DhcpClientToParentMsg>().unwrap();
        drop(child_fd); // Close child socket immediately

        let res: Option<DhcpClientToParentMsg> = parent_ipc.recv().await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_ipc_recv_corrupted_payload_returns_err() {
        let (parent_ipc, child_fd) = create_ipc_channel::<DhcpClientToParentMsg>().unwrap();
        let child_socket = UnixSeqpacket::try_from(child_fd).unwrap();

        // Send invalid postcard payload
        child_socket.send(&[0xff, 0xff, 0xff]).await.unwrap();

        let res: Result<Option<DhcpClientToParentMsg>, std::io::Error> = parent_ipc.recv().await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_ipc_send_oversized_payload_rejected() {
        let (parent_ipc, _child_fd) = create_ipc_channel::<DnsParentToWorkerMsg>().unwrap();

        // Create an oversized message with > 64KB of DNS servers
        let oversized_servers: Vec<Ipv4Addr> =
            (0..20_000).map(|i| Ipv4Addr::from(i as u32)).collect();
        let msg = DnsParentToWorkerMsg::SetUpstreamResolvers {
            servers: oversized_servers,
        };

        let res = parent_ipc.send(&msg).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum limit"));
    }
}
