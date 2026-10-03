use futures_util::StreamExt;
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::os::unix::io::OwnedFd;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

pub fn async_unix_stream(fd: OwnedFd) -> Result<UnixStream, std::io::Error> {
    let std_stream = std::os::unix::net::UnixStream::from(fd);
    std_stream.set_nonblocking(true)?;
    UnixStream::from_std(std_stream)
}

/// Represents a strongly-typed bidirectional Unix domain socket IPC channel.
///
/// Wraps a cancellation-safe `IpcReceiver<InMsg>` for incoming messages and an
/// `OwnedWriteHalf` for sending outgoing serialized frames.
///
/// NOTE: Both `rx` and `tx` (or the `IpcEndpoint` instance) must be kept alive in scope
/// for the entire lifetime of the process. Dropping either half closes the Unix domain socket,
/// causing the peer's EOF monitor to assume the process has crashed or terminated.
pub struct IpcEndpoint<InMsg> {
    pub rx: IpcReceiver<InMsg>,
    pub tx: OwnedWriteHalf,
}

impl<InMsg: for<'a> Deserialize<'a>> IpcEndpoint<InMsg> {
    pub fn new(reader: OwnedReadHalf, tx: OwnedWriteHalf) -> Self {
        Self {
            rx: IpcReceiver::new(reader),
            tx,
        }
    }

    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, std::io::Error> {
        let ipc_stream = async_unix_stream(fd)?;
        let (reader, tx) = ipc_stream.into_split();
        Ok(Self::new(reader, tx))
    }

    pub async fn recv(&mut self) -> Result<Option<InMsg>, std::io::Error> {
        self.rx.recv().await
    }

    pub async fn send<OutMsg: Serialize>(&mut self, msg: &OutMsg) -> Result<(), std::io::Error> {
        send_msg(&mut self.tx, msg).await
    }
}

pub fn create_ipc_channel<InMsg: for<'a> Deserialize<'a>>()
-> Result<(IpcEndpoint<InMsg>, OwnedFd), std::io::Error> {
    let (parent_stream, child_stream) = tokio::net::UnixStream::pair()?;
    let (reader, tx) = parent_stream.into_split();
    let child_std = child_stream.into_std()?;
    Ok((IpcEndpoint::new(reader, tx), child_std.into()))
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
        leases: Vec<(MacAddr, Ipv4Addr)>,
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

fn create_length_delimited_codec() -> LengthDelimitedCodec {
    LengthDelimitedCodec::builder()
        .length_field_length(4)
        .max_frame_length(MAX_IPC_MSG_LEN)
        .new_codec()
}

/// Cancellation-safe structured message receiver over an asynchronous byte stream.
///
/// Buffers incoming frame fragments across `tokio::select!` branch cancellations,
/// guaranteeing that no partial stream bytes are discarded or corrupted.
pub struct IpcReceiver<T, R = OwnedReadHalf> {
    framed: FramedRead<R, LengthDelimitedCodec>,
    _phantom: PhantomData<fn() -> T>,
}

impl<T: for<'a> Deserialize<'a>, R: AsyncRead + Unpin> IpcReceiver<T, R> {
    pub fn new(reader: R) -> Self {
        Self {
            framed: FramedRead::new(reader, create_length_delimited_codec()),
            _phantom: PhantomData,
        }
    }

    pub async fn recv(&mut self) -> Result<Option<T>, std::io::Error> {
        match self.framed.next().await {
            Some(Ok(bytes)) => {
                let msg = postcard::from_bytes(&bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Some(msg))
            }
            Some(Err(e)) => Err(e),
            None => Ok(None),
        }
    }
}

pub async fn send_msg<T: Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &T,
) -> Result<(), std::io::Error> {
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
    let len = serialized.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&serialized).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn recv_msg<T: for<'a> Deserialize<'a>, R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<T>, std::io::Error> {
    let mut rx = IpcReceiver::new(reader);
    rx.recv().await
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipc_roundtrip_all_message_types() {
        let (sock1, sock2) = UnixStream::pair().unwrap();
        let (mut r1, mut w1) = sock1.into_split();
        let (mut r2, mut w2) = sock2.into_split();

        // 1. DhcpClientToParentMsg::ApplyWanLease
        let client_msg = DhcpClientToParentMsg::ApplyWanLease {
            ip_address: Ipv4Addr::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        };
        send_msg(&mut w1, &client_msg).await.unwrap();
        let received: DhcpClientToParentMsg = recv_msg(&mut r2).await.unwrap().unwrap();
        assert_eq!(received, client_msg);

        // 2. DhcpClientToParentMsg::ClearWanLease
        let clear_msg = DhcpClientToParentMsg::ClearWanLease;
        send_msg(&mut w1, &clear_msg).await.unwrap();
        let received: DhcpClientToParentMsg = recv_msg(&mut r2).await.unwrap().unwrap();
        assert_eq!(received, clear_msg);

        // 3. DhcpServerParentToWorkerMsg::AddNeighbor
        let server_msg = DhcpServerParentToWorkerMsg::AddNeighbor {
            ip_address: Ipv4Addr::new(192, 168, 1, 10),
            mac_address: MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
        };
        send_msg(&mut w2, &server_msg).await.unwrap();
        let received: DhcpServerParentToWorkerMsg = recv_msg(&mut r1).await.unwrap().unwrap();
        assert_eq!(received, server_msg);

        // 3b. DhcpServerParentToWorkerMsg::SetStaticLeases
        let static_leases_msg = DhcpServerParentToWorkerMsg::SetStaticLeases {
            leases: vec![(
                MacAddr::new(0x52, 0x54, 0x00, 0x12, 0x34, 0x56),
                Ipv4Addr::new(192, 168, 1, 50),
            )],
        };
        send_msg(&mut w2, &static_leases_msg).await.unwrap();
        let received: DhcpServerParentToWorkerMsg = recv_msg(&mut r1).await.unwrap().unwrap();
        assert_eq!(received, static_leases_msg);

        // 4. DnsParentToWorkerMsg::SetUpstreamResolvers
        let dns_msg = DnsParentToWorkerMsg::SetUpstreamResolvers {
            servers: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        };
        send_msg(&mut w1, &dns_msg).await.unwrap();
        let received: DnsParentToWorkerMsg = recv_msg(&mut r2).await.unwrap().unwrap();
        assert_eq!(received, dns_msg);

        // 5. SntpClientToParentMsg::SetSystemTime
        let sntp_msg = SntpClientToParentMsg::SetSystemTime {
            seconds: 1724515200,
            nanoseconds: 500_000,
        };
        send_msg(&mut w2, &sntp_msg).await.unwrap();
        let received: SntpClientToParentMsg = recv_msg(&mut r1).await.unwrap().unwrap();
        assert_eq!(received, sntp_msg);

        // 6. SntpClientToParentMsg::ResolveTimeServer
        let resolve_msg = SntpClientToParentMsg::ResolveTimeServer;
        send_msg(&mut w2, &resolve_msg).await.unwrap();
        let received: SntpClientToParentMsg = recv_msg(&mut r1).await.unwrap().unwrap();
        assert_eq!(received, resolve_msg);

        // 7. SntpParentToClientMsg::TimeServerResolved
        let resolved_msg = SntpParentToClientMsg::TimeServerResolved {
            result: Ok(Ipv4Addr::new(216, 239, 35, 0)),
        };
        send_msg(&mut w1, &resolved_msg).await.unwrap();
        let received: SntpParentToClientMsg = recv_msg(&mut r2).await.unwrap().unwrap();
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
        send_msg(&mut w2, &dns_heartbeat).await.unwrap();
        let received: DnsWorkerToParentMsg = recv_msg(&mut r1).await.unwrap().unwrap();
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
        send_msg(&mut w2, &dhcp_heartbeat).await.unwrap();
        let received: DhcpServerWorkerToParentMsg = recv_msg(&mut r1).await.unwrap().unwrap();
        assert_eq!(received, dhcp_heartbeat);

        send_msg(&mut w2, &DhcpClientToParentMsg::Heartbeat)
            .await
            .unwrap();
        let received: DhcpClientToParentMsg = recv_msg(&mut r1).await.unwrap().unwrap();
        assert_eq!(received, DhcpClientToParentMsg::Heartbeat);
    }

    #[tokio::test]
    async fn test_ipc_receiver_cancellation_safety() {
        let (sock1, sock2) = UnixStream::pair().unwrap();
        let (r1, _w1) = sock1.into_split();
        let (_r2, mut w2) = sock2.into_split();
        let mut rx: IpcReceiver<DhcpClientToParentMsg> = IpcReceiver::new(r1);

        let msg = DhcpClientToParentMsg::ApplyWanLease {
            ip_address: Ipv4Addr::new(192, 168, 1, 100),
            prefix_len: 24,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1)],
        };
        let serialized = postcard::to_stdvec(&msg).unwrap();
        let len = (serialized.len() as u32).to_be_bytes();

        let mut full_frame = Vec::new();
        full_frame.extend_from_slice(&len);
        full_frame.extend_from_slice(&serialized);

        // 1. Send only partial bytes (first 3 bytes of the 4-byte length prefix)
        w2.write_all(&full_frame[..3]).await.unwrap();
        w2.flush().await.unwrap();

        // 2. Poll recv() inside select with immediate timeout: must cancel cleanly
        tokio::select! {
            _ = rx.recv() => panic!("Should not complete on partial prefix"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }

        // 3. Send the rest of the frame
        w2.write_all(&full_frame[3..]).await.unwrap();
        w2.flush().await.unwrap();

        // 4. Next recv() must successfully reconstruct the buffered frame without data corruption
        let received = rx.recv().await.unwrap().unwrap();
        assert_eq!(received, msg);

        // 5. Send a subsequent message to verify the stream remains synchronized
        let clear_msg = DhcpClientToParentMsg::ClearWanLease;
        send_msg(&mut w2, &clear_msg).await.unwrap();
        let second_received = rx.recv().await.unwrap().unwrap();
        assert_eq!(second_received, clear_msg);
    }

    #[tokio::test]
    async fn test_ipc_recv_eof_returns_none() {
        let (sock1, sock2) = UnixStream::pair().unwrap();
        let (mut r1, _w1) = sock1.into_split();
        drop(sock2); // Close writer socket immediately

        let res: Option<DhcpClientToParentMsg> = recv_msg(&mut r1).await.unwrap();
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn test_ipc_recv_corrupted_payload_returns_err() {
        let (sock1, sock2) = UnixStream::pair().unwrap();
        let (mut r1, _w1) = sock1.into_split();
        let (_r2, mut w2) = sock2.into_split();

        // Write a 4-byte length prefix of 3 bytes, followed by invalid postcard payload
        let len: u32 = 3;
        w2.write_all(&len.to_be_bytes()).await.unwrap();
        w2.write_all(&[0xff, 0xff, 0xff]).await.unwrap();
        w2.flush().await.unwrap();

        let res: Result<Option<DhcpClientToParentMsg>, std::io::Error> = recv_msg(&mut r1).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_ipc_recv_oversized_length_rejected() {
        let (sock1, sock2) = UnixStream::pair().unwrap();
        let (mut r1, _w1) = sock1.into_split();
        let (_r2, mut w2) = sock2.into_split();

        // Write a 4-byte length prefix exceeding MAX_IPC_MSG_LEN (e.g. 100,000 bytes)
        let len: u32 = 100_000;
        w2.write_all(&len.to_be_bytes()).await.unwrap();
        w2.flush().await.unwrap();

        let res: Result<Option<DhcpClientToParentMsg>, std::io::Error> = recv_msg(&mut r1).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn test_ipc_send_oversized_payload_rejected() {
        let (sock1, _sock2) = UnixStream::pair().unwrap();
        let (_r1, mut w1) = sock1.into_split();

        // Create an oversized message with > 64KB of DNS servers
        let oversized_servers: Vec<Ipv4Addr> =
            (0..20_000).map(|i| Ipv4Addr::from(i as u32)).collect();
        let msg = DnsParentToWorkerMsg::SetUpstreamResolvers {
            servers: oversized_servers,
        };

        let res = send_msg(&mut w1, &msg).await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum limit"));
    }

    #[tokio::test]
    async fn test_create_ipc_channel_and_endpoint() {
        let (mut parent_ipc, child_fd) = create_ipc_channel::<DhcpClientToParentMsg>().unwrap();
        let mut child_ipc: IpcEndpoint<DhcpClientToParentMsg> =
            IpcEndpoint::from_owned_fd(child_fd).unwrap();

        let client_msg = DhcpClientToParentMsg::ApplyWanLease {
            ip_address: Ipv4Addr::new(10, 0, 2, 15),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 0, 2, 2),
            dns_servers: vec![Ipv4Addr::new(8, 8, 8, 8)],
        };

        child_ipc.send(&client_msg).await.unwrap();
        let received = parent_ipc.recv().await.unwrap().unwrap();
        assert_eq!(received, client_msg);
    }
}
