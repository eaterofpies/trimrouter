use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::os::unix::io::OwnedFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

pub fn async_unix_stream(fd: OwnedFd) -> Result<UnixStream, std::io::Error> {
    let std_stream = std::os::unix::net::UnixStream::from(fd);
    std_stream.set_nonblocking(true)?;
    UnixStream::from_std(std_stream)
}

/// Represents the bidirectional Unix domain socket IPC channel for a sandboxed worker.
///
/// NOTE: Both `reader` and `writer` (or the `IpcEndpoint` instance) must be kept alive in scope
/// for the entire lifetime of the worker task. Dropping either half closes the Unix domain socket,
/// causing the parent supervisor's EOF monitor (`read(&mut buf) -> 0`) to assume the worker has
/// crashed or terminated and send `SIGTERM`.
pub struct IpcEndpoint {
    pub reader: OwnedReadHalf,
    pub writer: OwnedWriteHalf,
}

impl IpcEndpoint {
    pub fn from_owned_fd(fd: OwnedFd) -> Result<Self, std::io::Error> {
        let ipc_stream = async_unix_stream(fd)?;
        let (reader, writer) = ipc_stream.into_split();
        Ok(Self { reader, writer })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DnsParentToWorkerMsg {
    SetUpstreamResolvers { servers: Vec<Ipv4Addr> },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpServerParentToWorkerMsg {
    AddNeighbor {
        ip_address: Ipv4Addr,
        mac_address: [u8; 6],
    },
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

pub async fn send_msg<T: Serialize, W: AsyncWriteExt + Unpin>(
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

pub async fn recv_msg<T: for<'a> Deserialize<'a>, R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Option<T>, std::io::Error> {
    let mut len_bytes = [0u8; 4];
    match reader.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_IPC_MSG_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "IPC message length {} exceeds maximum limit of {}",
                len, MAX_IPC_MSG_LEN
            ),
        ));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let msg = postcard::from_bytes(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
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
            mac_address: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        };
        send_msg(&mut w2, &server_msg).await.unwrap();
        let received: DhcpServerParentToWorkerMsg = recv_msg(&mut r1).await.unwrap().unwrap();
        assert_eq!(received, server_msg);

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
        let err = res.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds maximum limit"));
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
}
