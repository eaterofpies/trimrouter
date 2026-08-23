use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

pub struct IpcEndpoint {
    pub reader: OwnedReadHalf,
    pub writer: Arc<Mutex<OwnedWriteHalf>>,
}

impl IpcEndpoint {
    pub fn from_raw_fd(fd: RawFd) -> Result<Self, std::io::Error> {
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let ipc_stream = UnixStream::from_std(std_stream)?;
        let (reader, writer) = ipc_stream.into_split();
        Ok(Self {
            reader,
            writer: Arc::new(Mutex::new(writer)),
        })
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
pub enum SntpParentToWorkerMsg {
    SetWanStatus { active: bool },
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
}

pub async fn send_msg<T: Serialize, W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &T,
) -> Result<(), std::io::Error> {
    let serialized = postcard::to_stdvec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    let msg = postcard::from_bytes(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(msg))
}
