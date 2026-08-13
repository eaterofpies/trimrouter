use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ParentToWorkerMsg {
    SetUpstreamResolvers {
        servers: Vec<Ipv4Addr>,
    },
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
