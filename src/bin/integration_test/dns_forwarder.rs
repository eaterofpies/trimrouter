use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use trimrouter::services::utils::{ROUTER_HOSTNAME, WanLeaseReceiver};
use trimrouter::services::{DnsForwarder, LocalHostEvent, Service};

const DNS_TCP_ADDR: &str = "192.168.1.1:53";
const DNS_HOST_VERIFY_ADDR: &str = "192.168.1.1:23457";
const DNS_CACHE_OK_PAYLOAD: &[u8] = b"DNS_CACHE_OK";
const ROUTER_QUERY_HOST: &str = "router.lan.";
const EXPECTED_ROUTER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const VERIFY_TIMEOUT_SECS: u64 = 15;
const STARTUP_WAIT_MS: u64 = 1000;
const CHANNEL_BUFFER_SIZE: usize = 64;
const UDP_BUF_SIZE: usize = 512;

pub async fn test_dns_forwarding(lease_rx: WanLeaseReceiver) -> Result<DnsForwarder, String> {
    std::println!("[test] Starting DNS Forwarder test...");

    // 1. Start DNS Forwarder with router.lan local host mapping
    let (local_hosts_tx, local_hosts_rx) =
        tokio::sync::mpsc::channel::<LocalHostEvent>(CHANNEL_BUFFER_SIZE);
    let _ = local_hosts_tx.try_send(LocalHostEvent::Register {
        name: ROUTER_HOSTNAME.to_string(),
        ip: EXPECTED_ROUTER_IP,
    });
    let mut dns_forwarder =
        DnsForwarder::with_custom_dns(lease_rx, Vec::new(), None, Some(local_hosts_rx));
    if let Err(e) = dns_forwarder.start().await {
        return Err(format!("Failed to start DNS Forwarder: {}", e));
    }

    // Wait for the worker to drop privileges, set up Seccomp, and bind UDP & TCP port 53
    std::thread::sleep(Duration::from_millis(STARTUP_WAIT_MS));

    // 2. Verify inbound TCP DNS resolution on port 53
    if let Err(e) = verify_tcp_dns_resolution().await {
        let _ = dns_forwarder.stop().await;
        return Err(format!("TCP DNS resolution failed: {}", e));
    }

    // 3. Bind to UDP port 23457 to receive verification from the host
    let socket = UdpSocket::bind(DNS_HOST_VERIFY_ADDR).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(VERIFY_TIMEOUT_SECS)))
        .map_err(|e| e.to_string())?;

    // 4. Trigger the host test coordinator
    std::println!("[test-control] TRIGGER_DNS_CLIENT_TEST");

    // 5. Await verification packet from the host
    if let Err(e) = await_host_verification_udp(&socket) {
        let _ = dns_forwarder.stop().await;
        return Err(e);
    }

    Ok(dns_forwarder)
}

pub async fn verify_tcp_dns_resolution() -> Result<(), String> {
    let mut stream = TcpStream::connect(DNS_TCP_ADDR)
        .await
        .map_err(|e| format!("Failed to connect to TCP DNS at {}: {}", DNS_TCP_ADDR, e))?;

    // Query router.lan
    let resp1 = query_tcp_stream(&mut stream, 0x1234, ROUTER_QUERY_HOST).await?;
    validate_router_a_record(&resp1, 0x1234)?;

    // Query again on same connection (connection reuse / pipelining test)
    let resp2 = query_tcp_stream(&mut stream, 0x5678, ROUTER_QUERY_HOST).await?;
    validate_router_a_record(&resp2, 0x5678)?;

    std::println!("[test] TCP DNS resolution verified successfully (with connection reuse).");
    Ok(())
}

fn build_a_query(id: u16, name_str: &str) -> Result<Vec<u8>, String> {
    let mut query = Message::new(id, hickory_proto::op::MessageType::Query, OpCode::Query);
    let qname = Name::from_ascii(name_str).map_err(|e| e.to_string())?;
    query.add_query(Query::query(qname, RecordType::A));
    let mut query_bytes = Vec::new();
    let mut enc = BinEncoder::new(&mut query_bytes);
    query.emit(&mut enc).map_err(|e| e.to_string())?;
    Ok(query_bytes)
}

async fn query_tcp_stream(
    stream: &mut TcpStream,
    id: u16,
    name_str: &str,
) -> Result<Message, String> {
    let query_bytes = build_a_query(id, name_str)?;
    let len_prefix = (query_bytes.len() as u16).to_be_bytes();
    stream
        .write_all(&len_prefix)
        .await
        .map_err(|e| format!("Failed to write TCP DNS length prefix: {}", e))?;
    stream
        .write_all(&query_bytes)
        .await
        .map_err(|e| format!("Failed to write TCP DNS query body: {}", e))?;

    let mut resp_len_buf = [0u8; 2];
    stream
        .read_exact(&mut resp_len_buf)
        .await
        .map_err(|e| format!("Failed to read TCP DNS response length: {}", e))?;
    let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(|e| format!("Failed to read TCP DNS response body: {}", e))?;

    Message::from_bytes(&resp_buf).map_err(|e| format!("Failed to decode DNS message: {}", e))
}

fn validate_router_a_record(msg: &Message, expected_id: u16) -> Result<(), String> {
    if msg.id != expected_id {
        return Err(format!(
            "DNS ID mismatch: expected 0x{:04x}, got 0x{:04x}",
            expected_id, msg.id
        ));
    }
    if msg.response_code != ResponseCode::NoError {
        return Err(format!(
            "Unexpected DNS response code: {:?}",
            msg.response_code
        ));
    }
    if msg.answers.is_empty() {
        return Err("No DNS answer returned in TCP query".to_string());
    }
    if let RData::A(A(ip)) = &msg.answers[0].data {
        if *ip != EXPECTED_ROUTER_IP {
            return Err(format!(
                "Unexpected IP in answer: got {}, expected {}",
                ip, EXPECTED_ROUTER_IP
            ));
        }
    } else {
        return Err("DNS answer is not an A record".to_string());
    }
    Ok(())
}

fn await_host_verification_udp(socket: &UdpSocket) -> Result<(), String> {
    let mut buf = [0u8; UDP_BUF_SIZE];
    let (amt, _src) = socket
        .recv_from(&mut buf)
        .map_err(|e| format!("Timed out waiting for DNS caching verification: {}", e))?;

    if &buf[..amt] == DNS_CACHE_OK_PAYLOAD {
        std::println!("[test] DNS Forwarder successfully resolved and cached query.");
        Ok(())
    } else {
        Err(format!(
            "Received invalid DNS verification payload: {:?}",
            String::from_utf8_lossy(&buf[..amt])
        ))
    }
}
