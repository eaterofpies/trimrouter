use crate::services::ipc::{SntpClientToParentMsg, SntpParentToClientMsg, recv_msg, send_msg};
use crate::services::utils::{
    NTP_PORT, SNTP_GID, SNTP_UID, is_valid_ntp_server_ip, run_sandboxed_worker, wait_ipc_eof,
};
use chrono::{DateTime, TimeZone, Utc};
use log::{error, info, warn};
use std::io::Error as IoError;
use std::os::unix::io::OwnedFd;
use std::time::Duration;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const SYNC_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes
const RETRY_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(900); // 15 minutes
const DNS_TIMEOUT: Duration = Duration::from_secs(5); // 5 seconds

pub async fn run_sntp_client_worker(
    ipc_fd: OwnedFd,
    ntp_socket_fd: OwnedFd,
) -> Result<(), IoError> {
    let ntp_socket = std::sync::Arc::new(crate::services::utils::async_udp_socket(ntp_socket_fd)?);

    run_sandboxed_worker(
        "sntp-client",
        SNTP_UID,
        SNTP_GID,
        ipc_fd,
        |ipc| async move {
            let mut ipc_writer = ipc.writer;
            let mut ipc_reader = ipc.reader;
            let mut current_retry_delay = RETRY_INTERVAL;

            loop {
                if !handle_sntp_iteration(
                    &mut ipc_writer,
                    &mut ipc_reader,
                    &ntp_socket,
                    &mut current_retry_delay,
                )
                .await
                {
                    info!("[sntp-client-worker] Parent closed IPC. Shutting down.");
                    break;
                }
            }

            Ok(())
        },
    )
    .await
}

async fn handle_sntp_iteration(
    ipc_writer: &mut OwnedWriteHalf,
    ipc_reader: &mut OwnedReadHalf,
    ntp_socket: &std::sync::Arc<tokio::net::UdpSocket>,
    current_retry_delay: &mut Duration,
) -> bool {
    let sync_res = sync_time(ipc_writer, ipc_reader, ntp_socket).await;

    match sync_res {
        Ok(chrono_dt) => {
            info!(
                "[sntp-client-worker] Successfully fetched NTP time: {}",
                chrono_dt
            );
            send_time_to_parent(ipc_writer, chrono_dt).await;
            *current_retry_delay = RETRY_INTERVAL;
            sleep_or_shutdown(SYNC_INTERVAL, ipc_reader).await
        }
        Err(e) => {
            warn!(
                "[sntp-client] Time synchronization failed: {}. Retrying in {}s...",
                e,
                current_retry_delay.as_secs()
            );
            let proceed = sleep_or_shutdown(*current_retry_delay, ipc_reader).await;
            *current_retry_delay = calculate_next_retry_delay(*current_retry_delay);
            proceed
        }
    }
}

fn calculate_next_retry_delay(current: Duration) -> Duration {
    std::cmp::min(current.saturating_mul(2), MAX_RETRY_INTERVAL)
}

fn datetime_to_time_components(chrono_dt: DateTime<Utc>) -> Option<(i64, i64)> {
    let duration = chrono_dt.signed_duration_since(DateTime::UNIX_EPOCH);
    let std_duration = duration.to_std().ok()?;
    Some((
        std_duration.as_secs() as i64,
        std_duration.subsec_nanos() as i64,
    ))
}

async fn send_time_to_parent(ipc_writer: &mut OwnedWriteHalf, chrono_dt: DateTime<Utc>) {
    if let Some((seconds, nanoseconds)) = datetime_to_time_components(chrono_dt) {
        let msg = SntpClientToParentMsg::SetSystemTime {
            seconds,
            nanoseconds,
        };
        if let Err(e) = send_msg(ipc_writer, &msg).await {
            error!("[sntp-client] Failed to send SetSystemTime IPC msg: {}", e);
        }
    }
}

async fn sleep_or_shutdown(duration: Duration, ipc_reader: &mut OwnedReadHalf) -> bool {
    tokio::select! {
        _ = wait_ipc_eof(ipc_reader) => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

use sntpc::{
    Error as SntpError, NtpContext, NtpResult as SntpResult, NtpUdpSocket, StdTimestampGen,
    get_time,
};

struct TokioUdpSocketRef<'a>(&'a tokio::net::UdpSocket);

impl NtpUdpSocket for TokioUdpSocketRef<'_> {
    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> Result<usize, SntpError> {
        self.0
            .send_to(buf, addr)
            .await
            .map_err(|_| SntpError::Network)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), SntpError> {
        self.0.recv_from(buf).await.map_err(|_| SntpError::Network)
    }
}

async fn sync_time(
    ipc_writer: &mut OwnedWriteHalf,
    ipc_reader: &mut OwnedReadHalf,
    ntp_socket: &tokio::net::UdpSocket,
) -> Result<DateTime<Utc>, String> {
    // 1. Request DNS resolution for time server from parent supervisor over IPC
    let msg = SntpClientToParentMsg::ResolveTimeServer;
    send_msg(ipc_writer, &msg)
        .await
        .map_err(|e| format!("Failed to send ResolveTimeServer IPC message: {}", e))?;

    // 2. Await TimeServerResolved response from parent with 5s timeout
    let resolved_msg: Option<SntpParentToClientMsg> =
        tokio::time::timeout(DNS_TIMEOUT, recv_msg(ipc_reader))
            .await
            .map_err(|_| "DNS resolution request timed out awaiting parent response".to_string())?
            .map_err(|e| format!("Failed to receive TimeServerResolved IPC message: {}", e))?;

    let ntp_server_ip = match resolved_msg {
        Some(SntpParentToClientMsg::TimeServerResolved { result }) => result?,
        None => return Err("Parent closed IPC during DNS resolution".to_string()),
    };

    if !is_valid_ntp_server_ip(ntp_server_ip) {
        return Err(format!(
            "Invalid/unroutable NTP server IP: {}",
            ntp_server_ip
        ));
    }
    let ntp_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ntp_server_ip), NTP_PORT);

    // 3. Query NTP server using sntpc library with passed UDP socket
    let ntp_context = NtpContext::new(StdTimestampGen::default());
    let socket_wrapper = TokioUdpSocketRef(ntp_socket);

    let result: SntpResult = tokio::time::timeout(
        Duration::from_secs(3),
        get_time(ntp_addr, &socket_wrapper, ntp_context),
    )
    .await
    .map_err(|_| "Timeout while waiting for SNTP server reply".to_string())?
    .map_err(|e| format!("SNTP get_time failed: {:?}", e))?;

    let unix_secs = result.sec() as i64;
    let nanos = (u64::from(result.sec_fraction()) * 1_000_000_000 / (1u64 << 32)) as u32;

    Utc.timestamp_opt(unix_secs, nanos)
        .single()
        .ok_or_else(|| format!("Invalid timestamp: secs={}, nanos={}", unix_secs, nanos))
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_sleep_or_shutdown_normal() {
        let (sock1, _sock2) = UnixStream::pair().unwrap();
        let (mut reader, _writer) = sock1.into_split();
        let result = sleep_or_shutdown(Duration::from_millis(10), &mut reader).await;
        assert!(result);
    }

    #[tokio::test]
    async fn test_sleep_or_shutdown_triggered() {
        let (sock1, sock2) = UnixStream::pair().unwrap();
        let (mut reader, _writer) = sock1.into_split();

        let handle =
            tokio::spawn(
                async move { sleep_or_shutdown(Duration::from_secs(10), &mut reader).await },
            );

        // Close sock2 to trigger EOF
        drop(sock2);

        let result = handle.await.unwrap();
        assert!(!result);
    }

    #[test]
    fn test_calculate_next_retry_delay_exponential_growth_and_cap() {
        let d1 = calculate_next_retry_delay(Duration::from_secs(60));
        assert_eq!(d1, Duration::from_secs(120));

        let d2 = calculate_next_retry_delay(d1);
        assert_eq!(d2, Duration::from_secs(240));

        let d3 = calculate_next_retry_delay(d2);
        assert_eq!(d3, Duration::from_secs(480));

        let d4 = calculate_next_retry_delay(d3);
        assert_eq!(d4, Duration::from_secs(900)); // Capped at MAX_RETRY_INTERVAL (15 min)

        let d5 = calculate_next_retry_delay(d4);
        assert_eq!(d5, Duration::from_secs(900)); // Stays at cap
    }

    #[test]
    fn test_is_valid_ntp_server_ip() {
        use std::net::Ipv4Addr;
        // Valid routable IP
        assert!(is_valid_ntp_server_ip(Ipv4Addr::new(216, 239, 35, 0))); // time.google.com
        assert!(is_valid_ntp_server_ip(Ipv4Addr::new(8, 8, 8, 8)));

        // Invalid IPs
        assert!(!is_valid_ntp_server_ip(Ipv4Addr::UNSPECIFIED)); // 0.0.0.0
        assert!(!is_valid_ntp_server_ip(Ipv4Addr::BROADCAST)); // 255.255.255.255
        assert!(!is_valid_ntp_server_ip(Ipv4Addr::new(127, 0, 0, 1))); // Loopback
    }

    #[tokio::test]
    async fn test_sync_time_dns_failure_returns_err() {
        let (sock1, sock2) = UnixStream::pair().unwrap();
        let (mut worker_reader, mut worker_writer) = sock1.into_split();
        let (mut parent_reader, mut parent_writer) = sock2.into_split();
        let udp_sock =
            std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        tokio::spawn(async move {
            if let Ok(Some(SntpClientToParentMsg::ResolveTimeServer)) =
                recv_msg(&mut parent_reader).await
            {
                let response = SntpParentToClientMsg::TimeServerResolved {
                    result: Err("DNS query timed out".to_string()),
                };
                let _ = send_msg(&mut parent_writer, &response).await;
            }
        });

        let res = sync_time(&mut worker_writer, &mut worker_reader, &udp_sock).await;
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("DNS query timed out"));
    }

    #[test]
    fn test_datetime_to_time_components_conversion() {
        // Valid date: 2024-01-01T00:00:00Z (timestamp 1704067200)
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let components = datetime_to_time_components(dt);
        assert_eq!(components, Some((1704067200, 0)));

        // Pre-1970 date: 1969-12-31T23:59:59Z (should return None)
        let pre_epoch_dt = Utc.with_ymd_and_hms(1969, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(datetime_to_time_components(pre_epoch_dt), None);
    }
}
