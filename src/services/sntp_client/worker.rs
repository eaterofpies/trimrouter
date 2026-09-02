use crate::services::SNTP_CLIENT_SERVICE_NAME;
use crate::services::ipc::{SntpClientToParentMsg, SntpParentToClientMsg, recv_msg, send_msg};
use crate::services::utils::{
    NTP_PORT, SNTP_GID, SNTP_UID, is_valid_ntp_server_ip, run_sandboxed_worker,
};
use chrono::{DateTime, TimeZone, Utc};
use log::{error, info, warn};
use sntpc::{
    Error as SntpError, NtpContext, NtpResult as SntpResult, NtpUdpSocket, StdTimestampGen,
    fraction_to_microseconds, get_time,
};
use std::io::Error as IoError;
use std::os::unix::io::OwnedFd;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const SYNC_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes
const RETRY_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(900); // 15 minutes
const NANOS_PER_MICRO: u32 = 1_000;

#[derive(Debug, PartialEq, Eq)]
struct SyncScheduleResult {
    next_sync_delay: Duration,
    next_retry_delay: Duration,
}

#[derive(Debug, PartialEq, Eq)]
struct TimeComponents {
    seconds: i64,
    nanoseconds: i64,
}

pub struct TokioUdpSocketRef<'a>(pub &'a UdpSocket);

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

pub async fn run_sntp_client_worker(
    ipc_fd: OwnedFd,
    ntp_socket_fd: OwnedFd,
) -> Result<(), IoError> {
    let ntp_socket = crate::services::utils::async_udp_socket(ntp_socket_fd)?;

    run_sandboxed_worker(
        SNTP_CLIENT_SERVICE_NAME,
        SNTP_UID,
        SNTP_GID,
        ipc_fd,
        |ipc| async move {
            run_sntp_worker_loop(ipc.writer, ipc.reader, &ntp_socket).await;
            Ok(())
        },
    )
    .await
}

async fn run_sntp_worker_loop(
    mut ipc_writer: OwnedWriteHalf,
    mut ipc_reader: OwnedReadHalf,
    ntp_socket: &UdpSocket,
) {
    let mut current_retry_delay = RETRY_INTERVAL;
    let mut sync_timer = tokio::time::interval(SYNC_INTERVAL);
    let _ = send_msg(&mut ipc_writer, &SntpClientToParentMsg::ResolveTimeServer).await;

    loop {
        tokio::select! {
            _ = sync_timer.tick() => {
                if let Err(e) = send_msg(&mut ipc_writer, &SntpClientToParentMsg::ResolveTimeServer).await {
                    error!("[sntp-client-worker] Failed to send ResolveTimeServer: {}", e);
                    break;
                }
            }
            ipc_msg = recv_msg::<SntpParentToClientMsg, _>(&mut ipc_reader) => {
                match ipc_msg {
                    Ok(Some(SntpParentToClientMsg::TimeServerResolved { result })) => {
                        let schedule = handle_time_server_resolved(
                            result,
                            &mut ipc_writer,
                            ntp_socket,
                            current_retry_delay,
                        ).await;
                        current_retry_delay = schedule.next_retry_delay;
                        sync_timer = tokio::time::interval_at(
                            tokio::time::Instant::now() + schedule.next_sync_delay,
                            SYNC_INTERVAL,
                        );
                    }
                    Ok(None) | Err(_) => {
                        info!("[sntp-client-worker] Parent closed IPC. Shutting down.");
                        break;
                    }
                }
            }
        }
    }
}

async fn handle_time_server_resolved(
    result: Result<std::net::Ipv4Addr, String>,
    ipc_writer: &mut OwnedWriteHalf,
    ntp_socket: &UdpSocket,
    current_retry_delay: Duration,
) -> SyncScheduleResult {
    match result {
        Ok(ntp_server_ip) if is_valid_ntp_server_ip(ntp_server_ip) => {
            let ntp_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ntp_server_ip), NTP_PORT);
            match query_ntp_time(ntp_addr, ntp_socket).await {
                Ok(chrono_dt) => {
                    info!(
                        "[sntp-client-worker] Successfully fetched NTP time: {}",
                        chrono_dt
                    );
                    send_time_to_parent(ipc_writer, chrono_dt).await;
                    SyncScheduleResult {
                        next_sync_delay: SYNC_INTERVAL,
                        next_retry_delay: RETRY_INTERVAL,
                    }
                }
                Err(e) => {
                    warn!(
                        "[sntp-client] Time synchronization failed: {}. Retrying in {}s...",
                        e,
                        current_retry_delay.as_secs()
                    );
                    SyncScheduleResult {
                        next_sync_delay: current_retry_delay,
                        next_retry_delay: calculate_next_retry_delay(current_retry_delay),
                    }
                }
            }
        }
        Ok(invalid_ip) => {
            warn!(
                "[sntp-client] Resolved unroutable NTP server IP {}. Retrying in {}s...",
                invalid_ip,
                current_retry_delay.as_secs()
            );
            SyncScheduleResult {
                next_sync_delay: current_retry_delay,
                next_retry_delay: calculate_next_retry_delay(current_retry_delay),
            }
        }
        Err(e) => {
            warn!(
                "[sntp-client] DNS resolution failed: {}. Retrying in {}s...",
                e,
                current_retry_delay.as_secs()
            );
            SyncScheduleResult {
                next_sync_delay: current_retry_delay,
                next_retry_delay: calculate_next_retry_delay(current_retry_delay),
            }
        }
    }
}

fn calculate_next_retry_delay(current: Duration) -> Duration {
    std::cmp::min(current.saturating_mul(2), MAX_RETRY_INTERVAL)
}

fn datetime_to_time_components(chrono_dt: DateTime<Utc>) -> Option<TimeComponents> {
    let duration = chrono_dt.signed_duration_since(DateTime::UNIX_EPOCH);
    let std_duration = duration.to_std().ok()?;
    Some(TimeComponents {
        seconds: std_duration.as_secs() as i64,
        nanoseconds: std_duration.subsec_nanos() as i64,
    })
}

async fn send_time_to_parent(ipc_writer: &mut OwnedWriteHalf, chrono_dt: DateTime<Utc>) {
    if let Some(components) = datetime_to_time_components(chrono_dt) {
        let msg = SntpClientToParentMsg::SetSystemTime {
            seconds: components.seconds,
            nanoseconds: components.nanoseconds,
        };
        if let Err(e) = send_msg(ipc_writer, &msg).await {
            error!("[sntp-client] Failed to send SetSystemTime IPC msg: {}", e);
        }
    }
}

async fn query_ntp_time(
    ntp_addr: std::net::SocketAddr,
    ntp_socket: &UdpSocket,
) -> Result<DateTime<Utc>, String> {
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
    let micros = fraction_to_microseconds(result.sec_fraction());
    let nanos = micros.saturating_mul(NANOS_PER_MICRO);

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
    use tokio::net::UnixStream;

    #[tokio::test]
    async fn test_tokio_udp_socket_ref_send_recv() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_b = sock_b.local_addr().unwrap();

        let wrapper_a = TokioUdpSocketRef(&sock_a);
        let wrapper_b = TokioUdpSocketRef(&sock_b);

        let sent = wrapper_a.send_to(b"ping", addr_b).await.unwrap();
        assert_eq!(sent, 4);

        let mut buf = [0u8; 16];
        let (recv_len, src) = wrapper_b.recv_from(&mut buf).await.unwrap();
        assert_eq!(recv_len, 4);
        assert_eq!(&buf[..recv_len], b"ping");
        assert_eq!(src, sock_a.local_addr().unwrap());
    }

    #[tokio::test]
    async fn test_handle_time_server_resolved_error_schedules_retry() {
        let (sock1, _sock2) = UnixStream::pair().unwrap();
        let (_reader, mut writer) = sock1.into_split();
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let retry_delay = Duration::from_secs(60);

        let schedule = handle_time_server_resolved(
            Err("DNS query failed".to_string()),
            &mut writer,
            &udp_sock,
            retry_delay,
        )
        .await;

        assert_eq!(
            schedule,
            SyncScheduleResult {
                next_sync_delay: Duration::from_secs(60),
                next_retry_delay: Duration::from_secs(120),
            }
        );
    }

    #[test]
    fn test_datetime_to_time_components_conversion() {
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        let components = datetime_to_time_components(dt);
        assert_eq!(
            components,
            Some(TimeComponents {
                seconds: 1704067200,
                nanoseconds: 0,
            })
        );

        let pre_epoch_dt = Utc.with_ymd_and_hms(1969, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(datetime_to_time_components(pre_epoch_dt), None);
    }
}
