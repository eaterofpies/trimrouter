use crate::services::ipc::{SntpClientToParentMsg, send_msg};
use crate::services::utils::{
    NTP_PORT, SNTP_GID, SNTP_UID, resolve_dns_a_record, run_sandboxed_worker, wait_ipc_eof,
};
use chrono::{DateTime, Utc};
use log::{error, info, warn};
use std::io::Error as IoError;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::OwnedFd;
use std::time::Duration;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

const SYNC_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes
const RETRY_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(900); // 15 minutes

pub async fn run_sntp_client_worker(ipc_fd: OwnedFd) -> Result<(), IoError> {
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
    current_retry_delay: &mut Duration,
) -> bool {
    let sync_res = tokio::select! {
        _ = wait_ipc_eof(ipc_reader) => return false,
        res = sync_time() => res,
    };

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
            *current_retry_delay = std::cmp::min(*current_retry_delay * 2, MAX_RETRY_INTERVAL);
            proceed
        }
    }
}

async fn send_time_to_parent(ipc_writer: &mut OwnedWriteHalf, chrono_dt: DateTime<Utc>) {
    let duration = chrono_dt.signed_duration_since(DateTime::UNIX_EPOCH);
    if let Ok(std_duration) = duration.to_std() {
        let msg = SntpClientToParentMsg::SetSystemTime {
            seconds: std_duration.as_secs() as i64,
            nanoseconds: std_duration.subsec_nanos() as i64,
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

async fn sync_time() -> Result<DateTime<Utc>, String> {
    // Resolve time.google.com manually via local DNS forwarder
    let ntp_server_ip = resolve_dns_a_record("time.google.com").await?;
    let ntp_addr = SocketAddr::new(IpAddr::V4(ntp_server_ip), NTP_PORT);

    // Synchronize using standard rsntp client
    let client = rsntp::AsyncSntpClient::new();
    let result = client
        .synchronize(ntp_addr)
        .await
        .map_err(|e| format!("NTP synchronization failed: {:?}", e))?;

    // Convert datetime using rsntp's integrated chrono feature
    let chrono_dt = result
        .datetime()
        .into_chrono_datetime()
        .map_err(|e| format!("Failed to convert NTP datetime: {}", e))?;

    Ok(chrono_dt)
}

// =========================================================================
// Tests
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
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
}
