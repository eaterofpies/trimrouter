use crate::managers::ipc::{recv_msg, send_msg, SntpClientToParentMsg, SntpParentToWorkerMsg};
use crate::managers::utils::{
    resolve_dns_a_record, run_sandboxed_worker, wait_shutdown, SNTP_GID, SNTP_UID,
};
use log::{error, info, warn};
use std::io::Error as IoError;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::RawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::watch::{channel, Receiver};
use tokio::sync::Mutex as TokioMutex;

const SYNC_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes
const RETRY_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(900); // 15 minutes

const NTP_PORT: u16 = 123;
const WAN_CHECK_INTERVAL: Duration = Duration::from_secs(5);

pub async fn run_sntp_client_worker(ipc_fd: RawFd) -> Result<(), IoError> {
    run_sandboxed_worker("sntp-client", SNTP_UID, SNTP_GID, ipc_fd, |ipc| async move {
        let (mut ipc_reader, shared_ipc_writer) = (ipc.reader, ipc.writer);
        let (shutdown_tx, mut shutdown_rx) = channel(false);
        let wan_active = Arc::new(Mutex::new(false));

    // Monitor parent messages
    let wan_active_clone = wan_active.clone();
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        loop {
            match recv_msg::<SntpParentToWorkerMsg, _>(&mut ipc_reader).await {
                Ok(Some(SntpParentToWorkerMsg::SetWanStatus { active })) => {
                    let mut lock = wan_active_clone.lock().unwrap();
                    *lock = active;
                }
                Ok(None) => {
                    info!("[sntp-client-worker] Parent closed IPC. Shutting down.");
                    let _ = shutdown_tx_clone.send(true);
                    break;
                }
                Err(e) => {
                    error!("[sntp-client-worker] IPC read error: {}. Shutting down.", e);
                    let _ = shutdown_tx_clone.send(true);
                    break;
                }
            }
        }
    });

    let mut current_retry_delay = RETRY_INTERVAL;

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        if !handle_sntp_iteration(
            &wan_active,
            &shared_ipc_writer,
            &mut shutdown_rx,
            &mut current_retry_delay,
        )
        .await
        {
            break;
        }
    }

    Ok(())
    })
    .await
}

async fn handle_sntp_iteration(
    wan_active: &Arc<Mutex<bool>>,
    ipc_writer: &Arc<TokioMutex<OwnedWriteHalf>>,
    shutdown_rx: &mut Receiver<bool>,
    current_retry_delay: &mut Duration,
) -> bool {
    if !wait_for_wan(wan_active, shutdown_rx).await {
        return false;
    }

    let sync_res = tokio::select! {
        _ = wait_shutdown(shutdown_rx) => {
            return false;
        }
        res = sync_time() => res,
    };

    match sync_res {
        Ok(chrono_dt) => {
            info!(
                "[sntp-client-worker] Successfully fetched NTP time: {}",
                chrono_dt
            );

            // Send time spec back to parent over IPC
            let duration = chrono_dt.signed_duration_since(chrono::DateTime::UNIX_EPOCH);
            if let Ok(std_duration) = duration.to_std() {
                let msg = SntpClientToParentMsg::SetSystemTime {
                    seconds: std_duration.as_secs() as i64,
                    nanoseconds: std_duration.subsec_nanos() as i64,
                };
                let mut writer = ipc_writer.lock().await;
                if let Err(e) = send_msg(&mut *writer, &msg).await {
                    error!("[sntp-client] Failed to send SetSystemTime IPC msg: {}", e);
                }
            }

            *current_retry_delay = RETRY_INTERVAL;
            sleep_or_shutdown(SYNC_INTERVAL, shutdown_rx).await
        }
        Err(e) => {
            warn!(
                "[sntp-client] Time synchronization failed: {}. Retrying in {}s...",
                e,
                current_retry_delay.as_secs()
            );
            let proceed = sleep_or_shutdown(*current_retry_delay, shutdown_rx).await;
            *current_retry_delay = std::cmp::min(*current_retry_delay * 2, MAX_RETRY_INTERVAL);
            proceed
        }
    }
}

async fn wait_for_wan(
    wan_active: &Arc<Mutex<bool>>,
    shutdown_rx: &mut Receiver<bool>,
) -> bool {
    loop {
        let has_wan = {
            let active = wan_active.lock().unwrap();
            *active
        };
        if has_wan {
            return true;
        }
        tokio::select! {
            _ = wait_shutdown(shutdown_rx) => {
                return false;
            }
            _ = tokio::time::sleep(WAN_CHECK_INTERVAL) => {}
        }
    }
}

async fn sleep_or_shutdown(
    duration: Duration,
    shutdown_rx: &mut Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = wait_shutdown(shutdown_rx) => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

async fn sync_time() -> Result<chrono::DateTime<chrono::Utc>, String> {
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

    #[tokio::test]
    async fn test_sleep_or_shutdown_normal() {
        let (_shutdown_tx, mut shutdown_rx) = channel(false);
        // Sleep for a short duration
        let result = sleep_or_shutdown(Duration::from_millis(10), &mut shutdown_rx).await;
        assert!(result); // should return true (sleep completed)
    }

    #[tokio::test]
    async fn test_sleep_or_shutdown_triggered() {
        let (shutdown_tx, mut shutdown_rx) = channel(false);

        let handle = tokio::spawn(async move {
            sleep_or_shutdown(Duration::from_secs(10), &mut shutdown_rx).await
        });

        // Trigger shutdown
        shutdown_tx.send(true).unwrap();

        let result = handle.await.unwrap();
        assert!(!result); // should return false (shutdown triggered)
    }

    #[tokio::test]
    async fn test_wait_for_wan_ready() {
        let (_shutdown_tx, mut shutdown_rx) = channel(false);
        let wan_active = Arc::new(Mutex::new(true));

        let result = wait_for_wan(&wan_active, &mut shutdown_rx).await;
        assert!(result); // should return true instantly
    }

    #[tokio::test]
    async fn test_wait_for_wan_delayed() {
        let (_shutdown_tx, mut shutdown_rx) = channel(false);
        let wan_active = Arc::new(Mutex::new(false));
        let wan_active_clone = wan_active.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut lock = wan_active_clone.lock().unwrap();
            *lock = true;
        });

        let result = wait_for_wan(&wan_active, &mut shutdown_rx).await;
        assert!(result); // should block and then return true
    }

    #[tokio::test]
    async fn test_wait_for_wan_shutdown() {
        let (shutdown_tx, mut shutdown_rx) = channel(false);
        let wan_active = Arc::new(Mutex::new(false));

        let handle = tokio::spawn(async move { wait_for_wan(&wan_active, &mut shutdown_rx).await });

        // Trigger shutdown while waiting
        tokio::time::sleep(Duration::from_millis(10)).await;
        shutdown_tx.send(true).unwrap();

        let result = handle.await.unwrap();
        assert!(!result); // should return false on shutdown
    }
}
