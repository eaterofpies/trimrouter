use super::utils::{WanLease, wait_shutdown};
use super::{Service, ServiceError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SYNC_INTERVAL: Duration = Duration::from_secs(1800); // 30 minutes
const RETRY_INTERVAL: Duration = Duration::from_secs(60); // 60 seconds

const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(900); // 15 minutes

const NTP_PORT: u16 = 123;
const WAN_CHECK_INTERVAL: Duration = Duration::from_secs(5);

pub struct SntpClient {
    lease_state: Arc<Mutex<WanLease>>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl SntpClient {
    pub fn new(lease_state: Arc<Mutex<WanLease>>) -> Self {
        Self {
            lease_state,
            shutdown_tx: None,
            task_handle: None,
        }
    }
}


impl Service for SntpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        if self.task_handle.is_some() {
            return Err(ServiceError::AlreadyRunning);
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let lease_state = self.lease_state.clone();
        let handle = tokio::spawn(async move {
            run_sntp_loop(lease_state, shutdown_rx).await;
        });
        self.task_handle = Some(handle);

        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;

        let _ = tx.send(true);
        let _ = handle.await;
        Ok(())
    }
}

async fn run_sntp_loop(
    lease_state: Arc<Mutex<WanLease>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    println!("[sntp-client] Starting NTP time synchronization service...");

    let mut current_retry_delay = RETRY_INTERVAL;

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        if !wait_for_wan(&lease_state, &mut shutdown_rx).await {
            break;
        }

        let sync_res = tokio::select! {
            _ = wait_shutdown(&mut shutdown_rx) => {
                break;
            }
            res = sync_time() => res,
        };

        match sync_res {
            Ok(time_now) => {
                println!(
                    "[sntp-client] Successfully synchronized system time: {}",
                    time_now
                );
                current_retry_delay = RETRY_INTERVAL;
                if !sleep_or_shutdown(SYNC_INTERVAL, &mut shutdown_rx).await {
                    break;
                }
            }
            Err(e) => {
                eprintln!(
                    "[sntp-client] Time synchronization failed: {}. Retrying in {}s...",
                    e,
                    current_retry_delay.as_secs()
                );
                if !sleep_or_shutdown(current_retry_delay, &mut shutdown_rx).await {
                    break;
                }
                current_retry_delay = std::cmp::min(current_retry_delay * 2, MAX_RETRY_INTERVAL);
            }
        }
    }
}

async fn wait_for_wan(
    lease_state: &Arc<Mutex<WanLease>>,
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    loop {
        let has_wan = {
            let lease = lease_state.lock().unwrap();
            lease.ip.is_some()
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
    shutdown_rx: &mut tokio::sync::watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = wait_shutdown(shutdown_rx) => false,
        _ = tokio::time::sleep(duration) => true,
    }
}

async fn sync_time() -> Result<chrono::DateTime<chrono::Utc>, String> {
    // Resolve pool.ntp.org manually via local DNS forwarder
    let ntp_server_ip = super::utils::resolve_dns_a_record("pool.ntp.org").await?;
    let ntp_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(ntp_server_ip), NTP_PORT);

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

    let duration = chrono_dt.signed_duration_since(chrono::DateTime::UNIX_EPOCH);
    let timespec = nix::sys::time::TimeSpec::from(duration.to_std().unwrap());
    nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, timespec)
        .map_err(|e| format!("Failed to set system clock: {}", e))?;

    Ok(chrono_dt)
}
