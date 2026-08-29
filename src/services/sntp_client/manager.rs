use crate::cli::WorkerService;
use crate::services::ipc::{SntpClientToParentMsg, async_unix_stream, recv_msg};
use crate::services::supervisor::{ExternalWorker, Service, ServiceController, ServiceError};
use crate::services::utils::{WanLeaseReceiver, create_ipc_fds, terminate_worker};
use log::{error, info, warn};
use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_settime};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::watch::Receiver;

const MIN_SANE_EPOCH_SECS: i64 = 1_700_000_000; // ~Nov 2023
const MAX_SANE_EPOCH_SECS: i64 = 4_102_444_800; // Jan 1, 2100
const NANOS_PER_SEC: i64 = 1_000_000_000;

pub struct SntpClient {
    lease_rx: WanLeaseReceiver,
    controller: ServiceController,
}

impl SntpClient {
    pub fn new(lease_rx: WanLeaseReceiver) -> Self {
        Self {
            lease_rx,
            controller: ServiceController::new(),
        }
    }
}

async fn run_sntp_manager_loop(mut lease_rx: WanLeaseReceiver, mut shutdown_rx: Receiver<bool>) {
    let mut active_child: Option<(u32, OwnedReadHalf, OwnedWriteHalf)> = None;

    // 1. Initial check on startup
    if lease_rx.borrow_and_update().ip.is_some() {
        active_child = spawn_sntp_worker().ok();
    }

    // 2. Single unified event loop
    while !*shutdown_rx.borrow() {
        tokio::select! {
            _ = shutdown_rx.changed() => break,

            // Branch A: React to WAN lease changes
            res = lease_rx.changed() => {
                if res.is_err() {
                    break;
                }
                let has_wan = lease_rx.borrow_and_update().ip.is_some();
                if has_wan && active_child.is_none() {
                    info!("[sntp-client-parent] WAN lease acquired. Spawning worker.");
                    active_child = spawn_sntp_worker().ok();
                } else if !has_wan && let Some((pid, _, _)) = active_child.take() {
                    info!("[sntp-client-parent] WAN lease lost. Stopping worker.");
                    terminate_worker(pid).await;
                }
            }

            // Branch B: Process IPC time updates from child (only active when child is running)
            msg = async {
                match active_child.as_mut() {
                    Some((_, reader, _)) => recv_msg::<SntpClientToParentMsg, _>(reader).await,
                    None => std::future::pending().await,
                }
            } => {
                match msg {
                    Ok(Some(SntpClientToParentMsg::SetSystemTime { seconds, nanoseconds })) => {
                        set_system_clock(seconds, nanoseconds);
                    }
                    _ => {
                        if let Some((pid, _, _)) = active_child.take() {
                            terminate_worker(pid).await;
                        }
                    }
                }
            }
        }
    }

    if let Some((pid, _, _)) = active_child.take() {
        terminate_worker(pid).await;
    }
}

fn spawn_sntp_worker() -> Result<(u32, OwnedReadHalf, OwnedWriteHalf), ServiceError> {
    let (parent_ipc, child_ipc) = create_ipc_fds()?;
    let ipc_stream = async_unix_stream(parent_ipc).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();

    let worker_service = WorkerService::SntpClient {
        ipc_fd: child_ipc.into(),
    };
    let args = worker_service.to_args();
    let arg_strs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let child_fds = worker_service.child_fds();

    let child = ExternalWorker::spawn_process("sntp-client", &arg_strs, &child_fds)
        .map_err(ServiceError::Io)?;
    let child_pid = child.id();

    info!(
        "[sntp-client-parent] Spawned SNTP worker process PID {}",
        child_pid
    );
    Ok((child_pid, ipc_reader, ipc_writer))
}

fn set_system_clock(seconds: i64, nanoseconds: i64) {
    if !is_valid_system_time(seconds, nanoseconds) {
        warn!(
            "[sntp-client-parent] Rejecting invalid/insane system time: seconds={}, nanoseconds={}",
            seconds, nanoseconds
        );
        return;
    }
    let timespec = TimeSpec::new(seconds as _, nanoseconds as _);
    if let Err(e) = clock_settime(ClockId::CLOCK_REALTIME, timespec) {
        error!("[sntp-client-parent] Failed to set system clock: {}", e);
    } else {
        info!("[sntp-client-parent] Successfully set system clock.");
    }
}

fn is_valid_system_time(seconds: i64, nanoseconds: i64) -> bool {
    (MIN_SANE_EPOCH_SECS..=MAX_SANE_EPOCH_SECS).contains(&seconds)
        && (0..NANOS_PER_SEC).contains(&nanoseconds)
}

impl Service for SntpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let lease_rx = self.lease_rx.clone();
        self.controller.start(|shutdown_rx| async move {
            run_sntp_manager_loop(lease_rx, shutdown_rx).await;
        })
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.controller.stop().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_system_time_valid_bounds() {
        // Year 2024 timestamp (~1.72 billion)
        assert!(is_valid_system_time(1_720_000_000, 0));
        // Year 2033 timestamp (~2.0 billion)
        assert!(is_valid_system_time(2_011_000_000, 500_000_000));
        // Max valid boundary (Jan 1, 2100)
        assert!(is_valid_system_time(MAX_SANE_EPOCH_SECS, 999_999_999));
        // Min valid boundary (~Nov 2023)
        assert!(is_valid_system_time(MIN_SANE_EPOCH_SECS, 0));
    }

    #[test]
    fn test_is_valid_system_time_rejects_insane_timestamps() {
        // Pre-2023 or 1970 timestamp (CVE-2015-5300 time warp / TLS invalidation attack)
        assert!(!is_valid_system_time(0, 0));
        assert!(!is_valid_system_time(-100, 0));
        assert!(!is_valid_system_time(1_000_000_000, 0)); // Year 2001

        // Far future timestamp (beyond year 2100)
        assert!(!is_valid_system_time(5_000_000_000, 0));
        assert!(!is_valid_system_time(i64::MAX, 0));

        // Invalid nanoseconds (>= 1_000_000_000 or negative)
        assert!(!is_valid_system_time(1_720_000_000, 1_000_000_000));
        assert!(!is_valid_system_time(1_720_000_000, -1));
    }
}
