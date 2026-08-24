use crate::cli::WorkerService;
use crate::services::ipc::{SntpClientToParentMsg, async_unix_stream, recv_msg};
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{WanLeaseReceiver, create_ipc_fds, terminate_worker};
use log::{error, info};
use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_settime};
use tokio::net::unix::OwnedReadHalf;
use tokio::sync::watch::{Receiver, Sender, channel};
use tokio::task::JoinHandle;

pub struct SntpClient {
    lease_rx: WanLeaseReceiver,
    shutdown_tx: Option<Sender<bool>>,
    task_handle: Option<JoinHandle<()>>,
}

impl SntpClient {
    pub fn new(lease_rx: WanLeaseReceiver) -> Self {
        Self {
            lease_rx,
            shutdown_tx: None,
            task_handle: None,
        }
    }
}

async fn run_sntp_manager_loop(mut lease_rx: WanLeaseReceiver, mut shutdown_rx: Receiver<bool>) {
    let mut active_child: Option<(u32, OwnedReadHalf)> = None;

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
                } else if !has_wan && let Some((pid, _)) = active_child.take() {
                    info!("[sntp-client-parent] WAN lease lost. Stopping worker.");
                    terminate_worker(pid).await;
                }
            }

            // Branch B: Process IPC time updates from child (only active when child is running)
            msg = async {
                match active_child.as_mut() {
                    Some((_, reader)) => recv_msg::<SntpClientToParentMsg, _>(reader).await,
                    None => std::future::pending().await,
                }
            } => {
                match msg {
                    Ok(Some(SntpClientToParentMsg::SetSystemTime { seconds, nanoseconds })) => {
                        set_system_clock(seconds, nanoseconds);
                    }
                    _ => {
                        if let Some((pid, _)) = active_child.take() {
                            terminate_worker(pid).await;
                        }
                    }
                }
            }
        }
    }

    if let Some((pid, _)) = active_child.take() {
        terminate_worker(pid).await;
    }
}

fn spawn_sntp_worker() -> Result<(u32, OwnedReadHalf), ServiceError> {
    let (parent_ipc, child_ipc) = create_ipc_fds()?;
    let ipc_stream = async_unix_stream(parent_ipc).map_err(ServiceError::Io)?;
    let (ipc_reader, _) = ipc_stream.into_split();

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
    Ok((child_pid, ipc_reader))
}

fn set_system_clock(seconds: i64, nanoseconds: i64) {
    let timespec = TimeSpec::new(seconds, nanoseconds);
    if let Err(e) = clock_settime(ClockId::CLOCK_REALTIME, timespec) {
        error!("[sntp-client-parent] Failed to set system clock: {}", e);
    } else {
        info!("[sntp-client-parent] Successfully set system clock.");
    }
}

impl Service for SntpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let (shutdown_tx, shutdown_rx) = channel(false);
        let lease_rx = self.lease_rx.clone();

        let handle = tokio::spawn(async move {
            run_sntp_manager_loop(lease_rx, shutdown_rx).await;
        });

        self.shutdown_tx = Some(shutdown_tx);
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
        Ok(())
    }
}
