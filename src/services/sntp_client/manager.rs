use crate::services::ipc::{
    SntpClientToParentMsg, SntpParentToWorkerMsg, async_unix_stream, recv_msg, send_msg,
};
use crate::services::supervisor::{ExternalWorker, Service, ServiceError};
use crate::services::utils::{WanLeaseReceiver, create_ipc_fds, terminate_worker};
use log::{error, info};
use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_settime};
use std::io::Error as IoError;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;
use tokio::sync::watch::Receiver;
use tokio::task::JoinHandle;

pub struct SntpClient {
    lease_rx: WanLeaseReceiver,
    state: ExternalWorker,
}

impl SntpClient {
    pub fn new(lease_rx: WanLeaseReceiver) -> Self {
        Self {
            lease_rx,
            state: ExternalWorker::new("sntp-client"),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
}

async fn run_wan_status_monitor(
    mut lease_rx: WanLeaseReceiver,
    shared_ipc_writer: Arc<Mutex<OwnedWriteHalf>>,
    mut shutdown_rx: Receiver<bool>,
) {
    let mut last_wan_status = false;

    // 1. Initial sync on startup
    {
        let has_wan = lease_rx.borrow_and_update().ip.is_some();
        if has_wan {
            let _ = update_wan_status(&shared_ipc_writer, true).await;
            last_wan_status = true;
        }
    }

    // 2. Reactive loop: wake up immediately when WAN lease updates
    while !*shutdown_rx.borrow() {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            res = lease_rx.changed() => {
                if res.is_err() {
                    break;
                }
                let has_wan = lease_rx.borrow_and_update().ip.is_some();
                if has_wan != last_wan_status {
                    if update_wan_status(&shared_ipc_writer, has_wan).await.is_err() {
                        break;
                    }
                    last_wan_status = has_wan;
                }
            }
        }
    }
}

async fn update_wan_status(
    shared_ipc_writer: &Arc<Mutex<OwnedWriteHalf>>,
    has_wan: bool,
) -> Result<(), IoError> {
    let msg = SntpParentToWorkerMsg::SetWanStatus { active: has_wan };
    let mut writer = shared_ipc_writer.lock().await;
    send_msg(&mut *writer, &msg).await
}

async fn run_parent_ipc_receiver(
    mut ipc_reader: OwnedReadHalf,
    child_pid: u32,
    mut shutdown_rx: Receiver<bool>,
) {
    info!(
        "[sntp-client-parent] Supervising SNTP client worker (PID {})",
        child_pid
    );

    while !*shutdown_rx.borrow() {
        tokio::select! {
            _ = shutdown_rx.changed() => {}
            res = recv_msg::<SntpClientToParentMsg, _>(&mut ipc_reader) => {
                if !handle_parent_ipc_message(res).await {
                    break;
                }
            }
        }
    }

    terminate_worker(child_pid).await;
}

async fn handle_parent_ipc_message(res: Result<Option<SntpClientToParentMsg>, IoError>) -> bool {
    match res {
        Ok(Some(SntpClientToParentMsg::SetSystemTime {
            seconds,
            nanoseconds,
        })) => {
            set_system_clock(seconds, nanoseconds);
            true
        }
        Ok(None) => {
            info!("[sntp-client-parent] Worker IPC socket closed.");
            false
        }
        Err(e) => {
            error!("[sntp-client-parent] IPC recv error: {}", e);
            false
        }
    }
}

fn set_system_clock(seconds: i64, nanoseconds: i64) {
    let timespec = TimeSpec::new(seconds, nanoseconds);
    if let Err(e) = clock_settime(ClockId::CLOCK_REALTIME, timespec) {
        error!("[sntp-client-parent] Failed to set system clock: {}", e);
    } else {
        info!("[sntp-client-parent] Successfully set system clock.");
    }
}

fn start_parent_sntp_monitor(
    parent_ipc_fd: OwnedFd,
    child_pid: u32,
    lease_rx: WanLeaseReceiver,
    shutdown_rx: Receiver<bool>,
) -> Result<JoinHandle<()>, ServiceError> {
    let ipc_stream = async_unix_stream(parent_ipc_fd).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(Mutex::new(ipc_writer));

    // Spawn WAN status monitor task
    let shutdown_rx_clone = shutdown_rx.clone();
    tokio::spawn(run_wan_status_monitor(
        lease_rx,
        shared_ipc_writer,
        shutdown_rx_clone,
    ));

    // Spawn parent IPC message receiver task
    let handle = tokio::spawn(run_parent_ipc_receiver(ipc_reader, child_pid, shutdown_rx));
    Ok(handle)
}

fn setup_sntp_attempt() -> Result<(crate::cli::WorkerService, OwnedFd), ServiceError> {
    let (parent_ipc, child_ipc) = create_ipc_fds()?;
    Ok((
        crate::cli::WorkerService::SntpClient {
            ipc_fd: child_ipc.into(),
        },
        parent_ipc,
    ))
}

impl Service for SntpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let lease_rx = self.lease_rx.clone();

        self.state.start_supervised(
            setup_sntp_attempt,
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                start_parent_sntp_monitor(parent_ipc_fd, child_pid, lease_rx.clone(), shutdown_rx)
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}
