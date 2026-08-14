use super::ipc::{SntpClientToParentMsg, SntpParentToWorkerMsg, recv_msg, send_msg};
use super::utils::{SharedWanLease, create_ipc_fds};
use super::{ExternalWorker, Service, ServiceError};
use std::os::unix::io::RawFd;
use std::sync::Arc;

pub struct SntpClient {
    lease_state: SharedWanLease,
    state: ExternalWorker,
}

impl SntpClient {
    pub fn new(lease_state: SharedWanLease) -> Self {
        Self {
            lease_state,
            state: ExternalWorker::new("sntp-client"),
        }
    }

    pub fn get_worker_pid(&self) -> u32 {
        self.state.get_worker_pid()
    }
}

async fn run_wan_status_monitor(
    lease_state: SharedWanLease,
    shared_ipc_writer: Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let mut last_wan_status = false;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    while !*shutdown_rx.borrow() {
        tokio::select! {
            _ = shutdown_rx.changed() => {}
            _ = interval.tick() => {
                let has_wan = lease_state.lock().unwrap().ip.is_some();
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
    shared_ipc_writer: &Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    has_wan: bool,
) -> Result<(), std::io::Error> {
    let msg = SntpParentToWorkerMsg::SetWanStatus { active: has_wan };
    let mut writer = shared_ipc_writer.lock().await;
    send_msg(&mut *writer, &msg).await
}

async fn run_parent_ipc_receiver(
    mut ipc_reader: tokio::net::unix::OwnedReadHalf,
    child_pid: u32,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    println!(
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

    let pid = nix::unistd::Pid::from_raw(child_pid as i32);
    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
}

async fn handle_parent_ipc_message(
    res: Result<Option<SntpClientToParentMsg>, std::io::Error>,
) -> bool {
    match res {
        Ok(Some(SntpClientToParentMsg::SetSystemTime {
            seconds,
            nanoseconds,
        })) => {
            set_system_clock(seconds, nanoseconds);
            true
        }
        Ok(None) => {
            println!("[sntp-client-parent] Worker IPC socket closed.");
            false
        }
        Err(e) => {
            eprintln!("[sntp-client-parent] IPC recv error: {}", e);
            false
        }
    }
}

fn set_system_clock(seconds: i64, nanoseconds: i64) {
    let timespec = nix::sys::time::TimeSpec::new(seconds, nanoseconds);
    if let Err(e) = nix::time::clock_settime(nix::time::ClockId::CLOCK_REALTIME, timespec) {
        eprintln!(
            "[sntp-client-parent] ERROR: Failed to set system clock: {}",
            e
        );
    } else {
        println!("[sntp-client-parent] Successfully set system clock.");
    }
}

fn start_parent_sntp_monitor(
    parent_ipc_fd: RawFd,
    child_pid: u32,
    lease_state: SharedWanLease,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>, ServiceError> {
    use std::os::unix::io::FromRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    let std_stream = unsafe { StdUnixStream::from_raw_fd(parent_ipc_fd) };
    std_stream.set_nonblocking(true).map_err(ServiceError::Io)?;
    let ipc_stream = tokio::net::UnixStream::from_std(std_stream).map_err(ServiceError::Io)?;
    let (ipc_reader, ipc_writer) = ipc_stream.into_split();
    let shared_ipc_writer = Arc::new(tokio::sync::Mutex::new(ipc_writer));

    // Spawn WAN status monitor task
    let shutdown_rx_clone = shutdown_rx.clone();
    tokio::spawn(run_wan_status_monitor(
        lease_state,
        shared_ipc_writer,
        shutdown_rx_clone,
    ));

    // Spawn parent IPC message receiver task
    let handle = tokio::spawn(run_parent_ipc_receiver(ipc_reader, child_pid, shutdown_rx));
    Ok(handle)
}

fn setup_sntp_attempt() -> Result<(crate::cli::WorkerService, RawFd), ServiceError> {
    let (parent_ipc_fd, child_ipc_fd) = create_ipc_fds()?;
    Ok((
        crate::cli::WorkerService::SntpClient {
            ipc_fd: child_ipc_fd,
        },
        parent_ipc_fd,
    ))
}

impl Service for SntpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        let lease_state = self.lease_state.clone();

        self.state.start_supervised(
            setup_sntp_attempt,
            move |parent_ipc_fd, child_pid, shutdown_rx| {
                start_parent_sntp_monitor(
                    parent_ipc_fd,
                    child_pid,
                    lease_state.clone(),
                    shutdown_rx,
                )
            },
        )
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        self.state.stop().await
    }
}
