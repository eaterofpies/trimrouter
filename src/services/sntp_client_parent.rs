use super::ipc::{SntpClientToParentMsg, SntpParentToWorkerMsg, recv_msg, send_msg};
use super::utils::{SharedWanLease, terminate_worker};
use super::{Service, ServiceError};
use std::os::unix::io::RawFd;
use std::sync::Arc;

pub struct SntpClient {
    lease_state: SharedWanLease,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    child_pid: Option<u32>,
}

impl SntpClient {
    pub fn new(lease_state: SharedWanLease) -> Self {
        Self {
            lease_state,
            shutdown_tx: None,
            task_handle: None,
            child_pid: None,
        }
    }
}

fn spawn_sntp_worker_process(child_ipc_fd: RawFd) -> Result<std::process::Child, ServiceError> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let binary_path = if std::path::Path::new("/bin/trimrouter").exists() {
        "/bin/trimrouter"
    } else {
        "/proc/self/exe"
    };

    let mut cmd = Command::new(binary_path);
    cmd.arg("worker");
    cmd.arg("sntp-client");
    cmd.arg(child_ipc_fd.to_string());

    unsafe {
        cmd.pre_exec(move || {
            libc::fcntl(child_ipc_fd, libc::F_SETFD, 0);
            Ok(())
        });
    }

    cmd.spawn()
        .map_err(|e| ServiceError::FailedToStart(format!("spawn failed: {}", e)))
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

impl Service for SntpClient {
    async fn start(&mut self) -> Result<(), ServiceError> {
        if self.task_handle.is_some() {
            return Err(ServiceError::AlreadyRunning);
        }

        let (parent_ipc_socket, child_ipc_socket) = match tokio::net::UnixStream::pair() {
            Ok(pair) => pair,
            Err(e) => {
                return Err(ServiceError::FailedToStart(format!(
                    "Failed to create IPC socketpair: {}",
                    e
                )));
            }
        };

        use std::os::unix::io::IntoRawFd;
        let child_ipc_fd = child_ipc_socket
            .into_std()
            .map_err(ServiceError::Io)?
            .into_raw_fd();
        let parent_ipc_fd = parent_ipc_socket
            .into_std()
            .map_err(ServiceError::Io)?
            .into_raw_fd();

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let child = match spawn_sntp_worker_process(child_ipc_fd) {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    libc::close(child_ipc_fd);
                    libc::close(parent_ipc_fd);
                }
                return Err(e);
            }
        };

        unsafe {
            libc::close(child_ipc_fd);
        }

        let child_pid = child.id();
        let handle = start_parent_sntp_monitor(
            parent_ipc_fd,
            child_pid,
            self.lease_state.clone(),
            shutdown_rx,
        )?;

        self.child_pid = Some(child_pid);
        self.task_handle = Some(handle);
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), ServiceError> {
        let child_pid = self.child_pid.take().ok_or(ServiceError::NotRunning)?;
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;

        println!(
            "[sntp-client-parent] Stopping SNTP worker process PID {}",
            child_pid
        );
        let _ = tx.send(true);
        terminate_worker(child_pid).await;

        let _ = handle.await;
        Ok(())
    }
}
