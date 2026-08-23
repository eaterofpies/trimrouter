pub mod dhcp_client;
pub mod dhcp_server;
pub mod dns_forwarder;
pub mod ipc;
pub mod lan_manager;
pub mod sntp_client;
pub mod utils;

use log::{error, info};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::io::RawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::watch::{self, Receiver, Sender};
use tokio::task::{self, JoinHandle};

pub use crate::network::{LAN_INTERFACE, WAN_INTERFACE};
pub use dhcp_client::DhcpClient;
pub use dhcp_server::DhcpServer;
pub use dns_forwarder::DnsForwarder;
pub use ipc::{
    DhcpClientToParentMsg, DhcpServerParentToWorkerMsg, DnsParentToWorkerMsg, SntpParentToWorkerMsg,
};
pub use lan_manager::LanManager;
pub use sntp_client::SntpClient;
pub use utils::{
    CHROOT_JAIL_PATH, NOBODY_GID, NOBODY_UID, ROUTER_BINARY_PATH, SELF_EXE_PATH, WanLease,
};

pub const DHCP_CLIENT_SERVICE_NAME: &str = "dhcp-client";
pub const DHCP_SERVER_SERVICE_NAME: &str = "dhcp-server";
pub const DNS_FORWARDER_SERVICE_NAME: &str = "dns-forwarder";
pub const SNTP_CLIENT_SERVICE_NAME: &str = "sntp-client";

#[derive(Debug)]
pub enum ServiceError {
    AlreadyRunning,
    NotRunning,
    Io(io::Error),
    FailedToStart(String),
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::AlreadyRunning => write!(f, "Service is already running"),
            ServiceError::NotRunning => write!(f, "Service is not running"),
            ServiceError::Io(e) => write!(f, "IO error: {}", e),
            ServiceError::FailedToStart(msg) => write!(f, "Failed to start: {}", msg),
        }
    }
}

impl Error for ServiceError {}

impl From<io::Error> for ServiceError {
    fn from(e: io::Error) -> Self {
        ServiceError::Io(e)
    }
}

pub trait Service: Send + Sync {
    fn start(&mut self) -> impl std::future::Future<Output = Result<(), ServiceError>> + Send;
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), ServiceError>> + Send;
}

// =========================================================================
// External Worker Process Management
// =========================================================================
pub struct ExternalWorker {
    service_name: &'static str,
    shutdown_tx: Option<Sender<bool>>,
    task_handle: Option<JoinHandle<()>>,
    child_pid: Arc<AtomicU32>,
}

impl ExternalWorker {
    pub fn new(service_name: &'static str) -> Self {
        Self {
            service_name,
            shutdown_tx: None,
            task_handle: None,
            child_pid: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn get_worker_pid(&self) -> u32 {
        self.child_pid.load(Ordering::SeqCst)
    }

    fn is_running(&self) -> bool {
        self.task_handle.is_some()
    }

    fn start(&mut self, shutdown_tx: Sender<bool>, handle: JoinHandle<()>) {
        self.shutdown_tx = Some(shutdown_tx);
        self.task_handle = Some(handle);
    }

    pub(crate) fn start_supervised<S, M>(
        &mut self,
        mut setup_attempt: S,
        mut run_monitor: M,
    ) -> Result<(), ServiceError>
    where
        S: FnMut() -> Result<(crate::cli::WorkerService, RawFd), ServiceError> + Send + 'static,
        M: FnMut(RawFd, u32, Receiver<bool>) -> Result<JoinHandle<()>, ServiceError>
            + Send
            + 'static,
    {
        if self.is_running() {
            return Err(ServiceError::AlreadyRunning);
        }

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let service_name = self.service_name;
        let child_pid_atomic = self.child_pid.clone();

        let handle = tokio::spawn(async move {
            let mut attempt = 0;
            while !*shutdown_rx.borrow() {
                if !utils::handle_supervisor_restart_delay(
                    service_name,
                    &mut attempt,
                    &mut shutdown_rx,
                )
                .await
                {
                    break;
                }

                // 1. Setup sockets and configuration
                let (worker_service, parent_ipc_fd) = match setup_attempt() {
                    Ok(res) => res,
                    Err(e) => {
                        error!("[{}-parent] Setup attempt failed: {:?}", service_name, e);
                        continue;
                    }
                };

                let (args, child_fds) = worker_service.to_args_and_child_fds();
                let arg_strs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

                // 2. Spawn and track process (handles storing PID and parent FDs cleanup)
                let child = match Self::spawn_and_track_process(
                    service_name,
                    child_pid_atomic.clone(),
                    &arg_strs,
                    &child_fds,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("[{}-parent] Spawn failed: {:?}", service_name, e);
                        unsafe {
                            let _ = libc::close(parent_ipc_fd);
                        }
                        continue;
                    }
                };

                let child_pid = child.id();

                // 3. Start supervisor monitor
                let monitor_handle =
                    match run_monitor(parent_ipc_fd, child_pid, shutdown_rx.clone()) {
                        Ok(h) => h,
                        Err(e) => {
                            error!(
                                "[{}-parent] Failed to start monitor task: {:?}",
                                service_name, e
                            );
                            let pid = nix::unistd::Pid::from_raw(child_pid as i32);
                            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                            unsafe {
                                let _ = libc::close(parent_ipc_fd);
                            }
                            continue;
                        }
                    };

                // 4. Wait for monitor to complete and reset attempt counter on sustained uptime
                let spawn_time = std::time::Instant::now();
                let _ = monitor_handle.await;
                if spawn_time.elapsed() >= std::time::Duration::from_secs(60) {
                    attempt = 0;
                }
            }
        });

        self.start(shutdown_tx, handle);
        Ok(())
    }

    pub(crate) async fn stop(&mut self) -> Result<(), ServiceError> {
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;
        let child_pid = self.child_pid.swap(0, Ordering::SeqCst);

        let _ = tx.send(true);
        if child_pid != 0 {
            info!(
                "[{}-parent] Stopping worker process PID {}",
                self.service_name, child_pid
            );
            utils::terminate_worker(child_pid).await;
        }

        let _ = handle.await;
        Ok(())
    }

    fn spawn_and_track_process(
        service_name: &'static str,
        child_pid: Arc<AtomicU32>,
        args: &[&str],
        child_fds: &[RawFd],
    ) -> io::Result<Child> {
        let res = Self::spawn_process(service_name, args, child_fds);

        // Always close worker FDs in parent
        for &fd in child_fds {
            unsafe {
                let _ = libc::close(fd);
            }
        }

        match res {
            Ok(child) => {
                child_pid.store(child.id(), Ordering::SeqCst);
                Ok(child)
            }
            Err(e) => Err(e),
        }
    }

    fn spawn_process(service_name: &str, args: &[&str], child_fds: &[RawFd]) -> io::Result<Child> {
        let binary_path = if Path::new(utils::ROUTER_BINARY_PATH).exists() {
            utils::ROUTER_BINARY_PATH
        } else {
            utils::SELF_EXE_PATH
        };

        let mut cmd = Command::new(binary_path);
        cmd.arg0("trimrouter");
        cmd.arg("worker");
        cmd.arg(service_name);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let fds = child_fds.to_vec();
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &fds {
                    libc::fcntl(fd, libc::F_SETFD, 0);
                }
                Ok(())
            });
        }

        let mut child = cmd.spawn()?;

        if let Some(stdout) = child.stdout.take() {
            stream_to_logger(stdout);
        }

        if let Some(stderr) = child.stderr.take() {
            stream_to_logger(stderr);
        }

        Ok(child)
    }
}

fn stream_to_logger<R: Read + Send + 'static>(pipe: R) {
    task::spawn_blocking(move || {
        let reader = BufReader::new(pipe);
        for line in reader.lines().map_while(Result::ok) {
            crate::logging::log_raw(&line);
        }
    });
}
