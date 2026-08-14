pub mod dhcp_client;
pub mod dhcp_server;
pub mod dns_forwarder;
pub mod ipc;
pub mod lan_manager;
pub mod sntp_client;
pub mod utils;

pub use crate::network::{LAN_INTERFACE, WAN_INTERFACE};

pub const DHCP_CLIENT_SERVICE_NAME: &str = "dhcp-client";
pub const DHCP_SERVER_SERVICE_NAME: &str = "dhcp-server";
pub const DNS_FORWARDER_SERVICE_NAME: &str = "dns-forwarder";
pub const SNTP_CLIENT_SERVICE_NAME: &str = "sntp-client";

pub use utils::{CHROOT_JAIL_PATH, NOBODY_GID, NOBODY_UID, ROUTER_BINARY_PATH, SELF_EXE_PATH};

pub use dhcp_client::DhcpClient;
pub use dhcp_server::DhcpServer;
pub use dns_forwarder::DnsForwarder;
pub use ipc::{
    DhcpClientToParentMsg, DhcpServerParentToWorkerMsg, DnsParentToWorkerMsg, SntpParentToWorkerMsg,
};
pub use lan_manager::LanManager;
pub use sntp_client::SntpClient;
pub use utils::WanLease;

#[derive(Debug)]
pub enum ServiceError {
    AlreadyRunning,
    NotRunning,
    Io(std::io::Error),
    FailedToStart(String),
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::AlreadyRunning => write!(f, "Service is already running"),
            ServiceError::NotRunning => write!(f, "Service is not running"),
            ServiceError::Io(e) => write!(f, "IO error: {}", e),
            ServiceError::FailedToStart(msg) => write!(f, "Failed to start: {}", msg),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<std::io::Error> for ServiceError {
    fn from(e: std::io::Error) -> Self {
        ServiceError::Io(e)
    }
}

pub trait Service: Send + Sync {
    async fn start(&mut self) -> Result<(), ServiceError>;
    async fn stop(&mut self) -> Result<(), ServiceError>;
}

// =========================================================================
// External Worker Process Management
// =========================================================================
pub struct ExternalWorker {
    service_name: &'static str,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    child_pid: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl ExternalWorker {
    pub fn new(service_name: &'static str) -> Self {
        Self {
            service_name,
            shutdown_tx: None,
            task_handle: None,
            child_pid: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    pub(crate) fn get_worker_pid(&self) -> u32 {
        self.child_pid.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn is_running(&self) -> bool {
        self.task_handle.is_some()
    }

    fn start(
        &mut self,
        shutdown_tx: tokio::sync::watch::Sender<bool>,
        handle: tokio::task::JoinHandle<()>,
    ) {
        self.shutdown_tx = Some(shutdown_tx);
        self.task_handle = Some(handle);
    }

    pub(crate) fn start_supervised<S, M>(
        &mut self,
        mut setup_attempt: S,
        mut run_monitor: M,
    ) -> Result<(), ServiceError>
    where
        S: FnMut() -> Result<(crate::cli::WorkerService, std::os::unix::io::RawFd), ServiceError>
            + Send
            + 'static,
        M: FnMut(
                std::os::unix::io::RawFd,
                u32,
                tokio::sync::watch::Receiver<bool>,
            ) -> Result<tokio::task::JoinHandle<()>, ServiceError>
            + Send
            + 'static,
    {
        if self.is_running() {
            return Err(ServiceError::AlreadyRunning);
        }

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
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
                        eprintln!("[{}-parent] Setup attempt failed: {:?}", service_name, e);
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
                        eprintln!("[{}-parent] Spawn failed: {:?}", service_name, e);
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
                            eprintln!(
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

                // 4. Wait for monitor to complete
                let _ = monitor_handle.await;
            }
        });

        self.start(shutdown_tx, handle);
        Ok(())
    }

    pub(crate) async fn stop(&mut self) -> Result<(), ServiceError> {
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;
        let child_pid = self.child_pid.swap(0, std::sync::atomic::Ordering::SeqCst);

        let _ = tx.send(true);
        if child_pid != 0 {
            println!(
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
        child_pid: std::sync::Arc<std::sync::atomic::AtomicU32>,
        args: &[&str],
        child_fds: &[std::os::unix::io::RawFd],
    ) -> std::io::Result<std::process::Child> {
        let res = Self::spawn_process(service_name, args, child_fds);

        // Always close worker FDs in parent
        for &fd in child_fds {
            unsafe {
                let _ = libc::close(fd);
            }
        }

        match res {
            Ok(child) => {
                child_pid.store(child.id(), std::sync::atomic::Ordering::SeqCst);
                Ok(child)
            }
            Err(e) => Err(e),
        }
    }

    fn spawn_process(
        service_name: &str,
        args: &[&str],
        child_fds: &[std::os::unix::io::RawFd],
    ) -> std::io::Result<std::process::Child> {
        use std::os::unix::process::CommandExt;
        use std::path::Path;
        use std::process::Command;

        let binary_path = if Path::new(utils::ROUTER_BINARY_PATH).exists() {
            utils::ROUTER_BINARY_PATH
        } else {
            utils::SELF_EXE_PATH
        };

        let mut cmd = Command::new(binary_path);
        cmd.arg("worker");
        cmd.arg(service_name);
        for arg in args {
            cmd.arg(arg);
        }

        let fds = child_fds.to_vec();
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &fds {
                    libc::fcntl(fd, libc::F_SETFD, 0);
                }
                Ok(())
            });
        }

        cmd.spawn()
    }
}
