use crate::services::utils;
use log::{error, info};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::watch::{self, Receiver, Sender};
use tokio::task::{self, JoinHandle};

pub const DHCP_CLIENT_SERVICE_NAME: &str = "dhcp-client";
pub const DHCP_SERVER_SERVICE_NAME: &str = "dhcp-server";
pub const DNS_FORWARDER_SERVICE_NAME: &str = "dns-forwarder";
pub const SNTP_CLIENT_SERVICE_NAME: &str = "sntp-client";
pub const LAN_MANAGER_SERVICE_NAME: &str = "lan-manager";
pub const INTERFACE_MONITOR_SERVICE_NAME: &str = "interface-monitor";

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
// Service Controller
// =========================================================================
#[derive(Default)]
pub struct ServiceController {
    shutdown_tx: Option<Sender<bool>>,
    task_handle: Option<JoinHandle<()>>,
}

impl ServiceController {
    pub const fn new() -> Self {
        Self {
            shutdown_tx: None,
            task_handle: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.task_handle.is_some()
    }

    pub fn start<F, Fut>(&mut self, spawn_fn: F) -> Result<(), ServiceError>
    where
        F: FnOnce(Receiver<bool>) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        if self.is_running() {
            return Err(ServiceError::AlreadyRunning);
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(spawn_fn(shutdown_rx));
        self.shutdown_tx = Some(shutdown_tx);
        self.task_handle = Some(handle);
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ServiceError> {
        let handle = self.task_handle.take().ok_or(ServiceError::NotRunning)?;
        let tx = self.shutdown_tx.take().ok_or(ServiceError::NotRunning)?;
        let _ = tx.send(true);
        let _ = handle.await;
        Ok(())
    }
}

// =========================================================================
// External Worker Process Management
// =========================================================================
pub struct ExternalWorker {
    service_name: &'static str,
    controller: ServiceController,
    child_pid: Arc<AtomicU32>,
}

impl ExternalWorker {
    pub fn new(service_name: &'static str) -> Self {
        Self {
            service_name,
            controller: ServiceController::new(),
            child_pid: Arc::new(AtomicU32::new(0)),
        }
    }

    pub(crate) fn get_worker_pid(&self) -> u32 {
        self.child_pid.load(Ordering::SeqCst)
    }

    async fn attempt_supervised_run<S, M>(
        service_name: &'static str,
        child_pid_atomic: Arc<AtomicU32>,
        setup_attempt: &mut S,
        run_monitor: &mut M,
        shutdown_rx: &Receiver<bool>,
        attempt: &mut u32,
    ) where
        S: FnMut() -> Result<(crate::cli::WorkerService, OwnedFd), ServiceError>,
        M: FnMut(OwnedFd, u32, Receiver<bool>) -> Result<JoinHandle<()>, ServiceError>,
    {
        let (worker_service, parent_ipc_fd) = match setup_attempt() {
            Ok(res) => res,
            Err(e) => {
                error!("[{}-parent] Setup attempt failed: {:?}", service_name, e);
                return;
            }
        };

        let args = worker_service.to_args();
        let arg_strs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let child_fds = worker_service.child_fds();

        let child = match Self::spawn_and_track_process(
            service_name,
            child_pid_atomic,
            &arg_strs,
            &child_fds,
        ) {
            Ok(c) => c,
            Err(e) => {
                error!("[{}-parent] Spawn failed: {:?}", service_name, e);
                return;
            }
        };
        drop(worker_service);

        let child_pid = child.id();
        let monitor_handle = match run_monitor(parent_ipc_fd, child_pid, shutdown_rx.clone()) {
            Ok(h) => h,
            Err(e) => {
                error!(
                    "[{}-parent] Failed to start monitor task: {:?}",
                    service_name, e
                );
                utils::terminate_worker(child_pid).await;
                return;
            }
        };

        let spawn_time = Instant::now();
        let _ = monitor_handle.await;
        if spawn_time.elapsed() >= Duration::from_secs(60) {
            *attempt = 0;
        }
    }

    pub(crate) fn start_supervised<S, M>(
        &mut self,
        mut setup_attempt: S,
        mut run_monitor: M,
    ) -> Result<(), ServiceError>
    where
        S: FnMut() -> Result<(crate::cli::WorkerService, OwnedFd), ServiceError> + Send + 'static,
        M: FnMut(OwnedFd, u32, Receiver<bool>) -> Result<JoinHandle<()>, ServiceError>
            + Send
            + 'static,
    {
        let service_name = self.service_name;
        let child_pid_atomic = self.child_pid.clone();

        self.controller.start(move |mut shutdown_rx| async move {
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

                Self::attempt_supervised_run(
                    service_name,
                    child_pid_atomic.clone(),
                    &mut setup_attempt,
                    &mut run_monitor,
                    &shutdown_rx,
                    &mut attempt,
                )
                .await;
            }
        })
    }

    pub(crate) async fn stop(&mut self) -> Result<(), ServiceError> {
        let child_pid = self.child_pid.swap(0, Ordering::SeqCst);
        if child_pid != 0 {
            info!(
                "[{}-parent] Stopping worker process PID {}",
                self.service_name, child_pid
            );
            utils::terminate_worker(child_pid).await;
        }

        self.controller.stop().await
    }

    fn spawn_and_track_process(
        service_name: &'static str,
        child_pid: Arc<AtomicU32>,
        args: &[&str],
        child_fds: &[BorrowedFd<'_>],
    ) -> io::Result<Child> {
        let child = Self::spawn_process(service_name, args, child_fds)?;
        child_pid.store(child.id(), Ordering::SeqCst);
        Ok(child)
    }

    pub(crate) fn spawn_process(
        service_name: &str,
        args: &[&str],
        child_fds: &[BorrowedFd<'_>],
    ) -> io::Result<Child> {
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

        let raw_fds: Vec<RawFd> = child_fds.iter().map(|fd| fd.as_raw_fd()).collect();
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &raw_fds {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_error_display_and_from_io() {
        let err_already = ServiceError::AlreadyRunning;
        assert_eq!(err_already.to_string(), "Service is already running");

        let err_not_running = ServiceError::NotRunning;
        assert_eq!(err_not_running.to_string(), "Service is not running");

        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "socket dropped");
        let err_io = ServiceError::from(io_err);
        assert!(err_io.to_string().contains("IO error: socket dropped"));

        let err_failed = ServiceError::FailedToStart("missing executable".to_string());
        assert_eq!(
            err_failed.to_string(),
            "Failed to start: missing executable"
        );
    }

    #[tokio::test]
    async fn test_service_controller_lifecycle_and_error_states() {
        let mut controller = ServiceController::new();
        assert!(!controller.is_running());

        // Stopping a non-running controller returns NotRunning
        let stop_res = controller.stop().await;
        assert!(matches!(stop_res, Err(ServiceError::NotRunning)));

        // Start controller
        let start_res = controller.start(|mut shutdown_rx| async move {
            let _ = shutdown_rx.changed().await;
        });
        assert!(start_res.is_ok());
        assert!(controller.is_running());

        // Starting an already-running controller returns AlreadyRunning
        let double_start = controller.start(|_| async {});
        assert!(matches!(double_start, Err(ServiceError::AlreadyRunning)));

        // Stop running controller
        let stop_res = controller.stop().await;
        assert!(stop_res.is_ok());
        assert!(!controller.is_running());

        // Stopping again returns NotRunning
        let stop_again = controller.stop().await;
        assert!(matches!(stop_again, Err(ServiceError::NotRunning)));
    }

    #[test]
    fn test_external_worker_initial_pid() {
        let worker = ExternalWorker::new("test-worker");
        assert_eq!(worker.get_worker_pid(), 0);
    }

    #[tokio::test]
    async fn test_external_worker_start_supervised_lifecycle() {
        let mut worker = ExternalWorker::new("test-worker");

        let res = worker.start_supervised(
            || Err(ServiceError::FailedToStart("test failure".to_string())),
            |_fd, _pid, _shutdown| Ok(tokio::spawn(async {})),
        );
        assert!(res.is_ok());

        let stop_res = worker.stop().await;
        assert!(stop_res.is_ok());
    }
}
