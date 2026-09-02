use super::system::ProcessOps;
use log::{debug, error, warn};
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, sleep};

async fn fallback_polling_reaper<S: ProcessOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    while !shutdown_flag.load(Ordering::Relaxed) {
        reap_zombies(sys.as_ref());
        sleep(Duration::from_millis(500)).await;
    }
}

pub async fn start_orphan_reaper<S: ProcessOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    debug!("[reaper] Starting orphan process reaper task...");

    let mut sigchld_stream = match signal(SignalKind::child()) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "[reaper] Error creating SIGCHLD stream: {}. Falling back to polling.",
                e
            );
            fallback_polling_reaper(sys, shutdown_flag).await;
            return;
        }
    };

    while !shutdown_flag.load(Ordering::Relaxed) {
        tokio::select! {
            _ = sigchld_stream.recv() => {
                reap_zombies(sys.as_ref());
            }
            _ = sleep(Duration::from_secs(5)) => {
                reap_zombies(sys.as_ref());
            }
        }
    }
}

fn try_reap_zombie<S: ProcessOps>(sys: &S) -> bool {
    match sys.waitpid(Some(Pid::from_raw(-1)), Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::Exited(pid, code)) => {
            debug!(
                "[reaper] Reaped child process (PID {}) which exited with status {}",
                pid, code
            );
            true
        }
        Ok(WaitStatus::Signaled(pid, sig, _)) => {
            warn!(
                "[reaper] Reaped child process (PID {}) which terminated with signal {}",
                pid, sig
            );
            true
        }
        Ok(WaitStatus::StillAlive) => false,
        Err(nix::Error::ECHILD) => false,
        Err(e) => {
            error!("[reaper] waitpid error: {}", e);
            false
        }
        _ => false,
    }
}

pub fn reap_zombies<S: ProcessOps>(sys: &S) {
    loop {
        if !try_reap_zombie(sys) {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::system::mock::MockSystem;

    #[test]
    fn test_zombie_reaping() {
        let sys = MockSystem::new();

        {
            let mut results = sys.waitpid_results.lock().unwrap();
            results.push(Ok(WaitStatus::Exited(Pid::from_raw(42), 0)));
            results.push(Ok(WaitStatus::Signaled(
                Pid::from_raw(43),
                nix::sys::signal::Signal::SIGKILL,
                false,
            )));
            results.push(Err(nix::Error::ECHILD));
        }

        reap_zombies(&sys);

        let results = sys.waitpid_results.lock().unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_try_reap_zombie_statuses() {
        let sys = MockSystem::new();

        // StillAlive returns false
        sys.waitpid_results
            .lock()
            .unwrap()
            .push(Ok(WaitStatus::StillAlive));
        assert!(!try_reap_zombie(&sys));

        // Unexpected error (e.g. EINVAL) returns false
        sys.waitpid_results
            .lock()
            .unwrap()
            .push(Err(nix::Error::EINVAL));
        assert!(!try_reap_zombie(&sys));

        // Other status (e.g. Stopped) returns false
        sys.waitpid_results
            .lock()
            .unwrap()
            .push(Ok(WaitStatus::Stopped(
                Pid::from_raw(100),
                nix::sys::signal::Signal::SIGSTOP,
            )));
        assert!(!try_reap_zombie(&sys));
    }

    #[tokio::test]
    async fn test_fallback_polling_reaper_stops_on_flag() {
        let sys = Arc::new(MockSystem::new());
        let shutdown = Arc::new(AtomicBool::new(false));

        let sys_clone = Arc::clone(&sys);
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = tokio::spawn(async move {
            fallback_polling_reaper(sys_clone, shutdown_clone).await;
        });

        // Set shutdown flag and wait for reaper to stop cleanly
        shutdown.store(true, Ordering::Relaxed);
        let res = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(res.is_ok());
    }
}
