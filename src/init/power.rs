use super::system::PowerOps;
use log::{debug, info, warn};
use nix::sys::reboot::RebootMode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, sleep};

pub async fn start_signal_monitor<S: PowerOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    debug!("[init] Starting system signal monitor...");

    let mut sigint = signal(SignalKind::interrupt()).expect("Failed to bind SIGINT");
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to bind SIGTERM");
    let mut sigpwr = signal(SignalKind::from_raw(libc::SIGPWR)).expect("Failed to bind SIGPWR");

    let received_signal = tokio::select! {
        _ = sigint.recv() => "SIGINT (Interrupt)",
        _ = sigterm.recv() => "SIGTERM (Termination)",
        _ = sigpwr.recv() => "SIGPWR (Power Down)",
    };

    info!("[init] Received system signal: {}", received_signal);
    info!("[init] Performing clean shutdown...");

    shutdown_flag.store(true, Ordering::Relaxed);

    // Placeholder for interface and firewall teardown
    info!("[init] Tearing down interfaces and rules...");

    sleep(Duration::from_millis(500)).await;

    info!("[init] Executing system poweroff...");
    crate::logging::flush();
    if let Err(e) = sys.reboot(RebootMode::RB_POWER_OFF) {
        warn!(
            "[init] Poweroff failed: {}. Falling back to default reboot.",
            e
        );
        let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
    }
}
