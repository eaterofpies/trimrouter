use super::system::PowerOps;
use futures_util::StreamExt;
use log::{debug, error, info, warn};
use nix::sys::reboot::RebootMode;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, sleep};

const MAX_INPUT_EVENT_DEVICES: usize = 32;
const ACPI_DEVICE_SCAN_INTERVAL: Duration = Duration::from_secs(2);
const SIGNAL_SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_millis(500);

pub fn is_power_event(event_type: evdev::EventType, code: u16, value: i32) -> bool {
    event_type == evdev::EventType::KEY
        && (code == evdev::KeyCode::KEY_POWER.code()
            || code == evdev::KeyCode::KEY_POWER2.code()
            || code == evdev::KeyCode::KEY_SLEEP.code())
        && value == 1
}

pub async fn start_power_button_monitor<S: PowerOps + 'static>(
    sys: Arc<S>,
    shutdown_flag: Arc<AtomicBool>,
) {
    debug!("[init] Starting ACPI power button monitor loop...");
    let mut opened_devices = HashSet::new();

    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            break;
        }

        for i in 0..MAX_INPUT_EVENT_DEVICES {
            let path = format!("/dev/input/event{}", i);
            if !opened_devices.contains(&path)
                && let Ok(device) = evdev::Device::open(&path)
            {
                info!(
                    "[init] Monitoring power button input device: {} ({})",
                    path,
                    device.name().unwrap_or("Unknown")
                );
                opened_devices.insert(path);
                tokio::spawn(monitor_single_power_device(
                    device,
                    sys.clone(),
                    shutdown_flag.clone(),
                ));
            }
        }

        sleep(ACPI_DEVICE_SCAN_INTERVAL).await;
    }
}

pub fn execute_clean_poweroff<S: PowerOps>(sys: &S, source: &'static str) {
    info!("[{}] Syncing filesystems to persistent storage...", source);
    crate::logging::flush();
    sys.sync();

    info!("[{}] Executing system poweroff...", source);
    crate::logging::flush();
    if let Err(e) = sys.reboot(RebootMode::RB_POWER_OFF) {
        warn!(
            "[{}] Poweroff failed: {}. Falling back to default reboot.",
            source, e
        );
        let _ = sys.reboot(RebootMode::RB_AUTOBOOT);
    }
}

async fn monitor_single_power_device<S: PowerOps>(
    device: evdev::Device,
    sys: Arc<S>,
    shutdown_flag: Arc<AtomicBool>,
) {
    let Ok(mut stream) = device.into_event_stream() else {
        return;
    };
    while let Some(Ok(event)) = stream.next().await {
        if is_power_event(event.event_type(), event.code(), event.value()) {
            info!(
                "[acpi] Power button pressed (event code: {}). Triggering system shutdown...",
                event.code()
            );
            shutdown_flag.store(true, Ordering::Relaxed);
            execute_clean_poweroff(&*sys, "acpi");
            break;
        }
    }
}

pub async fn start_signal_monitor<S: PowerOps>(sys: Arc<S>, shutdown_flag: Arc<AtomicBool>) {
    debug!("[init] Starting system signal monitor...");

    let Ok(mut sigint) = signal(SignalKind::interrupt()) else {
        error!("[init] Failed to bind SIGINT");
        return;
    };
    let Ok(mut sigterm) = signal(SignalKind::terminate()) else {
        error!("[init] Failed to bind SIGTERM");
        return;
    };
    let Ok(mut sigpwr) = signal(SignalKind::from_raw(libc::SIGPWR)) else {
        error!("[init] Failed to bind SIGPWR");
        return;
    };

    let received_signal = tokio::select! {
        _ = sigint.recv() => "SIGINT (Interrupt)",
        _ = sigterm.recv() => "SIGTERM (Termination)",
        _ = sigpwr.recv() => "SIGPWR (Power Down)",
    };

    info!("[init] Received system signal: {}", received_signal);
    info!("[init] Performing clean shutdown...");

    shutdown_flag.store(true, Ordering::Relaxed);

    sleep(SIGNAL_SHUTDOWN_GRACE_PERIOD).await;

    execute_clean_poweroff(&*sys, "init");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_power_event_recognized() {
        // Key down (value == 1) for power keys must be recognized
        assert!(is_power_event(
            evdev::EventType::KEY,
            evdev::KeyCode::KEY_POWER.code(),
            1
        ));
        assert!(is_power_event(
            evdev::EventType::KEY,
            evdev::KeyCode::KEY_POWER2.code(),
            1
        ));
        assert!(is_power_event(
            evdev::EventType::KEY,
            evdev::KeyCode::KEY_SLEEP.code(),
            1
        ));

        // Key up (value == 0) or repeat (value == 2) must not trigger shutdown
        assert!(!is_power_event(
            evdev::EventType::KEY,
            evdev::KeyCode::KEY_POWER.code(),
            0
        ));
        assert!(!is_power_event(
            evdev::EventType::KEY,
            evdev::KeyCode::KEY_POWER.code(),
            2
        ));

        // Non-power keys must not trigger shutdown
        assert!(!is_power_event(
            evdev::EventType::KEY,
            evdev::KeyCode::KEY_A.code(),
            1
        ));

        // Non-key event types must not trigger shutdown
        assert!(!is_power_event(
            evdev::EventType::RELATIVE,
            evdev::KeyCode::KEY_POWER.code(),
            1
        ));
    }

    #[test]
    fn test_execute_clean_poweroff_syncs_and_reboots() {
        let sys = crate::init::system::mock::MockSystem::new();
        execute_clean_poweroff(&sys, "test");

        assert_eq!(*sys.sync_calls.lock().unwrap(), 1);
        assert_eq!(
            *sys.reboot_call.lock().unwrap(),
            Some(RebootMode::RB_POWER_OFF)
        );
    }
}
