use chrono::Datelike;
use std::time::Duration;
use trimrouter::services::utils::WanLeaseReceiver;
use trimrouter::services::{Service, SntpClient};

pub async fn test_sntp_sync(lease_rx: WanLeaseReceiver) -> Result<SntpClient, String> {
    std::println!("[test] Starting SNTP Client test...");

    // 1. Start SNTP Client
    let mut sntp_client = SntpClient::new(lease_rx);
    if let Err(e) = sntp_client.start().await {
        return Err(format!("Failed to start SNTP Client: {}", e));
    }

    // 2. Await time synchronization (checking if year is >= 2030)
    let start = std::time::Instant::now();
    let mut synced = false;
    while start.elapsed() < Duration::from_secs(15) {
        let year = chrono::Utc::now().year();
        if year >= 2030 {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if !synced {
        if let Err(e) = sntp_client.stop().await {
            return Err(format!(
                "SNTP sync timed out, and failed to stop client: {}",
                e
            ));
        }
        return Err(format!(
            "SNTP time synchronization timed out. Current system year: {}",
            chrono::Utc::now().year()
        ));
    }

    std::println!(
        "[test] SNTP Client successfully synchronized system clock to year {}.",
        chrono::Utc::now().year()
    );
    Ok(sntp_client)
}
