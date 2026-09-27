use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use trimrouter::services::Service;
use trimrouter::services::observability::ObservabilityService;
use trimrouter::services::utils::WanLeaseReceiver;

pub async fn test_observability_subsystem(lease_rx: WanLeaseReceiver) -> Result<(), String> {
    std::println!("[test] Starting Observability Subsystem integration test...");

    let test_port = 8088;
    let mut svc = ObservabilityService::new(
        "lan".to_string(),
        "192.168.1.1/24".to_string(),
        lease_rx,
        true,
        test_port,
    );

    if let Err(e) = svc.start().await {
        return Err(format!("Failed to start ObservabilityService: {}", e));
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    // 1. Connect and test GET /
    let mut stream = TcpStream::connect(("127.0.0.1", test_port))
        .await
        .map_err(|e| format!("Failed to connect to observability server: {}", e))?;

    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .map_err(|e| format!("Failed to write GET / request: {}", e))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .await
        .map_err(|e| format!("Failed to read response line: {}", e))?;

    if !status_line.contains("200 OK") {
        let _ = svc.stop().await;
        return Err(format!("Expected 200 OK for GET /, got: {}", status_line));
    }

    // 2. Connect and test GET /api/status
    let mut stream_api = TcpStream::connect(("127.0.0.1", test_port))
        .await
        .map_err(|e| format!("Failed to connect to /api/status: {}", e))?;

    stream_api
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .map_err(|e| format!("Failed to write GET /api/status request: {}", e))?;

    let mut reader_api = BufReader::new(stream_api);
    let mut api_status_line = String::new();
    reader_api
        .read_line(&mut api_status_line)
        .await
        .map_err(|e| format!("Failed to read /api/status response line: {}", e))?;

    if !api_status_line.contains("200 OK") {
        let _ = svc.stop().await;
        return Err(format!(
            "Expected 200 OK for /api/status, got: {}",
            api_status_line
        ));
    }

    // 3. Clean shutdown
    if let Err(e) = svc.stop().await {
        return Err(format!("Failed to stop ObservabilityService: {}", e));
    }

    std::println!("[test] Observability Subsystem verified successfully.");
    Ok(())
}
