use std::fs;
use std::path::Path;

pub async fn test_logging_subsystem() -> Result<(), String> {
    let log_file = Path::new("/var/log/system.log");

    // Write verification entries through unified logger
    trimrouter::logging::log("test-logger", "Logging subsystem integration test start");
    trimrouter::logging::log(
        "test-logger",
        "Logging subsystem integration test verification line",
    );
    trimrouter::logging::flush();

    // Verify /var/log/system.log exists
    if !log_file.exists() {
        return Err(format!(
            "Log file {} does not exist on log partition",
            log_file.display()
        ));
    }

    let contents = fs::read_to_string(log_file)
        .map_err(|e| format!("Failed to read {}: {}", log_file.display(), e))?;

    if contents.is_empty() {
        return Err(format!("Log file {} is empty", log_file.display()));
    }

    if !contents.contains("[test-logger] Logging subsystem integration test verification line") {
        return Err("Log file does not contain expected logged message".to_string());
    }

    // Verify ISO 8601 UTC timestamp format "[YYYY-MM-DDTHH:MM:SSZ] [service] message"
    let mut found_valid_format = false;
    for line in contents.lines() {
        if line.starts_with('[') && line.contains("Z] [") {
            found_valid_format = true;
            break;
        }
    }
    if !found_valid_format {
        return Err(
            "No log line with standard ISO 8601 timestamp format found in system.log".to_string(),
        );
    }

    Ok(())
}
