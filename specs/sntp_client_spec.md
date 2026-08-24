# Specification: NTP Client (SNTP)

The SNTP Client is an embedded service in `trimrouter` that periodically synchronizes the system clock with `time.google.com` using the Simple Network Time Protocol (SNTP).

> [!NOTE]
> **Status: Implemented.**

---

## 1. Lifecycle and Dependencies

The SNTP service uses a decoupled, event-driven supervisor pattern:

1.  **Dynamic Worker Lifecycle**: The privileged parent supervisor (`SntpClient`) monitors the WAN lease watch channel (`WanLeaseReceiver`). When a valid WAN IP lease is acquired, the supervisor dynamically spawns the sandboxed worker child process. When the WAN lease is cleared or lost, the supervisor automatically stops and terminates the worker, ensuring zero CPU and memory resources are consumed when WAN is inactive.
2.  **Autonomous Sandboxed Worker**: The child worker has no dependency on interface states or IPC status messages. Once started, it queries NTP and reports the time back to the parent over IPC, retrying with exponential backoff on transient network failures.
3.  **DNS Dependency**: Resolves the domain `time.google.com` dynamically using the local DNS forwarder before initiating the NTP connection.
4.  **Shutdown Watch**: The supervisor cleanly stops the worker via `SIGTERM` when the service is stopped.

---

## 2. Sync Execution & System Call Integration

When executing a synchronization iteration:

*   **DNS Resolution**: Resolves `time.google.com`'s A record manually.
*   **Protocol Client**: Constructs a UDP connection to the resolved IP address on port `123` (NTP).
*   **SNTP Packet Exchange**: Uses the `rsntp` library to send an SNTP query and compute the offset and current time.
*   **Clock Update**:
    *   Converts the resulting `rsntp` datetime representation to standard duration format.
    *   Calls the `nix::time::clock_settime` system call using `ClockId::CLOCK_REALTIME` to set the system clock.
    *   All system time modifications are logged with millisecond resolution.

---

## 3. Timing and Backoff Strategy

To prevent overloading time servers and handle intermittent network drops, the client uses a backoff strategy:

*   **Normal Sync Interval**: Synchronizes system time successfully every 30 minutes (`SYNC_INTERVAL`).
*   **Initial Retry Interval**: On failure, retries after 60 seconds (`RETRY_INTERVAL`).
*   **Exponential Backoff**: For consecutive failures, the retry delay doubles (`delay = delay * 2`), capped at a maximum interval of 15 minutes (`MAX_RETRY_INTERVAL`).
*   **Reset**: Upon the next successful synchronization, the retry delay resets back to 60 seconds.
