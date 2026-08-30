# Specification: NTP Client (SNTP)

The SNTP Client is an embedded service in `trimrouter` that periodically synchronizes the system clock with `time.google.com` using the Simple Network Time Protocol (SNTP).

> [!NOTE]
> **Status: Implemented.**

---

## 1. Lifecycle and Dependencies

The SNTP service uses a decoupled, event-driven supervisor pattern:

1.  **Dynamic Worker Lifecycle**: The privileged parent supervisor (`SntpClient`) monitors the WAN lease watch channel (`WanLeaseReceiver`). When a valid WAN IP lease is acquired, the supervisor dynamically spawns the sandboxed worker child process. When the WAN lease is cleared or lost, the supervisor automatically stops and terminates the worker, ensuring zero CPU and memory resources are consumed when WAN is inactive.
2.  **Autonomous Sandboxed Worker**: The child worker has no dependency on interface states or IPC status messages. Once started, it queries NTP and reports the time back to the parent over IPC, retrying with exponential backoff on transient network failures.
3.  **DNS Dependency**: Resolves the domain `time.google.com` dynamically by querying the parent supervisor over IPC (`SntpClientToParentMsg::ResolveHost`), which resolves through `/etc/resolv.conf` and the embedded DNS forwarder. Transient DNS resolution failure does not terminate the worker; the worker retries in-place with exponential backoff.
4.  **Shutdown Watch**: The supervisor cleanly stops the worker via `SIGTERM` when the service is stopped.

---

## 2. Sync Execution & System Call Integration

When executing a synchronization iteration:

*   **DNS Resolution Delegation**: Because worker sandboxing isolates the child process, the SNTP worker sends a parameterless `ResolveTimeServer` IPC message to the privileged parent supervisor. The parent resolves the configured NTP host (`time.google.com`) using `/etc/resolv.conf` (pointing to the local DNS forwarder on `127.0.0.1:53`), validates the resolved IP address, and replies with a `TimeServerResolved` IPC message.
*   **Pre-Bound UDP Socket**: The supervisor opens and binds the UDP socket before spawning the worker and dropping privileges. The worker sends/receives packets over this passed socket without needing socket creation capabilities.
*   **SNTP Packet Exchange**: Uses the `sntpc` library with a `tokio::net::UdpSocket` transport adapter (`NtpUdpSocket`) to send an SNTP query to the resolved time server on port `123` and compute the time offset.
*   **Clock Update & Sanity Validation**:
    *   Validates timestamp sanity: bounds check ensures timestamps are within valid modern epoch bounds (`1_700_000_000` to `4_102_444_800` / Year 2100) and nanoseconds are `< 1_000_000_000`, rejecting bogus pre-1970 (CVE-2015-5300) or overflow dates.
    *   Calls the `nix::time::clock_settime` system call using `ClockId::CLOCK_REALTIME` in the privileged parent supervisor to set the system clock.
    *   All system time modifications are logged with millisecond resolution.

---

## 3. Timing and Backoff Strategy

To prevent overloading time servers and handle intermittent network drops, the client uses a backoff strategy:

*   **Normal Sync Interval**: Synchronizes system time successfully every 30 minutes (`SYNC_INTERVAL`).
*   **Initial Retry Interval**: On failure, retries after 60 seconds (`RETRY_INTERVAL`).
*   **Exponential Backoff**: For consecutive failures, the retry delay doubles (`delay = delay * 2`), capped at a maximum interval of 15 minutes (`MAX_RETRY_INTERVAL`).
*   **Reset**: Upon the next successful synchronization, the retry delay resets back to 60 seconds.
