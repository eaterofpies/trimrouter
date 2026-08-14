# Specification: NTP Client (SNTP)

The SNTP Client is an embedded service in `trimrouter` that periodically synchronizes the system clock with `time.google.com` using the Simple Network Time Protocol (SNTP).

> [!NOTE]
> **Status: Implemented.**

---

## 1. Lifecycle and Dependencies

The SNTP client relies on active network connectivity and DNS resolution:

1.  **WAN Dependency**: The service loop remains idle in a suspended state (`wait_for_wan`) until a valid IP address is assigned to the WAN interface.
2.  **DNS Dependency**: Resolves the domain `time.google.com` dynamically using the local DNS forwarder before initiating the NTP connection.
3.  **Shutdown Watch**: Monitors a watch channel for shutdown events to exit the loop cleanly and release resources.

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
