# Specification: Hardware Watchdog Integration

The Hardware Watchdog subsystem in `trimrouter` provides automated supervision and fault-recovery for the router appliance by interfacing directly with the Linux hardware watchdog device (`/dev/watchdog`).

> [!NOTE]
> **Status: Implemented.**

---

## 1. Architecture and Purpose

As an immutable, unattended embedded appliance running as PID 1, `trimrouter` must automatically recover (reboot) from deadlocks, kernel panics, or unrecoverable service failures. It employs an idiomatic, lock-free **Actor / Message-Passing Architecture (MPSC Channels)** paired with **Pure IPC Proof-of-Life Heartbeats** from sandboxed worker processes:

```
┌─────────────────────────────────┐
│ Child DNS Forwarder Process     │
│ - Ticks cleanup/event loop      │──┐ (IPC DnsWorkerToParentMsg::Heartbeat)
└─────────────────────────────────┘  │
                                     ▼
┌─────────────────────────────────┐  │ (heartbeat_tx.try_send(MonitoredService::DnsForwarder))
│ Parent DNS Forwarder Supervisor │──┤
└─────────────────────────────────┘  │
┌─────────────────────────────────┐  │
│ Parent LAN Manager / Server     │──┼────────► ┌──────────────────────────────────────┐
└─────────────────────────────────┘  │          │   mpsc::Receiver<MonitoredService>   │
┌─────────────────────────────────┐  │          └──────────────────┬───────────────────┘
│ Parent DHCP Client Supervisor   │──┤                             │
└─────────────────────────────────┘  │             ┌───────────────┴───────────────┐
┌─────────────────────────────────┐  │             │                               │
│ Netlink Interface Monitor       │──┘             ▼                               ▼
└─────────────────────────────────┘       [Watchdog Enabled]              [Watchdog Disabled]
                                                   │                               │
                                       Watchdog Monitor Task               Dummy Drain Task
                                       - Drains heartbeats into local      - Simply drains channel
                                         HashMap<MonitoredService,           via rx.recv() loop
                                                 Instant> (stack)          - 0 CPU / 0 locks / 0 errors
                                       - 0 Mutexes / 0 shared state
                                       - Verifies 30s freshness window
                                       - Pets /dev/watchdog on success
```

1. **Pure Child Worker Proof-of-Life (IPC Heartbeats)**:
   - Sandboxed worker processes (`dns-forwarder`, `dhcp-client`, `dhcp-server`) emit IPC heartbeat messages (`Heartbeat`) over their bidirectional UNIX domain socket during event loop iterations.
   - The parent supervisor tasks only relay heartbeats to the watchdog channel (`heartbeat_tx.try_send(service)`) when **genuine proof-of-life is received from the child worker**.
   - `ExternalWorker` acts strictly as a clean process supervisor without any internal heartbeat plumbing or artificial grace ticks.
2. **Automatic Discovery & Resilience**: Upon early startup, PID 1 checks for the existence of `/dev/watchdog`. If the device is not present (such as in unprivileged containers or VM environments lacking watchdog hardware), a lightweight dummy consumer task is spawned to drain incoming heartbeat pings without overhead or errors.
3. **Lock-Free Message Passing**: Supervised core tasks hold a clone of `HeartbeatSender` (`tokio::sync::mpsc::Sender<MonitoredService>`). Each active supervisor emits heartbeat pings over the channel during normal operation.
4. **Local Freshness Evaluation**: The watchdog task owns the `HeartbeatReceiver` and tracks the last-seen timestamp for each expected service in a local `HashMap<MonitoredService, Instant>` on its own stack without shared memory or mutex locks.
5. **Heartbeat Timeout Window (30s)**: Every 5 seconds (`DEFAULT_WATCHDOG_INTERVAL_SECS`), the watchdog checks that all expected critical core services have emitted a heartbeat within the freshness timeout window (`DEFAULT_HEARTBEAT_TIMEOUT_SECS = 30s`).
   - The 30s window provides ample headroom for transient process crashes to restart with exponential backoff (1s, 2s, 4s, 8s $\approx$ 15s total) and resume heartbeating.
   - If any critical service enters a fatal crash loop or freezes, no IPC heartbeats are emitted, and the 30s timeout expires, allowing the hardware timer to trigger an appliance reboot.
6. **Magic Close Clean Disarming**: When PID 1 initiates a clean shutdown or poweroff (e.g. from an ACPI power button event or termination signal), the supervisor writes the standard Linux magic close character (`'V'`) to `/dev/watchdog` before closing the descriptor, preventing inadvertent reboots during orderly shutdowns.

---

## 2. Monitored Services & Liveness Criteria

### 2.1 Critical Core Services (Watchdog Gating)

The watchdog monitor gates keepalive petting on timely heartbeats from core subsystems essential to routing and packet forwarding:

| Monitored Service | Monitored Health & Heartbeat Conditions |
| :--- | :--- |
| **`dns-forwarder`** | Child forwarder worker actively processing DNS queries and emitting IPC heartbeats; parent relays ticks to watchdog. |
| **`lan-manager`** | LAN interface manager active; coordinates LAN IP configuration and DHCP server worker heartbeats. |
| **`dhcp-client`** | WAN raw-socket listener and child DHCP client worker actively ticking state machine and emitting IPC heartbeats. |
| **`interface-monitor`** | Netlink link multicast listener and carrier management loop active. |

### 2.2 Non-Critical Auxiliary Services

Auxiliary services do not gate hardware watchdog keepalives to prevent unwanted appliance reboots:
* **`sntp-client`**: Time synchronization with upstream NTP servers. If an upstream NTP server is unreachable or DNS resolution for NTP fails, network routing, NAT, and LAN DHCP services remain fully functional. Therefore, `sntp-client` does not block watchdog keepalives.

### 2.3 Operational State vs. System Failure Differentiation

The system explicitly distinguishes normal operational waiting states from catastrophic failures:

* **Healthy (Watchdog Continues Heartbeat)**:
  * WAN cable disconnected or ISP DHCP server slow to respond (DHCP client child worker actively retrying and emitting IPC heartbeats).
  * LAN interface idle with no connected client devices.
* **Unhealthy (Heartbeat Suspended $\rightarrow$ Appliance Reboots)**:
  * Child worker deadlocked, hung in infinite loop, or frozen (IPC heartbeats cease).
  * Tokio runtime event loop deadlocked or blocked (heartbeats cease).
  * Worker process in a fatal crash loop exceeding 30s window without recovery.
  * Core service supervisor task panics or exits unexpectedly.

---

## 3. Linux Watchdog Interface

* **Device Node**: `/dev/watchdog`
* **Heartbeat Interval**: Fixed 5-second asynchronous keepalive interval (`DEFAULT_WATCHDOG_INTERVAL_SECS`).
* **Liveness Timeout Window**: 30 seconds (`DEFAULT_HEARTBEAT_TIMEOUT_SECS`).
* **Keepalive Protocol**: Periodic single-byte write (`b"\0"`).
* **Disarm / Teardown**: Magic close character byte (`b'V'`) written immediately prior to closing the file descriptor.

---

## 4. Configuration

Watchdog behavior is configured under the `[system]` section in `/boot/config/trimrouter.toml`:

```toml
[system]
watchdog = true         # Optional boolean, defaults to true
```

See [`router_spec.md`](router_spec.md) for global system configuration details.

---

## 5. Architectural Non-Goals & Fixed Configuration Rationale

* **No Custom Device Paths or Timing Knobs**: `trimrouter` intentionally does not expose configuration options for custom `/dev/watchdog` device paths, keepalive intervals, or freshness timeouts in `trimrouter.toml` or kernel parameters.
* **Universal Device Node Compatibility**: The standard character device node `/dev/watchdog` is universally provided by the Linux kernel Watchdog Core API across all supported target platforms (Raspberry Pi Broadcom `bcm2835_wdt`, Intel/AMD `iTCO_wdt`, QEMU `i6300esb`, softdog). Exposing path configuration adds unneeded schema surface without functional gain on dedicated router hardware.
* **Fixed Safe Margins vs. Misconfiguration Risk**: The fixed 5s keepalive interval and 30s freshness window safely match hardware watchdog margins (typically 15s to 60s) while leaving sufficient exponential backoff headroom for transient worker restarts. Exposing these timing parameters creates a risk of user misconfiguration (such as setting an interval tighter than the hardware driver's margin, triggering spurious reboots).
* **Binary Toggle Sufficiency**: The binary `watchdog = true | false` toggle completely fulfills operational requirements (disabling during development, debugging, and container environments; enabling for unattended appliance deployments).

