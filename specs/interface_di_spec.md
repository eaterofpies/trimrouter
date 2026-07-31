# Interface Dependency Injection & Lifecycle Specification

This specification details the architecture for unifying WAN and LAN interface lifecycles. Instead of separate event loops, watchdogs, and hardcoded service initializations, both interfaces will be managed by a common runtime component that dynamically spawns, monitors, and deletes relevant service containers depending on interface presence.

---
## 1. Architectural Overview

The network interface lifecycle management system employs an event-driven architecture utilizing the Linux kernel Netlink subsystem. Rather than relying on a polling watchdog, each monitored interface is managed by a dedicated task that establishes a Netlink socket subscribed to the `RTNLGRP_LINK` multicast group. The task remains suspended until the kernel broadcasts a link state event (`RTM_NEWLINK` or `RTM_DELLINK`).

This design eliminates periodic polling wakeups, triggering state machine transitions and service dependency injections only upon physical hardware insertion, removal, or link state changes:

```text
                     +---------------------------------------+
                     | Netlink Event Received (RTNLGRP_LINK) |
                     +-------------------+-------------------+
                                         |
                                         v
                         +---------------+---------------+
                         |   Is it NewLink or DelLink?   |
                         +---------------+---------------+
                                         |
                +------------------------+------------------------+
                | [NewLink]                                       | [DelLink]
                v                                                 v
    +-----------+-----------+                         +-----------+-----------+
    |   Does event MAC match|                         |   Does event Index    |
    |   target interface?   |                         |   match active_index? |
    +-----------+-----------+                         +-----------+-----------+
                |                                                 |
         +------+------+                                   +------+------+
         |             |                                   |             |
      [ Yes ]        [ No ]                             [ Yes ]        [ No ]
         |             |                                   |             |
  +------v------+   +--v----------+                 +------v------+    +--v---+
  | Is active?  |   | Does name   |                 | Stop & drop |    | Ignore|
  +------+------+   | collide?    |                 | services,   |    +------+
         |          +------+------+                 | clear index |
     +---+---+             |                        +-------------+
     |       |          [ Yes ]
  [ Yes ]  [ No ]          |
     |       |      +------v-------+
+----v----+  |      | Rename other |
|Watchdog:|  |      | interface to |
|Configure|  |      | "<name>_old" |
|Link/IP  |  |      +--------------+
+---------+  |
     +-------v-------------------------+
     | Rename interface to target name |
     | Configure Link state & IP       |
     | Instantiate services via DI     |
     | Start all active services       |
     | Save active_index = index       |
     +---------------------------------+
```

---

## 2. Common Data Structure

Both WAN and LAN will be defined as instances of `ManagedInterface`. The specific behaviors and services are injected dynamically.

```rust
pub enum InterfaceType {
    Wan,
    Lan,
}

pub enum RouterService {
    DhcpClient(services::DhcpClient),
    DhcpServer(services::DhcpServer),
    DnsForwarder(services::DnsForwarder),
    SntpClient(services::SntpClient),
}

pub struct ManagedInterface {
    /// The target system name (e.g. "wan", "lan")
    pub name: String,
    /// The hardware MAC address used for discovery
    pub mac: String,
    /// Optional static IP configuration (e.g., Some("192.168.1.1/24"))
    pub ip_config: Option<String>,
    /// The classification of this interface
    pub service_type: InterfaceType,
    /// Active running service containers managed via concrete enum variant wrappers
    pub active_services: Vec<RouterService>,
}
```

### Dynamic Service Mapping (Dependency Injection)

On interface discovery, the controller instantiates the service suite:

| Interface Type | Configured IP | Dynamic Services Injected |
| :--- | :--- | :--- |
| **WAN** (`InterfaceType::Wan`) | None (DHCP Assigned) | 1. `DhcpClient` (retrieves lease)<br>2. `SntpClient` (synchronizes system time) |
| **LAN** (`InterfaceType::Lan`) | Static (`192.168.1.1/24`) | 1. `DhcpServer` (allocates client leases)<br>2. `DnsForwarder` (resolves queries local/upstream) |

---

## 3. Lifecycle States & Transitions

Each interface task transitions through the following state machine:

```text
            +------------------------+
            |      [*] / Start       |
            +-----------+------------+
                        |
                        v
            +------------------------+
            |         ABSENT         | <---------------------+
            +-----------+------------+                       |
                        | (MAC detected in Netlink)          |
                        v                                    |
            +------------------------+                       | (Interface
            |        PRESENT         |                       |  removed/
            +-----------+------------+                       |  unplugged)
                        | (Link UP & IP assigned)            |
                        v                                    |
            +------------------------+                       |
            |       CONFIGURED       | ----------------------+
            +-----------+------------+                       |
                        | (Services started)                 |
                        v                                    |
            +------------------------+
            |         ACTIVE         | ----------------------+
            +------------------------+
```

> [!NOTE]
> In the implementation, these states are represented implicitly rather than via an explicit Rust state `enum`:
> * **`ABSENT`**: Indicated by `active_index` being `None` and `active_services` being empty.
> * **`ACTIVE`**: Indicated by `active_index` being `Some(index)` and `active_services` containing the active, running service wrappers.
> * **`PRESENT` / `CONFIGURED`**: Transient states handled sequentially inside the linear asynchronous execution of the `activate_interface` helper function.

### Action Table

- **MAC Detected**:
  1. Verify the interface matches the target name.
  2. If a different interface currently has the target name (e.g. name collision), rename the colliding interface to `<name>_old_<idx>`.
  3. Rename the matching interface to the target name.
  4. Bring the interface link `UP` and assign the IP address if a static CIDR is configured.
  5. Instantiate the interface's relevant services and call `.start().await` on each.
- **MAC Disappeared**:
  1. Invoke `.stop().await` on all active services.
  2. Drop the services (deleting the instances from memory).
  3. Reset state flags to wait for re-detection.

---

## 4. Implementation Code Layout

A new module [src/interface.rs](file:///workspaces/rustyrouter/src/interface.rs) will be created to isolate this logic:

```rust
// src/interface.rs

pub async fn monitor_interface(
    mut iface: ManagedInterface,
    lease_state: SharedWanLease,
) {
    // Shared monitoring loop logic...
}
```

The [src/main.rs](file:///workspaces/rustyrouter/src/main.rs) initialization code will be simplified to:

```rust
// src/main.rs (Proposed Initialization)

let lease_state = Arc::new(Mutex::new(WanLease::default()));

let wan_iface = ManagedInterface::new(
    network::WAN_INTERFACE.to_string(),
    config.wan_mac.clone(),
    None,
    InterfaceType::Wan,
);

let lan_iface = ManagedInterface::new(
    network::LAN_INTERFACE.to_string(),
    config.lan_mac.clone(),
    Some(config.lan_ip.clone()),
    InterfaceType::Lan,
);

tokio::spawn(interface::monitor_interface(wan_iface, lease_state.clone()));
tokio::spawn(interface::monitor_interface(lan_iface, lease_state.clone()));
```

---

## 5. Benefits

1. **Zero Resource Leaks**: Services are dropped entirely when an interface disappears, freeing sockets, memory, and background tasks.
2. **Unified Watchdog Code**: WAN and LAN hotplug logic share the same parsing and Link configuration flow.
3. **Flat Nested Logic**: All helpers comply with Rule 4 (Indentations at most 2 layers deep) and Rule 5 (Small, single-purpose functions).
