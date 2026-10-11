# Specification: Privilege Separation

This document specifies the privilege separation architecture for `trimrouter`. 

Currently, `trimrouter` runs as the initialization process (PID 1) entirely as the `root` user (UID 0), meaning all network-facing packet parsers (DHCP, DNS, SNTP) operate with full system privileges. To protect against remote code execution vulnerabilities in third-party parsing libraries, `trimrouter` must isolate network-facing services into unprivileged child processes.

> [!NOTE]
> **Status: Implemented.** Chroot jail, UID/GID dropping, seccomp-BPF filters, and socket passing are all in place. The IPC protocol (§4) and process supervision (§3.4) are implemented.

---

## 1. Threat Model & Security Goals

### 1.1 Threat Model
*   **Primary Vectors**: Malicious DHCP packets on the WAN or LAN interface, or malicious/poisoned DNS responses from upstream or local clients.
*   **Vulnerability Type**: Memory corruption, buffer overflows, or logical panics in parser dependencies (such as `dhcproto`).
*   **Attacker Objective**: Remote code execution (RCE) or Denial of Service (DoS) leading to total control of the gateway.

### 1.2 Security Goals
1.  **Least Privilege**: The process parsing network inputs must not run as UID 0 and must not possess capabilities to modify routing tables, firewall rules, load kernel modules, or mount filesystems.
2.  **Compromise Isolation**: A compromise of the DNS Forwarder or DHCP services must not allow access to other host processes, network interfaces, or filesystem states.
3.  **Minimal Privileged Core**: The privileged parent process (PID 1) must only handle configuration, virtual filesystem management, kernel module loading, and netlink configuration (routing, interfaces, firewall).

---

## 2. Process Architecture

`trimrouter` transitions from a monolithic process to a multi-process architecture:

```
                      [ trimrouter PID 1 (root) ]
                   (VFS, Kmod, Netlink Router, IPC)
                   /        /           \        \
                 /        /               \        \
               /        /                   \        \
  [ dhcp-client ]  [ dhcp-server ]  [ dns-forwarder ]  [ sntp-client ]
   (UID 10002)      (UID 10003)       (UID 10004)      (UID 10001)
```

### 2.1 The Privileged Parent (PID 1 Manager)
*   **Permissions**: Runs as `root` (UID 0, GID 0) in the host user namespace.
*   **Duties**:
    *   Mounts virtual filesystems (`/proc`, `/sys`, `/dev`, `/run`).
    *   Loads required kernel modules.
    *   Configures firewall tables/chains (`rustables`) and default routing.
    *   Manages interface-bound raw packet sockets (`AF_PACKET`) on WAN and LAN, routing incoming frames to worker processes over IPC and encoding/transmitting outgoing frames requested by workers.
    *   Binds non-raw sockets for unprivileged workers (DNS, SNTP) and passes them during launch.
    *   Reaps zombie child processes.
    *   Listens to IPC requests from child workers to mutate network configuration (IP addresses, routes, netfilter rules).
    *   **Netlink Neighbor Listener**: Subscribes to kernel neighbor updates via `MulticastGroup::Neigh` (which requires `CAP_NET_ADMIN` privileges) and forwards discovered IP/MAC associations to the unprivileged DHCP Server worker via IPC.

### 2.2 Unprivileged Child Workers
Every service is spawned as a child process of the parent. The child drops privileges immediately after startup:

| Worker Service | Target User/Group | Required Socket FDs | Required Capabilities | Sandboxing Mechanics |
| :--- | :--- | :--- | :--- | :--- |
| **DHCP Client** | `dhcp-client` (10002) | None (IPC-only, raw socket I/O handled by parent) | None | User Namespace, chroot, Seccomp (Pure IPC) |
| **DHCP Server** | `dhcp-server` (10003) | None (IPC-only, raw socket I/O handled by parent) | None | User Namespace, chroot, Seccomp (Pure IPC) |
| **DNS Forwarder** | `dns-forwarder` (10004) | Passed `AF_INET` UDP port 53 socket, TCP listener | None | User Namespace, chroot, Seccomp |
| **SNTP Client** | `sntp` (10001) | Passed `AF_INET` UDP socket | None | User Namespace, chroot, Seccomp |

---

## 3. Sandboxing & Privilege Dropping Mechanics

Because `trimrouter` runs on a read-only filesystem with no external binaries or user directories, sandboxing is initialized programmatically using system calls.

### 3.1 Socket Passing and Raw Socket Isolation
Unprivileged services cannot bind to privileged ports (like port 53) or open raw sockets (`AF_PACKET`):
1.  **Non-Raw Sockets (DNS, SNTP)**: The Privileged Parent opens and binds UDP port 53 (and the TCP listener) for the DNS forwarder and the UDP client socket for SNTP before dropping privileges. These descriptors are passed to the child process during launch.
2.  **Raw Packet Sockets (DHCP Client, DHCP Server)**: Raw packet sockets (`AF_PACKET`) are **retained entirely in the Privileged Parent** and are never passed to child workers. The parent opens interface-bound raw sockets on WAN and LAN bound to `ETH_P_IP` and installs an in-kernel Classic BPF filter (`SO_ATTACH_FILTER`) restricting incoming traffic strictly to the service's target UDP port (68 for client, 67 for server), dropping all non-DHCP transit traffic directly in the kernel. Inbound frames are routed to workers over IPC, and the parent encodes and transmits outbound frames on behalf of workers.

#### 3.1.1 Security Justification of Raw Socket Isolation
Retaining raw packet sockets in the privileged parent and restricting workers to IPC yields critical security benefits:
*   **Total Capability and Descriptor Stripping**: Child workers never hold an `AF_PACKET` file descriptor in their address space. Without a raw socket descriptor, a compromised worker cannot sniff arbitrary transit traffic on the gateway interfaces, configure promiscuous mode, or inject raw Ethernet frames onto the physical network wire.
*   **Asymmetric Processing Model (Decode in Child, Constrained Encode in Parent)**:
    *   *Inbound Decode*: The parent routes raw Layer-2 Ethernet frames to the child via IPC (`RawPacket`). The unprivileged child worker performs full packet decoding in userspace (Ethernet, IPv4, UDP, and DHCP options), applies anti-spoofing checks, and advances its protocol state machine.
    *   *Outbound Constrained Encode*: The worker cannot emit arbitrary raw bytes or forged packet headers. Instead, it sends specific, strongly typed semantic domain messages over IPC (such as `SendOffer`, `SendAck`, `SendNak`, `ProbeArpConflict`, `SendDiscover`, `SendRequest`).
    *   *Parent Gatekeeping*: The privileged parent validates the request (e.g., verifying that offered IPs reside within the configured LAN subnet), encodes the DHCP message and authoritative options (Subnet Mask, Router, DNS, Lease Time), encapsulates the UDP, IPv4, and Ethernet headers, and transmits the frame.
*   **Pure IPC Seccomp Profile**: Because DHCP workers possess no network descriptors, their Seccomp-BPF filters can be strictly hardened to a pure-IPC profile, dropping network syscalls like `SYS_accept`, `SYS_accept4`, `SYS_ioctl` (`SIOCGIFINDEX`), `SYS_getsockopt`, and `SYS_setsockopt`.

### 3.2 Programmatic Privilege Reduction
Each worker drops privileges using the following sequence:
1.  **Chroot**: Calls `chroot("/run/empty")` (a directory created by PID 1 on a `tmpfs` mount, owned by `root:root` with strict read-only `0555` permissions) and `chdir("/")` to lock the worker in an empty, non-writable root directory.
2.  **User Namespace & ID Shift**: Shifts the process's effective UID and GID to its designated unique system user/group (e.g., `10001` for `sntp`).
3.  **Capability Dropping**: Drops all capabilities from the bounding, effective, and permitted sets completely.
4.  **Seccomp Syscall Whitelisting**: Installs a strict Seccomp-BPF filter allowing only required system calls (e.g., `read`, `write`, `recvmsg`, `sendmsg`, `epoll_wait`, `nanosleep`, `exit`).

### 3.3 Helper Libraries (Rust Ecosystem)
The privilege dropping sequence uses:
*   **[`nix`](https://docs.rs/nix)**: Performs low-level POSIX and Linux system operations (e.g. `setuid`, `setgid`, `chroot`, signal handling, and process termination) safely in Rust.
*   **[`caps`](https://docs.rs/caps)**: Provides support for querying, clearing, and dropping specific Linux process/thread capability sets (Bounding, Inheritable, Effective, Permitted).
*   **[`seccompiler`](https://docs.rs/seccompiler)**: A pure-Rust Seccomp-BPF filter compiler from the `rust-vmm` project. It generates and applies BPF filters directly in Rust without calling out to `libseccomp` C libraries, ensuring completely static binaries.
*   **[`pktbaffle`](https://docs.rs/pktbaffle)**: A pure-Rust libpcap-compatible packet filter compiler. It compiles human-readable filter expressions (e.g. `ip and udp dst port 67`) directly into Classic BPF (`cBPF`) bytecode loaded via `SO_ATTACH_FILTER`, eliminating manual BPF bytecode construction without C dependencies.

### 3.4 Service Lifecycle & Process Supervision
Starting, stopping, and reconfiguring services corresponds directly to executing and terminating their respective child processes:
1.  **One-Way Privilege Dropping**: Because privilege dropping actions (`chroot`, `setuid`, dropping capabilities, and especially `seccomp` system call filters) are **one-way, irreversible operations** in the Linux kernel, a process cannot regain root permissions or relax its seccomp restrictions once they are applied. Consequently, a worker process cannot be "recycled" or reconfigured in-place.
2.  **Lifecycle Transitions**:
    *   **Start**: The parent binds required network/raw sockets, creates the IPC socket pair, forks/spawns a fresh child process, passes the file descriptors, and the child drops privileges immediately at startup.
    *   **Stop**: The parent sends a graceful `SIGTERM` signal to the worker's PID, grants a 500ms shutdown window, escalates to `SIGKILL` if needed, reaps it via the orphan reaper loop to prevent zombie processes, and closes the associated IPC and socket descriptors via RAII.
    *   **Reconfigure / Restart** (e.g., during a LAN/WAN subnet shift): The parent stops the active worker process, tears down the old interface parameters, opens new socket descriptors matching the updated configuration, and spawns a fresh worker instance.
3.  **Process Supervision**: The parent process tracks active child worker PIDs. If a child process terminates unexpectedly (e.g., due to a panic, segmentation fault, or out-of-memory kill), the parent's reaper loop traps the `SIGCHLD` signal, cleans up associated states (such as routes or IP leases), and executes an exponential back-off restart strategy (up to 60s max delay). If the worker runs stably for $\ge 60$ seconds, the restart backoff attempt counter automatically resets to 0.

---

## 4. Inter-Process Communication (IPC) Protocol

Workers communicate with the Privileged Parent over standard bidirectional **Unix Domain Sequenced-Packet Sockets** (`AF_UNIX` / `SOCK_SEQPACKET`) created via `UnixSeqpacket::pair` before fork.

### 4.1 Serialization & Message Boundaries
Rather than parsing complex and potentially vulnerable JSON strings, IPC relies on a **strongly-typed binary serialization** format:
1.  **Format**: Messages are serialized using **`postcard`**, a safe, zero-copy, `no_std` compatible binary format.
2.  **Kernel Datagram Framing**: Sockets use Linux `SOCK_SEQPACKET`, which preserves discrete message boundaries in the kernel. Each atomic `recv` returns an exact complete datagram, eliminating manual length-prefix framing while retaining connection-oriented EOF lifecycle detection when a peer closes or crashes.
3.  **Payload Length Cap**: IPC messages are strictly limited to a maximum length of 64 KB (`MAX_IPC_MSG_LEN = 65536`). Outgoing or incoming payloads exceeding this bound are rejected immediately with `io::ErrorKind::InvalidData`, preventing memory exhaustion (OOM) attacks against the privileged supervisor.
4.  **Security Benefit**: Since the parent and child are instances of the same compiled Rust binary, they share the exact same enum memory schemas. Postcard deserialization is linear and does not allocate arbitrary memory or parse nested string structures, eliminating parser-level vulnerability surfaces in PID 1.

### 4.2 Parent-to-Worker Protocol
The parent routes raw frames and configuration events to children using strongly typed enums isolated per channel:

```rust
/// Messages sent from the parent supervisor to the DHCP Client worker
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpClientParentToWorkerMsg {
    /// Inbound raw Ethernet frame received on WAN for full userspace decode in the worker
    RawPacket { frame: Vec<u8> },
}

/// Messages sent from the parent supervisor to the DHCP Server worker
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpServerParentToWorkerMsg {
    /// Inbound raw Ethernet frame received on LAN for full userspace decode in the worker
    RawPacket { frame: Vec<u8> },
    /// Active IP/MAC mappings discovered via the parent's Netlink listener
    AddNeighbor {
        ip_address: Ipv4Addr,
        mac_address: MacAddr,
    },
    /// Static DHCP lease reservations passed at startup or upon LAN reconfiguration
    SetStaticLeases {
        leases: Vec<StaticLease>,
    },
}

/// Messages sent from the parent supervisor to the DNS Forwarder worker
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DnsParentToWorkerMsg {
    /// Configures the DNS forwarder with the active upstream DNS servers
    SetUpstreamResolvers {
        servers: Vec<Ipv4Addr>,
    },
    /// Registers a local hostname mapping into the DNS table
    RegisterLocalHost { name: String, ip: Ipv4Addr },
    /// Deregisters a local hostname mapping
    DeregisterLocalHost { name: String },
}

/// Messages sent from the parent supervisor to the SNTP Client worker
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SntpParentToClientMsg {
    /// Response with the resolved time server IP
    TimeServerResolved {
        result: Result<Ipv4Addr, String>,
    },
}
```

### 4.3 Worker-to-Parent Protocol
To prevent a compromised worker from executing commands outside its scope or forging raw packets, worker messages are strictly constrained to semantic domain actions per channel. The parent performs packet encoding and transmission:

```rust
/// Messages that only the DHCP Client worker is permitted to send
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpClientToParentMsg {
    /// Requests the parent to encode and broadcast a DHCPDISCOVER frame on WAN
    SendDiscover {
        xid: u32,
    },
    /// Requests the parent to encode and transmit a DHCPREQUEST frame on WAN
    SendRequest {
        xid: u32,
        requested_ip: Ipv4Addr,
        server_ip: Option<Ipv4Addr>,
        ciaddr: Ipv4Addr,
    },
    /// Sent when a WAN lease is acquired
    ApplyWanLease {
        ip_address: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        dns_servers: Vec<Ipv4Addr>,
    },
    /// Sent when the WAN lease is lost or expired
    ClearWanLease,
    /// Keepalive tick for the watchdog supervisor
    Heartbeat,
}

/// Messages that only the DHCP Server worker is permitted to send
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DhcpServerWorkerToParentMsg {
    /// Requests the parent to validate, encode, and transmit a DHCPOFFER frame on LAN
    SendOffer {
        client_mac: MacAddr,
        xid: u32,
        offered_ip: Ipv4Addr,
        broadcast: bool,
    },
    /// Requests the parent to validate, encode, and transmit a DHCPACK frame on LAN
    SendAck {
        client_mac: MacAddr,
        xid: u32,
        leased_ip: Ipv4Addr,
        broadcast: bool,
    },
    /// Requests the parent to encode and broadcast a DHCPNAK frame on LAN
    SendNak {
        client_mac: MacAddr,
        xid: u32,
    },
    /// Requests the parent to emit an ARP resolution probe for conflict detection
    ProbeArpConflict {
        target_ip: Ipv4Addr,
    },
    /// Emitted periodically to synchronize active leases with the parent & observability
    Heartbeat {
        leases: Vec<DhcpLeaseInfo>,
    },
    /// Dynamic hostname registration discovered from client Option 12
    RegisterLocalHost { name: String, ip: Ipv4Addr },
    /// Dynamic hostname deregistration upon lease expiry or release
    DeregisterLocalHost { name: String },
}

/// Messages that only the SNTP Client worker is permitted to send
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SntpClientToParentMsg {
    /// Sent to update the system time
    SetSystemTime {
        seconds: i64,
        nanoseconds: i64,
    },
    /// Request resolution of the configured time server IP from the supervisor
    ResolveTimeServer,
}

/// Messages that only the DNS Forwarder worker is permitted to send
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum DnsWorkerToParentMsg {
    /// Telemetry and watchdog heartbeat
    Heartbeat { stats: DnsStatsInfo },
}
```

### 4.4 Channel Isolation & Endpoint Verification
To enforce this security boundary:
1.  **Dedicated Socketpairs**: The parent creates a dedicated, private `socketpair` for each worker immediately before spawning it. Sockets are never shared between different workers.
2.  **Compile-Time Deserialization Guard**: The parent's event loop binds each worker socket reader strictly to that worker's specific enum type. For example, the reader on the DHCP Client socket only compiles and deserializes payloads using `DhcpClientToParentMsg`.
3.  **Exploit Prevention**: If a compromised DNS Forwarder worker attempts to send an `ApplyWanLease` message, the parent's DNS reader fails to deserialize the byte stream (resulting in a parsing error and immediate termination of the offending child process).

---

## 5. Implementation Roadmap

1.  **Phase 1: Custom User Creation**: Implement user/group shifting in Rust.
2.  **Phase 2: IPC Framework**: Build the Unix socket message dispatcher loop in PID 1.
3.  **Phase 3: Worker Extraction**: Refactor the DNS Forwarder to run as a separate process utilizing an inherited socket descriptor.
4.  **Phase 4: DHCP Service Separation**: Extract the DHCP client/server into unprivileged child processes.
5.  **Phase 5: Seccomp lockdown**: Enable strict BPF syscall filters on all workers.

---

## 6. Trade-offs & Security Risks

While privilege separation increases the overall security posture, it introduces secondary risks and operational complexities:

1.  **IPC Attack Surface Expansion (Privilege Escalation)**:
    *   *Risk*: Shifting from monolithic calls to IPC (binary enums over Unix sockets) exposes an API in the privileged parent (PID 1) that processes input from unprivileged processes. If the parent has bugs in binary deserialization or logic validation, a compromised worker can exploit the IPC channel to execute code or change settings as root.
    *   *Mitigation*: Implement strict range/bounds checks and input sanitization on all incoming IPC message payloads in the parent. Treat all worker payloads as untrusted.

2.  **File Descriptor Leakage**:
    *   *Risk*: If the parent process opens sensitive system configurations, kernel log descriptors, or supervisor sockets, and forks workers without setting the `O_CLOEXEC` flag, the child workers inherit access to these resources.
    *   *Mitigation*: Enforce `O_CLOEXEC` on all descriptors opened by the parent. Programmatically close all file descriptors except standard streams (0, 1, 2) and explicitly passed sockets before spawning workers.

3.  **State Desynchronization (Split-Brain)**:
    *   *Risk*: If a child worker crashes and restarts, or if communication fails, the parent's kernel state and the worker's application state can diverge (e.g., a DHCP client crashes but the default route remains configured in the kernel).
    *   *Mitigation*: Actively supervise worker lifecycles. On worker crash/exit, the parent must tear down any transient network configurations (routes, IP addresses) associated with that worker before restarting it.

4.  **Resource Exhaustion (Denial of Service)**:
    *   *Risk*: A compromised worker could flood the Unix Domain socket with requests, causing memory exhaustion or blocking PID 1 execution.
    *   *Mitigation*: Enforce strict rate-limiting, non-blocking reads, and maximum payload buffer bounds on the IPC server.

