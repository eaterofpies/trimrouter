# Specification: `trimrouter`

`trimrouter` is a lightweight, self-contained Rust application designed to run as the initialization process (PID 1) in a minimalist Linux container or virtual machine. It acts as a basic NATting router, providing essential network services (DHCP client/server, DNS forwarding, and IP masquerading) while performing standard init process duties. 

Crucially, **no other files** will be present on the target filesystem other than the Linux kernel and this binary (statically linked). It requires zero external helper utilities (no `iptables`, `nft`, `ip`, `dnsmasq`, `udev`, etc.) and configures itself via kernel command line parameters or automatic interface detection.

> [!NOTE]
> **Status: Implemented.** Core routing, DHCP, DNS, SNTP, NAT, privilege separation, interface lifecycle, partition layout, and structured logging with rotation and reclamation are all implemented.

---

## 1. System Architecture

```
             [ Start ]
                 │
                 ▼
         [ Init Manager ] ──────────────► [ Orphan Reaper Loop ]
   (Mount VFS, Parse TOML Config)       (Continuous zombie collection)
                 │
                 ▼
     [ Network Initialization ]
      (Enable IPv4 Forwarding)
                 │
                 ▼
       [ Service Controller ]
        ├── DHCP WAN Client (Raw AF_PACKET)
        ├── DHCP LAN Server (Raw AF_PACKET)
        ├── DNS Forwarder (Tokio UDP)
        └── NAT/Netlink Controller
```

---

## 2. Core Requirements

### 2.1 PID 1 (Init) Responsibilities

1. **Virtual Filesystem (VFS) Mounting**: Mount `/proc`, `/sys`, `/dev` (devtmpfs), and `/run` (tmpfs). Boot and log partition mounting is specified in [`partition_layout_spec.md`](partition_layout_spec.md).
2. **Signal Handling**: Traps `SIGINT`, `SIGTERM`, `SIGPWR`. On receipt, logs a teardown message and calls `nix::sys::reboot::reboot(RebootMode::RB_POWER_OFF)` to halt. Full network/firewall teardown before poweroff is not yet implemented.
3. **Orphan Reaping**: Runs a non-blocking reaping loop using `waitpid` to prevent zombie processes.
4. **Configuration Extraction**: Reads and parses `/boot/config/trimrouter.toml`. `wan_mac` and `lan_mac` are strictly required — if either is missing or the file cannot be read, PID 1 panics (halts). See §3 for the full configuration schema.
5. **Kernel Module Autoloading**: Probes required modules at startup via a built-in `modprobe` emulator. Listens for `NETLINK_KOBJECT_UEVENT` broadcasts and loads modules matching received `modalias` strings by resolving `modules.dep` with cycle detection and recursion depth caps (`MAX_DEP_RECURSION_DEPTH = 64`), non-recursive polynomial wildcard matching (eliminating ReDoS / stack exhaustion), and path traversal sanitization. The binary also acts as a drop-in `modprobe` replacement when invoked as `argv[0] == "modprobe"`.
6. **Panic Handling**: Registers a custom panic hook via `std::panic::set_hook`. On panic, logs the traceback to stdout and hangs indefinitely (to avoid an unclean kernel panic) rather than exiting.
7. **ACPI Power Button**: Monitors `/dev/input/event0`–`event31` via the `evdev` crate with a dynamic background discovery loop for `KEY_POWER`, `KEY_POWER2`, or `KEY_SLEEP` key-down events to trigger a clean shutdown, since no `acpid` or `systemd-logind` is present.

### 2.2 Routing, Address & NAT Configuration

`trimrouter` configures the kernel entirely via Netlink — no external binaries required.

#### 2.2.1 IP Forwarding
Writes `"1"` to `/proc/sys/net/ipv4/ip_forward` at startup.

#### 2.2.2 Netlink Interface & Route Management (`NETLINK_ROUTE`)

1. **Loopback (`lo`)**: Brings link `UP`. The kernel assigns `127.0.0.1/8` automatically.
2. **LAN interface**: Brings link `UP`, clears existing addresses, assigns the static IP (e.g. `192.168.1.1/24`), and adds the subnet route.
3. **WAN interface**: Brings link `UP`. Address is assigned dynamically by the DHCP client.
4. **Dynamic WAN routing**:
   - *Lease obtained*: Assigns the leased IP, adds a default gateway route (`0.0.0.0/0`). Replaces the route if the lease changes.
   - *Lease lost/expired*: Removes the leased IP and default route to prevent routing blackholes.

#### 2.2.3 Netfilter / nftables NAT Configuration (`NETLINK_NETFILTER`)

Creates an IPv4 table named `trimrouter` containing two chains:

**`nat_postrouting`** — type `nat`, hook `postrouting`, priority `100`, policy `accept`:
- Masquerade rule: matches outbound traffic on the WAN interface (`oif`) and applies `masquerade`.

**`filter_input`** — type `filter`, hook `input`, priority `0`, policy `drop`:
- Drop `ct state invalid`
- Accept `iif == lo`
- Accept `iif == lan`
- Accept UDP `dport 68` on WAN (DHCP client replies)
- Accept ICMP on all interfaces
- Accept `ct state { established, related }`
- Drop all other inbound traffic

### 2.3 Network Services

| Service | Spec |
| :--- | :--- |
| DHCP Client (WAN) | [`dhcp_client_spec.md`](dhcp_client_spec.md) |
| DHCP Server (LAN) | [`dhcp_server_spec.md`](dhcp_server_spec.md) |
| DNS Forwarder | [`dns_forwarder_spec.md`](dns_forwarder_spec.md) |
| NTP Client (SNTP) | [`sntp_client_spec.md`](sntp_client_spec.md) |
| Interface Lifecycle | [`interface_di_spec.md`](interface_di_spec.md) |

### 2.4 Privilege Separation

Network-facing services run as unprivileged child processes isolated via chroot, UID/GID dropping, capability clearing, and seccomp-BPF filters. See [`privilege_separation_spec.md`](privilege_separation_spec.md).

### 2.5 Logging

Unified logging to `/var/log/system.log` on the dedicated log partition, with log rotation and oldest-first space reclamation. See [`logging_spec.md`](logging_spec.md).

---

## 3. Configuration

Settings are read from `/boot/config/trimrouter.toml` on the boot partition:

```toml
[network]
wan_mac = "52:54:00:12:34:56"   # Required — maps WAN interface, renames it to "wan"
lan_mac = "52:54:00:12:34:57"   # Required — maps LAN interface, renames it to "lan"
lan_ip = "192.168.1.1/24"       # Optional — defaults to "192.168.1.1/24"
backup_lan_ip = "10.0.0.1/24"   # Optional — defaults to "10.0.0.1/24"

[system]
reboot_delay = 10               # Optional — seconds before reboot on panic (omit for infinite hang)
```

If `wan_mac` or `lan_mac` is missing, invalid (e.g. zero, broadcast, multicast, or identical MACs), if `lan_ip`/`backup_lan_ip` are invalid CIDRs (or overlap with each other), or if the configuration file cannot be read, PID 1 prints a descriptive configuration error and halts.

---

## 4. Compilation

The binary must be compiled as a fully static MUSL target. See the README for build and test instructions.
