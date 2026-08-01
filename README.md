# trimrouter

`trimrouter` is a lightweight, self-contained NATting router written in Rust, designed to run as the initialization process (PID 1) in a minimalist Linux virtual machine or bare-metal environment. 

It manages virtual filesystems, signal forwarding, orphan reaping, and launches an asynchronous network controller managing routing, firewall, and local network services without requiring any userspace helper utilities (such as `ip`, `iptables`, or `dnsmasq`).

---

## Warning & Disclaimer
> [!WARNING]
> **DO NOT TRUST OR USE THIS SOFTWARE IN PRODUCTION.**
> This project is an experimental prototype and learning exercise. It has not undergone formal security audits. Under no circumstances should this software be trusted to secure any real-world networks or production systems.

---

## Key Features

- **Init Process (PID 1)**: Mounts virtual filesystems (`/proc`, `/sys`, `/dev`, `/run`), reaps orphaned processes, handles termination signals, and monitors ACPI power button events to gracefully power down the virtual machine.
- **Kernel Module Autoloading**: Bundles a built-in `modprobe` emulator; listens for `NETLINK_KOBJECT_UEVENT` broadcasts and automatically loads required kernel modules at startup and on device hotplug, with no external `modprobe` binary required.
- **Dynamic Interface Lifecycle**: Monitors Linux kernel Netlink multicast link events to hotplug interfaces, rename them dynamically by MAC, configure IP addresses, and orchestrate service lifecycles.
- **Kernel-Space NAT & Routing**: Interacts directly with the Linux kernel using Netlink sockets (`NETLINK_ROUTE` and `NETLINK_NETFILTER`) to manage interface states, IP assignments, default routes, and Source NAT (Masquerading).
- **Stateful Firewall**: Implements an `nftables` input filter chain that drops all unsolicited incoming traffic on the WAN interface by default.
- **Embedded Network Services**:
  - **DHCP Client (WAN)**: Handles dynamic leases and unicast renewals on the WAN interface over raw sockets.
  - **DHCP Server (LAN)**: Manages LAN lease allocations, address conflicts, and lease release/decline requests.
  - **DNS Forwarder/Proxy (LAN)**: Listens for DNS queries on the LAN interface and forwards them to the dynamic DNS servers obtained from the WAN lease.
  - **NTP Client (SNTP)**: Periodically synchronizes the router system time from time.google.com.

---

## Getting Started

### Prerequisites

You need a Rust toolchain and the target `x86_64-unknown-linux-musl` installed:
```bash
rustup target add x86_64-unknown-linux-musl
```
You will also need `cpio`, `qemu-system-x86_64`, `parted`, `mtools`, and standard build utilities (`make`, `gcc`).

### Building and Packaging

Compile the static release binary and package it into a compressed `cpio` initramfs archive:
```bash
make
```
This generates `target/x86_64/initramfs.cpio.gz` which contains the statically linked `trimrouter` binary mapped to `/init` and required Linux kernel modules.

Configuration is passed via kernel command-line parameters:
- `trimrouter.wan_mac=<mac>` — **Required.** MAC of the WAN interface.
- `trimrouter.lan_mac=<mac>` — **Required.** MAC of the LAN interface.
- `trimrouter.lan_ip=<cidr>` — Optional static LAN IP (default: `192.168.1.1/24`).
- `trimrouter.reboot_delay[=N]` — Optional. Reboot after `N` seconds on panic instead of hanging (standalone flag defaults to 10s).

### Testing

#### 1. Integration Test Suite
To run the automated integration tests that boot the target image inside a micro-QEMU VM to verify routing, DNS forwarding, firewall drops, and DHCP renewals:
```bash
make test
```

#### 2. Interactive QEMU Emulation
To boot the image interactively inside QEMU and inspect console output:
```bash
make qemu
```
*Press `Ctrl+A` then `X` to exit the QEMU console.*

---

## Raspberry Pi Image Pipeline

`trimrouter` includes a fully unprivileged pipeline to build bootable raw FAT32 SD card images for Raspberry Pi hardware (Zero 2 W / Pi 3 / Pi 4 / Pi 5):
```bash
make image
```
This outputs a bootable flash image at `target/trimrouter.img`. For full instructions on hardware deployment and ARM emulation testing, refer to the [specs/sd_card_image_spec.md](specs/sd_card_image_spec.md) document.
