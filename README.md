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

- **Init Process (PID 1)**: Mounts virtual filesystems (`/proc`, `/sys`, `/dev`, `/run`), reaps orphaned processes, handles termination signals, integrates with hardware watchdog timers (`/dev/watchdog`) with asynchronous health checks, and monitors ACPI power button events to gracefully power down the virtual machine.
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
You will also need `cpio`, `qemu-system-x86_64`, `parted`, `mtools`, `binutils`, `systemd-boot-efi`, `ovmf`, `erofs-utils` (for `mkfs.erofs`), and `make`.

### Building and Packaging

Compile the static release binary, package it into a compressed `cpio` initramfs archive, and wrap it into a bootable UEFI VM disk image:
```bash
make
```
This generates the bootable raw VM disk image at `target/x86_64/trimrouter.img` (which bundles the Unified Kernel Image `EFI/BOOT/BOOTX64.EFI` containing the kernel, initramfs, and `trimrouter` binary, plus the full kernel module tree in `modules.erofs`).

#### Custom Configuration Override
Build the image with a custom configuration:
```bash
make TRIMROUTER_CONFIG=path/to/custom_config.toml
```

Configuration is read from the TOML configuration file `/boot/config/trimrouter.toml` on the boot partition of the disk image:

```toml
[network]
# The MAC addresses used to map the WAN and LAN interfaces (Required)
wan_mac = "52:54:00:12:34:56"
lan_mac = "52:54:00:12:34:57"

# Optional static LAN gateway IP and subnet (default: "192.168.1.1/24")
lan_ip = "192.168.1.1/24"

[logging]
# Optional maximum size for active log before rotation in MiB (default: 100)
max_log_size_mb = 100
# Optional log level filter: "error", "warn", "info", "debug", "trace" (default: "info")
level = "info"

[system]
# Optional reboot delay in seconds on panic (defaults to infinite hang if omitted)
# reboot_delay = 10
# Optional hardware watchdog supervision (/dev/watchdog) (default: true)
# watchdog = true
```

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

`trimrouter` includes a fully unprivileged pipeline to build bootable raw FAT32 SD card images for Raspberry Pi hardware (Pi Zero through Pi 4, including Compute Modules):

```bash
make image-<arch>   # e.g. make image-arm64, make image-armhf
```

This outputs a bootable flash image at `target/<arch>/trimrouter.img`.

### Flash to Hardware

```bash
sudo dd if=target/arm64/trimrouter.img of=/dev/sdX bs=4M status=progress conv=fsync
```

*(Replace `/dev/sdX` with the target block device. The log partition is created automatically on first boot.)*

### Test with QEMU (ARM64)

Boot using QEMU's generic `virt` machine for full virtio network support:

```bash
qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a53 \
    -m 1024 \
    -kernel target/arm64/pi_boot/kernel8.img \
    -initrd target/arm64/pi_initramfs.cpio.gz \
    -drive file=target/arm64/trimrouter.img,format=raw,media=disk,if=virtio \
    -device virtio-net-pci,netdev=wan0,mac=52:54:00:12:34:56 \
    -netdev user,id=wan0 \
    -device virtio-net-pci,netdev=lan0,mac=52:54:00:12:34:57 \
    -netdev user,id=lan0 \
    -append "console=ttyAMA0 root=/dev/ram0 rdinit=/init quiet" \
    -nographic
```
