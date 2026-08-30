# Specification: Architectural Non-Goals & Rejected Designs

This document explicitly tracks architectural features, designs, and capabilities that have been evaluated and designated as **Non-Goals** ("Won't Do") for `trimrouter`, along with their respective technical rationales.

---

## 1. A/B Dual-Boot Partition Redundancy & Over-The-Air (OTA) Updates

*   **Status**: **Rejected / Non-Goal**
*   **Rationale**:
    *   `trimrouter` is engineered as an **immutable, single-image appliance** packaged as a self-contained disk image (`trimrouter-<arch>.img.xz`).
    *   Introducing an A/B dual-partition bootloader scheme (e.g. `boot_a`, `boot_b`, boot counter state flags, and atomic rollback scripts) requires a persistent, writable state partition to track boot health, complex bootloader integration (`systemd-boot` / U-Boot scripting), and update daemons.
    *   Operating as a single bootable read-only filesystem ensures zero configuration drift, deterministic hardware booting, and simple image flashing directly to SD cards or virtual disks.

---

## 2. Runtime Configuration Hot-Reloading (`SIGHUP` / In-Place Mutations)

*   **Status**: **Rejected / Non-Goal**
*   **Rationale**:
    *   `trimrouter` has **no mechanism (and intentionally will not provide any mechanism) to modify configuration at runtime**.
    *   The boot partition containing `/boot/config/trimrouter.toml` is mounted read-only (`MS_RDONLY`), and the entire root filesystem is immutable EROFS. There are no writable configuration directories, management daemons, administrative shells, or remote configuration APIs.
    *   Configuration can only be altered offline (e.g. by editing the configuration file directly on the storage media while the device is powered down) or passed via kernel command-line parameters at boot time.
    *   Because the running system has no writable access to its configuration, runtime hot-reloading (such as `SIGHUP` handlers) is fundamentally unsupported. All changes take effect exclusively upon the next hardware boot.

---

## 3. Per-Service Fine-Grained Seccomp-BPF Filters

*   **Status**: **Rejected / Non-Goal**
*   **Rationale**:
    *   All four sandboxed worker services (`dhcp-client`, `dhcp-server`, `dns-forwarder`, and `sntp-client`) execute on the **Tokio asynchronous runtime** and communicate exclusively via Unix domain sockets.
    *   Over 95% of required system calls (`epoll_*`, `futex`, `eventfd2`, `clock_gettime`, `nanosleep`, `read`, `write`, memory management) are mandatory across all services.
    *   Dangerous syscalls (`socket`, `bind`, `connect`, `open`, `openat`, `execve`, `fork`, `clone`, `mount`, `reboot`, etc.) are already universally blocked by the single shared Seccomp-BPF allowlist in `src/services/utils.rs`.
    *   Maintaining separate per-service syscall allowlists across three CPU architectures (`x86_64`, `aarch64`, `armhf`) increases maintenance overhead and introduces crash fragility without measurable security gains.

