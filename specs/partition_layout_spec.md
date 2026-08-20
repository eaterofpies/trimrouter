# Specification: Disk Image Partition Layout

This specification describes the on-disk partition structure of the `trimrouter` bootable raw image (`target/<arch>/trimrouter.img`), the contents placed in each partition, and how the init process locates and mounts both partitions at runtime.

> [!NOTE]
> **Status: Implemented.** MBR partitioning, label scanning, partition table reread, and fatfs-based formatting are all fully in place and verified in integration tests.

---

## 1. Partition Table Structure

All `trimrouter` disk images use a **Master Boot Record (MBR / msdos)** partition table. The base image ships with **one partition only** — the log partition does not exist in the image file and is created on first boot.

**Image file layout** (as distributed):

| Region | Byte Offset | Size | Filesystem | Flags |
| :--- | :--- | :--- | :--- | :--- |
| MBR + Alignment Gap | `0x00000000` (`0`) | `1 MiB` | — | — |
| **Partition 1 — Boot** | `0x00100000` (`1 MiB`) | `120 MiB` | FAT32 (`vfat`) | Active (bootable) |
| Unallocated | `0x07900000` (`121 MiB`) | `7 MiB` | — | — |
| **Total Image File Size** | — | `128 MiB` | — | — |

**Post-first-boot layout** (after `trimrouter` runs on the physical drive):

| Region | Byte Offset | Size | Filesystem | Flags |
| :--- | :--- | :--- | :--- | :--- |
| MBR + Alignment Gap | `0x00000000` (`0`) | `1 MiB` | — | — |
| **Partition 1 — Boot** | `0x00100000` (`1 MiB`) | `120 MiB` | FAT32 (`vfat`) | Active (bootable) |
| **Partition 2 — Log** | `0x07900000` (`121 MiB`) | Remainder of drive | FAT32 (`vfat`) | — |

On first boot, `trimrouter` writes the partition 2 MBR entry and formats it as FAT32, claiming all space from 121 MiB to the last sector of the physical drive.

The `1 MiB` alignment gap before the first partition is standard practice to ensure compatibility with both legacy BIOS systems and Raspberry Pi GPU firmware, which both expect the MBR at sector 0 and the boot partition at an aligned offset.

Both partitions use **FAT32** to ensure the log partition can be read and written from any desktop operating system (Linux, Windows, macOS) without additional drivers.

---

## 2. Build-Time Image Construction

The raw disk image is constructed by the `scripts/build_image.sh` script, invoked by the Makefile targets (`make image-<arch>`), using fully unprivileged tooling (no `sudo`, loop device, or `chroot`):

1. **Allocate blank image**: `dd` writes `128 MiB` of zeros into the raw block file.
2. **Write partition table**: `parted` stamps an MBR partition table with a single primary FAT32 partition:
   - Partition 1 (boot): `1 MiB` → `121 MiB` (120 MiB fixed)
3. **Format boot partition**: `mformat` (from `mtools`) formats partition 1 as FAT32, referenced by byte offset (e.g., `target/<arch>/trimrouter.img@@1M`).
4. **Stamp volume label**: `mlabel` writes the fixed volume label `TRIMROUTER` into the FAT32 boot sector of partition 1.
5. **Copy boot files**: `mcopy` (from `mtools`) copies all boot payloads directly into the FAT32 boot partition without mounting it.

No log partition is created at build time. The `7 MiB` of space after the boot partition in the image file remains unallocated.

---

## 3. Boot Partition Contents

The FAT32 boot partition stores all files required for kernel boot and system startup. The exact contents differ per architecture:

### 3.1 x86_64 (QEMU VirtIO / Generic)

| Path in Partition | Source | Description |
| :--- | :--- | :--- |
| `/vmlinuz` | `target/x86_64/test_boot/vmlinuz` | Linux kernel image (extracted from Debian generic package) |
| `/initramfs.cpio.gz` | `target/x86_64/initramfs.cpio.gz` | Compressed initramfs CPIO archive containing the `trimrouter` binary as `/init` and kernel modules |
| `/cmdline.txt` | Generated at build time | Kernel command line: `console=ttyS0 quiet panic=-1 net.ifnames=0` |
| `/config/trimrouter.toml` | `config/trimrouter.toml` (or `TRIMROUTER_CONFIG` override) | Router TOML configuration file |
| `/modules.erofs` | `target/x86_64/modules.erofs` | Read-only EROFS compressed image containing the full kernel module tree |

### 3.2 arm64 / armhf (Raspberry Pi)

| Path in Partition | Source | Description |
| :--- | :--- | :--- |
| `/bootcode.bin` | Raspberry Pi bootloader `.deb` | Stage 2 GPU bootloader (loads `start.elf`) |
| `/start.elf` | Raspberry Pi bootloader `.deb` | GPU firmware blob |
| `/fixup.dat` | Raspberry Pi bootloader `.deb` | GPU memory split configuration |
| `/kernel8.img` (arm64) or `/kernel.img` (armhf) | Raspberry Pi kernel `.deb` | Linux kernel image for the target architecture |
| `/pi_initramfs.cpio.gz` | `target/<arch>/pi_initramfs.cpio.gz` | Compressed initramfs CPIO archive containing the `trimrouter` binary as `/init` and kernel modules |
| `/config.txt` | Generated at build time | Raspberry Pi GPU firmware configuration: sets kernel file, 64-bit mode, initramfs load address, UART, and audio settings |
| `/cmdline.txt` | Generated at build time | Kernel command line: `console=serial0,115200 console=tty1 root=/dev/ram0 rdinit=/init quiet panic=-1 net.ifnames=0` |
| `/bcm*.dtb` | Raspberry Pi kernel `.deb` | Device Tree Blobs for all supported Pi board variants |
| `/overlays/` | Raspberry Pi kernel `.deb` | Directory of Device Tree overlay files |
| `/config/trimrouter.toml` | `config/trimrouter.toml` (or `TRIMROUTER_CONFIG` override) | Router TOML configuration file |

---

## 4. Runtime Partition Mounting

At startup, `trimrouter` running as PID 1 mounts both partitions before network configuration begins.

### 4.1 Boot Partition (Partition 1)

| Property | Value |
| :--- | :--- |
| **Mount Point** | `/boot` |
| **Filesystem Type** | `vfat` |
| **Mount Flags** | `MS_RDONLY` (read-only) |
| **Config File Path** | `/boot/config/trimrouter.toml` |

The boot partition is always mounted **read-only**. The router does not write to or modify it at runtime.

### 4.2 Log Partition (Partition 2)

| Property | Value |
| :--- | :--- |
| **Mount Point** | `/var/log` |
| **Filesystem Type** | `vfat` |
| **Mount Flags** | Read-write (no `MS_RDONLY`) |

The log partition is mounted **read-write** at `/var/log` and is accessible from any desktop operating system by inserting the SD card or disk directly.

> [!NOTE]
> FAT32 does not support Unix ownership, permissions, or symbolic links. Log files must not rely on file ownership or mode bits. Log rotation must track file size rather than inode metadata.

### 4.3 Centralized Logging via PID 1

Worker services do **not** write to the log partition directly. Instead, each worker process writes all log output to its own **stdout**. PID 1 captures this output via a pipe created at spawn time, reads it asynchronously, prefixes each line with a `[service-name]` tag, and is the **sole writer** to a **single unified log file**.

This design has several advantages over per-service log files:

- **Single writer**: Only PID 1 writes to FAT32, eliminating concurrent-write corruption risk.
- **Chronological ordering preserved**: All events from all services are interleaved in exact time order in one file, making cross-service debugging straightforward without mentally merging separate logs.
- **Simpler capacity math**: One active file means no `× num_services` multiplier on the size limit.
- **Simpler seccomp**: Workers need no `open`, `write`, or `close` syscalls for logging — their seccomp allowlist stays minimal.
- **No bind-mounts**: No per-worker mount lifecycle to manage; chroot setup is unchanged.

#### 4.3.1 Log File

PID 1 maintains a single active log file on the log partition:

| File | Description |
| :--- | :--- |
| `/var/log/system.log` | Active unified log — all services and PID 1 init output |

The file is opened in **append mode** so that logs accumulate across worker restarts within the same boot session.

Each line written by PID 1 is prefixed with a `[service]` tag so individual service output can be filtered with any text tool:

```
[2026-08-14T14:30:00Z] [init] Mounted /boot successfully.
[2026-08-14T14:30:01Z] [dhcp-client] Sending DHCPDISCOVER on wan...
[2026-08-14T14:30:01Z] [dns-forwarder] Listening on 192.168.1.1:53
[2026-08-14T14:30:02Z] [dhcp-client] DHCPOFFER received from 10.0.2.2
```

#### 4.3.2 Pipe Capture & Write Loop

For each worker, PID 1:

1. Creates a `pipe()` before spawning the worker.
2. Passes the **write end** of the pipe as the worker's `stdout` (fd 1) and `stderr` (fd 2), capturing all output.
3. Closes the write end in the parent after the fork.
4. Monitors the **read end** of the pipe alongside all other worker pipes using a single async event loop (`tokio::io::AsyncRead`).
5. On each complete line received, prepends a UTC timestamp and `[service-name]` tag, then appends the line to `/var/log/system.log`.
6. Closes the read end when the worker exits (pipe EOF). PID 1's own output is written to the same file directly.

If the log partition is not mounted (mount failure at boot), PID 1 falls back to writing all captured output directly to its own stdout (the system console), preserving the same prefixed format.

Log rotation, space reclamation, and configuration are covered in the **[Logging Specification](logging_spec.md)**.

### 4.4 Boot Device Identification

Baked-in device paths (e.g. `/dev/mmcblk0p1`) are not used because the kernel name assigned to a storage device is unpredictable — the same SD card may appear as `/dev/mmcblk0`, `/dev/sda`, or `/dev/sdb` depending on the host hardware, USB adapter, or attached peripheral count. This is the same problem live CDs and bootable USB sticks face, and the solution is the same: scan all block devices for a known volume label embedded in each partition's boot sector.

At build time, the boot partition is stamped with the fixed FAT32 volume label `TRIMROUTER` (see §2). At runtime, PID 1 identifies the boot partition by:

1. **Enumerate block devices**: Read `/sys/class/block/` to list every block device and its partitions.
2. **Attempt FAT32 parse**: Open each partition device and use the `fatfs` crate to parse it as a FAT filesystem. Any partition that is not a valid FAT volume is skipped.
3. **Match volume label**: Read the FAT32 volume label via `fs.volume_label()`. If the trimmed value equals `TRIMROUTER`, this is the boot partition.
4. **Identify parent disk**: Record the parent disk of the matched partition (e.g. `/dev/mmcblk0` for `/dev/mmcblk0p1`). The log partition device node (`p2`) is derived from this disk after first-boot creation in §5.

The scan iterates all partitions and accepts the first match.

> [!WARNING]
> This approach is ambiguous if more than one storage device carrying a `TRIMROUTER`-labelled partition is attached at the same time (e.g. an internal SSD and an SD card both containing trimrouter installs). In that case the wrong partition may be selected. This is a known limitation and is considered out of scope for now.

### 4.5 Timeout & Failure Behavior

| Partition | Poll Interval | Timeout | Failure Behavior |
| :--- | :--- | :--- | :--- |
| Boot (P1) | `100 ms` | `15 seconds` | Fatal `panic` — init halts |
| Log (P2) — first boot | — (single attempt) | — | Non-fatal warning — router continues without persistent logging |
| Log (P2) — subsequent boots | — (single attempt) | — | Non-fatal warning — router continues without persistent logging |

If the log partition fails to mount (e.g., filesystem corruption), `trimrouter` logs a warning to the console and continues booting. Persistent logging is degraded to console-only for that session.

### 4.6 Mount Sequence in Init

Both partitions are mounted as part of the ordered PID 1 startup sequence, after virtual filesystems are up (so `/dev` is populated) and before configuration is loaded:

```
1. mount_virtual_filesystems()          → /proc, /sys, /dev (devtmpfs), /run (tmpfs)
2. trigger_uevents()                    → early hardware coldplug discovery
3. load_required_modules()              → early filesystem & netfilter modules
4. wait_for_boot_partition()            → scans labels and returns when TRIMROUTER is found
5. ensure_log_partition_in_mbr()        → updates MBR and re-reads partition table if needed
6. mount_boot_partition()               → mounts /boot (vfat, read-only)
7. activate_boot_modules()              → mounts /boot/modules.erofs over /lib/modules & triggers coldplug uevents
8. setup_log_partition()                 → mounts /var/log (formats FAT32 first if mount fails)
9. configure_network()                  → interfaces, NAT, services
   └─ for each worker spawn:
      open log file                     → /var/log/system.log (append mode)
      create pipe()                     → worker stdout/stderr → pipe read end
      fork worker                       → stdout/stderr → pipe write end
      async read loop                   → pipe read end → log file
```

---

## 5. First-Boot Log Partition Creation

The base image ships with no log partition — only the boot partition exists in the image file. When booted for the first time on a physical drive, `trimrouter` detects the absence of partition 2 and creates it, formatted as FAT32, to fill all unallocated space on the drive.

### 5.1 Creation Trigger

The creation step runs when partition 2 does **not** exist on the parent disk identified in §4.4. No sentinel file is required — the presence or absence of the partition is the idempotency check. On all subsequent boots the partition exists and this step is skipped entirely with zero overhead.

### 5.2 Creation Operations

The creation sequence executes synchronously, after the boot partition is mounted but before any services start:

1. **Write MBR partition 2 entry**: Use the `mbrman` crate to parse the existing MBR, insert a new FAT32 LBA partition entry (`type 0x0C`) starting at sector `247808` (121 MiB ÷ 512 bytes/sector) and extending to the last usable sector of the disk. Write the updated MBR back to disk and issue `BLKRRPART` to instruct the kernel to re-read the updated partition table.
2. **Format as FAT32**: Attempt to mount the partition. If the mount fails (e.g. `EINVAL` on an unformatted device), format it as FAT32 using the `fatfs` crate, then retry the mount. The partition is created at its full final size so no later resize step is ever needed.
3. **Mount**: Mount the newly formatted partition read-write at `/var/log`.

> [!IMPORTANT]
> If either step 1 or step 2 fails, `trimrouter` logs a warning and continues booting without a log partition. Persistent logging is degraded to console-only for that session. The operation must not corrupt or modify partition 1 (the boot partition) in any way.

### 5.3 Implementation Note

The implementation uses the `mbrman` crate for structured MBR read/write and the `fatfs` crate for both volume label scanning and log partition formatting. The contract upheld:
- The partition-existence check (`/sys/class/block/<name>`) ensures idempotency with no additional state.
- The mount-first approach eliminates unnecessary formatting on subsequent boots.
- The FAT32 format creates the filesystem at full drive capacity in one step — no in-place resize is ever required.
- The MBR is written before `/dev/vda1` is mounted so `BLKRRPART` succeeds (the kernel rejects partition table rereads if any partition on the disk is mounted).

---

## 6. Test Image Isolation

Integration tests build a dedicated image (`target/<arch>/trimrouter-test.img`) that is strictly isolated from the production image:

| Property | Production Image | Test Image |
| :--- | :--- | :--- |
| **Filename** | `target/<arch>/trimrouter.img` | `target/<arch>/trimrouter-test.img` |
| **`/init` binary** | `trimrouter` (router binary) | `integration_test` (test harness binary) |
| **Config source** | `TRIMROUTER_CONFIG` (default: `config/trimrouter.toml`) | Always `config/trimrouter.toml` (hard-coded) |
| **Initramfs** | `initramfs.cpio.gz` | `initramfs-test.cpio.gz` |

The test image always packages the repository-default `config/trimrouter.toml` regardless of any `TRIMROUTER_CONFIG` override, ensuring user configuration changes do not interfere with integration test verification.
