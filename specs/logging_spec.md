# Specification: Logging

This specification describes how `trimrouter` captures, formats, persists, and rotates log output from PID 1 and all worker services.

---

## 1. Log File

All log output is written to a **single unified log file** on the log partition:

| File | Description |
| :--- | :--- |
| `/var/log/system.log` | Active log — all services and PID 1 init output, in chronological order |

The file is opened in **append mode** so that output accumulates across worker restarts within the same boot session.

---

## 2. Log Line Format

Each line written to `system.log` is stamped and tagged by PID 1 before being written:

```
[<UTC timestamp>] [<service>] <message>
```

Example:

```
[2026-08-14T14:30:00Z] [init] Mounted /boot successfully.
[2026-08-14T14:30:01Z] [dhcp-client] Sending DHCPDISCOVER on wan...
[2026-08-14T14:30:01Z] [dns-forwarder] Listening on 192.168.1.1:53
[2026-08-14T14:30:02Z] [dhcp-client] DHCPOFFER received from 10.0.2.2
```

Timestamps are UTC in ISO 8601 format. The `[service]` tag corresponds to one of: `init`, `dhcp-client`, `dhcp-server`, `dns-forwarder`, `sntp`.

Individual service output can be filtered from the unified log with any text tool, e.g.:

```bash
grep '\[dhcp-client\]' system.log
```

---

## 3. Log Rotation

PID 1 manages log rotation entirely in-process. No external tools or cron daemon are required.

### 3.1 Rotation Triggers

`system.log` is rotated when **either** of the following conditions is met:

| Trigger | Condition | Default |
| :--- | :--- | :--- |
| **Size limit** | The active log file reaches or exceeds the configured maximum size | `100 MiB` (configurable) |
| **Daily rollover** | Midnight UTC is crossed while the system is running | Fixed — once per calendar day |

PID 1 evaluates the size trigger on every write. The daily trigger is evaluated by comparing the current UTC date against the date recorded at the last rotation (or boot). Both triggers are checked independently; whichever fires first causes the rotation.

### 3.2 Rotation Procedure

1. **Check free space**: Query the log partition's available bytes (`statvfs`). If available space is less than `max_log_size`, run the **space reclamation** step (§3.3) before proceeding.
2. **Rename active log**: Rename `system.log` → `system.<timestamp>.log`, where `<timestamp>` is the ISO 8601 UTC datetime at the moment of rotation (e.g. `system.2026-08-14T143000Z.log`). A timestamp suffix is used instead of a counter to allow multiple size-triggered rotations within the same calendar day.
3. **Open new active log**: Create a fresh `system.log` in append mode and continue writing.

### 3.3 Space Reclamation

Before creating a new rotated log file, if available space on the log partition is below `max_log_size`, PID 1 deletes rotated `system.<timestamp>.log` files in order from **oldest to newest** until sufficient space is freed or no more rotated files remain.

The age of a rotated log file is determined by the UTC timestamp embedded in its filename. The active `system.log` file is **never** deleted by the reclamation process.

If reclamation cannot free enough space (all rotated files have already been deleted), PID 1 logs a warning to the console and **stops writing** to the log partition until the next boot.

> [!NOTE]
> FAT32 supports file modification and creation timestamps with 2-second resolution. PID 1 must use the filename timestamp (not FAT32 metadata) as the authoritative sort key for reclamation order, since FAT32 timestamps can be unreliable across timezones and host operating systems.

---

## 4. Configuration

The size limit is configurable in `trimrouter.toml` under the `[logging]` section:

```toml
[logging]
max_log_size_mb = 100   # (Optional: defaults to 100 MiB)
```

If the `[logging]` section or `max_log_size_mb` key is absent, the default of `100 MiB` is used.

---

## 5. Console Fallback

If the log partition is not mounted (mount failure at boot), PID 1 falls back to writing all captured output directly to its own stdout (the system console), preserving the same `[timestamp] [service] message` format.

Log rotation and reclamation are disabled in console-only mode.

---

## 6. Write Buffering & SD Card Wear

PID 1 does **not** implement application-level write buffering and does **not** call `fsync` on every log line. All write coalescing is delegated to the **Linux kernel page cache**, which batches multiple writes to the same page into a single flash write before flushing — more efficiently than any userspace buffer can achieve.

Because trimrouter is PID 1 and mounts `/proc` at startup, it configures the kernel writeback parameters directly via `/proc/sys/vm/` before opening the log file:

| Parameter | Path | Value |
| :--- | :--- | :--- |
| Dirty page expiry | `/proc/sys/vm/dirty_expire_centisecs` | `3000` (30 s) |
| Writeback interval | `/proc/sys/vm/dirty_writeback_centisecs` | `500` (5 s) |

These are set explicitly rather than relying on kernel defaults, since compile-time defaults vary across kernel configurations and distributions. Setting them at startup guarantees consistent flush behaviour regardless of the underlying kernel build.

These values ensure dirty log pages are flushed to flash within at most 35 seconds (30 s expiry + up to 5 s writeback check interval), regardless of log write frequency.

`fsync` is called only on two occasions:
1. **Before rotation** — to ensure the completed log file is fully persisted before it is renamed.
2. **On clean shutdown** — to flush any remaining buffered lines before the process exits.

> [!NOTE]
> On an unclean power-off, up to 35 seconds of log output may be lost. This is an accepted trade-off for a router where SD card longevity outweighs log completeness.

