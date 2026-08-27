use super::system::MountOps;
use crate::error::RouterError;
use log::{debug, info, warn};
use nix::mount::MsFlags;
use std::fs::{self, DirEntry, File, OpenOptions};
use std::io::{Error as IoError, Seek, SeekFrom};
use std::os::unix::io::{AsFd, AsRawFd};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const BOOT_MOUNT_POINT: &str = "/boot";
const BOOT_MOUNT_TIMEOUT: Duration = Duration::from_secs(15);
const BOOT_MOUNT_POLL_INTERVAL: Duration = Duration::from_millis(100);

// MBR Layout Constants
const MBR_SECTOR_SIZE: usize = 512;
const MBR_PART_TYPE_FAT32_LBA: u8 = 0x0C;

// Device node polling constants
const DEV_NODE_POLL_RETRIES: u32 = 50;
const DEV_NODE_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn get_partition_sectors(p2_name: &str) -> Result<u64, RouterError> {
    let size_path = format!("/sys/class/block/{}/size", p2_name);
    let size_str = fs::read_to_string(&size_path)
        .map_err(|e| RouterError::Generic(format!("Failed to read {}: {}", size_path, e)))?;
    let sectors = size_str
        .trim()
        .parse::<u64>()
        .map_err(|e| RouterError::Generic(format!("Failed to parse partition sectors: {}", e)))?;
    Ok(sectors)
}

fn reread_partition_table<F: AsFd>(fd: &F) {
    #[cfg(target_env = "musl")]
    const BLKRRPART: libc::c_int = 0x125F;
    #[cfg(not(target_env = "musl"))]
    const BLKRRPART: libc::c_ulong = 0x125F;

    unsafe {
        let res = libc::ioctl(fd.as_fd().as_raw_fd(), BLKRRPART);
        if res < 0 {
            let err = IoError::last_os_error();
            warn!(
                "[init] BLKRRPART ioctl failed: {}. Partition table changes might require a reboot.",
                err
            );
        } else {
            debug!("[init] BLKRRPART ioctl succeeded.");
        }
    }
}

pub fn calculate_p2_layout(
    p1_starting_lba: u32,
    p1_sectors: u32,
    disk_sectors: u64,
) -> Result<(u32, u32), RouterError> {
    if p1_sectors == 0 {
        return Err(RouterError::Generic(
            "Boot partition 1 has zero sectors".to_string(),
        ));
    }
    let start_sector = (p1_starting_lba as u64).saturating_add(p1_sectors as u64);
    if start_sector >= disk_sectors {
        return Err(RouterError::Generic(format!(
            "Disk is too small for log partition (size: {} sectors, required > {} sectors)",
            disk_sectors, start_sector
        )));
    }
    let p2_sectors = disk_sectors - start_sector;
    if p2_sectors == 0 {
        return Err(RouterError::Generic(
            "Calculated zero sectors for log partition".to_string(),
        ));
    }
    let p2_lba = u32::try_from(start_sector).map_err(|_| {
        RouterError::Generic("Starting sector exceeds 32-bit MBR LBA limit".to_string())
    })?;
    let p2_len = (p2_sectors.min(u32::MAX as u64)) as u32;
    Ok((p2_lba, p2_len))
}

pub fn derive_p2_device_name(boot_dev: &str) -> Result<String, RouterError> {
    let p1_name = Path::new(boot_dev)
        .file_name()
        .ok_or_else(|| RouterError::Generic("Invalid boot device path".to_string()))?
        .to_str()
        .ok_or_else(|| RouterError::Generic("Non-UTF8 boot device path".to_string()))?;

    if p1_name.ends_with('1') {
        let mut s = p1_name.to_string();
        s.pop();
        s.push('2');
        Ok(format!("/dev/{}", s))
    } else {
        Err(RouterError::Generic(format!(
            "Boot partition name {} does not end with 1",
            boot_dev
        )))
    }
}

fn write_mbr_partition_2(parent_disk: &str) -> Result<(), RouterError> {
    let disk_name = Path::new(parent_disk)
        .file_name()
        .ok_or_else(|| RouterError::Generic("Invalid parent disk path".to_string()))?
        .to_str()
        .ok_or_else(|| RouterError::Generic("Non-UTF8 parent disk path".to_string()))?;

    let disk_sectors = get_partition_sectors(disk_name)?;

    let mut disk_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(parent_disk)
        .map_err(|e| {
            RouterError::Generic(format!(
                "Failed to open {} for MBR write: {}",
                parent_disk, e
            ))
        })?;

    let mut mbr = mbrman::MBR::read_from(&mut disk_file, MBR_SECTOR_SIZE as u32)
        .map_err(|e| RouterError::Generic(format!("Failed to read MBR: {:?}", e)))?;

    let (p2_lba, p2_len) = calculate_p2_layout(mbr[1].starting_lba, mbr[1].sectors, disk_sectors)?;

    mbr[2] = mbrman::MBRPartitionEntry {
        boot: mbrman::BOOT_INACTIVE,
        first_chs: mbrman::CHS::empty(),
        sys: MBR_PART_TYPE_FAT32_LBA,
        last_chs: mbrman::CHS::empty(),
        starting_lba: p2_lba,
        sectors: p2_len,
    };

    disk_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| RouterError::Generic(format!("Failed to seek MBR: {}", e)))?;

    mbr.write_into(&mut disk_file)
        .map_err(|e| RouterError::Generic(format!("Failed to write MBR: {:?}", e)))?;

    disk_file
        .sync_all()
        .map_err(|e| RouterError::Generic(format!("Failed to flush MBR: {}", e)))?;

    info!("[init] MBR partition 2 entry written. Rereading partition table...");
    reread_partition_table(&disk_file);
    Ok(())
}

fn format_partition_as_fat32(p2_dev: &str) -> Result<(), RouterError> {
    let mut p2_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(p2_dev)
        .map_err(|e| {
            RouterError::Generic(format!(
                "Failed to open partition {} for formatting: {}",
                p2_dev, e
            ))
        })?;

    debug!("[init] Formatting {} using fatfs crate...", p2_dev);

    let options = fatfs::FormatVolumeOptions::new()
        .fat_type(fatfs::FatType::Fat32)
        .volume_label(*b"SYSTEM_LOG ");

    fatfs::format_volume(&mut p2_file, options)
        .map_err(|e| RouterError::Generic(format!("fatfs format failed: {}", e)))?;

    p2_file
        .sync_all()
        .map_err(|e| RouterError::Generic(format!("Failed to flush partition: {}", e)))?;

    info!(
        "[init] Partition {} formatted successfully using fatfs.",
        p2_dev
    );
    Ok(())
}

fn check_partition_entry(entry: DirEntry) -> Result<Option<(String, String)>, RouterError> {
    let name = entry.file_name().into_string().unwrap_or_default();
    if name.is_empty() {
        return Ok(None);
    }

    let block_dir = "/sys/class/block";
    let partition_file = format!("{}/{}/partition", block_dir, name);
    if !Path::new(&partition_file).exists() {
        return Ok(None);
    }

    let dev_path = format!("/dev/{}", name);
    let mut file = match File::open(&dev_path) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };

    let fs = match fatfs::FileSystem::new(&mut file, fatfs::FsOptions::new()) {
        Ok(fs) => fs,
        Err(_) => return Ok(None),
    };

    let label = fs.volume_label();
    if label.trim() != "TRIMROUTER" {
        return Ok(None);
    }

    let path_to_canon = format!("{}/{}", block_dir, name);
    let canon_path = fs::canonicalize(&path_to_canon)?;
    let parent_path = canon_path
        .parent()
        .ok_or_else(|| RouterError::Generic("No parent directory".to_string()))?;
    let parent_name_os = parent_path
        .file_name()
        .ok_or_else(|| RouterError::Generic("No file name for parent directory".to_string()))?;
    let parent_name = parent_name_os.to_string_lossy().into_owned();
    let parent_disk_path = format!("/dev/{}", parent_name);

    info!(
        "[init] Found boot partition at {} on parent disk {}",
        dev_path, parent_disk_path
    );
    Ok(Some((dev_path, parent_disk_path)))
}

pub fn find_boot_partition() -> Result<(String, String), RouterError> {
    let block_dir = "/sys/class/block";
    let entries = fs::read_dir(block_dir)
        .map_err(|e| RouterError::Generic(format!("Failed to read {}: {}", block_dir, e)))?;

    for entry in entries {
        let entry = entry?;
        if let Some(res) = check_partition_entry(entry)? {
            return Ok(res);
        }
    }

    Err(RouterError::Generic(
        "Could not find boot partition with TRIMROUTER label".to_string(),
    ))
}

pub fn ensure_log_partition_in_mbr(boot_dev: &str, parent_disk: &str) -> Result<(), RouterError> {
    let p2_dev_path = derive_p2_device_name(boot_dev)?;
    let p2_name = Path::new(&p2_dev_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| RouterError::Generic("Invalid partition 2 device name".to_string()))?;

    let p2_sys_path = format!("/sys/class/block/{}", p2_name);

    if !Path::new(&p2_sys_path).exists() {
        info!("[init] Partition 2 does not exist in MBR. Creating partition entry...");
        write_mbr_partition_2(parent_disk)?;

        let mut found = false;
        for _ in 0..DEV_NODE_POLL_RETRIES {
            if Path::new(&p2_dev_path).exists() {
                found = true;
                break;
            }
            thread::sleep(DEV_NODE_POLL_INTERVAL);
        }
        if !found {
            return Err(RouterError::Generic(format!(
                "Kernel did not create device node {} after partition table update",
                p2_dev_path
            )));
        }
    }
    Ok(())
}

pub fn wait_for_boot_partition() -> Result<(String, String), RouterError> {
    let start = Instant::now();
    info!("[init] Waiting for boot partition to become available...");

    while start.elapsed() < BOOT_MOUNT_TIMEOUT {
        if let Ok(res) = find_boot_partition() {
            return Ok(res);
        }
        thread::sleep(BOOT_MOUNT_POLL_INTERVAL);
    }

    Err(RouterError::from(
        "Timeout reached. Could not find boot partition with label TRIMROUTER.",
    ))
}

pub fn mount_boot_partition<S: MountOps>(sys: &S, boot_dev: &str) -> Result<(), RouterError> {
    if let Err(e) = fs::create_dir_all(BOOT_MOUNT_POINT) {
        warn!(
            "[init] Warning: failed to create {} directory: {}",
            BOOT_MOUNT_POINT, e
        );
    }

    sys.mount(
        Some(boot_dev),
        BOOT_MOUNT_POINT,
        "vfat",
        MsFlags::MS_RDONLY,
        None,
    )
    .map_err(|e| RouterError::Generic(format!("Failed to mount boot partition: {}", e)))?;

    info!(
        "[init] Successfully mounted {} on {} as read-only.",
        boot_dev, BOOT_MOUNT_POINT
    );
    Ok(())
}

pub fn setup_log_partition<S: MountOps>(
    sys: &S,
    boot_dev: &str,
    _parent_disk: &str,
) -> Result<(), RouterError> {
    let p2_dev_path = derive_p2_device_name(boot_dev)?;

    if let Err(e) = fs::create_dir_all("/var/log") {
        warn!("[init] Warning: failed to create /var/log: {}", e);
    }

    if let Err(e) = sys.mount(
        Some(&p2_dev_path),
        "/var/log",
        "vfat",
        MsFlags::empty(),
        None,
    ) {
        warn!(
            "[init] Log partition mount failed: {}. Formatting and retrying...",
            e
        );
        format_partition_as_fat32(&p2_dev_path)?;

        sys.mount(
            Some(&p2_dev_path),
            "/var/log",
            "vfat",
            MsFlags::empty(),
            None,
        )
        .map_err(|e| {
            RouterError::Generic(format!(
                "Failed to mount log partition after formatting: {}",
                e
            ))
        })?;
    }

    info!("[init] Log partition mounted successfully on /var/log.");
    // Reopen active log file immediately now that /var/log partition is mounted
    crate::logging::get_logger().lock().unwrap().open_log_file();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_p2_layout_valid() {
        let p1_start = 2048;
        let p1_sectors = 204800; // 100 MiB
        let disk_sectors = 2097152; // 1 GiB

        let (p2_start, p2_len) = calculate_p2_layout(p1_start, p1_sectors, disk_sectors).unwrap();
        assert_eq!(p2_start, 206848);
        assert_eq!(p2_len, 2097152 - 206848);
    }

    #[test]
    fn test_calculate_p2_layout_disk_too_small() {
        let p1_start = 2048;
        let p1_sectors = 204800;
        let disk_sectors = 200000; // Smaller than p1 start + sectors

        let res = calculate_p2_layout(p1_start, p1_sectors, disk_sectors);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Disk is too small"));
    }

    #[test]
    fn test_calculate_p2_layout_zero_p1_sectors() {
        let res = calculate_p2_layout(2048, 0, 1000000);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("zero sectors"));
    }

    #[test]
    fn test_calculate_p2_layout_overflow_protection() {
        let p1_start = u32::MAX - 10;
        let p1_sectors = 20;
        let disk_sectors = (u32::MAX as u64) + 100;

        let res = calculate_p2_layout(p1_start, p1_sectors, disk_sectors);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("exceeds 32-bit MBR LBA limit")
        );
    }

    #[test]
    fn test_derive_p2_device_name() {
        assert_eq!(
            derive_p2_device_name("/dev/sda1").unwrap(),
            "/dev/sda2".to_string()
        );
        assert_eq!(
            derive_p2_device_name("/dev/vda1").unwrap(),
            "/dev/vda2".to_string()
        );
        assert_eq!(
            derive_p2_device_name("/dev/mmcblk0p1").unwrap(),
            "/dev/mmcblk0p2".to_string()
        );
        assert_eq!(
            derive_p2_device_name("/dev/nvme0n1p1").unwrap(),
            "/dev/nvme0n1p2".to_string()
        );

        assert!(derive_p2_device_name("/dev/sda").is_err());
        assert!(derive_p2_device_name("/dev/sda2").is_err());
    }
}
