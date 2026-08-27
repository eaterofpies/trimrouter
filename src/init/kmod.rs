use kobject_uevent::{ActionType, UEvent};
use log::{debug, error, info, warn};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_KOBJECT_UEVENT};
use nix::mount::MsFlags;
use nix::sys::socket::{setsockopt, sockopt};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::thread;

/// Default receive buffer size (16 MiB) for the Netlink uevent socket to prevent drops during coldplug storms.
const UEVENT_RCVBUF_SIZE: usize = 16 * 1024 * 1024;

/// Tracks already-loaded kernel modules in user-space.
/// While the Linux kernel handles duplicate loads safely by returning `EEXIST` (which we catch and ignore),
/// caching loaded modules here prevents redundant disk I/O and expensive decompression CPU cycles (e.g. gzip/xz/zstd).
static LOADED_MODULES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn get_loaded_modules() -> &'static Mutex<HashSet<String>> {
    LOADED_MODULES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Resolves the active kernel release name.
fn get_kernel_release() -> String {
    if let Ok(uts) = nix::sys::utsname::uname()
        && let Some(release) = uts.release().to_str()
    {
        return release.to_string();
    }
    String::new()
}

fn find_module_recursive(dir: &Path, base_name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir()
            && let Some(found) = find_module_recursive(&path, base_name)
        {
            return Some(found);
        }
        if !path.is_dir()
            && let Some(file_name_str) = path.file_name().and_then(|n| n.to_str())
        {
            let stem = file_name_str
                .split('.')
                .next()
                .unwrap_or(file_name_str)
                .replace('_', "-");
            let target_stem = base_name
                .split('.')
                .next()
                .unwrap_or(base_name)
                .replace('_', "-");
            if stem == target_stem {
                return Some(path);
            }
        }
    }
    None
}

fn find_module_file(name: &str) -> Option<PathBuf> {
    // Raw modaliases contain subsystem prefixes with colons (e.g. `acpi:PNP0A03:`, `platform:alarmtimer`).
    // Real module file names never contain colons. Returning None immediately avoids expensive
    // recursive disk directory scans for non-existent module files when a modalias has no match.
    if name.contains(':') {
        return None;
    }
    let normalized = name.replace('_', "-");
    if let Some(dep_map) = get_or_load_dep_map()
        && let Some((path, _)) = dep_map.get(&normalized)
    {
        return Some(path.clone());
    }
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        return None;
    }
    let modules_dir = Path::new("/lib/modules").join(kdir);
    let base_name = format!("{}.ko", name);
    find_module_recursive(&modules_dir, &base_name)
}

/// Flag to finit_module indicating that the file is compressed and the kernel should decompress it.
const MODULE_INIT_COMPRESSED_FILE: u32 = 0x0004;

fn load_module(path: &Path) -> Result<(), io::Error> {
    debug!("[init] Loading kernel module: {:?}", path);
    let file = fs::File::open(path)?;
    let param = CString::default();

    let mut flags = nix::kmod::ModuleInitFlags::empty();
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    if extension == "xz" || extension == "gz" || extension == "zst" {
        flags = nix::kmod::ModuleInitFlags::from_bits_retain(MODULE_INIT_COMPRESSED_FILE);
    }

    if let Err(e) = nix::kmod::finit_module(&file, &param, flags)
        && e != nix::errno::Errno::EEXIST
    {
        return Err(io::Error::other(e.to_string()));
    }
    Ok(())
}

fn load_single_module(mod_name: &str) -> Result<(), io::Error> {
    let path = match find_module_file(mod_name) {
        Some(p) => p,
        None => {
            debug!(
                "[init] Module {} not found in /lib/modules, assuming built-in or not needed.",
                mod_name
            );
            return Ok(());
        }
    };

    if let Err(e) = load_module(&path) {
        error!("[init] Failed to load module {}: {}", mod_name, e);
        Err(e)
    } else {
        info!("[init] Successfully loaded module {}", mod_name);
        Ok(())
    }
}

fn parse_modules_dep(
    dep_file_path: &Path,
    modules_dir: &Path,
) -> HashMap<String, (PathBuf, Vec<String>)> {
    let mut map = HashMap::new();
    let content = match fs::read_to_string(dep_file_path) {
        Ok(c) => c,
        Err(_) => return map,
    };
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.is_empty() {
            continue;
        }
        let mod_path_str = parts[0].trim();
        let mod_path = Path::new(mod_path_str);
        let stem = match mod_path
            .file_name()
            .and_then(|f| f.to_str())
            .map(|f| f.split('.').next().unwrap_or(f).replace('_', "-"))
        {
            Some(s) => s,
            None => continue,
        };

        let mut deps = Vec::new();
        if parts.len() > 1 {
            for dep in parts[1].split_whitespace() {
                let dep_path = Path::new(dep.trim());
                let dep_stem = dep_path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .map(|f| f.split('.').next().unwrap_or(f).replace('_', "-"))
                    .unwrap_or_default();
                if !dep_stem.is_empty() {
                    deps.push(dep_stem);
                }
            }
        }
        map.insert(stem, (modules_dir.join(mod_path), deps));
    }
    map
}

fn resolve_deps_recursive(
    mod_name: &str,
    dep_map: &HashMap<String, (PathBuf, Vec<String>)>,
    resolved: &mut Vec<PathBuf>,
    visited: &mut HashSet<String>,
) {
    let normalized = mod_name.replace('_', "-");
    if visited.contains(&normalized) {
        return;
    }
    visited.insert(normalized.clone());

    if let Some((path, deps)) = dep_map.get(&normalized) {
        for dep in deps {
            resolve_deps_recursive(dep, dep_map, resolved, visited);
        }
        resolved.push(path.clone());
    }
}

fn load_resolved_module_paths(resolved: &[PathBuf]) -> bool {
    let mut all_loaded = true;
    for path in resolved {
        let stem = match path
            .file_name()
            .and_then(|f| f.to_str())
            .map(|f| f.split('.').next().unwrap_or(f).replace('_', "-"))
        {
            Some(s) => s,
            None => {
                all_loaded = false;
                continue;
            }
        };

        let loaded = get_loaded_modules().lock().unwrap();
        if !loaded.contains(&stem) {
            drop(loaded);
            if let Err(e) = load_module(path) {
                error!("[init] Failed to load module {} ({:?}): {}", stem, path, e);
                all_loaded = false;
            } else {
                info!("[init] Successfully loaded module {}", stem);
                get_loaded_modules().lock().unwrap().insert(stem.clone());
            }
        }
    }
    all_loaded
}

fn load_module_with_dep_map(
    mod_name: &str,
    dep_map: &HashMap<String, (PathBuf, Vec<String>)>,
) -> bool {
    let candidates = resolve_alias(mod_name);
    let mut any_success = false;

    for actual_name in &candidates {
        let normalized = actual_name.replace('_', "-");
        {
            let loaded = get_loaded_modules().lock().unwrap();
            if loaded.contains(&normalized) {
                any_success = true;
                continue;
            }
        }

        let mut resolved = Vec::new();
        let mut visited = HashSet::new();
        resolve_deps_recursive(actual_name, dep_map, &mut resolved, &mut visited);

        if resolved.is_empty() {
            if !actual_name.contains(':') && load_single_module(actual_name).is_ok() {
                any_success = true;
            }
            continue;
        }

        if load_resolved_module_paths(&resolved) {
            any_success = true;
            break; // Successfully loaded this candidate module, stop trying other candidates!
        }
    }

    any_success
}

pub fn load_module_with_dependencies(mod_name: &str) {
    if let Some(dep_map) = get_or_load_dep_map() {
        // Suppress errors for raw hardware modaliases (contain ':') that don't match any kernel module
        if !load_module_with_dep_map(mod_name, &dep_map) && !mod_name.contains(':') {
            error!(
                "[init] ERROR: All candidate modules for {} failed to load!",
                mod_name
            );
        }
        return;
    }

    let candidates = resolve_alias(mod_name);
    let mut any_success = false;
    for actual_name in &candidates {
        if load_single_module(actual_name).is_ok() {
            any_success = true;
        }
    }
    // Suppress errors for raw hardware modaliases (contain ':') that don't match any kernel module
    if !any_success && !mod_name.contains(':') {
        error!(
            "[init] ERROR: All candidate modules for {} failed to load!",
            mod_name
        );
    }
}

type DepMap = HashMap<String, (PathBuf, Vec<String>)>;
static DEP_CACHE: OnceLock<Mutex<Option<DepMap>>> = OnceLock::new();

fn get_dep_cache() -> &'static Mutex<Option<DepMap>> {
    DEP_CACHE.get_or_init(|| Mutex::new(None))
}

fn get_or_load_dep_map() -> Option<DepMap> {
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        return None;
    }
    let mut cache_guard = match get_dep_cache().lock() {
        Ok(g) => g,
        Err(_) => return None,
    };
    if let Some(map) = cache_guard.as_ref() {
        return Some(map.clone());
    }
    let modules_dir = Path::new("/lib/modules").join(&kdir);
    let dep_file_path = modules_dir.join("modules.dep");
    if !dep_file_path.exists() {
        return None;
    }
    let map = parse_modules_dep(&dep_file_path, &modules_dir);
    *cache_guard = Some(map.clone());
    Some(map)
}

type ModuleAlias = (Vec<char>, String);
type AliasCache = Option<Vec<ModuleAlias>>;

static ALIAS_CACHE: OnceLock<Mutex<AliasCache>> = OnceLock::new();

fn get_alias_cache() -> &'static Mutex<AliasCache> {
    ALIAS_CACHE.get_or_init(|| Mutex::new(None))
}

pub fn invalidate_module_caches() {
    if let Ok(mut guard) = get_alias_cache().lock() {
        *guard = None;
    }
    if let Ok(mut guard) = get_dep_cache().lock() {
        *guard = None;
    }
}

pub fn activate_boot_modules() {
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        eprintln!("[init] Skipping boot module activation: unknown kernel release");
        return;
    }
    let boot_img = Path::new("/boot/modules.erofs");
    let lib_mods = Path::new("/lib/modules");
    if !boot_img.exists() {
        eprintln!(
            "[init] No module image {} found on boot partition",
            boot_img.display()
        );
        return;
    }

    load_module_with_dependencies("erofs");

    if let Err(e) = nix::mount::mount(
        Some(boot_img),
        lib_mods,
        Some("erofs"),
        MsFlags::MS_RDONLY,
        None::<&Path>,
    ) {
        eprintln!("[init] WARNING: failed to mount EROFS module image: {}", e);
        return;
    }

    println!(
        "[init] Mounted {} over /lib/modules (full module set)",
        boot_img.display()
    );
    invalidate_module_caches();
    trigger_uevents();
}

pub fn load_required_modules() {
    // Only load essential filesystem and netfilter modules needed during early boot:
    let modules = [
        "fat",
        "vfat",
        "erofs",
        "nls_cp437",
        "nls_ascii",
        "nls_utf8",
        "nls_iso8859_1",
        "nft_chain_nat",
        "nft_ct",
        "nft_masq",
    ];

    if let Some(dep_map) = get_or_load_dep_map() {
        for mod_name in &modules {
            let _ = load_module_with_dep_map(mod_name, &dep_map);
        }
    } else {
        for mod_name in &modules {
            load_module_with_dependencies(mod_name);
        }
    }
}

fn wildcard_match(pattern: &[char], input: &[char]) -> bool {
    if pattern.is_empty() {
        return input.is_empty();
    }
    if pattern[0] == '*' {
        if pattern.len() == 1 {
            return true;
        }
        for i in 0..=input.len() {
            if wildcard_match(&pattern[1..], &input[i..]) {
                return true;
            }
        }
        return false;
    }
    if input.is_empty() {
        return false;
    }
    if pattern[0] == '?' || pattern[0] == input[0] {
        return wildcard_match(&pattern[1..], &input[1..]);
    }
    false
}

fn parse_modules_alias_line(line: &str) -> Option<(Vec<char>, String)> {
    let mut parts = line.split_whitespace();
    let is_alias = parts.next()? == "alias";
    if !is_alias {
        return None;
    }
    let pattern = parts.next()?;
    let module = parts.next()?;
    Some((pattern.chars().collect(), module.to_string()))
}

fn load_alias_list(kdir: &str) -> Vec<(Vec<char>, String)> {
    let alias_file_path = Path::new("/lib/modules").join(kdir).join("modules.alias");
    let Ok(content) = fs::read_to_string(alias_file_path) else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(parse_modules_alias_line)
        .collect()
}

pub fn resolve_alias(alias_or_name: &str) -> Vec<String> {
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        return vec![alias_or_name.to_string()];
    }

    let mut cache_guard = match get_alias_cache().lock() {
        Ok(g) => g,
        Err(_) => return vec![alias_or_name.to_string()],
    };

    let list = cache_guard.get_or_insert_with(|| load_alias_list(&kdir));
    let input_chars: Vec<char> = alias_or_name.chars().collect();
    let mut matches = Vec::new();

    for (pattern_chars, module_name) in list {
        if wildcard_match(pattern_chars, &input_chars) {
            debug!(
                "[modprobe] Resolved alias {} to module {}",
                alias_or_name, module_name
            );
            matches.push(module_name.clone());
        }
    }

    if matches.is_empty() {
        matches.push(alias_or_name.to_string());
    }
    matches
}

fn process_device_entry(entry: fs::DirEntry) {
    let Ok(ft) = entry.file_type() else {
        return;
    };
    let path = entry.path();
    if ft.is_dir() {
        traverse_and_trigger(&path);
    } else if path.file_name().is_some_and(|name| name == "uevent") {
        let _ = fs::write(&path, "add");
    }
}

fn traverse_and_trigger(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        process_device_entry(entry);
    }
}

pub fn trigger_uevents() {
    debug!("[uevent] Triggering coldplug uevents...");
    let sys_devices = Path::new("/sys/devices");
    if sys_devices.exists() {
        traverse_and_trigger(sys_devices);
    }
}

pub fn start_uevent_listener() {
    debug!("[uevent] Spawning uevent listener thread...");
    thread::spawn(move || {
        debug!("[uevent] Uevent listener thread spawned.");
        if let Err(e) = run_uevent_listener() {
            error!("[uevent] Error in uevent listener: {}", e);
        }
    });
}

fn handle_uevent(uevent: UEvent) {
    // Handle kernel module autoloading
    if uevent.action == ActionType::Add
        && let Some(modalias) = uevent.env.get("MODALIAS")
    {
        debug!("[uevent] Discovered device with modalias: {}", modalias);
        load_module_with_dependencies(modalias);
    }
}

fn run_uevent_listener() -> Result<(), Box<dyn std::error::Error>> {
    debug!("[uevent] Creating Netlink socket...");
    let mut socket = Socket::new(NETLINK_KOBJECT_UEVENT)?;
    let addr = SocketAddr::new(0, 1); // Group 1 is the standard multicast group for uevents
    debug!("[uevent] Binding Netlink socket...");
    socket.bind(&addr)?;

    // Increase socket receive buffer size to 16MB to avoid packet drops during coldplug storms
    let _ = setsockopt(&socket, sockopt::RcvBuf, &UEVENT_RCVBUF_SIZE);

    info!("[uevent] Netlink uevent listener started successfully.");

    let mut buf = [0u8; 8192];
    loop {
        let mut slice = &mut buf[..];
        let n = match socket.recv(&mut slice, 0) {
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                warn!(
                    "[uevent] ENOBUFS: socket buffer overflow detected, rescanning hardware for missed devices..."
                );
                trigger_uevents();
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        match UEvent::from_netlink_packet(&buf[..n]) {
            Ok(uevent) => handle_uevent(uevent),
            Err(e) => {
                // Malformed or non-UTF8 packets can occasionally arrive; log a warning but keep running
                warn!("[uevent] Warning: Failed to parse uevent packet: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "trimrouter_test_{}_{}",
                name,
                rand::random::<u64>()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_wildcard_match() {
        let pattern: Vec<char> = "usb:v*p*d*dc*dsc*dp*ic*isc*ip*".chars().collect();
        let input: Vec<char> = "usb:v045Ep00DBd0100dc00dsc00dp00icFFisc00ip00"
            .chars()
            .collect();
        assert!(wildcard_match(&pattern, &input));

        let pattern2: Vec<char> = "crypto-crc32*".chars().collect();
        let input2: Vec<char> = "crypto-crc32c-generic".chars().collect();
        assert!(wildcard_match(&pattern2, &input2));

        let pattern3: Vec<char> = "foo?bar".chars().collect();
        let input3: Vec<char> = "fooxbar".chars().collect();
        assert!(wildcard_match(&pattern3, &input3));
        let input3_fail: Vec<char> = "fooxxbar".chars().collect();
        assert!(!wildcard_match(&pattern3, &input3_fail));
    }

    #[test]
    fn test_dash_underscore_normalization() {
        let temp = TempDir::new("normalization");
        let sub = temp.path.join("kernel");
        fs::create_dir_all(&sub).unwrap();

        // Create files with mixed dashes and underscores
        let file1 = sub.join("foo-bar.ko");
        fs::write(&file1, b"").unwrap();
        let file2 = sub.join("baz_qux.ko");
        fs::write(&file2, b"").unwrap();

        // Check finding by name
        let found1 = find_module_recursive(&temp.path, "foo_bar.ko").unwrap();
        assert_eq!(found1, file1);

        let found2 = find_module_recursive(&temp.path, "baz-qux.ko").unwrap();
        assert_eq!(found2, file2);
    }

    #[test]
    fn test_recursive_dependency_resolution() {
        let temp = TempDir::new("deps");
        let dep_file = temp.path.join("modules.dep");

        // Write a multi-level dependency tree
        let dep_content = "\
kernel/drivers/net/foo.ko: kernel/net/bar.ko\n\
kernel/net/bar.ko: kernel/lib/baz.ko\n\
kernel/lib/baz.ko:\n\
";
        fs::write(&dep_file, dep_content).unwrap();

        let mut resolved = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let dep_map = parse_modules_dep(&dep_file, &temp.path);
        resolve_deps_recursive("foo", &dep_map, &mut resolved, &mut visited);

        assert_eq!(resolved.len(), 3);
        // Resolved in reverse topological order (leafs first)
        assert_eq!(resolved[0].file_name().unwrap().to_str().unwrap(), "baz.ko");
        assert_eq!(resolved[1].file_name().unwrap().to_str().unwrap(), "bar.ko");
        assert_eq!(resolved[2].file_name().unwrap().to_str().unwrap(), "foo.ko");
    }

    #[test]
    fn test_alias_resolution() {
        let temp = TempDir::new("alias");
        let alias_file = temp.path.join("modules.alias");

        let alias_content = "\
alias crc32c crc32c_generic\n\
alias usb:v045Ep* usbnet\n\
";
        fs::write(&alias_file, alias_content).unwrap();

        // Temporarily override the alias lookup path logic by mocking resolve_alias logic
        let test_resolve = |alias: &str| -> String {
            let content = fs::read_to_string(&alias_file).unwrap();
            let input_chars: Vec<char> = alias.chars().collect();
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 && parts[0] == "alias" {
                    let pattern = parts[1];
                    let module_name = parts[2];
                    let pattern_chars: Vec<char> = pattern.chars().collect();
                    if wildcard_match(&pattern_chars, &input_chars) {
                        return module_name.to_string();
                    }
                }
            }
            alias.to_string()
        };

        assert_eq!(test_resolve("crc32c"), "crc32c_generic");
        assert_eq!(test_resolve("usb:v045Ep00DB"), "usbnet");
        assert_eq!(test_resolve("other_mod"), "other_mod");
    }
}
