use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

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
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        return None;
    }
    let modules_dir = Path::new("/lib/modules").join(kdir);
    let base_name = format!("{}.ko", name);
    find_module_recursive(&modules_dir, &base_name)
}

fn decompress_module(data: &[u8], path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    match extension {
        "xz" => {
            let mut decompressed = Vec::new();
            let mut cursor = std::io::Cursor::new(data);
            lzma_rs::xz_decompress(&mut cursor, &mut decompressed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(decompressed)
        }
        "gz" => {
            use std::io::Read;
            let mut decompressed = Vec::new();
            let mut decoder = flate2::read::GzDecoder::new(data);
            decoder.read_to_end(&mut decompressed)?;
            Ok(decompressed)
        }
        "zst" => {
            let mut decompressed = Vec::new();
            let mut decoder = ruzstd::decoding::FrameDecoder::new();
            decoder
                .decode_all_to_vec(data, &mut decompressed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            Ok(decompressed)
        }
        _ => Ok(data.to_vec()),
    }
}

fn load_module(path: &Path) -> Result<(), std::io::Error> {
    println!("[init] Loading kernel module: {:?}", path);
    let raw_data = fs::read(path)?;
    let decompressed_data = decompress_module(&raw_data, path)?;

    let param = std::ffi::CString::new("").unwrap();
    if let Err(e) = nix::kmod::init_module(&decompressed_data, &param)
        && e != nix::errno::Errno::EEXIST
    {
        return Err(std::io::Error::other(e.to_string()));
    }
    Ok(())
}

fn load_single_module(mod_name: &str) -> Result<(), std::io::Error> {
    let path = match find_module_file(mod_name) {
        Some(p) => p,
        None => {
            println!(
                "[init] Module {} not found in /lib/modules, assuming built-in or not needed.",
                mod_name
            );
            return Ok(());
        }
    };

    if let Err(e) = load_module(&path) {
        eprintln!("[init] Failed to load module {}: {}", mod_name, e);
        Err(e)
    } else {
        println!("[init] Successfully loaded module {}", mod_name);
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
            if load_single_module(actual_name).is_ok() {
                any_success = true;
            }
            continue;
        }

        let mut all_resolved_loaded = true;
        for path in resolved {
            let stem = match path
                .file_name()
                .and_then(|f| f.to_str())
                .map(|f| f.split('.').next().unwrap_or(f).replace('_', "-"))
            {
                Some(s) => s,
                None => {
                    all_resolved_loaded = false;
                    continue;
                }
            };

            let loaded = get_loaded_modules().lock().unwrap();
            if !loaded.contains(&stem) {
                drop(loaded);
                if let Err(e) = load_module(&path) {
                    eprintln!("[init] Failed to load module {} ({:?}): {}", stem, path, e);
                    all_resolved_loaded = false;
                } else {
                    println!("[init] Successfully loaded module {}", stem);
                    get_loaded_modules().lock().unwrap().insert(stem.clone());
                }
            }
        }

        if all_resolved_loaded {
            any_success = true;
            break; // Successfully loaded this candidate module, stop trying other candidates!
        }
    }

    any_success
}

fn load_module_with_dependencies(mod_name: &str) {
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        let candidates = resolve_alias(mod_name);
        let mut any_success = false;
        for actual_name in &candidates {
            if load_single_module(actual_name).is_ok() {
                any_success = true;
            }
        }
        if !any_success {
            eprintln!(
                "[init] ERROR: All candidate modules for {} failed to load!",
                mod_name
            );
        }
        return;
    }

    let modules_dir = Path::new("/lib/modules").join(&kdir);
    let dep_file_path = modules_dir.join("modules.dep");

    if !dep_file_path.exists() {
        let candidates = resolve_alias(mod_name);
        let mut any_success = false;
        for actual_name in &candidates {
            if load_single_module(actual_name).is_ok() {
                any_success = true;
            }
        }
        if !any_success {
            eprintln!(
                "[init] ERROR: All candidate modules for {} failed to load!",
                mod_name
            );
        }
        return;
    }

    let dep_map = parse_modules_dep(&dep_file_path, &modules_dir);
    if !load_module_with_dep_map(mod_name, &dep_map) {
        eprintln!(
            "[init] ERROR: All candidate modules for {} failed to load!",
            mod_name
        );
    }
}

pub fn load_required_modules() {
    let kdir = get_kernel_release();
    // Only load essential modules needed during early boot:
    // - virtio_net/pci/mmio: Essential for device discovery; explicit loading prevents race conditions
    //   where network configuration runs before the virtual interfaces have finished registering.
    // - nft_chain_nat & nft_ct: Kernel netlink API does not trigger modprobe autoloading for NAT base
    //   chains or connection tracking state hooks. They must be loaded beforehand.
    let modules = [
        "virtio_net",
        "virtio_pci",
        "virtio_mmio",
        "nft_chain_nat",
        "nft_ct",
    ];

    if kdir.is_empty() {
        for mod_name in &modules {
            load_module_with_dependencies(mod_name);
        }
        return;
    }

    let modules_dir = Path::new("/lib/modules").join(&kdir);
    let dep_file_path = modules_dir.join("modules.dep");

    if !dep_file_path.exists() {
        for mod_name in &modules {
            load_module_with_dependencies(mod_name);
        }
        return;
    }

    let dep_map = parse_modules_dep(&dep_file_path, &modules_dir);
    for mod_name in &modules {
        if !load_module_with_dep_map(mod_name, &dep_map) {
            eprintln!(
                "[init] ERROR: Failed to load required boot module: {}",
                mod_name
            );
        }
    }
}

fn parse_args_for_mod_name(args: &[String]) -> Option<String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--" {
            return iter.next().cloned();
        }
        if !arg.starts_with('-') && arg != "modprobe" {
            return Some(arg.clone());
        }
    }
    None
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

fn resolve_alias(alias_or_name: &str) -> Vec<String> {
    let kdir = get_kernel_release();
    if kdir.is_empty() {
        return vec![alias_or_name.to_string()];
    }
    let alias_file_path = Path::new("/lib/modules").join(kdir).join("modules.alias");
    if !alias_file_path.exists() {
        return vec![alias_or_name.to_string()];
    }

    let content = match fs::read_to_string(&alias_file_path) {
        Ok(c) => c,
        Err(_) => return vec![alias_or_name.to_string()],
    };

    let input_chars: Vec<char> = alias_or_name.chars().collect();
    let mut matches = Vec::new();

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "alias" {
            let pattern = parts[1];
            let module_name = parts[2];
            let pattern_chars: Vec<char> = pattern.chars().collect();
            if wildcard_match(&pattern_chars, &input_chars) {
                println!(
                    "[modprobe] Resolved alias {} to module {}",
                    alias_or_name, module_name
                );
                matches.push(module_name.to_string());
            }
        }
    }

    if matches.is_empty() {
        matches.push(alias_or_name.to_string());
    }
    matches
}

pub fn run_as_modprobe(args: Vec<String>) -> Result<(), std::io::Error> {
    let raw_name = match parse_args_for_mod_name(&args) {
        Some(name) => name,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Missing module name",
            ));
        }
    };

    println!("[modprobe] Request to load module: {}", raw_name);
    load_module_with_dependencies(&raw_name);
    Ok(())
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
                "rustyrouter_test_{}_{}",
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
