use crate::kmod::load_module_with_dependencies;

pub fn run_as_modprobe(module_name: String) -> Result<(), std::io::Error> {
    println!("[modprobe] Request to load module: {}", module_name);
    load_module_with_dependencies(&module_name);
    Ok(())
}
