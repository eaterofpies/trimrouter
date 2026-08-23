use crate::init::kmod::load_module_with_dependencies;
use log::info;
use std::io;

pub fn run_as_modprobe(module_name: String) -> Result<(), io::Error> {
    info!("[modprobe] Request to load module: {}", module_name);
    load_module_with_dependencies(&module_name);
    Ok(())
}
