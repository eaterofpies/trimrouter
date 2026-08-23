use crate::cli::{Cli, Commands, TrimrouterSubcommands};
use crate::init::system::RealSystem;
use clap::Parser;
use log::error;
use std::process::exit;
use std::sync::Arc;

pub mod modprobe;
pub mod worker;

pub async fn run(args: Vec<String>) {
    // Parse using the multicall-enabled Cli
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to parse arguments: {}", e);
            exit(1);
        }
    };

    match cli.command {
        Some(Commands::Init { .. }) => {
            let sys = Arc::new(RealSystem);
            crate::init::run_as_init(sys).await;
        }
        Some(Commands::Worker { service }) => {
            worker::run_worker(service).await;
        }
        Some(Commands::Modprobe { module_name, .. }) => {
            if let Err(e) = modprobe::run_as_modprobe(module_name) {
                error!("[modprobe] ERROR: {}", e);
                exit(1);
            }
            exit(0);
        }
        Some(Commands::Trimrouter {
            sub: Some(TrimrouterSubcommands::Worker { service }),
        }) => {
            worker::run_worker(service).await;
        }
        Some(Commands::Trimrouter {
            sub: Some(TrimrouterSubcommands::Modprobe { module_name, .. }),
        }) => {
            if let Err(e) = modprobe::run_as_modprobe(module_name) {
                error!("[modprobe] ERROR: {}", e);
                exit(1);
            }
            exit(0);
        }
        Some(Commands::Trimrouter { sub: None }) | None => {
            // Default: run as init
            let sys = Arc::new(RealSystem);
            crate::init::run_as_init(sys).await;
        }
    }
}
