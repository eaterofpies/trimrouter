#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        std::print!("{}", $crate::managers::utils::get_timestamp_prefix());
        std::println!($($arg)*);
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        std::eprint!("{}", $crate::managers::utils::get_timestamp_prefix());
        std::eprintln!($($arg)*);
    }};
}

pub mod cli;
pub mod config;
pub mod error;
pub mod interface;
pub mod kmod;
pub mod managers;
pub mod modes;
pub mod netfilter;
pub mod network;
pub mod packet;
pub mod reaper;
pub mod signal;
pub mod system;
pub mod workers;
