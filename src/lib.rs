#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        std::print!("{}", $crate::services::utils::get_timestamp_prefix());
        std::println!($($arg)*);
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        std::eprint!("{}", $crate::services::utils::get_timestamp_prefix());
        std::eprintln!($($arg)*);
    }};
}

pub mod config;
pub mod error;
pub mod interface;
pub mod kmod;
pub mod netfilter;
pub mod network;
pub mod packet;
pub mod reaper;
pub mod services;
pub mod signal;
pub mod system;
