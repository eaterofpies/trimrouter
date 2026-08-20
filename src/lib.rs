#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        $crate::logging::log_raw(&format!($($arg)*));
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        $crate::logging::log_raw(&format!($($arg)*));
    }};
}

pub mod cli;
pub mod config;
pub mod error;
pub mod interface;
pub mod kmod;
pub mod logging;
pub mod managers;
pub mod modes;
pub mod netfilter;
pub mod network;
pub mod packet;
pub mod partition;
pub mod reaper;
pub mod signal;
pub mod system;
pub mod workers;
