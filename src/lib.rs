#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        $crate::logging::log_raw_with_level($crate::logging::Level::Info, &format!($($arg)*));
    }};
}

#[macro_export]
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        $crate::logging::log_raw_with_level($crate::logging::Level::Error, &format!($($arg)*));
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
