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
pub mod init;
pub mod interface;
pub mod logging;
pub mod modes;
pub mod network;
pub mod packet;
pub mod services;
