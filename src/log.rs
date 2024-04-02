use crate::connection_handler::Connection;

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => ({
        print!("[INFO] ");
        println!($($arg)*);
    })
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => ({
        print!("\x1b[93m[WARN] ");
        print!($($arg)*);
        println!("\x1b[0m");
    })
}

#[macro_export]
macro_rules! severe {
    ($($arg:tt)*) => ({
        print!("\x1b[91m[SEVERE] ");
        print!($($arg)*);
        println!("\x1b[0m");
    })
}

#[macro_export]
macro_rules! info_connection {
    ($tag:expr, $($arg:tt)*) => ({
        $crate::log::info_connection($tag, format_args!($($arg)*));
    })
}

#[macro_export]
macro_rules! warn_connection {
    ($tag:expr, $($arg:tt)*) => ({
        $crate::log::warn_connection($tag, format_args!($($arg)*));
    })
}

#[macro_export]
macro_rules! severe_connection {
    ($tag:expr, $($arg:tt)*) => ({
        $crate::log::severe_connection($tag, format_args!($($arg)*));
    })
}

#[derive(Debug)]
enum LogType {
    Info,
    Warn,
    Severe,
}

fn log_connection(log_type: &LogType, connection: &Connection, args: std::fmt::Arguments) {
    let ip_port = connection.ip_addr.to_string() + ":" + &connection.port.to_string();

    let prefix = if let Some(username) = &connection.username {
        ip_port + ", " + username
    } else {
        ip_port
    };

    match log_type {
        LogType::Info => info!("[{prefix}] {args}"),
        LogType::Warn => warn!("[{prefix}] {args}"),
        LogType::Severe => severe!("[{prefix}] {args}"),
    }
}

#[inline]
pub fn info_connection(connection: &Connection, args: std::fmt::Arguments) {
    log_connection(&LogType::Info, connection, args);
}

#[inline]
pub fn warn_connection(connection: &Connection, args: std::fmt::Arguments) {
    log_connection(&LogType::Warn, connection, args);
}

#[inline]
pub fn severe_connection(connection: &Connection, args: std::fmt::Arguments) {
    log_connection(&LogType::Severe, connection, args);
}
