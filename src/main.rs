use std::{net::TcpListener, time::Duration};

// Configuration, will put in a file config soon.
pub const BIND_IP: &str = "127.0.0.1";
pub const PORT: &str = "25565";
pub const STREAM_READ_TIMEOUT: Duration = Duration::from_millis(500);
pub const STREAM_WRITE_TIMEOUT: Duration = Duration::from_millis(500);

// Not yet used constants.
pub const _CONNECTION_STREAM_THREAD_POOL_SIZE: i32 = 4;

pub mod byte_helpers;
pub mod connection_handler;
pub mod protocol;

fn main() {
    let tcp_listener = TcpListener::bind(format!("{BIND_IP}:{PORT}")).unwrap();

    // TODO: Use a thread pool.
    for stream in tcp_listener.incoming() {
        println!("INCOMING");
        connection_handler::handle_connection(stream.unwrap());
    }
}
