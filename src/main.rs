use std::net::TcpListener;

const BIND_IP: &str = "127.0.0.1";
const PORT: &str = "25565";
const _CONNECTION_STREAM_THREAD_POOL_SIZE: i32 = 4;

pub mod byte_helpers;
pub mod connection_handler;

fn main() {
    let tcp_listener = TcpListener::bind(format!("{BIND_IP}:{PORT}")).unwrap();

    // TODO: Use a thread pool.
    for stream in tcp_listener.incoming() {
        println!("INCOMING");

        let mut stream = stream.unwrap();

        // TODO: set read timeout.

        let packet_len = byte_helpers::read_var_int(&mut stream);
        println!("{}", packet_len);
    }
}
