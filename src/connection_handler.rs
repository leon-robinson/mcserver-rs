use std::net::TcpStream;

use crate::{byte_helpers, STREAM_READ_TIMEOUT, STREAM_WRITE_TIMEOUT};

/// Take over from main to handle the TcpStream.
pub fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(STREAM_READ_TIMEOUT))
        .expect("Failed to set read timeout for TcpStream.");
    stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .expect("Failed to set write timeout for TcpStream.");

    let packet_len = byte_helpers::read_var_int(&mut stream);
    let packet_id = byte_helpers::read_var_int(&mut stream);
    println!("packet_len: {}, packet_id: {:x}", packet_len, packet_id);
}
