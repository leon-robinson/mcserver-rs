use std::net::TcpStream;

use crate::{byte_helpers, protocol, STREAM_READ_TIMEOUT, STREAM_WRITE_TIMEOUT};

/// Read and handle packet from the TcpStream.
fn handle_packet(stream: &mut TcpStream) {
    let packet_len = byte_helpers::read_var_int(stream);
    let packet_id = byte_helpers::read_var_int(stream);
    // TODO: Should probably check if the packet is too large.

    println!("packet_len: {}, packet_id: {:x}", packet_len, packet_id);

    if packet_id == 0 {
        let test = protocol::HandshakePacket::from(stream);
        println!("{:?}", test);
    }
}

/// Take over from main to handle the TcpStream.
pub fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(STREAM_READ_TIMEOUT))
        .expect("Failed to set read timeout for TcpStream.");
    stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .expect("Failed to set write timeout for TcpStream.");

    handle_packet(&mut stream); // Handle handshake.
}
