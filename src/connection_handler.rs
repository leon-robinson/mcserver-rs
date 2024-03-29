use std::net::TcpStream;

use crate::{
    byte_helpers,
    protocol::{self, Packet, Result},
    STREAM_READ_TIMEOUT, STREAM_WRITE_TIMEOUT,
};

/// Read and handle packet from the `TcpStream`.
fn handle_packet(stream: &mut TcpStream) -> Result<()> {
    let packet_len = byte_helpers::read_var_int(stream)?;
    let packet_id = byte_helpers::read_var_int(stream)?;
    // TODO: Should probably check if the packet is too large.

    println!("packet_len: {packet_len}, packet_id: {packet_id:x}");

    if packet_id == 0 {
        let test = protocol::HandshakePacket::from_stream(stream)?;
        println!("{test:?}");
    }

    Ok(())
}

/// Take over from main to handle the `TcpStream`.
///
/// # Panics
/// We panic for the moment when we have a `PacketError`, but in the future kick the player (if connected) and close the stream.
pub fn handle_connection(mut stream: TcpStream) {
    stream
        .set_read_timeout(Some(STREAM_READ_TIMEOUT))
        .expect("Failed to set read timeout for TcpStream.");
    stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .expect("Failed to set write timeout for TcpStream.");

    handle_packet(&mut stream).unwrap(); // Handle handshake.
}
