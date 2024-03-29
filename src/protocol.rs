use std::net::TcpStream;

use crate::byte_helpers::{read_u16, read_utf8_string, read_var_int};

#[derive(Debug)]
#[allow(dead_code)]
pub struct HandshakePacket {
    protocol_version: i32,
    server_address: String,
    server_port: u16,
    next_state: i32, // TODO: Make this enum of State
}

impl From<&mut TcpStream> for HandshakePacket {
    fn from(stream: &mut TcpStream) -> Self {
        Self {
            protocol_version: read_var_int(stream),
            server_address: read_utf8_string(stream),
            server_port: read_u16(stream),
            next_state: read_var_int(stream),
        }
    }
}
