use snafu::{prelude::*, ResultExt};
use std::{net::TcpStream, string::FromUtf8Error};

use crate::{
    back_to_enum,
    byte_helpers::{read_u16, read_utf8_string, read_var_int},
    macros::EnumBoundsError,
};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum PacketError {
    #[snafu(display("Failed to read string for field: '{field_name}' from stream."))]
    BadStringStreamRead {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("Failed to convert UTF-8 bytes to UTF-8 string for field: '{field_name}'"))]
    BadStringConversion {
        source: FromUtf8Error,
        field_name: &'static str,
    },
    #[snafu(display("String received has a bad range for field: '{field_name}'"))]
    BadStringRange { field_name: &'static str },
    #[snafu(display("String received has bad UTF-16 units for field: '{field_name}'"))]
    BadStringUTF16Units { field_name: &'static str },
    #[snafu(display("Failed to read u8 value from stream."))]
    BadU8Read { source: std::io::Error },
    #[snafu(display("Failed to read u16 value from stream."))]
    BadU16Read { source: std::io::Error },
    #[snafu(display("VarInt was too large."))]
    VarIntTooLarge,
    #[snafu(display("VarInt was too large."))]
    VarLongTooLarge,
    #[snafu(display("Invalid connection Status: '{status}'"))]
    InvalidStatus {
        source: EnumBoundsError,
        status: i32,
    },
}

pub type Result<T, E = PacketError> = std::result::Result<T, E>;

pub trait Packet: Sized {
    fn from_stream(stream: &mut TcpStream) -> Result<Self>;
}

back_to_enum! {
    #[derive(Debug)]
    pub enum State {
        Status = 1,
        Login = 2,
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct HandshakePacket {
    protocol_version: i32,
    server_address: String,
    server_port: u16,
    next_state: State,
}

impl Packet for HandshakePacket {
    fn from_stream(stream: &mut TcpStream) -> Result<Self> {
        let protocol_version = read_var_int(stream)?;
        let server_address = read_utf8_string(stream, "server_address")?;
        let server_port = read_u16(stream)?;
        let next_state = read_var_int(stream)?;
        let next_state = next_state
            .try_into()
            .context(InvalidStatusSnafu { status: next_state })?;

        Ok(Self {
            protocol_version,
            server_address,
            server_port,
            next_state,
        })
    }
}
