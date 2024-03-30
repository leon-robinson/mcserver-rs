use snafu::{prelude::*, ResultExt};
use std::string::FromUtf8Error;

use crate::{
    back_to_enum,
    byte_helpers::{create_utf8_string, create_var_int},
    connection_handler::Connection,
    macros::EnumBoundsError,
    sum_usize_to_i32,
};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
// TODO: Add field_name for the rest of the errors.
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
    BadStringRange {
        field_name: &'static str,
    },
    #[snafu(display("String received has bad UTF-16 units for field: '{field_name}'"))]
    BadStringUTF16Units {
        field_name: &'static str,
    },
    #[snafu(display("Failed to read u8 value from stream."))]
    BadU8Read {
        source: std::io::Error,
    },
    #[snafu(display("Failed to read u16 value from stream."))]
    BadU16Read {
        source: std::io::Error,
    },
    #[snafu(display("VarInt was too large."))]
    VarIntTooLarge,
    #[snafu(display("VarInt was too large."))]
    VarLongTooLarge,
    #[snafu(display("Invalid connection Status: '{status}'"))]
    InvalidStatus {
        source: EnumBoundsError,
        status: i32,
    },
    FailedToFlushStream {
        source: std::io::Error,
    },
    FailedByteWritesToStream {
        source: std::io::Error,
    },
}

pub type Result<T, E = PacketError> = std::result::Result<T, E>;

pub trait ServerboundPacket: Sized {
    fn from_connection(connection: &mut Connection) -> Result<Self>;
}

pub trait ClientboundPacket: Sized {
    fn to_bytes(packet: Self) -> Result<Vec<u8>>;
}

back_to_enum! {
    #[derive(Debug)]
    pub enum State {
        Unset = 0, // Not actually in the Minecraft protocol, just means that the Handshake has not been sent by the client yet.
        Status = 1,
        Login = 2,
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct HandshakePacket {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: State,
}

impl ServerboundPacket for HandshakePacket {
    fn from_connection(connection: &mut Connection) -> Result<Self> {
        let protocol_version = connection.read_var_int()?;
        let server_address = connection.read_utf8_string("server_address")?;
        let server_port = connection.read_u16()?;
        let next_state = connection.read_var_int()?;
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

#[derive(Debug)]
#[allow(dead_code)]
pub struct StatusResponse {
    pub version_name: String,
    pub version_protocol: i32,
    pub players_max: i32,
    pub players_online: i32,
    // TODO: players_sample
    pub motd: String,
    pub favicon_b64: String,
    pub enforces_secure_chat: bool,
    pub previews_chat: bool,
}

impl ClientboundPacket for StatusResponse {
    fn to_bytes(packet: Self) -> Result<Vec<u8>> {
        let version_name = packet.version_name;
        let version_protocol = packet.version_protocol;
        let players_max = packet.players_max;
        let players_online = packet.players_online;
        let motd = packet.motd;
        let favicon_b64 = packet.favicon_b64;
        let enforces_secure_chat = packet.enforces_secure_chat;
        let previews_chat = packet.previews_chat;

        let response_json = format!(
            r#"{{
            "version": {{
                "name": "{version_name}",
                "protocol": {version_protocol}
            }},
            "players": {{
                "max": {players_max},
                "online": {players_online},
                "sample": [
                    {{
                        "name": "test",
                        "id": "4566e69f-c907-48ee-8d71-d7ba5aa00d20"
                    }}
                ]
            }},
            "description": {{
                "text": "{motd}"
            }},
            "favicon": "data:image/png;base64,{favicon_b64}",
            "enforcesSecureChat": {enforces_secure_chat},
            "previewsChat": {previews_chat}
        }}"#
        );

        let mut s = create_utf8_string("json_status", &response_json)?;
        let mut packet_id = create_var_int(0)?;
        let mut packet_start = create_var_int(sum_usize_to_i32!(packet_id.len(), s.len()))?;

        packet_start.append(&mut packet_id);
        packet_start.append(&mut s);

        Ok(packet_start)
    }
}
