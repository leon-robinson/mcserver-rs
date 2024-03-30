use crate::byte_helpers::IntoBytes;
use snafu::{prelude::*, ResultExt};
use std::string::FromUtf8Error;
use uuid::Uuid;

use crate::{
    back_to_enum,
    byte_helpers::{create_utf8_string, create_var_int},
    connection_handler::Connection,
    macros::EnumBoundsError,
    sum_usize_to_i32,
};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
// TODO: Change field_name to err_info and add packet name to the error message instead of just field name.
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
    #[snafu(display("Failed to read u8 value from stream for field: '{field_name}'"))]
    BadU8Read {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("Failed to read u16 value from stream for field: '{field_name}'"))]
    BadU16Read {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("Failed to read i8 value from stream for field: '{field_name}'"))]
    BadI8Read {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("Failed to read i16 value from stream for field: '{field_name}'"))]
    BadI16Read {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("Failed to read i32 value from stream for field: '{field_name}'"))]
    BadI32Read {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("Failed to read i64 value from stream for field: '{field_name}'"))]
    BadI64Read {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("Failed to read UUID from stream for field: '{field_name}'"))]
    BadUUIDRead {
        source: std::io::Error,
        field_name: &'static str,
    },
    #[snafu(display("VarInt was too large."))]
    VarIntTooLarge { field_name: &'static str },
    #[snafu(display("VarInt was too large."))]
    VarLongTooLarge { field_name: &'static str },
    #[snafu(display("Invalid connection Status: '{status}'"))]
    InvalidStatus {
        source: EnumBoundsError,
        status: i32,
    },
    #[snafu(display("Failed to flush in TcpStream."))]
    FailedToFlushStream { source: std::io::Error },
    #[snafu(display("Failed to write bytes to TcpStream."))]
    FailedByteWritesToStream { source: std::io::Error },
    #[snafu(display("Player name was too long: '{player_name}'."))]
    PlayerNameTooLong { player_name: String },
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
        let protocol_version = connection.read_var_int("protocol_version")?;
        let server_address = connection.read_utf8_string("server_address")?;
        let server_port = connection.read_u16("server_port")?;
        let next_state = connection.read_var_int("next_state")?;
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
pub struct LoginStart {
    name: String,
    uuid: Uuid,
}

impl ServerboundPacket for LoginStart {
    fn from_connection(connection: &mut Connection) -> Result<Self> {
        let name = connection.read_utf8_string("name")?;

        ensure!(
            name.len() <= 16,
            PlayerNameTooLongSnafu { player_name: name }
        );

        Ok(Self {
            name,
            uuid: connection.read_uuid("uuid")?,
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PingRequest {
    pub sys_time_millis: i64,
}

impl ServerboundPacket for PingRequest {
    fn from_connection(connection: &mut Connection) -> Result<Self> {
        Ok(Self {
            sys_time_millis: connection.read_i64("sys_time_millis")?,
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
        let mut packet_id = create_var_int(0)?; // TODO: Cache these.
        let mut packet_start = create_var_int(sum_usize_to_i32!(packet_id.len(), s.len()))?;

        packet_start.append(&mut packet_id);
        packet_start.append(&mut s);

        Ok(packet_start)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PingResponse {
    pub sys_time_millis: i64,
}

impl ClientboundPacket for PingResponse {
    fn to_bytes(packet: Self) -> Result<Vec<u8>> {
        let mut sys_time_millis = i64::to_mc_bytes(packet.sys_time_millis);
        let mut packet_id = create_var_int(1)?;
        let mut packet_start =
            create_var_int(sum_usize_to_i32!(packet_id.len(), sys_time_millis.len()))?;

        packet_start.append(&mut packet_id);
        packet_start.append(&mut sys_time_millis);

        Ok(packet_start)
    }
}
