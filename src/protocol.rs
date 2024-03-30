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
    #[snafu(display("Failed to read string for field: '{field_name}' from stream"))]
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
    #[snafu(display("Failed to read into Vec<u8> of length '{len}' for field: '{field_name}'"))]
    BadByteVecRead {
        source: std::io::Error,
        len: usize,
        field_name: &'static str,
    },
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
    #[snafu(display("VarInt was too large"))]
    VarIntTooLarge { field_name: &'static str },
    #[snafu(display("VarInt was too large"))]
    VarLongTooLarge { field_name: &'static str },
    #[snafu(display("Invalid connection Status: '{status}'"))]
    InvalidStatus {
        source: EnumBoundsError,
        status: i32,
    },
    #[snafu(display("Failed to flush in TcpStream"))]
    FailedToFlushStream { source: std::io::Error },
    #[snafu(display("Failed to write bytes to TcpStream"))]
    FailedByteWritesToStream { source: std::io::Error },
    #[snafu(display("Player name was too long: '{player_name}'"))]
    PlayerNameTooLong { player_name: String },
    #[snafu(display("Packet was too large, size: '{size}', packet_id '{}'"))]
    PacketTooLarge { size: i32, packet_id: i32 },
    #[snafu(display("Server ID is too long in Encryption Request, server_id: {server_id}"))]
    ServerIDTooLong { server_id: String },
    #[snafu(display("Failed to generate RSA private key"))]
    PrivateKeyGenerationFailed { source: rsa::errors::Error },
    #[snafu(display("Failed to convert public key into Document"))]
    PublicKeyDocumentConversionFailed { source: rsa::pkcs8::spki::Error },
    #[snafu(display("Failed to convert i32 to usize"))]
    BadI32ToUsizeConversion { source: std::num::TryFromIntError },
    #[snafu(display("Failed to convert usize to i32"))]
    BadUsizeToI32Conversion { source: std::num::TryFromIntError },
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
pub struct EncryptionResponse {
    pub shared_secret_length: i32,
    pub shared_secret: Vec<u8>,
    pub verify_token_length: i32,
    pub verify_token: Vec<u8>,
}

impl ServerboundPacket for EncryptionResponse {
    fn from_connection(connection: &mut Connection) -> Result<Self> {
        let shared_secret_length = connection.read_var_int("shared_secret_length")?;
        let shared_secret = connection.read_bytes(
            "shared_secret",
            usize::try_from(shared_secret_length).context(BadI32ToUsizeConversionSnafu)?,
        )?;
        let verify_token_length = connection.read_var_int("verify_token_length")?;
        let verify_token = connection.read_bytes(
            "verify_token",
            usize::try_from(verify_token_length).context(BadI32ToUsizeConversionSnafu)?,
        )?;

        Ok(Self {
            shared_secret_length,
            shared_secret,
            verify_token_length,
            verify_token,
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

#[derive(Debug)]
#[allow(dead_code)]
pub struct EncryptionRequest {
    pub server_id: String,
    pub public_key_len: i32,
    pub public_key: Vec<u8>,
    pub verify_token_length: i32, // Should always be 4.
    pub verify_token: [u8; 4],    // A sequence of random bytes.
}

impl ClientboundPacket for EncryptionRequest {
    fn to_bytes(packet: Self) -> Result<Vec<u8>> {
        ensure!(
            packet.server_id.len() <= 20,
            ServerIDTooLongSnafu {
                server_id: packet.server_id
            }
        );

        let mut server_id = create_utf8_string("server_id", &packet.server_id)?;
        let mut public_key_len = create_var_int(packet.public_key_len)?;
        let mut public_key = packet.public_key;
        let mut verify_token_length = create_var_int(packet.verify_token_length)?;
        let verify_token = packet.verify_token;
        let mut packet_id = create_var_int(1)?;
        let mut packet_start = create_var_int(sum_usize_to_i32!(
            packet_id.len(),
            server_id.len(),
            public_key_len.len(),
            public_key.len(),
            verify_token_length.len(),
            verify_token.len()
        ))?;

        packet_start.append(&mut packet_id);
        packet_start.append(&mut server_id);
        packet_start.append(&mut public_key_len);
        packet_start.append(&mut public_key);
        packet_start.append(&mut verify_token_length);
        packet_start.extend_from_slice(&verify_token);

        Ok(packet_start)
    }
}
