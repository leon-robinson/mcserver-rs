use crate::{
    byte_helpers::{vec_to_array, IntoBytes},
    connection_handler::handle_packet,
    identifier::{Identifier, MINECRAFT_NAMESPACE},
    info_connection,
    read_stream::ReadStream,
    warn_connection, Dec, Enc, ENCRYPTION_INFO,
};
use cipher::KeyIvInit;
use rsa::Pkcs1v15Encrypt;
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
    #[snafu(display("Reached the end of read stream"))]
    EndOfReadStream { field_name: &'static str },
    #[snafu(display("Failed try_into() for slice"))]
    BadTryFromSlice {
        source: std::array::TryFromSliceError,
    },
    #[snafu(display("Failed to read bytes for packet"))]
    BadPacketBytesRead { source: std::io::Error },
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
    #[snafu(display("Packet was too large, packet_len: '{packet_len}', packet_id '{packet_id}'"))]
    PacketTooLarge { packet_len: i32, packet_id: i32 },
    #[snafu(display(
        "Packet was below zero, packet_len: '{packet_len}', packet_id '{packet_id}'"
    ))]
    PacketSizeBelowZero { packet_len: i32, packet_id: i32 },
    #[snafu(display("Packet ID below zero, packet_len: '{packet_len}', packet_id '{packet_id}'"))]
    PacketIDBelowZero { packet_len: i32, packet_id: i32 },
    #[snafu(display("Unknown Packet ID, packet_len: '{packet_len}', packet_id: '{packet_id}'"))]
    UnknownPacketID { packet_len: i32, packet_id: i32 },
    #[snafu(display("Server ID is too long in Encryption Request, server_id: {server_id}"))]
    ServerIDTooLong { server_id: String },
    #[snafu(display("Failed to generate RSA private key"))]
    PrivateKeyGenerationFailed { source: rsa::errors::Error },
    #[snafu(display("Failed to convert public key into Document"))]
    PublicKeyDocumentConversionFailed { source: rsa::pkcs8::spki::Error },
    #[snafu(display("Failed to convert i32 to usize"))]
    BadI32ToUsizeConversion {
        source: std::num::TryFromIntError,
        field_name: &'static str,
    },
    #[snafu(display("Failed to convert usize to i32"))]
    BadUsizeToI32Conversion {
        source: std::num::TryFromIntError,
        field_name: &'static str,
    },
    #[snafu(display("Failed to decrypt secret key"))]
    BadSecretKeyDecryption { source: rsa::Error },
    #[snafu(display("Failed to decrypt verify token"))]
    BadVerifyTokenDecryption { source: rsa::Error },
    #[snafu(display("Decrypted verify token length was bad"))]
    BadDecryptedVerifyTokenLength,
    #[snafu(display("Decrypted secret key length was bad"))]
    BadDecryptedSecretKeyLength,
    #[snafu(display("The verify tokens did not match"))]
    BadVerifyTokenComparison,
    #[snafu(display("Failed to create encryptor"))]
    BadEncryptorCreation { source: cipher::InvalidLength },
    #[snafu(display("Failed to create decryptor"))]
    BadDecryptorCreation { source: cipher::InvalidLength },
    #[snafu(display(
        "The packet handler did not read all the bytes from the packet, packet_id: {packet_id}"
    ))]
    BadPacketHandlerReads {
        packet_id: i32,
        expected_bytes_read: usize,
        actual_bytes_read: usize,
    },
    #[snafu(display("Player attempting to connect with username '{username}' skipped login"))]
    ClientSkippedLogin { username: String },
    #[snafu(display("Identifier creation failed, bad namespace, namespace was '{namespace}', sent_by_client='{sent_by_client}'"))]
    BadNewIdentifierNamespace {
        namespace: String,
        sent_by_client: bool,
    },
    #[snafu(display("Identifier creation failed, bad value, value was '{value}', sent_by_client='{sent_by_client}'"))]
    BadNewIdentifierValue { value: String, sent_by_client: bool },
    #[snafu(display("Identifier creation failed, was too long: '{identifier:?}', sent_by_client='{sent_by_client}'"))]
    BadNewIdentifierLength {
        identifier: Identifier,
        sent_by_client: bool,
    },
    #[snafu(display("Too many or too little ':' in identifier: '{identifier_raw}'"))]
    IdentifierStrangeColons { identifier_raw: String },
    #[snafu(display(
        "Received ServerboundPluginMessage with an unknown namespace: '{namespace}'"
    ))]
    ServerboundPluginMessageUnknownNamespace { namespace: String },
}

pub type Result<T, E = PacketError> = std::result::Result<T, E>;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Property {
    pub name: String,
    pub value: String,
    pub is_signed: bool,
    pub signature: Option<String>, // Must be Some if is_signed is true.
}

pub trait ServerboundPacket: Sized {
    // NOTE: packet_len does not include packet_id length.
    fn from_connection(connection: &mut Connection, packet_len: usize) -> Result<Self>;
    fn handle(self, connection: &mut Connection) -> Result<()>;
}

pub trait ClientboundPacket: Sized {
    fn to_bytes(packet: Self) -> Result<Vec<u8>>;
}

back_to_enum! {
    #[derive(Debug, Clone, Copy)]
    pub enum State {
        Configuration = -1, // No value correlates with the Configuration state, so set it to -1.
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
    fn from_connection(connection: &mut Connection, _packet_len: usize) -> Result<Self> {
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

    fn handle(self, connection: &mut Connection) -> Result<()> {
        info_connection!(
            connection,
            "Got handshake, they are connecting with {}:{} on protocol version {}, next state is {}.",
            self.server_address,
            self.server_port,
            self.protocol_version,
            self.next_state
        );

        connection.state = self.next_state;

        handle_packet(connection)?; // After receiving the initial HandshakePacket, a Login Start or Status Request packet will follow.
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct LoginStart {
    name: String,
    uuid: Uuid,
}

impl ServerboundPacket for LoginStart {
    fn from_connection(connection: &mut Connection, _packet_len: usize) -> Result<Self> {
        let name = connection.read_utf8_string("name")?;
        let uuid = connection.read_uuid("uuid")?;

        ensure!(
            name.len() <= 16,
            PlayerNameTooLongSnafu { player_name: name }
        );

        connection.username = Some(name.clone());
        connection.uuid = Some(uuid);

        Ok(Self { name, uuid })
    }

    fn handle(self, connection: &mut Connection) -> Result<()> {
        info_connection!(connection, "Now on LOGIN state.");

        info_connection!(connection, "{self:?}");
        // TODO: Set name & UUID in connection.

        connection.write_bytes_force_unencrypted(&ENCRYPTION_INFO.encryption_request_bytes)?;
        connection.flush()?;

        info_connection!(connection, "Sent encryption request.");

        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct PingRequest {
    pub sys_time_millis: i64,
}

impl ServerboundPacket for PingRequest {
    fn from_connection(connection: &mut Connection, _packet_len: usize) -> Result<Self> {
        Ok(Self {
            sys_time_millis: connection.read_i64("sys_time_millis")?,
        })
    }

    fn handle(self, connection: &mut Connection) -> Result<()> {
        info_connection!(
            connection,
            "Got PingRequest with millis: {}",
            self.sys_time_millis
        );

        connection.write_bytes(
            PingResponse::to_bytes(PingResponse {
                sys_time_millis: self.sys_time_millis,
            })?
            .as_mut_slice(),
        )?;
        connection.flush()?;

        info_connection!(
            connection,
            "Sent back PingResponse with millis: {}",
            self.sys_time_millis
        );

        Ok(())
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
    fn from_connection(connection: &mut Connection, _packet_len: usize) -> Result<Self> {
        let shared_secret_length = connection.read_var_int("shared_secret_length")?;

        let shared_secret = connection.read_bytes(
            "shared_secret",
            usize::try_from(shared_secret_length).context(BadI32ToUsizeConversionSnafu {
                field_name: "shared_secret",
            })?,
        )?;
        let verify_token_length = connection.read_var_int("verify_token_length")?;
        let verify_token = connection.read_bytes(
            "verify_token",
            usize::try_from(verify_token_length).context(BadI32ToUsizeConversionSnafu {
                field_name: "verify_token",
            })?,
        )?;

        Ok(Self {
            shared_secret_length,
            shared_secret,
            verify_token_length,
            verify_token,
        })
    }

    fn handle(self, connection: &mut Connection) -> Result<()> {
        let secret_key_encrypted = &self.shared_secret;
        let secret_key = ENCRYPTION_INFO
            .private_key
            .decrypt(Pkcs1v15Encrypt, secret_key_encrypted)
            .context(BadSecretKeyDecryptionSnafu)?;
        let verify_token_encrypted = &self.verify_token;
        let verify_token = ENCRYPTION_INFO
            .private_key
            .decrypt(Pkcs1v15Encrypt, verify_token_encrypted)
            .context(BadVerifyTokenDecryptionSnafu)?;

        ensure!(verify_token.len() == 4, BadDecryptedVerifyTokenLengthSnafu);
        ensure!(secret_key.len() == 16, BadDecryptedSecretKeyLengthSnafu);
        ensure!(
            verify_token.as_slice() == ENCRYPTION_INFO.verify_token,
            BadVerifyTokenComparisonSnafu
        );

        let key: [u8; 16] = vec_to_array(secret_key);

        let enc = Enc::new_from_slices(&key, &key).context(BadEncryptorCreationSnafu)?;
        let dec = Dec::new_from_slices(&key, &key).context(BadDecryptorCreationSnafu)?;

        connection.enc = Some(enc);
        connection.dec = Some(dec);

        info_connection!(
            connection,
            "Set encryptor and decryptor, sending Login Success"
        );

        // TODO: properties
        connection.write_bytes(
            LoginSuccess::to_bytes(LoginSuccess {
                uuid: connection.uuid.unwrap(),
                username: connection.username.clone().unwrap(),
                properties_length: 0,
                properties: None,
            })?
            .as_mut_slice(),
        )?;
        connection.flush()?;

        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ServerboundPluginMessage {
    pub channel: Identifier,
    pub data: Vec<u8>,
}

impl ServerboundPacket for ServerboundPluginMessage {
    fn from_connection(connection: &mut Connection, packet_len: usize) -> Result<Self> {
        let channel_and_len = connection.read_identifier_and_len("channel")?;
        let channel = channel_and_len.0;
        let channel_len: usize =
            channel_and_len
                .1
                .try_into()
                .context(BadI32ToUsizeConversionSnafu {
                    field_name: "channel_len",
                })?;
        let data_len = packet_len - channel_len;

        let data = connection.read_bytes("data", data_len)?;

        Ok(Self { channel, data })
    }

    fn handle(self, connection: &mut Connection) -> Result<()> {
        let channel = self.channel;

        ensure!(
            channel.namespace() == MINECRAFT_NAMESPACE,
            ServerboundPluginMessageUnknownNamespaceSnafu {
                namespace: channel.namespace()
            }
        );

        let mut data_read_stream = ReadStream { data: self.data };

        match channel.value() {
            "brand" => {
                let client_brand = data_read_stream.read_utf8_string("client_brand")?;
                info_connection!(connection, "Client brand is: '{client_brand}'");
                connection.client_brand = Some(client_brand);
            }
            channel_value => {
                warn_connection!(connection, "Unknown channel value: '{channel_value}' when handling ServerboundPluginMessage");
            }
        }

        Ok(())
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
        let mut packet_id = create_var_int(0x00); // TODO: Cache these.
        let mut packet_start = create_var_int(sum_usize_to_i32!(packet_id.len(), s.len()));

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
        let mut packet_id = create_var_int(0x01);
        let mut packet_start =
            create_var_int(sum_usize_to_i32!(packet_id.len(), sys_time_millis.len()));

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
        let mut public_key_len = create_var_int(packet.public_key_len);
        let mut public_key = packet.public_key;
        let mut verify_token_length = create_var_int(packet.verify_token_length);
        let verify_token = packet.verify_token;
        let mut packet_id = create_var_int(0x01);
        let mut packet_start = create_var_int(sum_usize_to_i32!(
            packet_id.len(),
            server_id.len(),
            public_key_len.len(),
            public_key.len(),
            verify_token_length.len(),
            verify_token.len()
        ));

        packet_start.append(&mut packet_id);
        packet_start.append(&mut server_id);
        packet_start.append(&mut public_key_len);
        packet_start.append(&mut public_key);
        packet_start.append(&mut verify_token_length);
        packet_start.extend_from_slice(&verify_token);

        Ok(packet_start)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct LoginSuccess {
    pub uuid: Uuid,
    pub username: String,
    pub properties_length: i32,
    pub properties: Option<Vec<Property>>,
}

impl ClientboundPacket for LoginSuccess {
    fn to_bytes(packet: Self) -> Result<Vec<u8>> {
        ensure!(
            packet.username.len() <= 16,
            PlayerNameTooLongSnafu {
                player_name: packet.username
            }
        );

        let uuid = packet.uuid.into_bytes();
        let mut username = create_utf8_string("username", &packet.username)?;
        // TODO: actually implement properties
        let mut properties_length = create_var_int(1);
        let mut packet_id = create_var_int(0x02);

        let mut textures = create_utf8_string("name", "textures")?;
        let mut value = create_utf8_string("value", "ewogICJ0aW1lc3RhbXAiIDogMTcxMTg4NzYyMzA5MywKICAicHJvZmlsZUlkIiA6ICI2OTI4NTg3ZjFiMjE0NzAzYmM3OWUzZWZiYWU2ZTRhOSIsCiAgInByb2ZpbGVOYW1lIiA6ICJsZW9ucm9iaSIsCiAgInNpZ25hdHVyZVJlcXVpcmVkIiA6IHRydWUsCiAgInRleHR1cmVzIiA6IHsKICAgICJTS0lOIiA6IHsKICAgICAgInVybCIgOiAiaHR0cDovL3RleHR1cmVzLm1pbmVjcmFmdC5uZXQvdGV4dHVyZS83ZmEyOGNkZjhjMWQ1NzE3NTFiM2FhZWNkM2IwYmU2MGMzMTkyNmQ1YWY4NjVmMjc5YzNlZmU1MWI5Nzc2N2ExIgogICAgfQogIH0KfQ==")?;
        let mut is_signed = bool::to_mc_bytes(false);
        let mut packet_start = create_var_int(sum_usize_to_i32!(
            packet_id.len(),
            uuid.len(),
            username.len(),
            properties_length.len(),
            textures.len(),
            value.len(),
            is_signed.len()
        ));

        packet_start.append(&mut packet_id);
        packet_start.extend_from_slice(&uuid);
        packet_start.append(&mut username);
        packet_start.append(&mut properties_length);
        packet_start.append(&mut textures);
        packet_start.append(&mut value);
        packet_start.append(&mut is_signed);

        Ok(packet_start)
    }
}
