use std::{io::Write, net::TcpStream};

use snafu::{ensure, ResultExt};
use uuid::Uuid;

use crate::{
    byte_helpers, info,
    protocol::{
        ClientboundPacket, EncryptionResponse, FailedToFlushStreamSnafu, HandshakePacket,
        LoginStart, PacketTooLargeSnafu, PingRequest, PingResponse, Result, ServerboundPacket,
        State, StatusResponse,
    },
    warn, KEY_AND_REQUEST, STREAM_READ_TIMEOUT, STREAM_WRITE_TIMEOUT,
};

#[derive(Debug)]
pub struct Connection {
    tcp_stream: TcpStream,
    state: State,
}

impl Connection {
    /// Read the first u8 from the `TcpStream`.
    #[inline]
    pub fn read_u8(&mut self, field_name: &'static str) -> Result<u8> {
        byte_helpers::read_u8(&mut self.tcp_stream, field_name)
    }

    /// Read the first u16 from the `TcpStream`
    #[inline]
    pub fn read_u16(&mut self, field_name: &'static str) -> Result<u16> {
        byte_helpers::read_u16(&mut self.tcp_stream, field_name)
    }

    /// Read the first i8 from the `TcpStream`
    #[inline]
    pub fn read_i8(&mut self, field_name: &'static str) -> Result<i8> {
        byte_helpers::read_i8(&mut self.tcp_stream, field_name)
    }

    /// Read the first i16 from the `TcpStream`
    #[inline]
    pub fn read_i16(&mut self, field_name: &'static str) -> Result<i16> {
        byte_helpers::read_i16(&mut self.tcp_stream, field_name)
    }

    /// Read the first i32 from the `TcpStream`
    #[inline]
    pub fn read_i32(&mut self, field_name: &'static str) -> Result<i32> {
        byte_helpers::read_i32(&mut self.tcp_stream, field_name)
    }

    /// Read the first i64 from the `TcpStream`
    #[inline]
    pub fn read_i64(&mut self, field_name: &'static str) -> Result<i64> {
        byte_helpers::read_i64(&mut self.tcp_stream, field_name)
    }

    /// Read the first `VarInt` from the `TcpStream`
    #[inline]
    pub fn read_var_int(&mut self, field_name: &'static str) -> Result<i32> {
        byte_helpers::read_var_int(&mut self.tcp_stream, field_name)
    }

    /// Read the first `VarLong` from the `TcpStream`
    #[inline]
    pub fn read_var_long(&mut self, field_name: &'static str) -> Result<i64> {
        byte_helpers::read_var_long(&mut self.tcp_stream, field_name)
    }

    /// Read the first UTF-8 String from the `TcpStream`
    #[inline]
    pub fn read_utf8_string(&mut self, field_name: &'static str) -> Result<String> {
        byte_helpers::read_utf8_string(&mut self.tcp_stream, field_name)
    }

    /// Read the first `Uuid` from the `TcpStream`
    #[inline]
    pub fn read_uuid(&mut self, field_name: &'static str) -> Result<Uuid> {
        byte_helpers::read_uuid(&mut self.tcp_stream, field_name)
    }

    #[inline]
    pub fn read_bytes(&mut self, field_name: &'static str, len: usize) -> Result<Vec<u8>> {
        byte_helpers::read_bytes(&mut self.tcp_stream, field_name, len)
    }

    /// NOTE: Remember to flush after sending all data!
    #[inline]
    pub fn write_bytes(&mut self, slice: &[u8]) -> Result<()> {
        byte_helpers::write_byte_slice(&mut self.tcp_stream, slice)
    }

    #[inline]
    pub fn flush(&mut self) -> Result<()> {
        self.tcp_stream.flush().context(FailedToFlushStreamSnafu)?;
        Ok(())
    }
}

/// Read and handle packet from the `TcpStream`.
fn handle_packet(connection: &mut Connection) -> Result<()> {
    let packet_len = connection.read_var_int("packet_len")?;
    let packet_id = connection.read_var_int("packet_id")?;

    ensure!(
        packet_len <= 2_097_151,
        PacketTooLargeSnafu {
            size: packet_len,
            packet_id
        }
    );

    match packet_id {
        0x00 => match connection.state {
            State::Unset => {
                // Handshake.
                let handshake_packet = HandshakePacket::from_connection(connection)?;
                info!(
                    "Got handshake, they are connecting with {}:{} on protocol version {}, next state is {}.",
                    handshake_packet.server_address,
                    handshake_packet.server_port,
                    handshake_packet.protocol_version,
                    handshake_packet.next_state
                );

                connection.state = handshake_packet.next_state;

                handle_packet(connection)?; // After receiving the initial HandshakePacket, a Login Start or Status Request packet will follow.
            }
            State::Status => {
                // We get here from the handle_packet in the State::Unset handler.

                // TODO: Cache the packet instead of creating it every request.
                let packet = StatusResponse::to_bytes(StatusResponse {
                    version_name: "1.20.4".into(),
                    version_protocol: 765,
                    players_max: 20,
                    players_online: 7,
                    motd: "Test\nNew line".into(),
                    favicon_b64: "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABHNCSVQICAgIfAhkiAAAAIlJREFUeF7t1QERACAMAzHAv+fBYeODg/Uauue9FX4nfPs/XQAaEE8AgXgBfIIIIBBPAIF4AawAAgjEE0AgXgArgAAC8QQQiBfACiCAQDwBBOIFsAIIIBBPAIF4AawAAgjEE0AgXgArgAAC8QQQiBfACiCAQDwBBOIFsAIIIBBPAIF4AawAAnUCF1U6BHx5JYjsAAAAAElFTkSuQmCC".into(),
                    enforces_secure_chat: false,
                    previews_chat: true,
                })?;

                connection.write_bytes(&packet)?;
                connection.flush()?;

                info!("Sent back StatusReponse packet.");

                handle_packet(connection)?; // Wait for Ping Request from client.
            }
            State::Login => {
                // We get here from the handle_packet in the State::Unset handler.

                info!("Now on LOGIN state.");

                let login_start_packet = LoginStart::from_connection(connection)?;
                info!("{login_start_packet:?}");

                connection.write_bytes(&KEY_AND_REQUEST.1)?;
                connection.flush()?;

                info!("Sent encryption request.");

                handle_packet(connection)?;
            }
        },
        0x01 => match connection.state {
            State::Status => {
                let packet = PingRequest::from_connection(connection)?;

                info!("Got PingRequest with millis: {}", packet.sys_time_millis);

                connection.write_bytes(
                    PingResponse::to_bytes(PingResponse {
                        sys_time_millis: packet.sys_time_millis,
                    })?
                    .as_slice(),
                )?;
                connection.flush()?;

                info!(
                    "Sent back PingResponse with millis: {}",
                    packet.sys_time_millis
                );
            }
            State::Login => {
                let encryption_response = EncryptionResponse::from_connection(connection)?;

                info!("{encryption_response:?}");
            }
            _ => {
                warn!("Got packet_id 0x01 with state: {}", connection.state);
            }
        },
        _ => {
            warn!(
                "Unknown packet, skipping. packet_len (bytes): {packet_len}, packet_id: 0x{packet_id:02x}"
            );
        }
    }

    Ok(())
}

/// Take over from main to handle the `TcpStream`.
///
/// # Panics
/// We panic for the moment when we have a `PacketError`, but in the future kick the player (if connected) and close the connection.
pub fn handle_connection(stream: TcpStream) {
    stream
        .set_read_timeout(Some(STREAM_READ_TIMEOUT))
        .expect("Failed to set read timeout for TcpStream.");
    stream
        .set_write_timeout(Some(STREAM_WRITE_TIMEOUT))
        .expect("Failed to set write timeout for TcpStream.");
    stream
        .set_nonblocking(false)
        .expect("Failed to set nonblocking false for TcpStream.");

    let mut connection = Connection {
        tcp_stream: stream,
        state: State::Unset,
    };

    handle_packet(&mut connection).unwrap(); // Handle handshake.
}
