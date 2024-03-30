use std::{io::Write, net::TcpStream};

use snafu::ResultExt;

use crate::{
    byte_helpers::{self},
    protocol::{
        ClientboundPacket, FailedToFlushStreamSnafu, HandshakePacket, Result, ServerboundPacket,
        State, StatusResponse,
    },
    STREAM_READ_TIMEOUT, STREAM_WRITE_TIMEOUT,
};

#[derive(Debug)]
pub struct Connection {
    tcp_stream: TcpStream,
    state: State,
}

impl Connection {
    /// Read the first u8 from the `TcpStream`.
    #[inline]
    pub fn read_u8(&mut self) -> Result<u8> {
        byte_helpers::read_u8(&mut self.tcp_stream)
    }

    /// Read the first u16 from the `TcpStream`
    #[inline]
    pub fn read_u16(&mut self) -> Result<u16> {
        byte_helpers::read_u16(&mut self.tcp_stream)
    }

    /// Read the first `VarInt` from the `TcpStream`
    #[inline]
    pub fn read_var_int(&mut self) -> Result<i32> {
        byte_helpers::read_var_int(&mut self.tcp_stream)
    }

    /// Read the first `VarLong` from the `TcpStream`
    #[inline]
    pub fn read_var_long(&mut self) -> Result<i64> {
        byte_helpers::read_var_long(&mut self.tcp_stream)
    }

    /// Read the first UTF-8 String from the `TcpStream`
    #[inline]
    pub fn read_utf8_string(&mut self, field_name: &'static str) -> Result<String> {
        byte_helpers::read_utf8_string(&mut self.tcp_stream, field_name)
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
    let packet_len = connection.read_var_int()?;
    let packet_id = connection.read_var_int()?;
    // TODO: Should probably check if the packet is too large.

    match packet_id {
        0 => match connection.state {
            State::Unset => {
                // Handshake.
                let handshake_packet = HandshakePacket::from_connection(connection)?;
                println!(
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

                println!("Sent back StatusReponse packet.");

                // TODO: Handle and respond to ping request.
            }
            State::Login => {
                // We get here from the handle_packet in the State::Unset handler.

                println!("Now on LOGIN state.");
            }
        },
        _ => {
            eprintln!("WARN: Unknown packet, skipping. packet_len: {packet_len}, packet_id: {packet_id:x}");
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

    let mut connection = Connection {
        tcp_stream: stream,
        state: State::Unset,
    };

    handle_packet(&mut connection).unwrap(); // Handle handshake.
}
