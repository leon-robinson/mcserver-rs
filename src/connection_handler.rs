use std::io::Read;
use std::{io::Write, net::TcpStream};

use snafu::{ensure, ResultExt};
use uuid::Uuid;

use crate::byte_helpers::{CONTINUE_BITS, SEGMENT_BITS};
use crate::crypto::{decrypt_inout, encrypt_inout};
use crate::packet_handlers;
use crate::protocol::PacketIDBelowZeroSnafu;
use crate::protocol::PacketSizeBelowZeroSnafu;
use crate::protocol::UnknownPacketIDSnafu;
use crate::protocol::{BadI32ToUsizeConversionSnafu, BadU8ReadSnafu};
use crate::protocol::{BadUsizeToI32ConversionSnafu, VarIntTooLargeSnafu};
use crate::read_stream::ReadStream;
use crate::Dec;
use crate::Enc;
use crate::{
    byte_helpers,
    protocol::{FailedToFlushStreamSnafu, PacketTooLargeSnafu, Result, State},
    STREAM_READ_TIMEOUT, STREAM_WRITE_TIMEOUT,
};

#[derive(Debug)]
pub struct Connection {
    pub tcp_stream: TcpStream,
    pub read_stream: ReadStream,
    pub state: State,
    pub uuid: Option<Uuid>, // None if we are in the Handshake stage or it's a ping connection.
    pub username: Option<String>, // None if we are in the Handshake stage or it's a ping connection.
    pub enc: Option<Enc>,
    pub dec: Option<Dec>,
}

impl Connection {
    /// Read the first u8 from the `ReadStream`.
    #[inline]
    pub fn read_u8(&mut self, field_name: &'static str) -> Result<u8> {
        self.read_stream.read_u8(field_name)
    }

    /// Read the first u16 from the `ReadStream`
    #[inline]
    pub fn read_u16(&mut self, field_name: &'static str) -> Result<u16> {
        self.read_stream.read_u16(field_name)
    }

    /// Read the first u32 from the `ReadStream`
    #[inline]
    pub fn read_u32(&mut self, field_name: &'static str) -> Result<u32> {
        self.read_stream.read_u32(field_name)
    }

    /// Read the first u64 from the `ReadStream`
    #[inline]
    pub fn read_u64(&mut self, field_name: &'static str) -> Result<u64> {
        self.read_stream.read_u64(field_name)
    }

    /// Read the first i8 from the `ReadStream`
    #[inline]
    pub fn read_i8(&mut self, field_name: &'static str) -> Result<i8> {
        self.read_stream.read_i8(field_name)
    }

    /// Read the first i16 from the `ReadStream`
    #[inline]
    pub fn read_i16(&mut self, field_name: &'static str) -> Result<i16> {
        self.read_stream.read_i16(field_name)
    }

    /// Read the first i32 from the `ReadStream`
    #[inline]
    pub fn read_i32(&mut self, field_name: &'static str) -> Result<i32> {
        self.read_stream.read_i32(field_name)
    }

    /// Read the first i64 from the `ReadStream`
    #[inline]
    pub fn read_i64(&mut self, field_name: &'static str) -> Result<i64> {
        self.read_stream.read_i64(field_name)
    }

    /// Read the first `VarInt` from the `ReadStream`
    #[inline]
    pub fn read_var_int(&mut self, field_name: &'static str) -> Result<i32> {
        self.read_stream.read_var_int(field_name)
    }

    /// Read the first `VarLong` from the `ReadStream`
    #[inline]
    pub fn read_var_long(&mut self, field_name: &'static str) -> Result<i64> {
        self.read_stream.read_var_long(field_name)
    }

    /// Read the first UTF-8 String from the `ReadStream`
    #[inline]
    pub fn read_utf8_string(&mut self, field_name: &'static str) -> Result<String> {
        self.read_stream.read_utf8_string(field_name)
    }

    /// Read the first `Uuid` from the `ReadStream`
    #[inline]
    pub fn read_uuid(&mut self, field_name: &'static str) -> Result<Uuid> {
        self.read_stream.read_uuid(field_name)
    }

    #[inline]
    pub fn read_bytes(&mut self, field_name: &'static str, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_stream.read_bytes(field_name, &mut buf)?;
        Ok(buf)
    }

    /// Algorithm from: <https://wiki.vg/Protocol#VarInt_and_VarLong>
    ///
    /// This reads each byte directly from the `TcpStream` and decrypts it if encryption is enabled, eventually forming a `VarInt`
    fn read_var_int_directly(&mut self, field_name: &'static str) -> Result<i32> {
        let mut value: i32 = 0;
        let mut pos = 0;
        let mut current_byte: u8;

        loop {
            let mut slice = [0u8; 1];
            self.tcp_stream
                .read_exact(&mut slice)
                .context(BadU8ReadSnafu { field_name })?;
            if let Some(dec) = &mut self.dec {
                let slice: &mut [u8] = &mut slice;
                decrypt_inout(dec, slice.into());
            }

            current_byte = slice[0];
            value |= ((i32::from(current_byte)) & SEGMENT_BITS) << pos;

            if ((i32::from(current_byte)) & CONTINUE_BITS) == 0 {
                break;
            }

            pos += 7;

            ensure!(pos < 32, VarIntTooLargeSnafu { field_name });
        }

        Ok(value)
    }

    /// NOTE: Remember to flush after sending all data!
    #[inline]
    pub fn write_bytes_force_unencrypted(&mut self, slice: &[u8]) -> Result<()> {
        byte_helpers::write_byte_slice(&mut self.tcp_stream, slice)
    }

    /// NOTE: Remember to flush after sending all data!
    ///
    /// NOTE: The `slice` will be encrypted after `write_bytes` is done.
    #[inline]
    pub fn write_bytes(&mut self, slice: &mut [u8]) -> Result<()> {
        // Encrypt if encryption is enabled.
        if let Some(enc) = &mut self.enc {
            encrypt_inout(enc, slice.into());
        }
        byte_helpers::write_byte_slice(&mut self.tcp_stream, slice)
    }

    #[inline]
    pub fn flush(&mut self) -> Result<()> {
        self.tcp_stream.flush().context(FailedToFlushStreamSnafu)?;
        Ok(())
    }
}

/// Read and handle packet from the `TcpStream`.
///
/// Return true if should keep connection alive, false if should close the connection.
pub fn handle_packet(connection: &mut Connection) -> Result<bool> {
    let packet_len = if connection.read_stream.data.is_empty() {
        let packet_len = connection.read_var_int_directly("packet_len")?;

        let packet_field_name = "no_field_im_reading_whole_packet_thanks";

        // Create empty packet vec with length of `packet_len`.
        let mut packet_raw =
            vec![
                0u8;
                usize::try_from(packet_len).context(BadI32ToUsizeConversionSnafu {
                    field_name: packet_field_name
                })?
            ];

        // Read the raw bytes of the packet into packet_raw.
        connection
            .tcp_stream
            .read_exact(&mut packet_raw)
            .context(BadU8ReadSnafu {
                field_name: packet_field_name,
            })?;

        // If encryption is enabled, decrypt the raw bytes of the packet.
        if let Some(dec) = &mut connection.dec {
            let slice: &mut [u8] = &mut packet_raw;
            decrypt_inout(dec, slice.into());
        }

        // Add the bytes to the end of the `ReadStream`
        connection.read_stream.data.extend(packet_raw);

        packet_len
    } else {
        // This will most likely happen when multiple packets are sent at the same time by the client.
        connection.read_var_int("packet_len")?
    };

    let packet_id = connection.read_var_int("packet_id")?;

    ensure!(
        packet_len <= 2_097_151,
        PacketTooLargeSnafu {
            packet_len,
            packet_id
        }
    );

    ensure!(
        packet_len >= 0,
        PacketSizeBelowZeroSnafu {
            packet_len,
            packet_id
        }
    );

    ensure!(
        packet_id >= 0,
        PacketIDBelowZeroSnafu {
            packet_len,
            packet_id
        }
    );

    ensure!(
        packet_id
            < packet_handlers::PACKET_HANDLERS.len().try_into().context(
                BadUsizeToI32ConversionSnafu {
                    field_name: "PACKET_HANDLERS"
                }
            )?,
        UnknownPacketIDSnafu {
            packet_len,
            packet_id
        }
    );

    let packet_handler_index =
        usize::try_from(packet_id).context(BadI32ToUsizeConversionSnafu {
            field_name: "packet_id",
        })?;
    let keep_alive =
        packet_handlers::PACKET_HANDLERS[packet_handler_index](connection, packet_len)?;

    Ok(keep_alive)
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
        read_stream: ReadStream { data: vec![] },
        state: State::Unset,
        uuid: None,
        username: None,
        enc: None,
        dec: None,
    };

    loop {
        if !handle_packet(&mut connection).unwrap() {
            println!("[CONNECTION OVER]");
            break;
        }
    }
}
