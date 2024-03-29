const SEGMENT_BITS: i32 = 0x7F;
const CONTINUE_BIT: i32 = 0x80;

use std::{io::Read, net::TcpStream};

use snafu::{ensure, ResultExt};

use crate::protocol::{
    BadStringConversionSnafu, BadStringRangeSnafu, BadStringStreamReadSnafu,
    BadStringUTF16UnitsSnafu, BadU16ReadSnafu, BadU8ReadSnafu, PacketError, Result,
    VarIntTooLargeSnafu, VarLongTooLargeSnafu,
};

/// Simply read from the `TcpStream` into a byte slice of length 1 and return index 0.
// // TODO: Handle errors better.
#[inline]
pub fn read_u8(stream: &mut TcpStream) -> Result<u8> {
    let mut slice = [0u8; 1];
    stream.read_exact(&mut slice).context(BadU8ReadSnafu)?;
    Ok(slice[0])
}

/// Read from the `TcpStream` into a byte slice of length 2 and convert to u16 from big endian.
// TODO: Handle errors better.
#[inline]
pub fn read_u16(stream: &mut TcpStream) -> Result<u16> {
    let mut buf = [0; 2];
    stream.read_exact(&mut buf).context(BadU16ReadSnafu)?;
    Ok(u16::from_be_bytes(buf))
}

/// Algorithm from: <https://wiki.vg/Protocol#VarInt_and_VarLong>
pub fn read_var_int(stream: &mut TcpStream) -> Result<i32> {
    let mut value: i32 = 0;
    let mut pos = 0;
    let mut current_byte: u8;

    loop {
        current_byte = read_u8(stream)?;
        value |= ((i32::from(current_byte)) & SEGMENT_BITS) << pos;

        if ((i32::from(current_byte)) & CONTINUE_BIT) == 0 {
            break;
        }

        pos += 7;

        ensure!(pos < 32, VarIntTooLargeSnafu);
    }

    Ok(value)
}

/// Algorithm from:  <https://wiki.vg/Protocol#VarInt_and_VarLong>
pub fn read_var_long(stream: &mut TcpStream) -> Result<i64> {
    let mut value: i64 = 0;
    let mut pos = 0;
    let mut current_byte: u8;

    loop {
        current_byte = read_u8(stream)?;
        value |= ((i64::from(current_byte)) & (i64::from(SEGMENT_BITS))) << pos;

        if ((i32::from(current_byte)) & CONTINUE_BIT) == 0 {
            break;
        }

        pos += 7;

        ensure!(pos < 64, VarLongTooLargeSnafu);
    }

    Ok(value)
}

/// Implementation from 'Notes' from: <https://wiki.vg/Protocol#Type:String>
///
/// Note that `field_name` is just for extra info when logging if there is an error.
#[allow(clippy::cast_sign_loss)] // We already check that the string length is between 0..=32767
pub fn read_utf8_string(
    stream: &mut TcpStream,
    field_name: &'static str,
) -> Result<String, PacketError> {
    let string_len_bytes = read_var_int(stream)?;

    ensure!(
        (0..=32767).contains(&string_len_bytes),
        BadStringRangeSnafu { field_name }
    );

    let mut utf8_bytes = vec![0; string_len_bytes as usize];
    stream
        .read_exact(&mut utf8_bytes)
        .context(BadStringStreamReadSnafu { field_name })?;

    let utf8_string =
        String::from_utf8(utf8_bytes).context(BadStringConversionSnafu { field_name })?;

    let utf16_units = utf8_string.chars().count();
    ensure!(
        utf16_units <= string_len_bytes as usize * 3,
        BadStringUTF16UnitsSnafu { field_name }
    );

    Ok(utf8_string)
}
