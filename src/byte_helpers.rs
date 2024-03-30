const SEGMENT_BITS: i32 = 0x7F;
const CONTINUE_BIT: i32 = 0x80;

use std::{
    io::{Read, Write},
    net::TcpStream,
};

use snafu::{ensure, ResultExt};
use uuid::Uuid;

use crate::protocol::{
    BadByteVecReadSnafu, BadI16ReadSnafu, BadI32ReadSnafu, BadI64ReadSnafu, BadI8ReadSnafu,
    BadStringConversionSnafu, BadStringRangeSnafu, BadStringStreamReadSnafu,
    BadStringUTF16UnitsSnafu, BadU16ReadSnafu, BadU8ReadSnafu, BadUUIDReadSnafu,
    FailedByteWritesToStreamSnafu, PacketError, Result, VarIntTooLargeSnafu, VarLongTooLargeSnafu,
};

#[macro_export]
macro_rules! sum_usize_to_i32 {
    () => {
        0
    };
    ($head:expr $(, $tail:expr)*) => {
        $head as i32 + sum_usize_to_i32!($($tail),*)
    };
}

/// Read from the `TcpStream` into a `Vec<u8>`
#[inline]
pub fn read_bytes(stream: &mut TcpStream, field_name: &'static str, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .context(BadByteVecReadSnafu { len, field_name })?;
    Ok(buf)
}

/// Simply read from the `TcpStream` into a byte slice of length 1 and return index 0.
#[inline]
pub fn read_u8(stream: &mut TcpStream, field_name: &'static str) -> Result<u8> {
    let mut slice = [0u8; 1];
    stream
        .read_exact(&mut slice)
        .context(BadU8ReadSnafu { field_name })?;
    Ok(slice[0])
}

/// Read from the `TcpStream` into a byte slice of length 2 and convert to u16 from big endian.
#[inline]
pub fn read_u16(stream: &mut TcpStream, field_name: &'static str) -> Result<u16> {
    let mut buf = [0; 2];
    stream
        .read_exact(&mut buf)
        .context(BadU16ReadSnafu { field_name })?;
    Ok(u16::from_be_bytes(buf))
}

/// Read from the `TcpStream` into a byte slice of length 1 and convert to i8 from big endian.
#[inline]
pub fn read_i8(stream: &mut TcpStream, field_name: &'static str) -> Result<i8> {
    let mut buf = [0; 1];
    stream
        .read_exact(&mut buf)
        .context(BadI8ReadSnafu { field_name })?;
    Ok(i8::from_be_bytes(buf))
}

/// Read from the `TcpStream` into a byte slice of length 2 and convert to i16 from big endian.
#[inline]
pub fn read_i16(stream: &mut TcpStream, field_name: &'static str) -> Result<i16> {
    let mut buf = [0; 2];
    stream
        .read_exact(&mut buf)
        .context(BadI16ReadSnafu { field_name })?;
    Ok(i16::from_be_bytes(buf))
}

/// Read from the `TcpStream` into a byte slice of length 4 and convert to i32 from big endian.
#[inline]
pub fn read_i32(stream: &mut TcpStream, field_name: &'static str) -> Result<i32> {
    let mut buf = [0; 4];
    stream
        .read_exact(&mut buf)
        .context(BadI32ReadSnafu { field_name })?;
    Ok(i32::from_be_bytes(buf))
}

/// Read from the `TcpStream` into a byte slice of length 8 and convert to i64 from big endian.
#[inline]
pub fn read_i64(stream: &mut TcpStream, field_name: &'static str) -> Result<i64> {
    let mut buf = [0; 8];
    stream
        .read_exact(&mut buf)
        .context(BadI64ReadSnafu { field_name })?;
    Ok(i64::from_be_bytes(buf))
}

/// Algorithm from: <https://wiki.vg/Protocol#VarInt_and_VarLong>
pub fn read_var_int(stream: &mut TcpStream, field_name: &'static str) -> Result<i32> {
    let mut value: i32 = 0;
    let mut pos = 0;
    let mut current_byte: u8;

    loop {
        current_byte = read_u8(stream, field_name)?;
        value |= ((i32::from(current_byte)) & SEGMENT_BITS) << pos;

        if ((i32::from(current_byte)) & CONTINUE_BIT) == 0 {
            break;
        }

        pos += 7;

        ensure!(pos < 32, VarIntTooLargeSnafu { field_name });
    }

    Ok(value)
}

/// Algorithm from: <https://wiki.vg/Protocol#VarInt_and_VarLong>
///
/// NOTE: Remember to flush after sending all data!
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
pub fn create_var_int(data: i32) -> Result<Vec<u8>> {
    let mut data = data;
    let mut bytes: Vec<u8> = Vec::new();

    loop {
        if (data & !SEGMENT_BITS) == 0 {
            bytes.push(data as u8);
            return Ok(bytes);
        }

        bytes.push(((data & SEGMENT_BITS) | CONTINUE_BIT) as u8);

        data >>= 7;
    }
}

/// Algorithm from:  <https://wiki.vg/Protocol#VarInt_and_VarLong>
pub fn read_var_long(stream: &mut TcpStream, field_name: &'static str) -> Result<i64> {
    let mut value: i64 = 0;
    let mut pos = 0;
    let mut current_byte: u8;

    loop {
        current_byte = read_u8(stream, field_name)?;
        value |= ((i64::from(current_byte)) & (i64::from(SEGMENT_BITS))) << pos;

        if ((i32::from(current_byte)) & CONTINUE_BIT) == 0 {
            break;
        }

        pos += 7;

        ensure!(pos < 64, VarLongTooLargeSnafu { field_name });
    }

    Ok(value)
}

pub fn read_uuid(stream: &mut TcpStream, field_name: &'static str) -> Result<Uuid> {
    let mut buf = [0; 16];
    stream
        .read_exact(&mut buf)
        .context(BadUUIDReadSnafu { field_name })?;
    Ok(Uuid::from_bytes(buf))
}

/// Implementation from 'Notes' from: <https://wiki.vg/Protocol#Type:String>
///
/// Note that `field_name` is just for extra info when logging if there is an error.
#[allow(clippy::cast_sign_loss)] // We already check that the string length is between 0..=32767
pub fn read_utf8_string(
    stream: &mut TcpStream,
    field_name: &'static str,
) -> Result<String, PacketError> {
    let string_len_bytes = read_var_int(stream, field_name)?;

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

    let utf16_units = utf8_string.len(); // TODO: Might be incorrect, this should probably be amount of chars instead of len.
    ensure!(
        utf16_units <= string_len_bytes as usize * 3,
        BadStringUTF16UnitsSnafu { field_name }
    );

    Ok(utf8_string)
}

/// Implementation from 'Notes' from: <https://wiki.vg/Protocol#Type:String>
///
/// Creates and returns a UTF-8 string prefixed with `VarInt` that can be sent to a client.
///
/// Note that `field_name` is just for extra info when logging if there is an error.
/// NOTE: Remember to flush after sending all data!
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn create_utf8_string(field_name: &'static str, s: &str) -> Result<Vec<u8>> {
    let utf8_bytes_len = s.len(); // Might be incorrect, this should probably be amount of chars instead of len.

    ensure!(
        utf8_bytes_len <= 32767 * 3,
        BadStringUTF16UnitsSnafu { field_name }
    );

    let mut vec = create_var_int(utf8_bytes_len as i32)?;
    vec.extend_from_slice(s.as_bytes());

    Ok(vec)
}

#[inline]
/// NOTE: Remember to flush after sending all data!
pub fn write_byte_slice(stream: &mut TcpStream, slice: &[u8]) -> Result<()> {
    stream
        .write_all(slice)
        .context(FailedByteWritesToStreamSnafu)?;
    Ok(())
}

pub trait IntoBytes {
    fn to_mc_bytes(a: Self) -> Vec<u8>;
}

macro_rules! impl_into_bytes {
    ($($t:ty),*) => {
        $(
            impl IntoBytes for $t {
                fn to_mc_bytes(a: Self) -> Vec<u8> {
                    a.to_be_bytes().to_vec()
                }
            }
        )*
    };
}

impl_into_bytes!(u8, u16, u32, u64, i8, i16, i32, i64);
