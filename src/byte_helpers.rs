pub const SEGMENT_BITS: i32 = 0x7F;
pub const CONTINUE_BITS: i32 = 0x80;

use std::{io::Write, net::TcpStream};

use snafu::{ensure, ResultExt};

use crate::protocol::{BadStringUTF16UnitsSnafu, FailedByteWritesToStreamSnafu, Result};

#[macro_export]
macro_rules! sum_usize_to_i32 {
    () => {
        0
    };
    ($head:expr $(, $tail:expr)*) => {
        $head as i32 + sum_usize_to_i32!($($tail),*)
    };
}

/// Algorithm from: <https://wiki.vg/Protocol#VarInt_and_VarLong>
///
/// NOTE: Remember to flush after sending all data!
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
#[must_use]
pub fn create_var_int(data: i32) -> Vec<u8> {
    let mut data = data;
    let mut bytes: Vec<u8> = Vec::new();

    loop {
        if (data & !SEGMENT_BITS) == 0 {
            bytes.push(data as u8);
            return bytes;
        }

        bytes.push(((data & SEGMENT_BITS) | CONTINUE_BITS) as u8);

        data >>= 7;
    }
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

    let mut vec = create_var_int(utf8_bytes_len as i32);
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

impl IntoBytes for bool {
    fn to_mc_bytes(a: Self) -> Vec<u8> {
        vec![u8::from(a)]
    }
}

impl_into_bytes!(u8, u16, u32, u64, i8, i16, i32, i64);

/// Converts a vector with a set size to an array
///
/// # Panics
/// Panics when vec length is not equal to `N`
#[must_use]
pub fn vec_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}
