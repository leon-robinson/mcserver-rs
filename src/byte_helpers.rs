const SEGMENT_BITS: i32 = 0x7F;
const CONTINUE_BIT: i32 = 0x80;

use std::{io::Read, net::TcpStream};

/// Simply read from the TcpStream into a byte slice of length 1 and return index 0.
// // TODO: Handle errors better.
#[inline]
pub fn read_u8(stream: &mut TcpStream) -> u8 {
    let mut slice = [0u8; 1];
    stream.read_exact(&mut slice).unwrap();
    slice[0]
}

/// Read from the TcpStream into a byte slice of length 2 and convert to u16 from big endian.
// TODO: Handle errors better.
#[inline]
pub fn read_u16(stream: &mut TcpStream) -> u16 {
    let mut buf = [0; 2];
    stream.read_exact(&mut buf).unwrap();
    u16::from_be_bytes(buf)
}

/// Algorithm from: https://wiki.vg/Protocol#VarInt_and_VarLong
pub fn read_var_int(stream: &mut TcpStream) -> i32 {
    let mut value: i32 = 0;
    let mut pos = 0;
    let mut current_byte: u8;

    loop {
        current_byte = read_u8(stream);
        value |= ((current_byte as i32) & SEGMENT_BITS) << pos;

        if ((current_byte as i32) & CONTINUE_BIT) == 0 {
            break;
        }

        pos += 7;

        assert!(pos < 32);
    }

    value
}

/// Algorithm from:  https://wiki.vg/Protocol#VarInt_and_VarLong
pub fn read_var_long(stream: &mut TcpStream) -> i64 {
    let mut value: i64 = 0;
    let mut pos = 0;
    let mut current_byte: u8;

    loop {
        current_byte = read_u8(stream);
        value |= ((current_byte as i64) & (SEGMENT_BITS as i64)) << pos;

        if ((current_byte as i32) & CONTINUE_BIT) == 0 {
            break;
        }

        pos += 7;

        assert!(pos < 64);
    }

    value
}

// TODO: Handle errors correctly.
pub fn read_utf8_string(stream: &mut TcpStream) -> String {
    let string_len_bytes = read_var_int(stream);

    assert!((0..=32767).contains(&string_len_bytes));

    let mut utf8_bytes = vec![0; string_len_bytes as usize];
    stream.read_exact(&mut utf8_bytes).unwrap();

    let utf8_string = String::from_utf8(utf8_bytes).unwrap();

    let utf16_units = utf8_string.chars().count();
    assert!(utf16_units <= string_len_bytes as usize * 3);

    utf8_string
}
