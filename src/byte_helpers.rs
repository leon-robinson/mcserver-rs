const SEGMENT_BITS: i32 = 0x7F;
const CONTINUE_BIT: i32 = 0x80;

use std::{io::Read, net::TcpStream};

/// Simply read from a TcpStream into a byte slice of length 1 and return index 0.
#[inline]
pub fn read_byte(stream: &mut TcpStream) -> u8 {
    let mut slice = [0u8; 1];
    stream.read_exact(&mut slice).unwrap();
    slice[0]
}

/// Algorithm from: https://wiki.vg/Protocol#VarInt_and_VarLong
pub fn read_var_int(stream: &mut TcpStream) -> i32 {
    let mut value: i32 = 0;
    let mut pos = 0;
    let mut current_byte: u8;

    loop {
        current_byte = read_byte(stream);
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
        current_byte = read_byte(stream);
        value |= ((current_byte as i64) & (SEGMENT_BITS as i64)) << pos;

        if ((current_byte as i32) & CONTINUE_BIT) == 0 {
            break;
        }

        pos += 7;

        assert!(pos < 64);
    }

    value
}
