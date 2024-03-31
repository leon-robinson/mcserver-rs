use snafu::{ensure, ResultExt};
use uuid::Uuid;

use crate::{
    byte_helpers::{CONTINUE_BITS, SEGMENT_BITS},
    protocol::{
        BadStringConversionSnafu, BadStringRangeSnafu, BadStringUTF16UnitsSnafu,
        BadTryFromSliceSnafu, EndOfReadStreamSnafu, Result, VarIntTooLargeSnafu,
        VarLongTooLargeSnafu,
    },
};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct ReadStream {
    pub data: Vec<u8>,
}

impl ReadStream {
    pub fn read_bytes(&mut self, field_name: &'static str, buf: &mut [u8]) -> Result<()> {
        ensure!(
            self.data.len() >= buf.len(),
            EndOfReadStreamSnafu { field_name }
        );

        let len = buf.len();
        buf.copy_from_slice(&self.data[..len]);
        self.data.drain(..len);

        Ok(())
    }

    /// Move 1 byte from the start of the data and interpret it as an `i8`
    pub fn read_i8(&mut self, field_name: &'static str) -> Result<i8> {
        ensure!(!self.data.is_empty(), EndOfReadStreamSnafu { field_name });

        let val = i8::from_be_bytes(self.data[..1].try_into().context(BadTryFromSliceSnafu)?);
        self.data.drain(0..1);

        Ok(val)
    }

    /// Move 1 byte from the start of the data and interpret it as a `u8`
    pub fn read_u8(&mut self, field_name: &'static str) -> Result<u8> {
        ensure!(!self.data.is_empty(), EndOfReadStreamSnafu { field_name });

        let val = self.data[0];
        self.data.drain(0..1);

        Ok(val)
    }

    /// Move 2 bytes from the start of the data and interpret them as an `i16`
    pub fn read_i16(&mut self, field_name: &'static str) -> Result<i16> {
        ensure!(self.data.len() >= 2, EndOfReadStreamSnafu { field_name });

        let val = i16::from_be_bytes(self.data[..2].try_into().context(BadTryFromSliceSnafu)?);
        self.data.drain(..2);

        Ok(val)
    }

    /// Move 2 bytes from the start of the data and interpret them as a `u16`
    pub fn read_u16(&mut self, field_name: &'static str) -> Result<u16> {
        ensure!(self.data.len() >= 2, EndOfReadStreamSnafu { field_name });

        let val = u16::from_be_bytes(self.data[..2].try_into().context(BadTryFromSliceSnafu)?);
        self.data.drain(..2);

        Ok(val)
    }

    /// Move 4 bytes from the start of the data and interpret them as an `i32`
    pub fn read_i32(&mut self, field_name: &'static str) -> Result<i32> {
        ensure!(self.data.len() >= 4, EndOfReadStreamSnafu { field_name });

        let val = i32::from_be_bytes(self.data[..4].try_into().context(BadTryFromSliceSnafu)?);
        self.data.drain(..4);

        Ok(val)
    }

    /// Move 4 bytes from the start of the data and interpret them as a `u32`
    pub fn read_u32(&mut self, field_name: &'static str) -> Result<u32> {
        ensure!(self.data.len() >= 4, EndOfReadStreamSnafu { field_name });

        let val = u32::from_be_bytes(self.data[..4].try_into().context(BadTryFromSliceSnafu)?);
        self.data.drain(..4);

        Ok(val)
    }

    /// Move 8 bytes from the start of the data and interpret them as an `i64`
    pub fn read_i64(&mut self, field_name: &'static str) -> Result<i64> {
        ensure!(self.data.len() >= 8, EndOfReadStreamSnafu { field_name });

        let val = i64::from_be_bytes(self.data[..8].try_into().context(BadTryFromSliceSnafu)?);
        self.data.drain(..8);

        Ok(val)
    }

    /// Move 8 bytes from the start of the data and interpret them as a `u64`
    pub fn read_u64(&mut self, field_name: &'static str) -> Result<u64> {
        ensure!(self.data.len() >= 8, EndOfReadStreamSnafu { field_name });

        let val = u64::from_be_bytes(self.data[..8].try_into().context(BadTryFromSliceSnafu)?);
        self.data.drain(..8);

        Ok(val)
    }

    /// Algorithm from: <https://wiki.vg/Protocol#VarInt_and_VarLong>
    pub fn read_var_int(&mut self, field_name: &'static str) -> Result<i32> {
        let mut value: i32 = 0;
        let mut pos = 0;
        let mut current_byte: u8;

        loop {
            current_byte = self.read_u8(field_name)?;
            value |= ((i32::from(current_byte)) & SEGMENT_BITS) << pos;

            if ((i32::from(current_byte)) & CONTINUE_BITS) == 0 {
                break;
            }

            pos += 7;

            ensure!(pos < 32, VarIntTooLargeSnafu { field_name });
        }

        Ok(value)
    }

    /// Algorithm from:  <https://wiki.vg/Protocol#VarInt_and_VarLong>
    pub fn read_var_long(&mut self, field_name: &'static str) -> Result<i64> {
        let mut value: i64 = 0;
        let mut pos = 0;
        let mut current_byte: u8;

        loop {
            current_byte = self.read_u8(field_name)?;
            value |= ((i64::from(current_byte)) & (i64::from(SEGMENT_BITS))) << pos;

            if ((i32::from(current_byte)) & CONTINUE_BITS) == 0 {
                break;
            }

            pos += 7;

            ensure!(pos < 64, VarLongTooLargeSnafu { field_name });
        }

        Ok(value)
    }

    pub fn read_uuid(&mut self, field_name: &'static str) -> Result<Uuid> {
        let mut buf = [0; 16];
        self.read_bytes(field_name, &mut buf)?;
        Ok(Uuid::from_bytes(buf))
    }

    /// Implementation from 'Notes' from: <https://wiki.vg/Protocol#Type:String>
    ///
    /// Note that `field_name` is just for extra info when logging if there is an error.
    #[allow(clippy::cast_sign_loss)] // We already check that the string length is between 0..=32767
    pub fn read_utf8_string(&mut self, field_name: &'static str) -> Result<String> {
        let string_len_bytes = self.read_var_int(field_name)?;

        ensure!(
            (0..=32767).contains(&string_len_bytes),
            BadStringRangeSnafu { field_name }
        );

        let mut utf8_bytes = vec![0; string_len_bytes as usize];
        self.read_bytes(field_name, &mut utf8_bytes)?;

        let utf8_string =
            String::from_utf8(utf8_bytes).context(BadStringConversionSnafu { field_name })?;

        let utf16_units = utf8_string.len(); // TODO: Might be incorrect, this should probably be amount of chars instead of len.
        ensure!(
            utf16_units <= string_len_bytes as usize * 3,
            BadStringUTF16UnitsSnafu { field_name }
        );

        Ok(utf8_string)
    }
}

impl From<Vec<u8>> for ReadStream {
    fn from(value: Vec<u8>) -> Self {
        Self { data: value }
    }
}
