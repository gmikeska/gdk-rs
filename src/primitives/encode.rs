//! Consensus-critical serialization and deserialization.

use crate::Result;
use std::io::{Read, Write};

pub trait Encodable {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize>;
}

pub trait Decodable: Sized {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self>;
}

// Helper for writing a variable-length integer (CompactSize).
pub fn write_varint<W: Write>(writer: &mut W, n: u64) -> Result<usize> {
    let mut written = 0;
    if n < 0xfd {
        written += writer.write(&[n as u8])?;
    } else if n <= 0xffff {
        written += writer.write(&[0xfd])?;
        written += writer.write(&u16::to_le_bytes(n as u16))?;
    } else if n <= 0xffffffff {
        written += writer.write(&[0xfe])?;
        written += writer.write(&u32::to_le_bytes(n as u32))?;
    } else {
        written += writer.write(&[0xff])?;
        written += writer.write(&u64::to_le_bytes(n))?;
    }
    Ok(written)
}

impl Encodable for u32 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

impl Encodable for i32 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

impl Encodable for u64 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

impl<T: Encodable> Encodable for Vec<T> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, self.len() as u64)?;
        for item in self {
            written += item.consensus_encode(writer)?;
        }
        Ok(written)
    }
}

impl Encodable for &[u8] {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(self)?)
    }
}

impl Encodable for [u8; 32] {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(self)?)
    }
}
