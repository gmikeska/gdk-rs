//! Consensus-critical serialization and deserialization.

use crate::{Result, GdkError};
use std::io::{Read, Write};

pub trait Encodable {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize>;
    
    fn consensus_encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.consensus_encode(&mut buf)?;
        Ok(buf)
    }
}

pub trait Decodable: Sized {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self>;
    
    fn consensus_decode_from_slice(data: &[u8]) -> Result<Self> {
        let mut cursor = std::io::Cursor::new(data);
        Self::consensus_decode(&mut cursor)
    }
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

// Helper for reading a variable-length integer (CompactSize).
pub fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    
    match buf[0] {
        0xfd => {
            let mut buf = [0u8; 2];
            reader.read_exact(&mut buf)?;
            Ok(u16::from_le_bytes(buf) as u64)
        }
        0xfe => {
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf)?;
            Ok(u32::from_le_bytes(buf) as u64)
        }
        0xff => {
            let mut buf = [0u8; 8];
            reader.read_exact(&mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
        n => Ok(n as u64),
    }
}

impl Encodable for u32 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

impl Decodable for u32 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }
}

impl Encodable for i32 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

impl Decodable for i32 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }
}

impl Encodable for u64 {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(&self.to_le_bytes())?)
    }
}

impl Decodable for u64 {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
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

impl<T: Decodable> Decodable for Vec<T> {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let len = read_varint(reader)?;
        let mut vec = Vec::with_capacity(len as usize);
        for _ in 0..len {
            vec.push(T::consensus_decode(reader)?);
        }
        Ok(vec)
    }
}

impl Encodable for &[u8] {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(self)?)
    }
}

impl Encodable for Vec<u8> {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, self.len() as u64)?;
        written += writer.write(self)?;
        Ok(written)
    }
}

impl Decodable for Vec<u8> {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let len = read_varint(reader)?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl Encodable for [u8; 32] {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        Ok(writer.write(self)?)
    }
}

impl Decodable for [u8; 32] {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0u8; 32];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}
