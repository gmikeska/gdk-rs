//! Bitcoin transaction data structures with SegWit support.

use super::encode::{Encodable, Decodable, write_varint, read_varint};
use super::hash::{sha256d, Hash256};
use super::script::Script;
use crate::{Result, GdkError};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};



#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        OutPoint { txid, vout }
    }
    
    pub fn null() -> Self {
        OutPoint {
            txid: [0; 32],
            vout: 0xffffffff,
        }
    }
    
    pub fn is_null(&self) -> bool {
        self.txid == [0; 32] && self.vout == 0xffffffff
    }
}

impl Encodable for OutPoint {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.txid.consensus_encode(writer)?;
        written += self.vout.consensus_encode(writer)?;
        Ok(written)
    }
}

impl Decodable for OutPoint {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let txid = <[u8; 32]>::consensus_decode(reader)?;
        let vout = u32::consensus_decode(reader)?;
        Ok(OutPoint { txid, vout })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

impl TxIn {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        TxIn {
            previous_output,
            script_sig,
            sequence,
            witness: Vec::new(),
        }
    }
    
    pub fn has_witness(&self) -> bool {
        !self.witness.is_empty()
    }
}

impl Encodable for TxIn {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.previous_output.consensus_encode(writer)?;
        written += self.script_sig.consensus_encode(writer)?;
        written += self.sequence.consensus_encode(writer)?;
        Ok(written)
    }
}

impl Decodable for TxIn {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let previous_output = OutPoint::consensus_decode(reader)?;
        let script_sig = Script::consensus_decode(reader)?;
        let sequence = u32::consensus_decode(reader)?;
        Ok(TxIn {
            previous_output,
            script_sig,
            sequence,
            witness: Vec::new(), // Witness data is decoded separately
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Script,
}

impl TxOut {
    pub fn new(value: u64, script_pubkey: Script) -> Self {
        TxOut { value, script_pubkey }
    }
}

impl Encodable for TxOut {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.value.consensus_encode(writer)?;
        written += self.script_pubkey.consensus_encode(writer)?;
        Ok(written)
    }
}

impl Decodable for TxOut {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let value = u64::consensus_decode(reader)?;
        let script_pubkey = Script::consensus_decode(reader)?;
        Ok(TxOut { value, script_pubkey })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub lock_time: u32,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
}

impl Transaction {
    pub fn new() -> Self {
        Transaction {
            version: 1,
            lock_time: 0,
            input: Vec::new(),
            output: Vec::new(),
        }
    }
    
    /// Check if this transaction has witness data
    pub fn has_witness(&self) -> bool {
        self.input.iter().any(|input| input.has_witness())
    }
    
    /// Calculate the transaction ID (excluding witness data) - BIP141
    pub fn txid(&self) -> Hash256 {
        let serialized = self.consensus_encode_legacy().expect("encoding should not fail");
        sha256d(&serialized)
    }
    
    /// Calculate the witness transaction ID (including witness data) - BIP141
    pub fn wtxid(&self) -> Hash256 {
        if self.has_witness() {
            let serialized = self.consensus_encode_to_vec().expect("encoding should not fail");
            sha256d(&serialized)
        } else {
            // For non-witness transactions, wtxid == txid
            self.txid()
        }
    }
    
    /// Encode transaction in legacy format (without witness data)
    pub fn consensus_encode_legacy(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.version.consensus_encode(&mut buf)?;
        self.input.consensus_encode(&mut buf)?;
        self.output.consensus_encode(&mut buf)?;
        self.lock_time.consensus_encode(&mut buf)?;
        Ok(buf)
    }
    
    /// Check if this transaction signals RBF (Replace-By-Fee)
    /// A transaction signals RBF if any of its inputs has a sequence number < 0xfffffffe
    pub fn is_rbf_signaling(&self) -> bool {
        self.input.iter().any(|input| input.sequence < 0xfffffffe)
    }
    
    /// Encode witness data for a single input
    fn encode_witness<W: Write>(witness: &[Vec<u8>], writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, witness.len() as u64)?;
        for item in witness {
            written += write_varint(writer, item.len() as u64)?;
            written += writer.write(item)?;
        }
        Ok(written)
    }
    
    /// Decode witness data for a single input
    fn decode_witness<R: Read>(reader: &mut R) -> Result<Vec<Vec<u8>>> {
        let len = read_varint(reader)?;
        let mut witness = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let item_len = read_varint(reader)?;
            let mut item = vec![0u8; item_len as usize];
            reader.read_exact(&mut item)?;
            witness.push(item);
        }
        Ok(witness)
    }
}

impl Encodable for Transaction {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.version.consensus_encode(writer)?;
        
        if self.has_witness() {
            // BIP141 witness serialization format
            // marker (0x00) + flag (0x01)
            written += writer.write(&[0x00, 0x01])?;
        }
        
        written += self.input.consensus_encode(writer)?;
        written += self.output.consensus_encode(writer)?;
        
        if self.has_witness() {
            // Encode witness data for each input
            for input in &self.input {
                written += Self::encode_witness(&input.witness, writer)?;
            }
        }
        
        written += self.lock_time.consensus_encode(writer)?;
        Ok(written)
    }
}

impl Decodable for Transaction {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let version = i32::consensus_decode(reader)?;
        
        // Peek at the next bytes to check for witness marker
        let mut first_byte = [0u8; 1];
        reader.read_exact(&mut first_byte)?;
        
        let (input, has_witness) = if first_byte[0] == 0x00 {
            // Potential witness transaction - check flag
            let mut flag = [0u8; 1];
            reader.read_exact(&mut flag)?;
            if flag[0] == 0x01 {
                // This is a witness transaction
                let input = Vec::<TxIn>::consensus_decode(reader)?;
                (input, true)
            } else {
                return Err(GdkError::invalid_input_simple("Invalid witness flag".to_string()));
            }
        } else {
            // This is a legacy transaction, first_byte[0] is the start of input count varint
            let input_count = if first_byte[0] < 0xfd {
                first_byte[0] as u64
            } else if first_byte[0] == 0xfd {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf)?;
                u16::from_le_bytes(buf) as u64
            } else if first_byte[0] == 0xfe {
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf)?;
                u32::from_le_bytes(buf) as u64
            } else if first_byte[0] == 0xff {
                let mut buf = [0u8; 8];
                reader.read_exact(&mut buf)?;
                u64::from_le_bytes(buf)
            } else {
                return Err(GdkError::invalid_input_simple("Invalid varint".to_string()));
            };
            
            let mut input = Vec::with_capacity(input_count as usize);
            for _ in 0..input_count {
                input.push(TxIn::consensus_decode(reader)?);
            }
            (input, false)
        };
        
        let output = Vec::<TxOut>::consensus_decode(reader)?;
        
        let mut final_input = input;
        if has_witness {
            // Decode witness data for each input
            for input in &mut final_input {
                input.witness = Self::decode_witness(reader)?;
            }
        }
        
        let lock_time = u32::consensus_decode(reader)?;
        
        Ok(Transaction {
            version,
            lock_time,
            input: final_input,
            output,
        })
    }
}

