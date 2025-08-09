//! Bitcoin transaction data structures.

use super::encode::{Encodable, write_varint};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Script(pub Vec<u8>);

impl Encodable for Script {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, self.0.len() as u64)?;
        written += writer.write(&self.0)?;
        Ok(written)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl Encodable for OutPoint {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.txid.consensus_encode(writer)?;
        written += self.vout.consensus_encode(writer)?;
        Ok(written)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl Encodable for TxIn {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.previous_output.consensus_encode(writer)?;
        written += self.script_sig.consensus_encode(writer)?;
        written += self.sequence.consensus_encode(writer)?;
        Ok(written)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Script,
}

impl Encodable for TxOut {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.value.consensus_encode(writer)?;
        written += self.script_pubkey.consensus_encode(writer)?;
        Ok(written)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: i32,
    pub lock_time: u32,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
}

impl Encodable for Transaction {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.version.consensus_encode(writer)?;
        written += self.input.consensus_encode(writer)?;
        written += self.output.consensus_encode(writer)?;
        written += self.lock_time.consensus_encode(writer)?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_encode() {
        // A simple test transaction (from a real Bitcoin transaction)
        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: [0; 32], // Dummy txid
                    vout: 0,
                },
                script_sig: Script(vec![]),
                sequence: 0xffffffff,
            }],
            output: vec![
                TxOut {
                    value: 10000000,
                    script_pubkey: Script(vec![]),
                },
            ],
        };

        let mut buffer = Vec::new();
        let bytes_written = tx.consensus_encode(&mut buffer).unwrap();
        assert!(bytes_written > 0);
    }
}
