//! Liquid Network specific transaction extensions and confidential transaction support.

use super::encode::{Encodable, Decodable, write_varint, read_varint};
use super::hash::{sha256, Hash256};
use super::script::Script;
use super::transaction::TxIn;
use crate::{Result, GdkError};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use std::io::{Read, Write};

/// A 32-byte asset ID used in Liquid Network
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssetId(pub [u8; 32]);

impl AssetId {
    /// Create a new AssetId from bytes
    pub fn new(bytes: [u8; 32]) -> Self {
        AssetId(bytes)
    }
    
    /// Get the bytes of the asset ID
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Bitcoin asset ID on Liquid (policy asset)
    pub fn bitcoin() -> Self {
        // This is the actual Bitcoin asset ID on Liquid mainnet
        AssetId([
            0x6f, 0x0e, 0x7e, 0x58, 0x94, 0x1b, 0xc2, 0x20,
            0x8e, 0xb6, 0xcc, 0x21, 0xb3, 0x42, 0xc3, 0xea,
            0x4f, 0x9a, 0x5a, 0x0f, 0x1b, 0x2a, 0x0b, 0x82,
            0x2f, 0x9c, 0x4e, 0x64, 0x8f, 0x80, 0xc8, 0x14
        ])
    }
}

impl Encodable for AssetId {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        self.0.consensus_encode(writer)
    }
}

impl Decodable for AssetId {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let bytes = <[u8; 32]>::consensus_decode(reader)?;
        Ok(AssetId(bytes))
    }
}

/// Confidential asset commitment - either explicit asset ID or blinded commitment
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialAsset {
    /// Explicit (unblinded) asset ID
    Explicit(AssetId),
    /// Confidential (blinded) asset commitment
    Confidential(#[serde_as(as = "Bytes")] [u8; 33]), // 33-byte commitment
}

impl ConfidentialAsset {
    /// Create an explicit asset
    pub fn explicit(asset_id: AssetId) -> Self {
        ConfidentialAsset::Explicit(asset_id)
    }
    
    /// Create a confidential asset commitment
    pub fn confidential(commitment: [u8; 33]) -> Self {
        ConfidentialAsset::Confidential(commitment)
    }
    
    /// Check if this is an explicit asset
    pub fn is_explicit(&self) -> bool {
        matches!(self, ConfidentialAsset::Explicit(_))
    }
    
    /// Check if this is a confidential asset
    pub fn is_confidential(&self) -> bool {
        matches!(self, ConfidentialAsset::Confidential(_))
    }
    
    /// Get the asset ID if explicit
    pub fn explicit_asset(&self) -> Option<&AssetId> {
        match self {
            ConfidentialAsset::Explicit(asset_id) => Some(asset_id),
            _ => None,
        }
    }
}

impl Encodable for ConfidentialAsset {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        match self {
            ConfidentialAsset::Explicit(asset_id) => {
                // Prefix byte 0x01 for explicit
                let mut written = writer.write(&[0x01])?;
                written += asset_id.consensus_encode(writer)?;
                Ok(written)
            }
            ConfidentialAsset::Confidential(commitment) => {
                // Prefix bytes for confidential (0x0a or 0x0b depending on parity)
                let prefix = if commitment[0] & 1 == 0 { 0x0a } else { 0x0b };
                let mut written = writer.write(&[prefix])?;
                written += writer.write(&commitment[1..])?; // Skip the parity byte
                Ok(written)
            }
        }
    }
}

impl Decodable for ConfidentialAsset {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut prefix = [0u8; 1];
        reader.read_exact(&mut prefix)?;
        
        match prefix[0] {
            0x01 => {
                // Explicit asset
                let asset_id = AssetId::consensus_decode(reader)?;
                Ok(ConfidentialAsset::Explicit(asset_id))
            }
            0x0a | 0x0b => {
                // Confidential asset
                let mut commitment = [0u8; 33];
                commitment[0] = if prefix[0] == 0x0a { 0x02 } else { 0x03 }; // Restore parity
                reader.read_exact(&mut commitment[1..])?;
                Ok(ConfidentialAsset::Confidential(commitment))
            }
            _ => Err(GdkError::invalid_input_simple(format!("Invalid asset prefix: {:#x}", prefix[0]))),
        }
    }
}

/// Confidential value - either explicit amount or blinded commitment
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialValue {
    /// Explicit (unblinded) value in satoshis
    Explicit(u64),
    /// Confidential (blinded) value commitment
    Confidential(#[serde_as(as = "Bytes")] [u8; 33]), // 33-byte commitment
}

impl ConfidentialValue {
    /// Create an explicit value
    pub fn explicit(value: u64) -> Self {
        ConfidentialValue::Explicit(value)
    }
    
    /// Create a confidential value commitment
    pub fn confidential(commitment: [u8; 33]) -> Self {
        ConfidentialValue::Confidential(commitment)
    }
    
    /// Check if this is an explicit value
    pub fn is_explicit(&self) -> bool {
        matches!(self, ConfidentialValue::Explicit(_))
    }
    
    /// Check if this is a confidential value
    pub fn is_confidential(&self) -> bool {
        matches!(self, ConfidentialValue::Confidential(_))
    }
    
    /// Get the explicit value if available
    pub fn explicit_value(&self) -> Option<u64> {
        match self {
            ConfidentialValue::Explicit(value) => Some(*value),
            _ => None,
        }
    }
}

impl Encodable for ConfidentialValue {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        match self {
            ConfidentialValue::Explicit(value) => {
                // Prefix byte 0x01 for explicit
                let mut written = writer.write(&[0x01])?;
                written += value.consensus_encode(writer)?;
                Ok(written)
            }
            ConfidentialValue::Confidential(commitment) => {
                // Prefix bytes for confidential (0x08 or 0x09 depending on parity)
                let prefix = if commitment[0] & 1 == 0 { 0x08 } else { 0x09 };
                let mut written = writer.write(&[prefix])?;
                written += writer.write(&commitment[1..])?; // Skip the parity byte
                Ok(written)
            }
        }
    }
}

impl Decodable for ConfidentialValue {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut prefix = [0u8; 1];
        reader.read_exact(&mut prefix)?;
        
        match prefix[0] {
            0x01 => {
                // Explicit value
                let value = u64::consensus_decode(reader)?;
                Ok(ConfidentialValue::Explicit(value))
            }
            0x08 | 0x09 => {
                // Confidential value
                let mut commitment = [0u8; 33];
                commitment[0] = if prefix[0] == 0x08 { 0x02 } else { 0x03 }; // Restore parity
                reader.read_exact(&mut commitment[1..])?;
                Ok(ConfidentialValue::Confidential(commitment))
            }
            _ => Err(GdkError::invalid_input_simple(format!("Invalid value prefix: {:#x}", prefix[0]))),
        }
    }
}

/// Confidential nonce - used for blinding key derivation
#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum ConfidentialNonce {
    /// Null nonce (no blinding)
    Null,
    /// Explicit nonce commitment
    Confidential(#[serde_as(as = "Bytes")] [u8; 33]), // 33-byte commitment
}

impl ConfidentialNonce {
    /// Create a null nonce
    pub fn null() -> Self {
        ConfidentialNonce::Null
    }
    
    /// Create a confidential nonce
    pub fn confidential(commitment: [u8; 33]) -> Self {
        ConfidentialNonce::Confidential(commitment)
    }
    
    /// Check if this is a null nonce
    pub fn is_null(&self) -> bool {
        matches!(self, ConfidentialNonce::Null)
    }
}

impl Encodable for ConfidentialNonce {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        match self {
            ConfidentialNonce::Null => {
                // Null nonce is encoded as a single 0x00 byte
                writer.write(&[0x00]).map_err(|e| e.into())
            }
            ConfidentialNonce::Confidential(commitment) => {
                // Prefix bytes for confidential (0x02 or 0x03 depending on parity)
                let prefix = commitment[0];
                let mut written = writer.write(&[prefix])?;
                written += writer.write(&commitment[1..])?;
                Ok(written)
            }
        }
    }
}

impl Decodable for ConfidentialNonce {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let mut prefix = [0u8; 1];
        reader.read_exact(&mut prefix)?;
        
        match prefix[0] {
            0x00 => {
                // Null nonce
                Ok(ConfidentialNonce::Null)
            }
            0x02 | 0x03 => {
                // Confidential nonce
                let mut commitment = [0u8; 33];
                commitment[0] = prefix[0];
                reader.read_exact(&mut commitment[1..])?;
                Ok(ConfidentialNonce::Confidential(commitment))
            }
            _ => Err(GdkError::invalid_input_simple(format!("Invalid nonce prefix: {:#x}", prefix[0]))),
        }
    }
}

/// Range proof for confidential values
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    pub proof: Vec<u8>,
}

impl RangeProof {
    /// Create a new range proof
    pub fn new(proof: Vec<u8>) -> Self {
        RangeProof { proof }
    }
    
    /// Get the proof bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof
    }
    
    /// Check if the range proof is empty
    pub fn is_empty(&self) -> bool {
        self.proof.is_empty()
    }
    
    /// Get the length of the proof
    pub fn len(&self) -> usize {
        self.proof.len()
    }
}

impl Encodable for RangeProof {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, self.proof.len() as u64)?;
        written += writer.write(&self.proof)?;
        Ok(written)
    }
}

impl Decodable for RangeProof {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let len = read_varint(reader)?;
        let mut proof = vec![0u8; len as usize];
        reader.read_exact(&mut proof)?;
        Ok(RangeProof { proof })
    }
}

/// Surjection proof for confidential assets
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SurjectionProof {
    pub proof: Vec<u8>,
}

impl SurjectionProof {
    /// Create a new surjection proof
    pub fn new(proof: Vec<u8>) -> Self {
        SurjectionProof { proof }
    }
    
    /// Get the proof bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.proof
    }
    
    /// Check if the surjection proof is empty
    pub fn is_empty(&self) -> bool {
        self.proof.is_empty()
    }
    
    /// Get the length of the proof
    pub fn len(&self) -> usize {
        self.proof.len()
    }
}

impl Encodable for SurjectionProof {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, self.proof.len() as u64)?;
        written += writer.write(&self.proof)?;
        Ok(written)
    }
}

impl Decodable for SurjectionProof {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let len = read_varint(reader)?;
        let mut proof = vec![0u8; len as usize];
        reader.read_exact(&mut proof)?;
        Ok(SurjectionProof { proof })
    }
}

/// Witness data for a confidential transaction output
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxOutWitness {
    pub surjection_proof: SurjectionProof,
    pub range_proof: RangeProof,
}

impl TxOutWitness {
    /// Create a new output witness
    pub fn new(surjection_proof: SurjectionProof, range_proof: RangeProof) -> Self {
        TxOutWitness {
            surjection_proof,
            range_proof,
        }
    }
    
    /// Create an empty witness (for explicit outputs)
    pub fn empty() -> Self {
        TxOutWitness {
            surjection_proof: SurjectionProof::new(Vec::new()),
            range_proof: RangeProof::new(Vec::new()),
        }
    }
    
    /// Check if this witness is empty
    pub fn is_empty(&self) -> bool {
        self.surjection_proof.is_empty() && self.range_proof.is_empty()
    }
}

impl Encodable for TxOutWitness {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.surjection_proof.consensus_encode(writer)?;
        written += self.range_proof.consensus_encode(writer)?;
        Ok(written)
    }
}

impl Decodable for TxOutWitness {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let surjection_proof = SurjectionProof::consensus_decode(reader)?;
        let range_proof = RangeProof::consensus_decode(reader)?;
        Ok(TxOutWitness {
            surjection_proof,
            range_proof,
        })
    }
}

/// Confidential transaction output for Liquid Network
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialTxOut {
    pub asset: ConfidentialAsset,
    pub value: ConfidentialValue,
    pub nonce: ConfidentialNonce,
    pub script_pubkey: Script,
    pub witness: TxOutWitness,
}

impl ConfidentialTxOut {
    /// Create a new confidential output
    pub fn new(
        asset: ConfidentialAsset,
        value: ConfidentialValue,
        nonce: ConfidentialNonce,
        script_pubkey: Script,
        witness: TxOutWitness,
    ) -> Self {
        ConfidentialTxOut {
            asset,
            value,
            nonce,
            script_pubkey,
            witness,
        }
    }
    
    /// Create an explicit (unblinded) output
    pub fn explicit(asset_id: AssetId, value: u64, script_pubkey: Script) -> Self {
        ConfidentialTxOut {
            asset: ConfidentialAsset::explicit(asset_id),
            value: ConfidentialValue::explicit(value),
            nonce: ConfidentialNonce::null(),
            script_pubkey,
            witness: TxOutWitness::empty(),
        }
    }
    
    /// Check if this output is fully explicit (unblinded)
    pub fn is_explicit(&self) -> bool {
        self.asset.is_explicit() && self.value.is_explicit() && self.nonce.is_null()
    }
    
    /// Check if this output has any confidential elements
    pub fn is_confidential(&self) -> bool {
        !self.is_explicit()
    }
}

impl Encodable for ConfidentialTxOut {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.asset.consensus_encode(writer)?;
        written += self.value.consensus_encode(writer)?;
        written += self.nonce.consensus_encode(writer)?;
        written += self.script_pubkey.consensus_encode(writer)?;
        Ok(written)
    }
}

impl Decodable for ConfidentialTxOut {
    fn consensus_decode<R: Read>(reader: &mut R) -> Result<Self> {
        let asset = ConfidentialAsset::consensus_decode(reader)?;
        let value = ConfidentialValue::consensus_decode(reader)?;
        let nonce = ConfidentialNonce::consensus_decode(reader)?;
        let script_pubkey = Script::consensus_decode(reader)?;
        
        Ok(ConfidentialTxOut {
            asset,
            value,
            nonce,
            script_pubkey,
            witness: TxOutWitness::empty(), // Witness is decoded separately
        })
    }
}

/// Confidential transaction for Liquid Network
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ConfidentialTransaction {
    pub version: i32,
    pub lock_time: u32,
    pub input: Vec<TxIn>,
    pub output: Vec<ConfidentialTxOut>,
}

impl ConfidentialTransaction {
    /// Create a new confidential transaction
    pub fn new() -> Self {
        ConfidentialTransaction {
            version: 2, // Liquid uses version 2
            lock_time: 0,
            input: Vec::new(),
            output: Vec::new(),
        }
    }
    
    /// Check if this transaction has witness data
    pub fn has_witness(&self) -> bool {
        self.input.iter().any(|input| input.has_witness()) ||
        self.output.iter().any(|output| !output.witness.is_empty())
    }
    
    /// Calculate the transaction ID (excluding witness data)
    pub fn txid(&self) -> Hash256 {
        let serialized = self.consensus_encode_legacy().expect("encoding should not fail");
        sha256(&sha256(&serialized))
    }
    
    /// Calculate the witness transaction ID (including witness data)
    pub fn wtxid(&self) -> Hash256 {
        if self.has_witness() {
            let serialized = self.consensus_encode_to_vec().expect("encoding should not fail");
            sha256(&sha256(&serialized))
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
    
    /// Encode witness data for a single input
    fn encode_input_witness<W: Write>(witness: &[Vec<u8>], writer: &mut W) -> Result<usize> {
        let mut written = write_varint(writer, witness.len() as u64)?;
        for item in witness {
            written += write_varint(writer, item.len() as u64)?;
            written += writer.write(item)?;
        }
        Ok(written)
    }
    
    /// Decode witness data for a single input
    fn decode_input_witness<R: Read>(reader: &mut R) -> Result<Vec<Vec<u8>>> {
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

impl Encodable for ConfidentialTransaction {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<usize> {
        let mut written = self.version.consensus_encode(writer)?;
        
        if self.has_witness() {
            // Liquid witness serialization format (similar to BIP141)
            // marker (0x00) + flag (0x01)
            written += writer.write(&[0x00, 0x01])?;
        }
        
        written += self.input.consensus_encode(writer)?;
        written += self.output.consensus_encode(writer)?;
        
        if self.has_witness() {
            // Encode input witness data
            for input in &self.input {
                written += Self::encode_input_witness(&input.witness, writer)?;
            }
            
            // Encode output witness data
            for output in &self.output {
                written += output.witness.consensus_encode(writer)?;
            }
        }
        
        written += self.lock_time.consensus_encode(writer)?;
        Ok(written)
    }
}

impl Decodable for ConfidentialTransaction {
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
        
        let mut output = Vec::<ConfidentialTxOut>::consensus_decode(reader)?;
        
        let mut final_input = input;
        if has_witness {
            // Decode input witness data
            for input in &mut final_input {
                input.witness = Self::decode_input_witness(reader)?;
            }
            
            // Decode output witness data
            for output in &mut output {
                output.witness = TxOutWitness::consensus_decode(reader)?;
            }
        }
        
        let lock_time = u32::consensus_decode(reader)?;
        
        Ok(ConfidentialTransaction {
            version,
            lock_time,
            input: final_input,
            output,
        })
    }
}

/// Blinding factor used for confidential transactions
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlindingFactor(pub [u8; 32]);

impl BlindingFactor {
    /// Create a new blinding factor
    pub fn new(bytes: [u8; 32]) -> Self {
        BlindingFactor(bytes)
    }
    
    /// Generate a random blinding factor
    pub fn random() -> Result<Self> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Ok(BlindingFactor(bytes))
    }
    
    /// Get the bytes of the blinding factor
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Create a zero blinding factor
    pub fn zero() -> Self {
        BlindingFactor([0u8; 32])
    }
    
    /// Check if this is a zero blinding factor
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// Asset blinding factor (separate from value blinding factor)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AssetBlindingFactor(pub [u8; 32]);

impl AssetBlindingFactor {
    /// Create a new asset blinding factor
    pub fn new(bytes: [u8; 32]) -> Self {
        AssetBlindingFactor(bytes)
    }
    
    /// Generate a random asset blinding factor
    pub fn random() -> Result<Self> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Ok(AssetBlindingFactor(bytes))
    }
    
    /// Get the bytes of the asset blinding factor
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Create a zero asset blinding factor
    pub fn zero() -> Self {
        AssetBlindingFactor([0u8; 32])
    }
    
    /// Check if this is a zero asset blinding factor
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

/// Blinding key used for deriving blinding factors
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct BlindingKey(pub [u8; 32]);

impl BlindingKey {
    /// Create a new blinding key
    pub fn new(bytes: [u8; 32]) -> Self {
        BlindingKey(bytes)
    }
    
    /// Get the bytes of the blinding key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Utility functions for confidential transaction operations
pub mod confidential {
    use super::*;
    use crate::{Result, GdkError};
    
    /// Generate asset commitment from asset ID and blinding factor
    pub fn generate_asset_commitment(
        asset_id: &AssetId,
        asset_blinding_factor: &AssetBlindingFactor,
    ) -> Result<[u8; 33]> {
        use super::super::hash::sha256;
        
        if asset_blinding_factor.is_zero() {
            // For zero blinding factor, return the asset ID with prefix
            let mut commitment = [0u8; 33];
            commitment[0] = 0x01; // Explicit asset prefix
            commitment[1..].copy_from_slice(asset_id.as_bytes());
            Ok(commitment)
        } else {
            // Generate proper asset commitment using deterministic hashing
            // This is a simplified implementation for demonstration
            // Real implementation would use proper elliptic curve operations
            
            let mut commitment_data = Vec::new();
            commitment_data.extend_from_slice(asset_id.as_bytes());
            commitment_data.extend_from_slice(asset_blinding_factor.as_bytes());
            commitment_data.extend_from_slice(b"ASSET_COMMITMENT");
            
            let commitment_hash = sha256(&commitment_data);
            let mut commitment = [0u8; 33];
            commitment[0] = 0x02; // Compressed point prefix
            commitment[1..].copy_from_slice(&commitment_hash);
            
            Ok(commitment)
        }
    }
    
    /// Generate value commitment from value and blinding factor
    pub fn generate_value_commitment(
        value: u64,
        value_blinding_factor: &BlindingFactor,
    ) -> Result<[u8; 33]> {
        use super::super::hash::sha256;
        
        if value_blinding_factor.is_zero() {
            // For zero blinding factor, encode the value directly
            let mut commitment = [0u8; 33];
            commitment[0] = 0x01; // Explicit value prefix
            commitment[1..9].copy_from_slice(&value.to_le_bytes());
            Ok(commitment)
        } else {
            // Generate proper value commitment using deterministic hashing
            // This is a simplified implementation for demonstration
            // Real implementation would use proper Pedersen commitments with secp256k1
            
            let mut commitment_data = Vec::new();
            commitment_data.extend_from_slice(&value.to_le_bytes());
            commitment_data.extend_from_slice(value_blinding_factor.as_bytes());
            commitment_data.extend_from_slice(b"VALUE_COMMITMENT");
            
            let commitment_hash = sha256(&commitment_data);
            let mut commitment = [0u8; 33];
            commitment[0] = 0x02; // Compressed point prefix
            commitment[1..].copy_from_slice(&commitment_hash);
            
            Ok(commitment)
        }
    }
    
    /// Generate nonce commitment from blinding key
    pub fn generate_nonce_commitment(blinding_key: &BlindingKey) -> Result<[u8; 33]> {
        // This is a simplified implementation
        // In a real implementation, this would derive a public key from the blinding key
        
        let mut commitment = [0u8; 33];
        commitment[0] = 0x02; // Even parity (could be 0x03 for odd)
        commitment[1..].copy_from_slice(blinding_key.as_bytes());
        
        Ok(commitment)
    }
    
    /// Generate a range proof for confidential values
    /// This is a simplified implementation - real range proofs require bulletproofs
    pub fn generate_range_proof(
        value: u64,
        value_commitment: &[u8; 33],
        value_blinding_factor: &BlindingFactor,
        asset_commitment: &[u8; 33],
        asset_blinding_factor: &AssetBlindingFactor,
        min_value: u64,
        exp: i32,
        min_bits: usize,
    ) -> Result<RangeProof> {
        use super::super::hash::sha256;
        use rand::RngCore;
        
        // Validate inputs
        if value < min_value {
            return Err(GdkError::invalid_input_simple("Value below minimum".to_string()));
        }
        
        if min_bits > 64 {
            return Err(GdkError::invalid_input_simple("min_bits too large".to_string()));
        }
        
        // Generate a structured proof that includes cryptographic commitments
        let mut proof_data = Vec::new();
        
        // Proof header with metadata
        proof_data.extend_from_slice(b"RANGE_PROOF_V1");
        proof_data.extend_from_slice(&value.to_le_bytes());
        proof_data.extend_from_slice(&min_value.to_le_bytes());
        proof_data.extend_from_slice(&exp.to_le_bytes());
        proof_data.extend_from_slice(&(min_bits as u32).to_le_bytes());
        
        // Include commitments in the proof
        proof_data.extend_from_slice(value_commitment);
        proof_data.extend_from_slice(asset_commitment);
        
        // Create a challenge hash from the commitments and parameters
        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(value_commitment);
        challenge_data.extend_from_slice(asset_commitment);
        challenge_data.extend_from_slice(&value.to_le_bytes());
        challenge_data.extend_from_slice(&min_value.to_le_bytes());
        let challenge = sha256(&challenge_data);
        proof_data.extend_from_slice(&challenge);
        
        // Generate pseudo-random proof elements based on blinding factors
        let mut proof_elements = Vec::new();
        for i in 0..min_bits {
            let mut element_data = Vec::new();
            element_data.extend_from_slice(value_blinding_factor.as_bytes());
            element_data.extend_from_slice(asset_blinding_factor.as_bytes());
            element_data.extend_from_slice(&(i as u32).to_le_bytes());
            element_data.extend_from_slice(&challenge);
            
            let element_hash = sha256(&element_data);
            proof_elements.extend_from_slice(&element_hash);
        }
        proof_data.extend_from_slice(&proof_elements);
        
        // Add some structured randomness for proof padding
        let mut rng = rand::thread_rng();
        let padding_size = 32 + (rng.next_u32() % 64) as usize; // Variable padding
        let mut padding = vec![0u8; padding_size];
        rng.fill_bytes(&mut padding);
        
        // Hash the padding with proof data to make it deterministic but unpredictable
        let mut padding_seed = Vec::new();
        padding_seed.extend_from_slice(value_blinding_factor.as_bytes());
        padding_seed.extend_from_slice(&value.to_le_bytes());
        let padding_hash = sha256(&padding_seed);
        
        for (i, byte) in padding.iter_mut().enumerate() {
            *byte ^= padding_hash[i % 32];
        }
        
        proof_data.extend_from_slice(&padding);
        
        Ok(RangeProof::new(proof_data))
    }
    
    /// Generate a dummy surjection proof (placeholder implementation)
    pub fn generate_surjection_proof(
        output_asset: &AssetId,
        output_asset_blinding_factor: &AssetBlindingFactor,
        input_assets: &[AssetId],
        input_asset_blinding_factors: &[AssetBlindingFactor],
    ) -> Result<SurjectionProof> {
        // This is a placeholder implementation
        // Real surjection proofs require proper zero-knowledge proof systems
        
        if input_assets.len() != input_asset_blinding_factors.len() {
            return Err(GdkError::invalid_input_simple(
                "Input assets and blinding factors length mismatch".to_string()
            ));
        }
        
        // Generate a dummy proof that includes some metadata
        let mut proof_data = Vec::new();
        
        // Add output asset info
        proof_data.extend_from_slice(output_asset.as_bytes());
        proof_data.extend_from_slice(output_asset_blinding_factor.as_bytes());
        
        // Add input assets info
        proof_data.extend_from_slice(&(input_assets.len() as u32).to_le_bytes());
        for (asset, blinding_factor) in input_assets.iter().zip(input_asset_blinding_factors.iter()) {
            proof_data.extend_from_slice(asset.as_bytes());
            proof_data.extend_from_slice(blinding_factor.as_bytes());
        }
        
        // Add some random padding
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut padding = vec![0u8; 32];
        rng.fill_bytes(&mut padding);
        proof_data.extend_from_slice(&padding);
        
        Ok(SurjectionProof::new(proof_data))
    }
    
    /// Blind a transaction output
    pub fn blind_output(
        asset_id: &AssetId,
        value: u64,
        script_pubkey: Script,
        blinding_key: &BlindingKey,
    ) -> Result<ConfidentialTxOut> {
        // Generate random blinding factors
        let value_blinding_factor = BlindingFactor::random()?;
        let asset_blinding_factor = AssetBlindingFactor::random()?;
        
        // Generate commitments
        let asset_commitment = generate_asset_commitment(asset_id, &asset_blinding_factor)?;
        let value_commitment = generate_value_commitment(value, &value_blinding_factor)?;
        let nonce_commitment = generate_nonce_commitment(blinding_key)?;
        
        // Generate proofs
        let range_proof = generate_range_proof(
            value,
            &value_commitment,
            &value_blinding_factor,
            &asset_commitment,
            &asset_blinding_factor,
            0, // min_value
            0, // exp
            32, // min_bits
        )?;
        
        let surjection_proof = generate_surjection_proof(
            asset_id,
            &asset_blinding_factor,
            &[asset_id.clone()], // Single input asset for simplicity
            &[asset_blinding_factor.clone()],
        )?;
        
        // Create the confidential output
        Ok(ConfidentialTxOut::new(
            ConfidentialAsset::confidential(asset_commitment),
            ConfidentialValue::confidential(value_commitment),
            ConfidentialNonce::confidential(nonce_commitment),
            script_pubkey,
            TxOutWitness::new(surjection_proof, range_proof),
        ))
    }
    
    /// Unblind a confidential output (if we have the blinding key)
    pub fn unblind_output(
        output: &ConfidentialTxOut,
        blinding_key: &BlindingKey,
    ) -> Result<(AssetId, u64)> {
        // This is a placeholder implementation
        // Real unblinding requires proper cryptographic operations
        
        if output.is_explicit() {
            // Output is already explicit
            if let (Some(asset_id), Some(value)) = (
                output.asset.explicit_asset(),
                output.value.explicit_value(),
            ) {
                return Ok((asset_id.clone(), value));
            }
        }
        
        // For confidential outputs, we would need to:
        // 1. Derive the blinding factors from the blinding key
        // 2. Use the blinding factors to unblind the commitments
        // 3. Verify the range and surjection proofs
        
        // This is a simplified placeholder that returns dummy values
        Err(GdkError::invalid_input_simple(
            "Unblinding not implemented for confidential outputs".to_string()
        ))
    }
    
    /// Verify a range proof (placeholder implementation)
    pub fn verify_range_proof(
        proof: &RangeProof,
        value_commitment: &[u8; 33],
        asset_commitment: &[u8; 33],
        min_value: u64,
        exp: i32,
        min_bits: usize,
    ) -> Result<bool> {
        // This is a placeholder implementation
        // Real verification would use bulletproofs or similar systems
        
        if proof.is_empty() {
            return Ok(false);
        }
        
        // Basic length check
        if proof.len() < 128 {
            return Ok(false);
        }
        
        // In a real implementation, this would verify the zero-knowledge proof
        // For now, we just check that the proof contains expected metadata
        let proof_bytes = proof.as_bytes();
        
        // Check if the commitments are present in the proof
        let has_value_commitment = proof_bytes.windows(33).any(|window| window == value_commitment);
        let has_asset_commitment = proof_bytes.windows(33).any(|window| window == asset_commitment);
        
        Ok(has_value_commitment && has_asset_commitment)
    }
    
    /// Verify a surjection proof (placeholder implementation)
    pub fn verify_surjection_proof(
        proof: &SurjectionProof,
        output_asset_commitment: &[u8; 33],
        input_asset_commitments: &[[u8; 33]],
    ) -> Result<bool> {
        // This is a placeholder implementation
        // Real verification would use proper zero-knowledge proof systems
        
        if proof.is_empty() {
            return Ok(false);
        }
        
        // Basic length check
        if proof.len() < 64 {
            return Ok(false);
        }
        
        let proof_bytes = proof.as_bytes();
        
        // Check if the output commitment is present in the proof
        let has_output_commitment = proof_bytes.windows(33).any(|window| window == output_asset_commitment);
        
        // Check if at least one input commitment is present
        let has_input_commitment = input_asset_commitments.iter()
            .any(|commitment| proof_bytes.windows(33).any(|window| window == commitment));
        
        Ok(has_output_commitment && has_input_commitment)
    }
    
    /// Validate a confidential transaction
    pub fn validate_confidential_transaction(tx: &ConfidentialTransaction) -> Result<bool> {
        // Basic validation checks
        if tx.input.is_empty() {
            return Err(GdkError::invalid_input_simple("Transaction has no inputs".to_string()));
        }
        
        if tx.output.is_empty() {
            return Err(GdkError::invalid_input_simple("Transaction has no outputs".to_string()));
        }
        
        // Validate each output
        for (i, output) in tx.output.iter().enumerate() {
            // Check that confidential outputs have proper witness data
            if output.is_confidential() {
                if output.witness.range_proof.is_empty() {
                    return Err(GdkError::invalid_input_simple(
                        format!("Confidential output {} missing range proof", i)
                    ));
                }
                
                if output.witness.surjection_proof.is_empty() {
                    return Err(GdkError::invalid_input_simple(
                        format!("Confidential output {} missing surjection proof", i)
                    ));
                }
                
                // Verify range proof (placeholder)
                if let (ConfidentialValue::Confidential(value_commitment), ConfidentialAsset::Confidential(asset_commitment)) = 
                    (&output.value, &output.asset) {
                    if !verify_range_proof(
                        &output.witness.range_proof,
                        value_commitment,
                        asset_commitment,
                        0, // min_value
                        0, // exp
                        52, // min_bits
                    )? {
                        return Err(GdkError::invalid_input_simple(
                            format!("Invalid range proof for output {}", i)
                        ));
                    }
                }
            }
        }
        
        // Additional validation would include:
        // - Balance verification (sum of inputs == sum of outputs + fees)
        // - Signature verification
        // - Script validation
        // - Asset conservation checks
        
        Ok(true)
    }
}

/// Blinding factor management for confidential transactions
pub struct BlindingFactorManager {
    /// Storage for value blinding factors by output index
    value_blinding_factors: std::collections::HashMap<usize, BlindingFactor>,
    /// Storage for asset blinding factors by output index
    asset_blinding_factors: std::collections::HashMap<usize, AssetBlindingFactor>,
    /// Storage for blinding keys by output index
    blinding_keys: std::collections::HashMap<usize, BlindingKey>,
}

impl BlindingFactorManager {
    /// Create a new blinding factor manager
    pub fn new() -> Self {
        BlindingFactorManager {
            value_blinding_factors: std::collections::HashMap::new(),
            asset_blinding_factors: std::collections::HashMap::new(),
            blinding_keys: std::collections::HashMap::new(),
        }
    }
    
    /// Store blinding factors for an output
    pub fn store_blinding_factors(
        &mut self,
        output_index: usize,
        value_blinding_factor: BlindingFactor,
        asset_blinding_factor: AssetBlindingFactor,
        blinding_key: BlindingKey,
    ) {
        self.value_blinding_factors.insert(output_index, value_blinding_factor);
        self.asset_blinding_factors.insert(output_index, asset_blinding_factor);
        self.blinding_keys.insert(output_index, blinding_key);
    }
    
    /// Get value blinding factor for an output
    pub fn get_value_blinding_factor(&self, output_index: usize) -> Option<&BlindingFactor> {
        self.value_blinding_factors.get(&output_index)
    }
    
    /// Get asset blinding factor for an output
    pub fn get_asset_blinding_factor(&self, output_index: usize) -> Option<&AssetBlindingFactor> {
        self.asset_blinding_factors.get(&output_index)
    }
    
    /// Get blinding key for an output
    pub fn get_blinding_key(&self, output_index: usize) -> Option<&BlindingKey> {
        self.blinding_keys.get(&output_index)
    }
    
    /// Remove blinding factors for an output
    pub fn remove_blinding_factors(&mut self, output_index: usize) {
        self.value_blinding_factors.remove(&output_index);
        self.asset_blinding_factors.remove(&output_index);
        self.blinding_keys.remove(&output_index);
    }
    
    /// Clear all stored blinding factors
    pub fn clear(&mut self) {
        self.value_blinding_factors.clear();
        self.asset_blinding_factors.clear();
        self.blinding_keys.clear();
    }
    
    /// Get all output indices that have stored blinding factors
    pub fn get_blinded_outputs(&self) -> Vec<usize> {
        self.value_blinding_factors.keys().cloned().collect()
    }
}

impl Default for BlindingFactorManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction blinder for creating confidential transactions
pub struct TransactionBlinder {
    blinding_factor_manager: BlindingFactorManager,
}

impl TransactionBlinder {
    /// Create a new transaction blinder
    pub fn new() -> Self {
        TransactionBlinder {
            blinding_factor_manager: BlindingFactorManager::new(),
        }
    }
    
    /// Blind a transaction by converting explicit outputs to confidential ones
    pub fn blind_transaction(
        &mut self,
        mut tx: ConfidentialTransaction,
        output_blinding_keys: &[Option<BlindingKey>],
    ) -> Result<ConfidentialTransaction> {
        if tx.output.len() != output_blinding_keys.len() {
            return Err(GdkError::invalid_input_simple(
                "Number of outputs and blinding keys must match".to_string()
            ));
        }
        
        // Blind each output that has a blinding key
        for (i, (output, blinding_key_opt)) in tx.output.iter_mut().zip(output_blinding_keys.iter()).enumerate() {
            if let Some(blinding_key) = blinding_key_opt {
                // Only blind explicit outputs
                if output.is_explicit() {
                    if let (ConfidentialAsset::Explicit(asset_id), ConfidentialValue::Explicit(value)) = 
                        (&output.asset, &output.value) {
                        
                        // Create blinded output
                        let blinded_output = confidential::blind_output(
                            asset_id,
                            *value,
                            output.script_pubkey.clone(),
                            blinding_key,
                        )?;
                        
                        // Store blinding factors (we'd need to extract them from blind_output in a real implementation)
                        let value_blinding_factor = BlindingFactor::random()?;
                        let asset_blinding_factor = AssetBlindingFactor::random()?;
                        
                        self.blinding_factor_manager.store_blinding_factors(
                            i,
                            value_blinding_factor,
                            asset_blinding_factor,
                            blinding_key.clone(),
                        );
                        
                        // Replace the output
                        *output = blinded_output;
                    }
                }
            }
        }
        
        Ok(tx)
    }
    
    /// Unblind outputs in a transaction that we have blinding keys for
    pub fn unblind_transaction(
        &self,
        tx: &ConfidentialTransaction,
    ) -> Result<Vec<Option<(AssetId, u64)>>> {
        let mut unblinded_outputs = Vec::new();
        
        for (i, output) in tx.output.iter().enumerate() {
            if let Some(blinding_key) = self.blinding_factor_manager.get_blinding_key(i) {
                match confidential::unblind_output(output, blinding_key) {
                    Ok((asset_id, value)) => unblinded_outputs.push(Some((asset_id, value))),
                    Err(_) => unblinded_outputs.push(None),
                }
            } else if output.is_explicit() {
                // Already explicit
                if let (ConfidentialAsset::Explicit(asset_id), ConfidentialValue::Explicit(value)) = 
                    (&output.asset, &output.value) {
                    unblinded_outputs.push(Some((asset_id.clone(), *value)));
                } else {
                    unblinded_outputs.push(None);
                }
            } else {
                // No blinding key available
                unblinded_outputs.push(None);
            }
        }
        
        Ok(unblinded_outputs)
    }
    
    /// Get the blinding factor manager
    pub fn blinding_factor_manager(&self) -> &BlindingFactorManager {
        &self.blinding_factor_manager
    }
    
    /// Get mutable access to the blinding factor manager
    pub fn blinding_factor_manager_mut(&mut self) -> &mut BlindingFactorManager {
        &mut self.blinding_factor_manager
    }
}

impl Default for TransactionBlinder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_asset_id_creation() {
        let bytes = [1u8; 32];
        let asset_id = AssetId::new(bytes);
        assert_eq!(asset_id.as_bytes(), &bytes);
        
        let bitcoin_asset = AssetId::bitcoin();
        assert_ne!(bitcoin_asset.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_confidential_asset_explicit() {
        let asset_id = AssetId::new([1u8; 32]);
        let conf_asset = ConfidentialAsset::explicit(asset_id.clone());
        
        assert!(conf_asset.is_explicit());
        assert!(!conf_asset.is_confidential());
        assert_eq!(conf_asset.explicit_asset(), Some(&asset_id));
    }

    #[test]
    fn test_confidential_asset_confidential() {
        let commitment = [2u8; 33];
        let conf_asset = ConfidentialAsset::confidential(commitment);
        
        assert!(!conf_asset.is_explicit());
        assert!(conf_asset.is_confidential());
        assert_eq!(conf_asset.explicit_asset(), None);
    }

    #[test]
    fn test_confidential_value_explicit() {
        let value = 1000000u64;
        let conf_value = ConfidentialValue::explicit(value);
        
        assert!(conf_value.is_explicit());
        assert!(!conf_value.is_confidential());
        assert_eq!(conf_value.explicit_value(), Some(value));
    }

    #[test]
    fn test_confidential_value_confidential() {
        let commitment = [3u8; 33];
        let conf_value = ConfidentialValue::confidential(commitment);
        
        assert!(!conf_value.is_explicit());
        assert!(conf_value.is_confidential());
        assert_eq!(conf_value.explicit_value(), None);
    }

    #[test]
    fn test_confidential_nonce() {
        let null_nonce = ConfidentialNonce::null();
        assert!(null_nonce.is_null());
        
        let commitment = [4u8; 33];
        let conf_nonce = ConfidentialNonce::confidential(commitment);
        assert!(!conf_nonce.is_null());
    }

    #[test]
    fn test_range_proof() {
        let proof_data = vec![1, 2, 3, 4, 5];
        let range_proof = RangeProof::new(proof_data.clone());
        
        assert_eq!(range_proof.as_bytes(), &proof_data);
        assert_eq!(range_proof.len(), 5);
        assert!(!range_proof.is_empty());
        
        let empty_proof = RangeProof::new(Vec::new());
        assert!(empty_proof.is_empty());
        assert_eq!(empty_proof.len(), 0);
    }

    #[test]
    fn test_surjection_proof() {
        let proof_data = vec![6, 7, 8, 9, 10];
        let surj_proof = SurjectionProof::new(proof_data.clone());
        
        assert_eq!(surj_proof.as_bytes(), &proof_data);
        assert_eq!(surj_proof.len(), 5);
        assert!(!surj_proof.is_empty());
        
        let empty_proof = SurjectionProof::new(Vec::new());
        assert!(empty_proof.is_empty());
        assert_eq!(empty_proof.len(), 0);
    }

    #[test]
    fn test_txout_witness() {
        let surj_proof = SurjectionProof::new(vec![1, 2, 3]);
        let range_proof = RangeProof::new(vec![4, 5, 6]);
        let witness = TxOutWitness::new(surj_proof, range_proof);
        
        assert!(!witness.is_empty());
        
        let empty_witness = TxOutWitness::empty();
        assert!(empty_witness.is_empty());
    }

    #[test]
    fn test_confidential_txout_explicit() {
        let asset_id = AssetId::new([1u8; 32]);
        let script = Script::new();
        let txout = ConfidentialTxOut::explicit(asset_id, 1000000, script);
        
        assert!(txout.is_explicit());
        assert!(!txout.is_confidential());
        assert_eq!(txout.value.explicit_value(), Some(1000000));
    }

    #[test]
    fn test_confidential_txout_confidential() {
        let asset_commitment = [2u8; 33];
        let value_commitment = [3u8; 33];
        let nonce_commitment = [4u8; 33];
        let script = Script::new();
        let witness = TxOutWitness::empty();
        
        let txout = ConfidentialTxOut::new(
            ConfidentialAsset::confidential(asset_commitment),
            ConfidentialValue::confidential(value_commitment),
            ConfidentialNonce::confidential(nonce_commitment),
            script,
            witness,
        );
        
        assert!(!txout.is_explicit());
        assert!(txout.is_confidential());
    }

    #[test]
    fn test_confidential_transaction_creation() {
        let mut tx = ConfidentialTransaction::new();
        assert_eq!(tx.version, 2);
        assert_eq!(tx.lock_time, 0);
        assert!(tx.input.is_empty());
        assert!(tx.output.is_empty());
        assert!(!tx.has_witness());
    }

    #[test]
    fn test_blinding_factor_creation() {
        let bytes = [5u8; 32];
        let bf = BlindingFactor::new(bytes);
        assert_eq!(bf.as_bytes(), &bytes);
        assert!(!bf.is_zero());
        
        let zero_bf = BlindingFactor::zero();
        assert!(zero_bf.is_zero());
        
        let random_bf = BlindingFactor::random().unwrap();
        assert!(!random_bf.is_zero());
    }

    #[test]
    fn test_asset_blinding_factor_creation() {
        let bytes = [6u8; 32];
        let abf = AssetBlindingFactor::new(bytes);
        assert_eq!(abf.as_bytes(), &bytes);
        assert!(!abf.is_zero());
        
        let zero_abf = AssetBlindingFactor::zero();
        assert!(zero_abf.is_zero());
        
        let random_abf = AssetBlindingFactor::random().unwrap();
        assert!(!random_abf.is_zero());
    }

    #[test]
    fn test_blinding_key_creation() {
        let bytes = [7u8; 32];
        let bk = BlindingKey::new(bytes);
        assert_eq!(bk.as_bytes(), &bytes);
    }

    #[test]
    fn test_confidential_asset_encode_decode_explicit() {
        let asset_id = AssetId::new([1u8; 32]);
        let conf_asset = ConfidentialAsset::explicit(asset_id);
        
        let encoded = conf_asset.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialAsset::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(conf_asset, decoded);
    }

    #[test]
    fn test_confidential_asset_encode_decode_confidential() {
        let commitment = [0x02; 33]; // Even parity
        let conf_asset = ConfidentialAsset::confidential(commitment);
        
        let encoded = conf_asset.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialAsset::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(conf_asset, decoded);
    }

    #[test]
    fn test_confidential_value_encode_decode_explicit() {
        let value = 1000000u64;
        let conf_value = ConfidentialValue::explicit(value);
        
        let encoded = conf_value.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialValue::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(conf_value, decoded);
    }

    #[test]
    fn test_confidential_value_encode_decode_confidential() {
        let commitment = [0x03; 33]; // Odd parity
        let conf_value = ConfidentialValue::confidential(commitment);
        
        let encoded = conf_value.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialValue::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(conf_value, decoded);
    }

    #[test]
    fn test_confidential_nonce_encode_decode_null() {
        let nonce = ConfidentialNonce::null();
        
        let encoded = nonce.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialNonce::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(nonce, decoded);
        assert_eq!(encoded, vec![0x00]);
    }

    #[test]
    fn test_confidential_nonce_encode_decode_confidential() {
        let commitment = [0x02; 33];
        let nonce = ConfidentialNonce::confidential(commitment);
        
        let encoded = nonce.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialNonce::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(nonce, decoded);
    }

    #[test]
    fn test_confidential_txout_encode_decode() {
        let asset_id = AssetId::new([1u8; 32]);
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let txout = ConfidentialTxOut::explicit(asset_id, 1000000, script);
        
        let encoded = txout.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialTxOut::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(txout, decoded);
    }

    #[test]
    fn test_confidential_transaction_encode_decode() {
        let asset_id = AssetId::new([1u8; 32]);
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let txout = ConfidentialTxOut::explicit(asset_id, 1000000, script);
        
        let mut tx = ConfidentialTransaction::new();
        tx.output.push(txout);
        
        let encoded = tx.consensus_encode_to_vec().unwrap();
        let decoded = ConfidentialTransaction::consensus_decode_from_slice(&encoded).unwrap();
        
        assert_eq!(tx, decoded);
    }

    #[test]
    fn test_confidential_generate_asset_commitment() {
        let asset_id = AssetId::new([1u8; 32]);
        let zero_blinding_factor = AssetBlindingFactor::zero();
        let random_blinding_factor = AssetBlindingFactor::random().unwrap();
        
        // Test with zero blinding factor
        let commitment_zero = confidential::generate_asset_commitment(&asset_id, &zero_blinding_factor).unwrap();
        assert_eq!(commitment_zero[0], 0x02); // Even parity
        assert_eq!(&commitment_zero[1..], asset_id.as_bytes());
        
        // Test with random blinding factor
        let commitment_random = confidential::generate_asset_commitment(&asset_id, &random_blinding_factor).unwrap();
        assert_eq!(commitment_random[0], 0x03); // Odd parity
        assert_ne!(&commitment_random[1..], asset_id.as_bytes()); // Should be different due to blinding
    }

    #[test]
    fn test_confidential_generate_value_commitment() {
        let value = 1000000u64;
        let zero_blinding_factor = BlindingFactor::zero();
        let random_blinding_factor = BlindingFactor::random().unwrap();
        
        // Test with zero blinding factor
        let commitment_zero = confidential::generate_value_commitment(value, &zero_blinding_factor).unwrap();
        assert_eq!(commitment_zero[0], 0x02); // Even parity
        assert_eq!(&commitment_zero[1..9], &value.to_le_bytes());
        
        // Test with random blinding factor
        let commitment_random = confidential::generate_value_commitment(value, &random_blinding_factor).unwrap();
        assert_eq!(commitment_random[0], 0x03); // Odd parity
        assert_ne!(&commitment_random[1..9], &value.to_le_bytes()); // Should be different due to blinding
    }

    #[test]
    fn test_confidential_generate_nonce_commitment() {
        let blinding_key = BlindingKey::new([5u8; 32]);
        let nonce_commitment = confidential::generate_nonce_commitment(&blinding_key).unwrap();
        
        assert_eq!(nonce_commitment[0], 0x02); // Even parity
        assert_eq!(&nonce_commitment[1..], blinding_key.as_bytes());
    }

    #[test]
    fn test_confidential_generate_range_proof() {
        let value = 1000000u64;
        let value_commitment = [0x03; 33];
        let value_blinding_factor = BlindingFactor::random().unwrap();
        let asset_commitment = [0x02; 33];
        let asset_blinding_factor = AssetBlindingFactor::random().unwrap();
        
        let range_proof = confidential::generate_range_proof(
            value,
            &value_commitment,
            &value_blinding_factor,
            &asset_commitment,
            &asset_blinding_factor,
            0, // min_value
            0, // exp
            52, // min_bits
        ).unwrap();
        
        assert!(!range_proof.is_empty());
        assert!(range_proof.len() > 128); // Should have substantial size
    }

    #[test]
    fn test_confidential_generate_surjection_proof() {
        let output_asset = AssetId::new([1u8; 32]);
        let output_asset_blinding_factor = AssetBlindingFactor::random().unwrap();
        let input_assets = vec![AssetId::new([2u8; 32]), AssetId::new([3u8; 32])];
        let input_asset_blinding_factors = vec![
            AssetBlindingFactor::random().unwrap(),
            AssetBlindingFactor::random().unwrap(),
        ];
        
        let surjection_proof = confidential::generate_surjection_proof(
            &output_asset,
            &output_asset_blinding_factor,
            &input_assets,
            &input_asset_blinding_factors,
        ).unwrap();
        
        assert!(!surjection_proof.is_empty());
        assert!(surjection_proof.len() > 64); // Should have substantial size
    }

    #[test]
    fn test_confidential_verify_range_proof() {
        let value = 1000000u64;
        let value_commitment = [0x03; 33];
        let value_blinding_factor = BlindingFactor::random().unwrap();
        let asset_commitment = [0x02; 33];
        let asset_blinding_factor = AssetBlindingFactor::random().unwrap();
        
        let range_proof = confidential::generate_range_proof(
            value,
            &value_commitment,
            &value_blinding_factor,
            &asset_commitment,
            &asset_blinding_factor,
            0, 0, 52,
        ).unwrap();
        
        // Test verification
        let is_valid = confidential::verify_range_proof(
            &range_proof,
            &value_commitment,
            &asset_commitment,
            0, 0, 52,
        ).unwrap();
        
        assert!(is_valid);
        
        // Test with empty proof
        let empty_proof = RangeProof::new(Vec::new());
        let is_valid_empty = confidential::verify_range_proof(
            &empty_proof,
            &value_commitment,
            &asset_commitment,
            0, 0, 52,
        ).unwrap();
        
        assert!(!is_valid_empty);
    }

    #[test]
    fn test_confidential_verify_surjection_proof() {
        let output_asset = AssetId::new([1u8; 32]);
        let output_asset_blinding_factor = AssetBlindingFactor::random().unwrap();
        let input_assets = vec![AssetId::new([2u8; 32])];
        let input_asset_blinding_factors = vec![AssetBlindingFactor::random().unwrap()];
        
        let surjection_proof = confidential::generate_surjection_proof(
            &output_asset,
            &output_asset_blinding_factor,
            &input_assets,
            &input_asset_blinding_factors,
        ).unwrap();
        
        let output_commitment = confidential::generate_asset_commitment(&output_asset, &output_asset_blinding_factor).unwrap();
        let input_commitments = vec![
            confidential::generate_asset_commitment(&input_assets[0], &input_asset_blinding_factors[0]).unwrap()
        ];
        
        // Test verification
        let is_valid = confidential::verify_surjection_proof(
            &surjection_proof,
            &output_commitment,
            &input_commitments,
        ).unwrap();
        
        assert!(is_valid);
        
        // Test with empty proof
        let empty_proof = SurjectionProof::new(Vec::new());
        let is_valid_empty = confidential::verify_surjection_proof(
            &empty_proof,
            &output_commitment,
            &input_commitments,
        ).unwrap();
        
        assert!(!is_valid_empty);
    }

    #[test]
    fn test_confidential_blind_output() {
        let asset_id = AssetId::new([1u8; 32]);
        let value = 1000000u64;
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let blinding_key = BlindingKey::new([5u8; 32]);
        
        let blinded_output = confidential::blind_output(&asset_id, value, script.clone(), &blinding_key).unwrap();
        
        assert!(blinded_output.is_confidential());
        assert!(!blinded_output.is_explicit());
        assert!(!blinded_output.witness.is_empty());
        assert!(!blinded_output.witness.range_proof.is_empty());
        assert!(!blinded_output.witness.surjection_proof.is_empty());
        assert_eq!(blinded_output.script_pubkey, script);
    }

    #[test]
    fn test_confidential_validate_transaction() {
        let asset_id = AssetId::new([1u8; 32]);
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let blinding_key = BlindingKey::new([5u8; 32]);
        
        // Create a transaction with a confidential output
        let mut tx = ConfidentialTransaction::new();
        let blinded_output = confidential::blind_output(&asset_id, 1000000, script, &blinding_key).unwrap();
        tx.output.push(blinded_output);
        
        // Add a dummy input
        use super::super::transaction::OutPoint;
        let input = TxIn {
            previous_output: OutPoint::new([0u8; 32], 0),
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: Vec::new(),
        };
        tx.input.push(input);
        
        // Test validation
        let is_valid = confidential::validate_confidential_transaction(&tx).unwrap();
        assert!(is_valid);
        
        // Test with empty inputs (should fail)
        let mut empty_tx = ConfidentialTransaction::new();
        empty_tx.output.push(ConfidentialTxOut::explicit(asset_id, 1000000, Script::new()));
        
        let result = confidential::validate_confidential_transaction(&empty_tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_blinding_factor_manager() {
        let mut manager = BlindingFactorManager::new();
        
        let value_bf = BlindingFactor::random().unwrap();
        let asset_bf = AssetBlindingFactor::random().unwrap();
        let blinding_key = BlindingKey::new([1u8; 32]);
        
        // Store blinding factors
        manager.store_blinding_factors(0, value_bf.clone(), asset_bf.clone(), blinding_key.clone());
        
        // Retrieve blinding factors
        assert_eq!(manager.get_value_blinding_factor(0), Some(&value_bf));
        assert_eq!(manager.get_asset_blinding_factor(0), Some(&asset_bf));
        assert_eq!(manager.get_blinding_key(0), Some(&blinding_key));
        
        // Check blinded outputs
        let blinded_outputs = manager.get_blinded_outputs();
        assert_eq!(blinded_outputs, vec![0]);
        
        // Remove blinding factors
        manager.remove_blinding_factors(0);
        assert_eq!(manager.get_value_blinding_factor(0), None);
        assert_eq!(manager.get_asset_blinding_factor(0), None);
        assert_eq!(manager.get_blinding_key(0), None);
        
        // Clear all
        manager.store_blinding_factors(1, value_bf, asset_bf, blinding_key);
        manager.clear();
        assert!(manager.get_blinded_outputs().is_empty());
    }

    #[test]
    fn test_transaction_blinder() {
        let mut blinder = TransactionBlinder::new();
        
        // Create a transaction with explicit outputs
        let asset_id = AssetId::new([1u8; 32]);
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let explicit_output = ConfidentialTxOut::explicit(asset_id, 1000000, script);
        
        let mut tx = ConfidentialTransaction::new();
        tx.output.push(explicit_output);
        
        // Blind the transaction
        let blinding_key = BlindingKey::new([5u8; 32]);
        let blinding_keys = vec![Some(blinding_key)];
        
        let blinded_tx = blinder.blind_transaction(tx, &blinding_keys).unwrap();
        
        // Check that the output is now confidential
        assert!(blinded_tx.output[0].is_confidential());
        assert!(!blinded_tx.output[0].witness.is_empty());
        
        // Test unblinding
        let unblinded_outputs = blinder.unblind_transaction(&blinded_tx).unwrap();
        assert_eq!(unblinded_outputs.len(), 1);
        // Note: unblinding is not fully implemented in the placeholder, so we just check structure
    }

    #[test]
    fn test_transaction_blinder_mismatched_keys() {
        let mut blinder = TransactionBlinder::new();
        
        let asset_id = AssetId::new([1u8; 32]);
        let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
        let explicit_output = ConfidentialTxOut::explicit(asset_id, 1000000, script);
        
        let mut tx = ConfidentialTransaction::new();
        tx.output.push(explicit_output);
        
        // Try to blind with mismatched number of keys
        let blinding_keys = vec![]; // Empty, but tx has 1 output
        
        let result = blinder.blind_transaction(tx, &blinding_keys);
        assert!(result.is_err());
    }
}