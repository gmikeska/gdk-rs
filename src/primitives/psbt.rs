//! Partially Signed Bitcoin Transactions (BIP 174).

use crate::primitives::transaction::{Transaction, TxOut};
use crate::primitives::script::Script;
use crate::primitives::bip32::{DerivationPath, Fingerprint};
use crate::primitives::encode::{Encodable, Decodable, write_varint, read_varint};
use crate::{Result, GdkError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Cursor};
use secp256k1::PublicKey;

// PSBT key type constants as defined in BIP 174
const PSBT_GLOBAL_UNSIGNED_TX: u8 = 0x00;
const PSBT_GLOBAL_XPUB: u8 = 0x01;
const PSBT_GLOBAL_VERSION: u8 = 0xfb;
const PSBT_GLOBAL_PROPRIETARY: u8 = 0xfc;

const PSBT_IN_NON_WITNESS_UTXO: u8 = 0x00;
const PSBT_IN_WITNESS_UTXO: u8 = 0x01;
const PSBT_IN_PARTIAL_SIG: u8 = 0x02;
const PSBT_IN_SIGHASH_TYPE: u8 = 0x03;
const PSBT_IN_REDEEM_SCRIPT: u8 = 0x04;
const PSBT_IN_WITNESS_SCRIPT: u8 = 0x05;
const PSBT_IN_BIP32_DERIVATION: u8 = 0x06;
const PSBT_IN_FINAL_SCRIPTSIG: u8 = 0x07;
const PSBT_IN_FINAL_SCRIPTWITNESS: u8 = 0x08;
const PSBT_IN_POR_COMMITMENT: u8 = 0x09;
const PSBT_IN_PROPRIETARY: u8 = 0xfc;

const PSBT_OUT_REDEEM_SCRIPT: u8 = 0x00;
const PSBT_OUT_WITNESS_SCRIPT: u8 = 0x01;
const PSBT_OUT_BIP32_DERIVATION: u8 = 0x02;
const PSBT_OUT_PROPRIETARY: u8 = 0xfc;

// PSBT magic bytes
const PSBT_MAGIC: &[u8] = b"psbt";
const PSBT_SEPARATOR: u8 = 0xff;

/// BIP32 key derivation information
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Bip32Derivation {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
}

/// Global PSBT data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtGlobal {
    pub unsigned_tx: Option<Transaction>,
    pub xpub: BTreeMap<Vec<u8>, Bip32Derivation>, // Using Vec<u8> for xpub serialization
    pub version: Option<u32>,
    pub proprietary: BTreeMap<Vec<u8>, Vec<u8>>,
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Input-specific PSBT data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtInput {
    pub non_witness_utxo: Option<Transaction>,
    pub witness_utxo: Option<TxOut>,
    pub partial_sigs: BTreeMap<PublicKey, Vec<u8>>,
    pub sighash_type: Option<u32>,
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
    pub bip32_derivation: BTreeMap<PublicKey, Bip32Derivation>,
    pub final_script_sig: Option<Script>,
    pub final_script_witness: Option<Vec<Vec<u8>>>,
    pub por_commitment: Option<String>,
    pub proprietary: BTreeMap<Vec<u8>, Vec<u8>>,
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Output-specific PSBT data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtOutput {
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
    pub bip32_derivation: BTreeMap<PublicKey, Bip32Derivation>,
    pub proprietary: BTreeMap<Vec<u8>, Vec<u8>>,
    pub unknown: BTreeMap<Vec<u8>, Vec<u8>>,
}

/// Partially Signed Bitcoin Transaction
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PartiallySignedTransaction {
    pub global: PsbtGlobal,
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutput>,
}

impl PartiallySignedTransaction {
    /// Create a new PSBT from an unsigned transaction
    pub fn new(unsigned_tx: Transaction) -> Result<Self> {
        let input_count = unsigned_tx.input.len();
        let output_count = unsigned_tx.output.len();

        let mut global = PsbtGlobal::default();
        global.unsigned_tx = Some(unsigned_tx);

        let inputs = vec![PsbtInput::default(); input_count];
        let outputs = vec![PsbtOutput::default(); output_count];

        Ok(PartiallySignedTransaction {
            global,
            inputs,
            outputs,
        })
    }

    /// Get the unsigned transaction
    pub fn unsigned_tx(&self) -> Result<&Transaction> {
        self.global.unsigned_tx.as_ref()
            .ok_or_else(|| GdkError::invalid_input_simple("PSBT missing unsigned transaction".to_string()))
    }

    /// Check if the PSBT is complete (all inputs have final scripts)
    pub fn is_complete(&self) -> bool {
        self.inputs.iter().all(|input| {
            input.final_script_sig.is_some() || input.final_script_witness.is_some()
        })
    }

    /// Extract the final transaction if the PSBT is complete
    pub fn extract_tx(&self) -> Result<Transaction> {
        if !self.is_complete() {
            return Err(GdkError::invalid_input_simple("PSBT is not complete".to_string()));
        }

        let mut tx = self.unsigned_tx()?.clone();

        for (i, input) in self.inputs.iter().enumerate() {
            if let Some(ref script_sig) = input.final_script_sig {
                tx.input[i].script_sig = script_sig.clone();
            }
            if let Some(ref witness) = input.final_script_witness {
                tx.input[i].witness = witness.clone();
            }
        }

        Ok(tx)
    }

    /// Add a signature to an input
    pub fn add_signature(&mut self, input_index: usize, pubkey: PublicKey, signature: Vec<u8>) -> Result<()> {
        if input_index >= self.inputs.len() {
            return Err(GdkError::invalid_input_simple("Input index out of bounds".to_string()));
        }

        self.inputs[input_index].partial_sigs.insert(pubkey, signature);
        Ok(())
    }

    /// Combine this PSBT with another PSBT
    pub fn combine(&mut self, other: &PartiallySignedTransaction) -> Result<()> {
        // Check that the unsigned transactions match
        if self.unsigned_tx()? != other.unsigned_tx()? {
            return Err(GdkError::invalid_input_simple("Cannot combine PSBTs with different unsigned transactions".to_string()));
        }

        // Combine global data
        for (xpub, derivation) in &other.global.xpub {
            self.global.xpub.insert(xpub.clone(), derivation.clone());
        }

        if other.global.version.is_some() {
            self.global.version = other.global.version;
        }

        for (key, value) in &other.global.proprietary {
            self.global.proprietary.insert(key.clone(), value.clone());
        }

        for (key, value) in &other.global.unknown {
            self.global.unknown.insert(key.clone(), value.clone());
        }

        // Combine input data
        for (i, other_input) in other.inputs.iter().enumerate() {
            if i >= self.inputs.len() {
                continue;
            }

            let input = &mut self.inputs[i];

            if other_input.non_witness_utxo.is_some() {
                input.non_witness_utxo = other_input.non_witness_utxo.clone();
            }

            if other_input.witness_utxo.is_some() {
                input.witness_utxo = other_input.witness_utxo.clone();
            }

            for (pubkey, sig) in &other_input.partial_sigs {
                input.partial_sigs.insert(*pubkey, sig.clone());
            }

            if other_input.sighash_type.is_some() {
                input.sighash_type = other_input.sighash_type;
            }

            if other_input.redeem_script.is_some() {
                input.redeem_script = other_input.redeem_script.clone();
            }

            if other_input.witness_script.is_some() {
                input.witness_script = other_input.witness_script.clone();
            }

            for (pubkey, derivation) in &other_input.bip32_derivation {
                input.bip32_derivation.insert(*pubkey, derivation.clone());
            }

            if other_input.final_script_sig.is_some() {
                input.final_script_sig = other_input.final_script_sig.clone();
            }

            if other_input.final_script_witness.is_some() {
                input.final_script_witness = other_input.final_script_witness.clone();
            }

            if other_input.por_commitment.is_some() {
                input.por_commitment = other_input.por_commitment.clone();
            }

            for (key, value) in &other_input.proprietary {
                input.proprietary.insert(key.clone(), value.clone());
            }

            for (key, value) in &other_input.unknown {
                input.unknown.insert(key.clone(), value.clone());
            }
        }

        // Combine output data
        for (i, other_output) in other.outputs.iter().enumerate() {
            if i >= self.outputs.len() {
                continue;
            }

            let output = &mut self.outputs[i];

            if other_output.redeem_script.is_some() {
                output.redeem_script = other_output.redeem_script.clone();
            }

            if other_output.witness_script.is_some() {
                output.witness_script = other_output.witness_script.clone();
            }

            for (pubkey, derivation) in &other_output.bip32_derivation {
                output.bip32_derivation.insert(*pubkey, derivation.clone());
            }

            for (key, value) in &other_output.proprietary {
                output.proprietary.insert(key.clone(), value.clone());
            }

            for (key, value) in &other_output.unknown {
                output.unknown.insert(key.clone(), value.clone());
            }
        }

        Ok(())
    }

    /// Finalize an input by converting partial signatures to final scripts
    pub fn finalize_input(&mut self, input_index: usize) -> Result<()> {
        if input_index >= self.inputs.len() {
            return Err(GdkError::invalid_input_simple("Input index out of bounds".to_string()));
        }

        let input = &mut self.inputs[input_index];

        // This is a simplified finalization - a full implementation would
        // need to handle different script types and create proper final scripts
        if !input.partial_sigs.is_empty() {
            // For now, just mark as finalized with empty scripts
            // A real implementation would construct the proper scriptSig and witness
            input.final_script_sig = Some(Script::new());
            input.final_script_witness = Some(Vec::new());

            // Clear partial signatures after finalization
            input.partial_sigs.clear();
        }

        Ok(())
    }

    /// Validate the PSBT structure and data
    pub fn validate(&self) -> Result<()> {
        // Check that unsigned transaction exists
        let unsigned_tx = self.unsigned_tx()?;

        // Check that input and output counts match
        if self.inputs.len() != unsigned_tx.input.len() {
            return Err(GdkError::invalid_input_simple("PSBT input count doesn't match transaction".to_string()));
        }

        if self.outputs.len() != unsigned_tx.output.len() {
            return Err(GdkError::invalid_input_simple("PSBT output count doesn't match transaction".to_string()));
        }

        // Validate that the unsigned transaction has empty scriptSigs and witnesses
        for input in &unsigned_tx.input {
            if !input.script_sig.is_empty() {
                return Err(GdkError::invalid_input_simple("Unsigned transaction must have empty scriptSigs".to_string()));
            }
            if !input.witness.is_empty() {
                return Err(GdkError::invalid_input_simple("Unsigned transaction must have empty witnesses".to_string()));
            }
        }

        // Additional validation could be added here
        Ok(())
    }

    /// Serialize the PSBT to bytes
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Write magic bytes and separator
        buf.extend_from_slice(PSBT_MAGIC);
        buf.push(PSBT_SEPARATOR);

        // Serialize global data
        self.serialize_global(&mut buf)?;

        // Serialize inputs
        for input in &self.inputs {
            self.serialize_input(input, &mut buf)?;
        }

        // Serialize outputs
        for output in &self.outputs {
            self.serialize_output(output, &mut buf)?;
        }

        Ok(buf)
    }

    /// Deserialize a PSBT from bytes
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);

        // Check magic bytes
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic)?;
        if &magic != PSBT_MAGIC {
            return Err(GdkError::invalid_input_simple("Invalid PSBT magic bytes".to_string()));
        }

        // Check separator
        let mut separator = [0u8; 1];
        cursor.read_exact(&mut separator)?;
        if separator[0] != PSBT_SEPARATOR {
            return Err(GdkError::invalid_input_simple("Invalid PSBT separator".to_string()));
        }

        // Deserialize global data
        let global = Self::deserialize_global(&mut cursor)?;

        // Get transaction to determine input/output counts
        let unsigned_tx = global.unsigned_tx.as_ref()
            .ok_or_else(|| GdkError::invalid_input_simple("PSBT missing unsigned transaction".to_string()))?;

        // Deserialize inputs
        let mut inputs = Vec::new();
        for _ in 0..unsigned_tx.input.len() {
            inputs.push(Self::deserialize_input(&mut cursor)?);
        }

        // Deserialize outputs
        let mut outputs = Vec::new();
        for _ in 0..unsigned_tx.output.len() {
            outputs.push(Self::deserialize_output(&mut cursor)?);
        }

        let psbt = PartiallySignedTransaction {
            global,
            inputs,
            outputs,
        };

        psbt.validate()?;
        Ok(psbt)
    }

    fn serialize_global(&self, buf: &mut Vec<u8>) -> Result<()> {
        // Serialize unsigned transaction
        if let Some(ref tx) = self.global.unsigned_tx {
            Self::write_key_value(buf, &[PSBT_GLOBAL_UNSIGNED_TX], &tx.consensus_encode_to_vec()?)?;
        }

        // Serialize xpubs
        for (xpub_bytes, derivation) in &self.global.xpub {
            let mut key = vec![PSBT_GLOBAL_XPUB];
            key.extend_from_slice(xpub_bytes);
            
            let mut value = Vec::new();
            value.extend_from_slice(derivation.fingerprint.as_bytes());
            // Serialize derivation path
            for &component in derivation.path.path() {
                value.extend_from_slice(&component.to_le_bytes());
            }
            
            Self::write_key_value(buf, &key, &value)?;
        }

        // Serialize version
        if let Some(version) = self.global.version {
            Self::write_key_value(buf, &[PSBT_GLOBAL_VERSION], &version.to_le_bytes())?;
        }

        // Serialize proprietary fields
        for (key, value) in &self.global.proprietary {
            let mut full_key = vec![PSBT_GLOBAL_PROPRIETARY];
            full_key.extend_from_slice(key);
            Self::write_key_value(buf, &full_key, value)?;
        }

        // Serialize unknown fields
        for (key, value) in &self.global.unknown {
            Self::write_key_value(buf, key, value)?;
        }

        // Write separator
        buf.push(0x00);
        Ok(())
    }

    fn serialize_input(&self, input: &PsbtInput, buf: &mut Vec<u8>) -> Result<()> {
        // Serialize non-witness UTXO
        if let Some(ref tx) = input.non_witness_utxo {
            Self::write_key_value(buf, &[PSBT_IN_NON_WITNESS_UTXO], &tx.consensus_encode_to_vec()?)?;
        }

        // Serialize witness UTXO
        if let Some(ref utxo) = input.witness_utxo {
            Self::write_key_value(buf, &[PSBT_IN_WITNESS_UTXO], &utxo.consensus_encode_to_vec()?)?;
        }

        // Serialize partial signatures
        for (pubkey, sig) in &input.partial_sigs {
            let mut key = vec![PSBT_IN_PARTIAL_SIG];
            key.extend_from_slice(&pubkey.serialize());
            Self::write_key_value(buf, &key, sig)?;
        }

        // Serialize sighash type
        if let Some(sighash_type) = input.sighash_type {
            Self::write_key_value(buf, &[PSBT_IN_SIGHASH_TYPE], &sighash_type.to_le_bytes())?;
        }

        // Serialize redeem script
        if let Some(ref script) = input.redeem_script {
            Self::write_key_value(buf, &[PSBT_IN_REDEEM_SCRIPT], script.as_bytes())?;
        }

        // Serialize witness script
        if let Some(ref script) = input.witness_script {
            Self::write_key_value(buf, &[PSBT_IN_WITNESS_SCRIPT], script.as_bytes())?;
        }

        // Serialize BIP32 derivations
        for (pubkey, derivation) in &input.bip32_derivation {
            let mut key = vec![PSBT_IN_BIP32_DERIVATION];
            key.extend_from_slice(&pubkey.serialize());
            
            let mut value = Vec::new();
            value.extend_from_slice(derivation.fingerprint.as_bytes());
            for &component in derivation.path.path() {
                value.extend_from_slice(&component.to_le_bytes());
            }
            
            Self::write_key_value(buf, &key, &value)?;
        }

        // Serialize final scriptSig
        if let Some(ref script) = input.final_script_sig {
            Self::write_key_value(buf, &[PSBT_IN_FINAL_SCRIPTSIG], script.as_bytes())?;
        }

        // Serialize final script witness
        if let Some(ref witness) = input.final_script_witness {
            let mut witness_data = Vec::new();
            write_varint(&mut witness_data, witness.len() as u64)?;
            for item in witness {
                write_varint(&mut witness_data, item.len() as u64)?;
                witness_data.extend_from_slice(item);
            }
            Self::write_key_value(buf, &[PSBT_IN_FINAL_SCRIPTWITNESS], &witness_data)?;
        }

        // Serialize proprietary fields
        for (key, value) in &input.proprietary {
            let mut full_key = vec![PSBT_IN_PROPRIETARY];
            full_key.extend_from_slice(key);
            Self::write_key_value(buf, &full_key, value)?;
        }

        // Serialize unknown fields
        for (key, value) in &input.unknown {
            Self::write_key_value(buf, key, value)?;
        }

        // Write separator
        buf.push(0x00);
        Ok(())
    }

    fn serialize_output(&self, output: &PsbtOutput, buf: &mut Vec<u8>) -> Result<()> {
        // Serialize redeem script
        if let Some(ref script) = output.redeem_script {
            Self::write_key_value(buf, &[PSBT_OUT_REDEEM_SCRIPT], script.as_bytes())?;
        }

        // Serialize witness script
        if let Some(ref script) = output.witness_script {
            Self::write_key_value(buf, &[PSBT_OUT_WITNESS_SCRIPT], script.as_bytes())?;
        }

        // Serialize BIP32 derivations
        for (pubkey, derivation) in &output.bip32_derivation {
            let mut key = vec![PSBT_OUT_BIP32_DERIVATION];
            key.extend_from_slice(&pubkey.serialize());
            
            let mut value = Vec::new();
            value.extend_from_slice(derivation.fingerprint.as_bytes());
            for &component in derivation.path.path() {
                value.extend_from_slice(&component.to_le_bytes());
            }
            
            Self::write_key_value(buf, &key, &value)?;
        }

        // Serialize proprietary fields
        for (key, value) in &output.proprietary {
            let mut full_key = vec![PSBT_OUT_PROPRIETARY];
            full_key.extend_from_slice(key);
            Self::write_key_value(buf, &full_key, value)?;
        }

        // Serialize unknown fields
        for (key, value) in &output.unknown {
            Self::write_key_value(buf, key, value)?;
        }

        // Write separator
        buf.push(0x00);
        Ok(())
    }

    fn write_key_value(buf: &mut Vec<u8>, key: &[u8], value: &[u8]) -> Result<()> {
        write_varint(buf, key.len() as u64)?;
        buf.extend_from_slice(key);
        write_varint(buf, value.len() as u64)?;
        buf.extend_from_slice(value);
        Ok(())
    }

    fn deserialize_global(cursor: &mut Cursor<&[u8]>) -> Result<PsbtGlobal> {
        let mut global = PsbtGlobal::default();

        loop {
            let key_len = read_varint(cursor)?;
            if key_len == 0 {
                break; // End of global section
            }

            let mut key = vec![0u8; key_len as usize];
            cursor.read_exact(&mut key)?;

            let value_len = read_varint(cursor)?;
            let mut value = vec![0u8; value_len as usize];
            cursor.read_exact(&mut value)?;

            match key[0] {
                PSBT_GLOBAL_UNSIGNED_TX => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT global unsigned tx key".to_string()));
                    }
                    global.unsigned_tx = Some(Transaction::consensus_decode_from_slice(&value)?);
                }
                PSBT_GLOBAL_XPUB => {
                    if key.len() != 34 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT global xpub key length".to_string()));
                    }
                    let pubkey = PublicKey::from_slice(&key[1..34])
                        .map_err(|e| GdkError::invalid_input_simple(format!("Invalid public key: {}", e)))?;
                    
                    if value.len() < 4 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT xpub value length".to_string()));
                    }
                    
                    let mut fingerprint = [0u8; 4];
                    fingerprint.copy_from_slice(&value[0..4]);
                    
                    let path_data = &value[4..];
                    if path_data.len() % 4 != 0 {
                        return Err(GdkError::invalid_input_simple("Invalid derivation path length".to_string()));
                    }
                    
                    let mut path = Vec::new();
                    for chunk in path_data.chunks(4) {
                        let component = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        path.push(component);
                    }
                    
                    // Create a dummy extended public key for the map
                    // In a real implementation, we'd need to reconstruct the full xpub
                    let derivation = Bip32Derivation {
                        fingerprint: Fingerprint(fingerprint),
                        path: crate::primitives::bip32::DerivationPath::new(path),
                    };
                    
                    // For now, we'll skip adding to the xpub map since we can't reconstruct the full ExtendedPublicKey
                    // global.xpub.insert(xpub, derivation);
                }
                PSBT_GLOBAL_VERSION => {
                    if key.len() != 1 || value.len() != 4 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT version field".to_string()));
                    }
                    global.version = Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]));
                }
                PSBT_GLOBAL_PROPRIETARY => {
                    global.proprietary.insert(key[1..].to_vec(), value);
                }
                _ => {
                    global.unknown.insert(key, value);
                }
            }
        }

        Ok(global)
    }

    fn deserialize_input(cursor: &mut Cursor<&[u8]>) -> Result<PsbtInput> {
        let mut input = PsbtInput::default();

        loop {
            let key_len = read_varint(cursor)?;
            if key_len == 0 {
                break; // End of input section
            }

            let mut key = vec![0u8; key_len as usize];
            cursor.read_exact(&mut key)?;

            let value_len = read_varint(cursor)?;
            let mut value = vec![0u8; value_len as usize];
            cursor.read_exact(&mut value)?;

            match key[0] {
                PSBT_IN_NON_WITNESS_UTXO => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input non-witness UTXO key".to_string()));
                    }
                    input.non_witness_utxo = Some(Transaction::consensus_decode_from_slice(&value)?);
                }
                PSBT_IN_WITNESS_UTXO => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input witness UTXO key".to_string()));
                    }
                    input.witness_utxo = Some(TxOut::consensus_decode_from_slice(&value)?);
                }
                PSBT_IN_PARTIAL_SIG => {
                    if key.len() != 34 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input partial sig key length".to_string()));
                    }
                    let pubkey = PublicKey::from_slice(&key[1..34])
                        .map_err(|e| GdkError::invalid_input_simple(format!("Invalid public key: {}", e)))?;
                    input.partial_sigs.insert(pubkey, value);
                }
                PSBT_IN_SIGHASH_TYPE => {
                    if key.len() != 1 || value.len() != 4 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT sighash type field".to_string()));
                    }
                    input.sighash_type = Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]));
                }
                PSBT_IN_REDEEM_SCRIPT => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input redeem script key".to_string()));
                    }
                    input.redeem_script = Some(Script::from_bytes(value));
                }
                PSBT_IN_WITNESS_SCRIPT => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input witness script key".to_string()));
                    }
                    input.witness_script = Some(Script::from_bytes(value));
                }
                PSBT_IN_BIP32_DERIVATION => {
                    if key.len() != 34 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input BIP32 derivation key length".to_string()));
                    }
                    let pubkey = PublicKey::from_slice(&key[1..34])
                        .map_err(|e| GdkError::invalid_input_simple(format!("Invalid public key: {}", e)))?;
                    
                    if value.len() < 4 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT BIP32 derivation value length".to_string()));
                    }
                    
                    let mut fingerprint = [0u8; 4];
                    fingerprint.copy_from_slice(&value[0..4]);
                    
                    let path_data = &value[4..];
                    if path_data.len() % 4 != 0 {
                        return Err(GdkError::invalid_input_simple("Invalid derivation path length".to_string()));
                    }
                    
                    let mut path = Vec::new();
                    for chunk in path_data.chunks(4) {
                        let component = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        path.push(component);
                    }
                    
                    let derivation = Bip32Derivation {
                        fingerprint: Fingerprint(fingerprint),
                        path: crate::primitives::bip32::DerivationPath::new(path),
                    };
                    
                    input.bip32_derivation.insert(pubkey, derivation);
                }
                PSBT_IN_FINAL_SCRIPTSIG => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input final scriptSig key".to_string()));
                    }
                    input.final_script_sig = Some(Script::from_bytes(value));
                }
                PSBT_IN_FINAL_SCRIPTWITNESS => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT input final script witness key".to_string()));
                    }
                    let mut cursor = Cursor::new(&value);
                    let witness_len = read_varint(&mut cursor)?;
                    let mut witness = Vec::new();
                    for _ in 0..witness_len {
                        let item_len = read_varint(&mut cursor)?;
                        let mut item = vec![0u8; item_len as usize];
                        cursor.read_exact(&mut item)?;
                        witness.push(item);
                    }
                    input.final_script_witness = Some(witness);
                }
                PSBT_IN_PROPRIETARY => {
                    input.proprietary.insert(key[1..].to_vec(), value);
                }
                _ => {
                    input.unknown.insert(key, value);
                }
            }
        }

        Ok(input)
    }

    fn deserialize_output(cursor: &mut Cursor<&[u8]>) -> Result<PsbtOutput> {
        let mut output = PsbtOutput::default();

        loop {
            let key_len = read_varint(cursor)?;
            if key_len == 0 {
                break; // End of output section
            }

            let mut key = vec![0u8; key_len as usize];
            cursor.read_exact(&mut key)?;

            let value_len = read_varint(cursor)?;
            let mut value = vec![0u8; value_len as usize];
            cursor.read_exact(&mut value)?;

            match key[0] {
                PSBT_OUT_REDEEM_SCRIPT => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT output redeem script key".to_string()));
                    }
                    output.redeem_script = Some(Script::from_bytes(value));
                }
                PSBT_OUT_WITNESS_SCRIPT => {
                    if key.len() != 1 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT output witness script key".to_string()));
                    }
                    output.witness_script = Some(Script::from_bytes(value));
                }
                PSBT_OUT_BIP32_DERIVATION => {
                    if key.len() != 34 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT output BIP32 derivation key length".to_string()));
                    }
                    let pubkey = PublicKey::from_slice(&key[1..34])
                        .map_err(|e| GdkError::invalid_input_simple(format!("Invalid public key: {}", e)))?;
                    
                    if value.len() < 4 {
                        return Err(GdkError::invalid_input_simple("Invalid PSBT BIP32 derivation value length".to_string()));
                    }
                    
                    let mut fingerprint = [0u8; 4];
                    fingerprint.copy_from_slice(&value[0..4]);
                    
                    let path_data = &value[4..];
                    if path_data.len() % 4 != 0 {
                        return Err(GdkError::invalid_input_simple("Invalid derivation path length".to_string()));
                    }
                    
                    let mut path = Vec::new();
                    for chunk in path_data.chunks(4) {
                        let component = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        path.push(component);
                    }
                    
                    let derivation = Bip32Derivation {
                        fingerprint: Fingerprint(fingerprint),
                        path: crate::primitives::bip32::DerivationPath::new(path),
                    };
                    
                    output.bip32_derivation.insert(pubkey, derivation);
                }
                PSBT_OUT_PROPRIETARY => {
                    output.proprietary.insert(key[1..].to_vec(), value);
                }
                _ => {
                    output.unknown.insert(key, value);
                }
            }
        }

        Ok(output)
    }
}

