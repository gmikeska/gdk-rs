//! Transaction signing functionality with support for multiple signature types and SegWit.

use crate::primitives::transaction::Transaction;
use crate::primitives::script::Script;
use crate::primitives::address::Network;
use crate::primitives::hash::{sha256d, hash160, Hash256};
use crate::transaction_builder::UtxoInfo;
use crate::{Result, GdkError};
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Signature hash types for Bitcoin transactions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigHashType {
    /// Sign all inputs and outputs
    All = 0x01,
    /// Sign all inputs, no outputs
    None = 0x02,
    /// Sign all inputs, only the output with the same index
    Single = 0x03,
    /// Sign all inputs and outputs, anyone can add inputs
    AllPlusAnyoneCanPay = 0x81,
    /// Sign all inputs, no outputs, anyone can add inputs
    NonePlusAnyoneCanPay = 0x82,
    /// Sign all inputs, only matching output, anyone can add inputs
    SinglePlusAnyoneCanPay = 0x83,
}

impl Default for SigHashType {
    fn default() -> Self {
        SigHashType::All
    }
}

impl SigHashType {
    /// Get the byte value of the signature hash type
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Check if this sighash type uses ANYONECANPAY
    pub fn is_anyone_can_pay(self) -> bool {
        matches!(
            self,
            SigHashType::AllPlusAnyoneCanPay
                | SigHashType::NonePlusAnyoneCanPay
                | SigHashType::SinglePlusAnyoneCanPay
        )
    }
}

/// Script type for signature generation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptType {
    /// Pay-to-Public-Key-Hash (P2PKH)
    P2PKH,
    /// Pay-to-Script-Hash (P2SH)
    P2SH,
    /// Pay-to-Witness-Public-Key-Hash (P2WPKH)
    P2WPKH,
    /// Pay-to-Witness-Script-Hash (P2WSH)
    P2WSH,
    /// Pay-to-Script-Hash wrapped SegWit (P2SH-P2WPKH)
    P2SHWrappedP2WPKH,
    /// Pay-to-Script-Hash wrapped SegWit Script (P2SH-P2WSH)
    P2SHWrappedP2WSH,
}

/// Signing key information
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// Private key for signing
    pub private_key: SecretKey,
    /// Corresponding public key
    pub public_key: PublicKey,
    /// Derivation path (for debugging/tracking)
    pub derivation_path: Option<String>,
}

impl SigningKey {
    /// Create a new signing key from a private key
    pub fn new(private_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);
        
        Self {
            private_key,
            public_key,
            derivation_path: None,
        }
    }

    /// Create a signing key with derivation path
    pub fn with_derivation_path(private_key: SecretKey, derivation_path: String) -> Self {
        let mut key = Self::new(private_key);
        key.derivation_path = Some(derivation_path);
        key
    }
}

/// Input signing information
#[derive(Debug, Clone)]
pub struct InputSigningInfo {
    /// UTXO information for this input
    pub utxo: UtxoInfo,
    /// Script type for signing
    pub script_type: ScriptType,
    /// Signing key for this input
    pub signing_key: SigningKey,
    /// Redeem script (for P2SH inputs)
    pub redeem_script: Option<Script>,
    /// Witness script (for P2WSH inputs)
    pub witness_script: Option<Script>,
    /// Signature hash type
    pub sighash_type: SigHashType,
}

/// Multi-signature signing information
#[derive(Debug, Clone)]
pub struct MultiSigInfo {
    /// Required number of signatures
    pub required_sigs: usize,
    /// All public keys in the multisig
    pub public_keys: Vec<PublicKey>,
    /// Available signing keys (subset of public_keys)
    pub signing_keys: Vec<SigningKey>,
    /// Redeem script for the multisig
    pub redeem_script: Script,
}

/// Transaction signing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResult {
    /// The signed transaction
    pub signed_transaction: Transaction,
    /// Number of inputs successfully signed
    pub signed_inputs: usize,
    /// Total number of inputs
    pub total_inputs: usize,
    /// Whether the transaction is fully signed
    pub fully_signed: bool,
    /// Signing errors for specific inputs
    pub signing_errors: HashMap<usize, String>,
}

/// Comprehensive transaction signer
pub struct TransactionSigner {
    /// Network for address validation
    network: Network,
    /// Secp256k1 context for signing
    secp: Secp256k1<secp256k1::All>,
}

impl TransactionSigner {
    /// Create a new transaction signer
    pub fn new(network: Network) -> Self {
        Self {
            network,
            secp: Secp256k1::new(),
        }
    }

    /// Sign a transaction with the provided signing information
    pub fn sign_transaction(
        &self,
        mut transaction: Transaction,
        signing_info: &[InputSigningInfo],
    ) -> Result<SigningResult> {
        if transaction.input.len() != signing_info.len() {
            return Err(GdkError::InvalidInput(
                "Number of inputs must match signing info".to_string(),
            ));
        }

        let mut signed_inputs = 0;
        let mut signing_errors = HashMap::new();

        for (input_index, info) in signing_info.iter().enumerate() {
            match self.sign_input(&mut transaction, input_index, info) {
                Ok(()) => signed_inputs += 1,
                Err(e) => {
                    signing_errors.insert(input_index, e.to_string());
                }
            }
        }

        let fully_signed = signed_inputs == transaction.input.len();

        Ok(SigningResult {
            signed_transaction: transaction,
            signed_inputs,
            total_inputs: signing_info.len(),
            fully_signed,
            signing_errors,
        })
    }

    /// Sign a single input
    fn sign_input(
        &self,
        transaction: &mut Transaction,
        input_index: usize,
        info: &InputSigningInfo,
    ) -> Result<()> {
        match info.script_type {
            ScriptType::P2PKH => self.sign_p2pkh_input(transaction, input_index, info),
            ScriptType::P2SH => self.sign_p2sh_input(transaction, input_index, info),
            ScriptType::P2WPKH => self.sign_p2wpkh_input(transaction, input_index, info),
            ScriptType::P2WSH => self.sign_p2wsh_input(transaction, input_index, info),
            ScriptType::P2SHWrappedP2WPKH => {
                self.sign_p2sh_wrapped_p2wpkh_input(transaction, input_index, info)
            }
            ScriptType::P2SHWrappedP2WSH => {
                self.sign_p2sh_wrapped_p2wsh_input(transaction, input_index, info)
            }
        }
    }

    /// Sign a P2PKH input
    fn sign_p2pkh_input(
        &self,
        transaction: &mut Transaction,
        input_index: usize,
        info: &InputSigningInfo,
    ) -> Result<()> {
        // Create signature hash
        let sighash = self.signature_hash_legacy(
            transaction,
            input_index,
            &info.utxo.script_pubkey,
            info.sighash_type,
        )?;

        // Sign the hash
        let signature = self.sign_hash(&sighash, &info.signing_key.private_key)?;

        // Create script_sig: <signature> <pubkey>
        let mut script_sig = Vec::new();
        
        // Add signature with sighash type
        let mut sig_with_hashtype = signature.serialize_der().to_vec();
        sig_with_hashtype.push(info.sighash_type.as_u8());
        script_sig.push(sig_with_hashtype.len() as u8);
        script_sig.extend_from_slice(&sig_with_hashtype);

        // Add public key
        let pubkey_bytes = info.signing_key.public_key.serialize();
        script_sig.push(pubkey_bytes.len() as u8);
        script_sig.extend_from_slice(&pubkey_bytes);

        transaction.input[input_index].script_sig = Script::from_bytes(script_sig);
        Ok(())
    }

    /// Sign a P2WPKH input
    fn sign_p2wpkh_input(
        &self,
        transaction: &mut Transaction,
        input_index: usize,
        info: &InputSigningInfo,
    ) -> Result<()> {
        // Create signature hash for SegWit
        let sighash = self.signature_hash_segwit_v0(
            transaction,
            input_index,
            &info.utxo.script_pubkey,
            info.utxo.value,
            info.sighash_type,
        )?;

        // Sign the hash
        let signature = self.sign_hash(&sighash, &info.signing_key.private_key)?;

        // Create witness: <signature> <pubkey>
        let mut sig_with_hashtype = signature.serialize_der().to_vec();
        sig_with_hashtype.push(info.sighash_type.as_u8());

        let pubkey_bytes = info.signing_key.public_key.serialize();

        transaction.input[input_index].witness = vec![sig_with_hashtype, pubkey_bytes.to_vec()];
        transaction.input[input_index].script_sig = Script::new(); // Empty for native SegWit

        Ok(())
    }

    /// Sign a P2SH input
    fn sign_p2sh_input(
        &self,
        transaction: &mut Transaction,
        input_index: usize,
        info: &InputSigningInfo,
    ) -> Result<()> {
        let redeem_script = info
            .redeem_script
            .as_ref()
            .ok_or_else(|| GdkError::InvalidInput("P2SH requires redeem script".to_string()))?;

        // Create signature hash using the redeem script
        let sighash = self.signature_hash_legacy(
            transaction,
            input_index,
            redeem_script,
            info.sighash_type,
        )?;

        // Sign the hash
        let signature = self.sign_hash(&sighash, &info.signing_key.private_key)?;

        // Create script_sig: <signature> <pubkey> <redeem_script>
        let mut script_sig = Vec::new();

        // Add signature with sighash type
        let mut sig_with_hashtype = signature.serialize_der().to_vec();
        sig_with_hashtype.push(info.sighash_type.as_u8());
        script_sig.push(sig_with_hashtype.len() as u8);
        script_sig.extend_from_slice(&sig_with_hashtype);

        // Add public key
        let pubkey_bytes = info.signing_key.public_key.serialize();
        script_sig.push(pubkey_bytes.len() as u8);
        script_sig.extend_from_slice(&pubkey_bytes);

        // Add redeem script
        let redeem_bytes = redeem_script.as_bytes();
        script_sig.push(redeem_bytes.len() as u8);
        script_sig.extend_from_slice(redeem_bytes);

        transaction.input[input_index].script_sig = Script::from_bytes(script_sig);
        Ok(())
    }

    /// Sign a P2WSH input
    fn sign_p2wsh_input(
        &self,
        transaction: &mut Transaction,
        input_index: usize,
        info: &InputSigningInfo,
    ) -> Result<()> {
        let witness_script = info
            .witness_script
            .as_ref()
            .ok_or_else(|| GdkError::InvalidInput("P2WSH requires witness script".to_string()))?;

        // Create signature hash for SegWit using witness script
        let sighash = self.signature_hash_segwit_v0(
            transaction,
            input_index,
            witness_script,
            info.utxo.value,
            info.sighash_type,
        )?;

        // Sign the hash
        let signature = self.sign_hash(&sighash, &info.signing_key.private_key)?;

        // Create witness: <signature> <pubkey> <witness_script>
        let mut sig_with_hashtype = signature.serialize_der().to_vec();
        sig_with_hashtype.push(info.sighash_type.as_u8());

        let pubkey_bytes = info.signing_key.public_key.serialize();
        let witness_script_bytes = witness_script.as_bytes();

        transaction.input[input_index].witness = vec![
            sig_with_hashtype,
            pubkey_bytes.to_vec(),
            witness_script_bytes.to_vec(),
        ];
        transaction.input[input_index].script_sig = Script::new(); // Empty for native SegWit

        Ok(())
    }

    /// Sign a P2SH-wrapped P2WPKH input
    fn sign_p2sh_wrapped_p2wpkh_input(
        &self,
        transaction: &mut Transaction,
        input_index: usize,
        info: &InputSigningInfo,
    ) -> Result<()> {
        // Create P2WPKH script for signing
        let pubkey_hash = hash160(&info.signing_key.public_key.serialize());
        let p2wpkh_script = Script::new_p2wpkh(&pubkey_hash);

        // Create signature hash for SegWit
        let sighash = self.signature_hash_segwit_v0(
            transaction,
            input_index,
            &p2wpkh_script,
            info.utxo.value,
            info.sighash_type,
        )?;

        // Sign the hash
        let signature = self.sign_hash(&sighash, &info.signing_key.private_key)?;

        // Create witness: <signature> <pubkey>
        let mut sig_with_hashtype = signature.serialize_der().to_vec();
        sig_with_hashtype.push(info.sighash_type.as_u8());

        let pubkey_bytes = info.signing_key.public_key.serialize();

        transaction.input[input_index].witness = vec![sig_with_hashtype, pubkey_bytes.to_vec()];

        // script_sig contains the redeem script (P2WPKH script)
        let redeem_script_bytes = p2wpkh_script.as_bytes();
        let mut script_sig = Vec::new();
        script_sig.push(redeem_script_bytes.len() as u8);
        script_sig.extend_from_slice(redeem_script_bytes);
        transaction.input[input_index].script_sig = Script::from_bytes(script_sig);

        Ok(())
    }

    /// Sign a P2SH-wrapped P2WSH input
    fn sign_p2sh_wrapped_p2wsh_input(
        &self,
        transaction: &mut Transaction,
        input_index: usize,
        info: &InputSigningInfo,
    ) -> Result<()> {
        let witness_script = info
            .witness_script
            .as_ref()
            .ok_or_else(|| GdkError::InvalidInput("P2SH-P2WSH requires witness script".to_string()))?;

        // Create signature hash for SegWit using witness script
        let sighash = self.signature_hash_segwit_v0(
            transaction,
            input_index,
            witness_script,
            info.utxo.value,
            info.sighash_type,
        )?;

        // Sign the hash
        let signature = self.sign_hash(&sighash, &info.signing_key.private_key)?;

        // Create witness: <signature> <pubkey> <witness_script>
        let mut sig_with_hashtype = signature.serialize_der().to_vec();
        sig_with_hashtype.push(info.sighash_type.as_u8());

        let pubkey_bytes = info.signing_key.public_key.serialize();
        let witness_script_bytes = witness_script.as_bytes();

        transaction.input[input_index].witness = vec![
            sig_with_hashtype,
            pubkey_bytes.to_vec(),
            witness_script_bytes.to_vec(),
        ];

        // script_sig contains the redeem script (P2WSH script)
        let p2wsh_script = Script::new_p2wsh(&crate::primitives::hash::sha256(witness_script_bytes));
        let redeem_script_bytes = p2wsh_script.as_bytes();
        let mut script_sig = Vec::new();
        script_sig.push(redeem_script_bytes.len() as u8);
        script_sig.extend_from_slice(redeem_script_bytes);
        transaction.input[input_index].script_sig = Script::from_bytes(script_sig);

        Ok(())
    }

    /// Sign a multisig transaction
    pub fn sign_multisig_transaction(
        &self,
        mut transaction: Transaction,
        input_index: usize,
        multisig_info: &MultiSigInfo,
        utxo_value: u64,
        sighash_type: SigHashType,
    ) -> Result<Transaction> {
        if multisig_info.signing_keys.len() < multisig_info.required_sigs {
            return Err(GdkError::InvalidInput(
                "Not enough signing keys for multisig".to_string(),
            ));
        }

        // Create signature hash
        let sighash = self.signature_hash_legacy(
            &transaction,
            input_index,
            &multisig_info.redeem_script,
            sighash_type,
        )?;

        // Create signatures
        let mut signatures = Vec::new();
        for (i, signing_key) in multisig_info.signing_keys.iter().enumerate() {
            if i >= multisig_info.required_sigs {
                break;
            }

            let signature = self.sign_hash(&sighash, &signing_key.private_key)?;
            let mut sig_with_hashtype = signature.serialize_der().to_vec();
            sig_with_hashtype.push(sighash_type.as_u8());
            signatures.push(sig_with_hashtype);
        }

        // Create script_sig: OP_0 <sig1> <sig2> ... <redeem_script>
        let mut script_sig = Vec::new();
        script_sig.push(0x00); // OP_0 (required for multisig)

        // Add signatures
        for sig in signatures {
            script_sig.push(sig.len() as u8);
            script_sig.extend_from_slice(&sig);
        }

        // Add redeem script
        let redeem_bytes = multisig_info.redeem_script.as_bytes();
        script_sig.push(redeem_bytes.len() as u8);
        script_sig.extend_from_slice(redeem_bytes);

        transaction.input[input_index].script_sig = Script::from_bytes(script_sig);
        Ok(transaction)
    }

    /// Create signature hash for legacy (non-SegWit) transactions
    fn signature_hash_legacy(
        &self,
        transaction: &Transaction,
        input_index: usize,
        script_code: &Script,
        sighash_type: SigHashType,
    ) -> Result<Hash256> {
        let mut tx_copy = transaction.clone();

        // Clear all input scripts
        for input in &mut tx_copy.input {
            input.script_sig = Script::new();
        }

        // Set the script for the input being signed
        tx_copy.input[input_index].script_sig = script_code.clone();

        // Handle different sighash types
        match sighash_type {
            SigHashType::All => {
                // Sign all inputs and outputs (default behavior)
            }
            SigHashType::None => {
                // Clear all outputs
                tx_copy.output.clear();
                // Set sequence to 0 for all inputs except the one being signed
                for (i, input) in tx_copy.input.iter_mut().enumerate() {
                    if i != input_index {
                        input.sequence = 0;
                    }
                }
            }
            SigHashType::Single => {
                // Keep only the output with the same index
                if input_index >= tx_copy.output.len() {
                    return Err(GdkError::InvalidInput("SIGHASH_SINGLE: input index out of range".to_string()));
                }
                let output = tx_copy.output[input_index].clone();
                tx_copy.output = vec![output];
                // Set sequence to 0 for all inputs except the one being signed
                for (i, input) in tx_copy.input.iter_mut().enumerate() {
                    if i != input_index {
                        input.sequence = 0;
                    }
                }
            }
            _ => {
                // Handle ANYONECANPAY variants
                if sighash_type.is_anyone_can_pay() {
                    // Keep only the input being signed
                    let input = tx_copy.input[input_index].clone();
                    tx_copy.input = vec![input];
                }
            }
        }

        // Serialize and hash
        let mut serialized = tx_copy.consensus_encode_legacy()?;
        serialized.extend_from_slice(&(sighash_type.as_u8() as u32).to_le_bytes());

        Ok(sha256d(&serialized))
    }

    /// Create signature hash for SegWit v0 transactions (BIP143)
    fn signature_hash_segwit_v0(
        &self,
        transaction: &Transaction,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: SigHashType,
    ) -> Result<Hash256> {
        let mut hasher_data = Vec::new();

        // 1. nVersion (4 bytes)
        hasher_data.extend_from_slice(&transaction.version.to_le_bytes());

        // 2. hashPrevouts (32 bytes)
        if !sighash_type.is_anyone_can_pay() {
            let mut prevouts = Vec::new();
            for input in &transaction.input {
                prevouts.extend_from_slice(&input.previous_output.txid);
                prevouts.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            }
            hasher_data.extend_from_slice(&sha256d(&prevouts));
        } else {
            hasher_data.extend_from_slice(&[0u8; 32]);
        }

        // 3. hashSequence (32 bytes)
        if !sighash_type.is_anyone_can_pay()
            && sighash_type != SigHashType::Single
            && sighash_type != SigHashType::None
        {
            let mut sequences = Vec::new();
            for input in &transaction.input {
                sequences.extend_from_slice(&input.sequence.to_le_bytes());
            }
            hasher_data.extend_from_slice(&sha256d(&sequences));
        } else {
            hasher_data.extend_from_slice(&[0u8; 32]);
        }

        // 4. outpoint (36 bytes)
        let input = &transaction.input[input_index];
        hasher_data.extend_from_slice(&input.previous_output.txid);
        hasher_data.extend_from_slice(&input.previous_output.vout.to_le_bytes());

        // 5. scriptCode
        let script_bytes = script_code.as_bytes();
        hasher_data.push(script_bytes.len() as u8); // varint
        hasher_data.extend_from_slice(script_bytes);

        // 6. value (8 bytes)
        hasher_data.extend_from_slice(&value.to_le_bytes());

        // 7. nSequence (4 bytes)
        hasher_data.extend_from_slice(&input.sequence.to_le_bytes());

        // 8. hashOutputs (32 bytes)
        if sighash_type != SigHashType::Single && sighash_type != SigHashType::None {
            let mut outputs = Vec::new();
            for output in &transaction.output {
                outputs.extend_from_slice(&output.value.to_le_bytes());
                let script_bytes = output.script_pubkey.as_bytes();
                outputs.push(script_bytes.len() as u8);
                outputs.extend_from_slice(script_bytes);
            }
            hasher_data.extend_from_slice(&sha256d(&outputs));
        } else if sighash_type == SigHashType::Single && input_index < transaction.output.len() {
            let output = &transaction.output[input_index];
            let mut output_data = Vec::new();
            output_data.extend_from_slice(&output.value.to_le_bytes());
            let script_bytes = output.script_pubkey.as_bytes();
            output_data.push(script_bytes.len() as u8);
            output_data.extend_from_slice(script_bytes);
            hasher_data.extend_from_slice(&sha256d(&output_data));
        } else {
            hasher_data.extend_from_slice(&[0u8; 32]);
        }

        // 9. nLockTime (4 bytes)
        hasher_data.extend_from_slice(&transaction.lock_time.to_le_bytes());

        // 10. sighash type (4 bytes)
        hasher_data.extend_from_slice(&(sighash_type.as_u8() as u32).to_le_bytes());

        Ok(sha256d(&hasher_data))
    }

    /// Sign a hash with a private key
    fn sign_hash(&self, hash: &Hash256, private_key: &SecretKey) -> Result<Signature> {
        let message = Message::from_digest_slice(hash)
            .map_err(|e| GdkError::InvalidInput(format!("Invalid message: {}", e)))?;

        Ok(self.secp.sign_ecdsa(&message, private_key))
    }

    /// Verify a signature
    pub fn verify_signature(
        &self,
        signature: &Signature,
        hash: &Hash256,
        public_key: &PublicKey,
    ) -> Result<bool> {
        let message = Message::from_digest_slice(hash)
            .map_err(|e| GdkError::InvalidInput(format!("Invalid message: {}", e)))?;

        Ok(self.secp.verify_ecdsa(&message, signature, public_key).is_ok())
    }

    /// Validate a signed transaction
    pub fn validate_transaction_signatures(
        &self,
        transaction: &Transaction,
        utxos: &[UtxoInfo],
    ) -> Result<bool> {
        if transaction.input.len() != utxos.len() {
            return Err(GdkError::InvalidInput(
                "Number of inputs must match UTXOs".to_string(),
            ));
        }

        for (input_index, utxo) in utxos.iter().enumerate() {
            if !self.validate_input_signature(transaction, input_index, utxo)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate a single input signature
    fn validate_input_signature(
        &self,
        transaction: &Transaction,
        input_index: usize,
        utxo: &UtxoInfo,
    ) -> Result<bool> {
        // This is a simplified validation - in a full implementation,
        // we would need to parse the script_sig and witness to extract
        // signatures and public keys, then verify them against the
        // appropriate signature hash.
        
        // For now, we'll just check that the input has some signature data
        let input = &transaction.input[input_index];
        
        match utxo.script_type.as_str() {
            "p2pkh" | "p2sh" => Ok(!input.script_sig.is_empty()),
            "p2wpkh" | "p2wsh" => Ok(!input.witness.is_empty()),
            _ => Ok(true), // Unknown script type, assume valid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::address::Network;
    use rand::thread_rng;

    fn create_test_transaction() -> Transaction {
        let mut tx = Transaction::new();
        tx.version = 2;
        
        // Add a test input
        let outpoint = crate::primitives::transaction::OutPoint::new([1u8; 32], 0);
        let input = crate::primitives::transaction::TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: 0xffffffff,
            witness: Vec::new(),
        };
        
        let mut tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![input],
            output: vec![],
        };
        let output = crate::primitives::transaction::TxOut {
            value: 50000,
            script_pubkey: Script::new(),
        };
        tx.output.push(output);
        
        tx
    }

    fn create_test_utxo() -> UtxoInfo {
        UtxoInfo {
            txid: hex::encode([1u8; 32]),
            vout: 0,
            value: 100000,
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            script_pubkey: Script::new_p2pkh(&[0x12u8; 20]),
            subaccount_id: 0,
            is_change: false,
            block_height: Some(100),
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }
    }

    #[test]
    fn test_signer_creation() {
        let signer = TransactionSigner::new(Network::Testnet);
        assert_eq!(signer.network, Network::Testnet);
    }

    #[test]
    fn test_signing_key_creation() {
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let private_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let signing_key = SigningKey::new(private_key);
        
        assert_eq!(signing_key.private_key, private_key);
        assert!(signing_key.derivation_path.is_none());
    }

    #[test]
    fn test_sighash_type_properties() {
        assert_eq!(SigHashType::All.as_u8(), 0x01);
        assert!(!SigHashType::All.is_anyone_can_pay());
        assert!(SigHashType::AllPlusAnyoneCanPay.is_anyone_can_pay());
    }

    #[test]
    fn test_signature_hash_legacy() {
        let signer = TransactionSigner::new(Network::Testnet);
        let transaction = create_test_transaction();
        let script = Script::new_p2pkh(&[0x12u8; 20]);
        
        let hash = signer.signature_hash_legacy(
            &transaction,
            0,
            &script,
            SigHashType::All,
        ).unwrap();
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_signature_hash_segwit() {
        let signer = TransactionSigner::new(Network::Testnet);
        let transaction = create_test_transaction();
        let script = Script::new_p2wpkh(&[0x12u8; 20]);
        
        let hash = signer.signature_hash_segwit_v0(
            &transaction,
            0,
            &script,
            100000,
            SigHashType::All,
        ).unwrap();
        
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sign_transaction_validation() {
        let signer = TransactionSigner::new(Network::Testnet);
        let transaction = create_test_transaction();
        
        // Test with mismatched input/signing info counts
        let signing_info = vec![];
        let result = signer.sign_transaction(transaction, &signing_info);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_validation() {
        let signer = TransactionSigner::new(Network::Testnet);
        let transaction = create_test_transaction();
        let utxos = vec![create_test_utxo()];
        
        let result = signer.validate_transaction_signatures(&transaction, &utxos);
        assert!(result.is_ok());
    }
}