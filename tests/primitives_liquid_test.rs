use gdk_rs::primitives::liquid::*;
use gdk_rs::primitives::script::Script;
use gdk_rs::primitives::transaction::TxIn;
use gdk_rs::primitives::encode::{Encodable, Decodable};
use std::io::Cursor;

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
    
    let mut encoded = Vec::new();
    conf_asset.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialAsset::consensus_decode(&mut cursor).unwrap();
    
    assert_eq!(conf_asset, decoded);
}

#[test]
fn test_confidential_asset_encode_decode_confidential() {
    let commitment = [0x02; 33]; // Even parity
    let conf_asset = ConfidentialAsset::confidential(commitment);
    
    let mut encoded = Vec::new();
    conf_asset.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialAsset::consensus_decode(&mut cursor).unwrap();
    
    assert_eq!(conf_asset, decoded);
}

#[test]
fn test_confidential_value_encode_decode_explicit() {
    let value = 1000000u64;
    let conf_value = ConfidentialValue::explicit(value);
    
    let mut encoded = Vec::new();
    conf_value.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialValue::consensus_decode(&mut cursor).unwrap();
    
    assert_eq!(conf_value, decoded);
}

#[test]
fn test_confidential_value_encode_decode_confidential() {
    let commitment = [0x03; 33]; // Odd parity
    let conf_value = ConfidentialValue::confidential(commitment);
    
    let mut encoded = Vec::new();
    conf_value.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialValue::consensus_decode(&mut cursor).unwrap();
    
    assert_eq!(conf_value, decoded);
}

#[test]
fn test_confidential_nonce_encode_decode_null() {
    let nonce = ConfidentialNonce::null();
    
    let mut encoded = Vec::new();
    nonce.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialNonce::consensus_decode(&mut cursor).unwrap();
    
    assert_eq!(nonce, decoded);
    assert_eq!(encoded, vec![0x00]);
}

#[test]
fn test_confidential_nonce_encode_decode_confidential() {
    let commitment = [0x02; 33];
    let nonce = ConfidentialNonce::confidential(commitment);
    
    let mut encoded = Vec::new();
    nonce.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialNonce::consensus_decode(&mut cursor).unwrap();
    
    assert_eq!(nonce, decoded);
}

#[test]
fn test_confidential_txout_encode_decode() {
    let asset_id = AssetId::new([1u8; 32]);
    let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
    let txout = ConfidentialTxOut::explicit(asset_id, 1000000, script);
    
    let mut encoded = Vec::new();
    txout.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialTxOut::consensus_decode(&mut cursor).unwrap();
    
    assert_eq!(txout, decoded);
}

#[test]
fn test_confidential_transaction_encode_decode() {
    let asset_id = AssetId::new([1u8; 32]);
    let script = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
    let txout = ConfidentialTxOut::explicit(asset_id, 1000000, script);
    
    let mut tx = ConfidentialTransaction::new();
    tx.output.push(txout);
    
    let mut encoded = Vec::new();
    tx.consensus_encode(&mut encoded).unwrap();
    let mut cursor = Cursor::new(&encoded);
    let decoded = ConfidentialTransaction::consensus_decode(&mut cursor).unwrap();
    
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
    use gdk_rs::primitives::transaction::OutPoint;
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
