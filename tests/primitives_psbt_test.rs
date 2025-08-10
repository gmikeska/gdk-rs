use gdk_rs::*;
use gdk_rs::primitives::psbt::*;
use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
use gdk_rs::primitives::script::Script;
use gdk_rs::primitives::bip32::{DerivationPath, Fingerprint};
use secp256k1::{Secp256k1, SecretKey};
use std::str::FromStr;

fn create_test_transaction() -> Transaction {
    Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint::new([1u8; 32], 0),
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: Vec::new(),
            },
        ],
        output: vec![
            TxOut {
                value: 1000000,
                script_pubkey: Script::from_bytes(vec![0x76, 0xa9, 0x14]),
            },
        ],
    }
}

#[test]
fn test_psbt_creation() {
    let tx = create_test_transaction();
    let psbt = PartiallySignedTransaction::new(tx.clone()).unwrap();

    assert_eq!(psbt.unsigned_tx().unwrap(), &tx);
    assert_eq!(psbt.inputs.len(), 1);
    assert_eq!(psbt.outputs.len(), 1);
    assert!(!psbt.is_complete());
}

#[test]
fn test_psbt_validation() {
    let tx = create_test_transaction();
    let psbt = PartiallySignedTransaction::new(tx).unwrap();

    // Should validate successfully
    assert!(psbt.validate().is_ok());

    // Test with invalid transaction (non-empty scriptSig)
    let mut invalid_tx = create_test_transaction();
    invalid_tx.input[0].script_sig = Script::from_bytes(vec![0x01, 0x02]);
    let invalid_psbt = PartiallySignedTransaction::new(invalid_tx).unwrap();
    assert!(invalid_psbt.validate().is_err());
}

#[test]
fn test_add_signature() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = secret_key.public_key(&secp);
    let signature = vec![0x30, 0x44, 0x02, 0x20]; // Dummy signature

    // Add signature to input 0
    psbt.add_signature(0, public_key, signature.clone()).unwrap();

    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);
    assert_eq!(psbt.inputs[0].partial_sigs.get(&public_key), Some(&signature));

    // Test invalid input index
    assert!(psbt.add_signature(1, public_key, signature).is_err());
}

#[test]
fn test_psbt_combine() {
    let tx = create_test_transaction();
    let mut psbt1 = PartiallySignedTransaction::new(tx.clone()).unwrap();
    let mut psbt2 = PartiallySignedTransaction::new(tx).unwrap();

    let secp = Secp256k1::new();
    let secret_key1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key1 = secret_key1.public_key(&secp);
    let signature1 = vec![0x30, 0x44, 0x02, 0x20];

    let secret_key2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let public_key2 = secret_key2.public_key(&secp);
    let signature2 = vec![0x30, 0x45, 0x02, 0x21];

    // Add different signatures to each PSBT
    psbt1.add_signature(0, public_key1, signature1.clone()).unwrap();
    psbt2.add_signature(0, public_key2, signature2.clone()).unwrap();

    // Combine PSBTs
    psbt1.combine(&psbt2).unwrap();

    // Should have both signatures
    assert_eq!(psbt1.inputs[0].partial_sigs.len(), 2);
    assert_eq!(psbt1.inputs[0].partial_sigs.get(&public_key1), Some(&signature1));
    assert_eq!(psbt1.inputs[0].partial_sigs.get(&public_key2), Some(&signature2));
}

#[test]
fn test_psbt_combine_different_transactions() {
    let tx1 = create_test_transaction();
    let mut tx2 = create_test_transaction();
    tx2.version = 1; // Make it different

    let psbt1 = PartiallySignedTransaction::new(tx1).unwrap();
    let mut psbt2 = PartiallySignedTransaction::new(tx2).unwrap();

    // Should fail to combine PSBTs with different transactions
    assert!(psbt2.combine(&psbt1).is_err());
}

#[test]
fn test_finalize_input() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = secret_key.public_key(&secp);
    let signature = vec![0x30, 0x44, 0x02, 0x20];

    // Add signature
    psbt.add_signature(0, public_key, signature).unwrap();
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 1);

    // Finalize input
    psbt.finalize_input(0).unwrap();

    // Should have final scripts and no partial signatures
    assert!(psbt.inputs[0].final_script_sig.is_some());
    assert!(psbt.inputs[0].final_script_witness.is_some());
    assert_eq!(psbt.inputs[0].partial_sigs.len(), 0);

    // Test invalid input index
    assert!(psbt.finalize_input(1).is_err());
}

#[test]
fn test_is_complete_and_extract_tx() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx.clone()).unwrap();

    // Initially not complete
    assert!(!psbt.is_complete());
    assert!(psbt.extract_tx().is_err());

    // Add final scripts to make it complete
    psbt.inputs[0].final_script_sig = Some(Script::from_bytes(vec![0x01, 0x02]));
    psbt.inputs[0].final_script_witness = Some(vec![vec![0x03, 0x04]]);

    // Now should be complete
    assert!(psbt.is_complete());

    let final_tx = psbt.extract_tx().unwrap();
    assert_eq!(final_tx.version, tx.version);
    assert_eq!(final_tx.input.len(), tx.input.len());
    assert_eq!(final_tx.output.len(), tx.output.len());
    assert_eq!(final_tx.input[0].script_sig.as_bytes(), &[0x01, 0x02]);
    assert_eq!(final_tx.input[0].witness, vec![vec![0x03, 0x04]]);
}

#[test]
fn test_psbt_serialization_roundtrip() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    // Add some data to make it more interesting
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = secret_key.public_key(&secp);
    let signature = vec![0x30, 0x44, 0x02, 0x20];

    psbt.add_signature(0, public_key, signature).unwrap();
    psbt.inputs[0].sighash_type = Some(0x01);
    psbt.inputs[0].redeem_script = Some(Script::from_bytes(vec![0x51])); // OP_1
    psbt.global.version = Some(0);

    // Serialize
    let serialized = psbt.serialize().unwrap();
    assert!(!serialized.is_empty());

    // Check magic bytes
    assert_eq!(&serialized[0..4], b"psbt");
    assert_eq!(serialized[4], 0xff);

    // Deserialize
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    // Should be equal
    assert_eq!(psbt.global.unsigned_tx, deserialized.global.unsigned_tx);
    assert_eq!(psbt.global.version, deserialized.global.version);
    assert_eq!(psbt.inputs.len(), deserialized.inputs.len());
    assert_eq!(psbt.outputs.len(), deserialized.outputs.len());
    assert_eq!(psbt.inputs[0].partial_sigs, deserialized.inputs[0].partial_sigs);
    assert_eq!(psbt.inputs[0].sighash_type, deserialized.inputs[0].sighash_type);
    assert_eq!(psbt.inputs[0].redeem_script, deserialized.inputs[0].redeem_script);
}

#[test]
fn test_psbt_deserialization_invalid_magic() {
    let invalid_data = b"xxxx\xff";
    assert!(PartiallySignedTransaction::deserialize(invalid_data).is_err());
}

#[test]
fn test_psbt_deserialization_invalid_separator() {
    let invalid_data = b"psbt\x00";
    assert!(PartiallySignedTransaction::deserialize(invalid_data).is_err());
}

#[test]
fn test_bip32_derivation() {
    let fingerprint = Fingerprint([0x01, 0x02, 0x03, 0x04]);
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    
    let derivation = Bip32Derivation {
        fingerprint,
        path: path.clone(),
    };

    assert_eq!(derivation.fingerprint.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(derivation.path.to_string(), "m/44'/0'/0'/0/0");
}

#[test]
fn test_psbt_with_witness_utxo() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    let witness_utxo = TxOut {
        value: 5000000,
        script_pubkey: Script::from_bytes(vec![0x00, 0x14]), // P2WPKH
    };

    psbt.inputs[0].witness_utxo = Some(witness_utxo.clone());

    // Test serialization roundtrip
    let serialized = psbt.serialize().unwrap();
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    assert_eq!(deserialized.inputs[0].witness_utxo, Some(witness_utxo));
}

#[test]
fn test_psbt_with_scripts() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    let redeem_script = Script::from_bytes(vec![0x51, 0x52, 0x53]); // OP_1 OP_2 OP_3
    let witness_script = Script::from_bytes(vec![0x54, 0x55]); // OP_4 OP_5

    psbt.inputs[0].redeem_script = Some(redeem_script.clone());
    psbt.inputs[0].witness_script = Some(witness_script.clone());
    psbt.outputs[0].redeem_script = Some(redeem_script.clone());
    psbt.outputs[0].witness_script = Some(witness_script.clone());

    // Test serialization roundtrip
    let serialized = psbt.serialize().unwrap();
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    assert_eq!(deserialized.inputs[0].redeem_script, Some(redeem_script.clone()));
    assert_eq!(deserialized.inputs[0].witness_script, Some(witness_script.clone()));
    assert_eq!(deserialized.outputs[0].redeem_script, Some(redeem_script));
    assert_eq!(deserialized.outputs[0].witness_script, Some(witness_script));
}

#[test]
fn test_psbt_proprietary_fields() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    // Add proprietary fields
    psbt.global.proprietary.insert(b"test_key".to_vec(), b"test_value".to_vec());
    psbt.inputs[0].proprietary.insert(b"input_key".to_vec(), b"input_value".to_vec());
    psbt.outputs[0].proprietary.insert(b"output_key".to_vec(), b"output_value".to_vec());

    // Test serialization roundtrip
    let serialized = psbt.serialize().unwrap();
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    assert_eq!(
        deserialized.global.proprietary.get(b"test_key".as_slice()),
        Some(&b"test_value".to_vec())
    );
    assert_eq!(
        deserialized.inputs[0].proprietary.get(b"input_key".as_slice()),
        Some(&b"input_value".to_vec())
    );
    assert_eq!(
        deserialized.outputs[0].proprietary.get(b"output_key".as_slice()),
        Some(&b"output_value".to_vec())
    );
}

#[test]
fn test_psbt_unknown_fields() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    // Add unknown fields
    psbt.global.unknown.insert(vec![0x99], b"global_unknown".to_vec());
    psbt.inputs[0].unknown.insert(vec![0x98], b"input_unknown".to_vec());
    psbt.outputs[0].unknown.insert(vec![0x97], b"output_unknown".to_vec());

    // Test serialization roundtrip
    let serialized = psbt.serialize().unwrap();
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    assert_eq!(
        deserialized.global.unknown.get(&vec![0x99]),
        Some(&b"global_unknown".to_vec())
    );
    assert_eq!(
        deserialized.inputs[0].unknown.get(&vec![0x98]),
        Some(&b"input_unknown".to_vec())
    );
    assert_eq!(
        deserialized.outputs[0].unknown.get(&vec![0x97]),
        Some(&b"output_unknown".to_vec())
    );
}

#[test]
fn test_psbt_final_witness_serialization() {
    let tx = create_test_transaction();
    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    let witness = vec![
        vec![0x30, 0x44, 0x02, 0x20], // signature
        vec![0x03, 0x21], // pubkey
    ];

    psbt.inputs[0].final_script_witness = Some(witness.clone());

    // Test serialization roundtrip
    let serialized = psbt.serialize().unwrap();
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    assert_eq!(deserialized.inputs[0].final_script_witness, Some(witness));
}

#[test]
fn test_empty_psbt_serialization() {
    let tx = Transaction::new();
    let psbt = PartiallySignedTransaction::new(tx).unwrap();

    let serialized = psbt.serialize().unwrap();
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    assert_eq!(psbt.inputs.len(), deserialized.inputs.len());
    assert_eq!(psbt.outputs.len(), deserialized.outputs.len());
}

#[test]
fn test_psbt_multiple_inputs_outputs() {
    let mut tx = Transaction::new();
    tx.input = vec![
        TxIn::new(OutPoint::new([1u8; 32], 0), Script::new(), 0xffffffff),
        TxIn::new(OutPoint::new([2u8; 32], 1), Script::new(), 0xfffffffe),
    ];
    tx.output = vec![
        TxOut::new(1000000, Script::from_bytes(vec![0x76, 0xa9])),
        TxOut::new(2000000, Script::from_bytes(vec![0x00, 0x14])),
        TxOut::new(3000000, Script::from_bytes(vec![0x51])),
    ];

    let mut psbt = PartiallySignedTransaction::new(tx).unwrap();

    assert_eq!(psbt.inputs.len(), 2);
    assert_eq!(psbt.outputs.len(), 3);

    // Add data to different inputs/outputs
    let secp = Secp256k1::new();
    let secret_key1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key1 = secret_key1.public_key(&secp);
    let secret_key2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let public_key2 = secret_key2.public_key(&secp);

    psbt.add_signature(0, public_key1, vec![0x30, 0x44]).unwrap();
    psbt.add_signature(1, public_key2, vec![0x30, 0x45]).unwrap();

    psbt.inputs[0].sighash_type = Some(0x01);
    psbt.inputs[1].sighash_type = Some(0x02);

    psbt.outputs[0].redeem_script = Some(Script::from_bytes(vec![0x51]));
    psbt.outputs[2].witness_script = Some(Script::from_bytes(vec![0x52]));

    // Test serialization roundtrip
    let serialized = psbt.serialize().unwrap();
    let deserialized = PartiallySignedTransaction::deserialize(&serialized).unwrap();

    assert_eq!(deserialized.inputs.len(), 2);
    assert_eq!(deserialized.outputs.len(), 3);
    assert_eq!(deserialized.inputs[0].partial_sigs.len(), 1);
    assert_eq!(deserialized.inputs[1].partial_sigs.len(), 1);
    assert_eq!(deserialized.inputs[0].sighash_type, Some(0x01));
    assert_eq!(deserialized.inputs[1].sighash_type, Some(0x02));
    assert!(deserialized.outputs[0].redeem_script.is_some());
    assert!(deserialized.outputs[2].witness_script.is_some());
}
