use gdk_rs::primitives::transaction::*;
use gdk_rs::primitives::script::Script;
use gdk_rs::primitives::encode::{Encodable, Decodable};
use std::io::Cursor;

#[test]
fn test_legacy_transaction_encode_decode_roundtrip() {
    // A simple legacy transaction
    let tx = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: [1; 32], // Dummy txid
                vout: 0,
            },
            script_sig: Script(vec![0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 <20 bytes>
            sequence: 0xffffffff,
            witness: Vec::new(),
        }],
        output: vec![
            TxOut {
                value: 10000000,
                script_pubkey: Script(vec![0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 <20 bytes>
            },
        ],
    };

    // Test encoding
    let mut encoded = Vec::new();
    tx.consensus_encode(&mut encoded).unwrap();
    assert!(!encoded.is_empty());

    // Test decoding
    let mut cursor = Cursor::new(&encoded);
    let decoded = Transaction::consensus_decode(&mut cursor).unwrap();
    assert_eq!(tx, decoded);
    
    // Verify it's not a witness transaction
    assert!(!tx.has_witness());
    assert!(!decoded.has_witness());
}

#[test]
fn test_witness_transaction_encode_decode_roundtrip() {
    // A witness transaction
    let mut tx = Transaction {
        version: 2,
        lock_time: 500000,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: [2; 32], // Dummy txid
                vout: 1,
            },
            script_sig: Script(vec![]), // Empty script_sig for witness input
            sequence: 0xfffffffe,
            witness: vec![
                vec![0x30, 0x44, 0x02, 0x20], // Dummy signature
                vec![0x03, 0x21], // Dummy pubkey
            ],
        }],
        output: vec![
            TxOut {
                value: 5000000,
                script_pubkey: Script(vec![0x00, 0x14]), // OP_0 <20 bytes> (P2WPKH)
            },
            TxOut {
                value: 4999000,
                script_pubkey: Script(vec![0x76, 0xa9, 0x14]), // OP_DUP OP_HASH160 <20 bytes>
            },
        ],
    };

    // Test encoding
    let mut encoded = Vec::new();
    tx.consensus_encode(&mut encoded).unwrap();
    assert!(!encoded.is_empty());

    // Test decoding
    let mut cursor = Cursor::new(&encoded);
    let decoded = Transaction::consensus_decode(&mut cursor).unwrap();
    assert_eq!(tx, decoded);
    
    // Verify it's a witness transaction
    assert!(tx.has_witness());
    assert!(decoded.has_witness());
    assert_eq!(decoded.input[0].witness.len(), 2);
}

#[test]
fn test_transaction_ids() {
    // Create a witness transaction
    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: [3; 32],
                vout: 0,
            },
            script_sig: Script(vec![]),
            sequence: 0xffffffff,
            witness: vec![
                vec![0x01, 0x02, 0x03], // Some witness data
            ],
        }],
        output: vec![
            TxOut {
                value: 1000000,
                script_pubkey: Script(vec![0x00, 0x14]), // P2WPKH
            },
        ],
    };

    let txid = tx.txid();
    let wtxid = tx.wtxid();
    
    // For witness transactions, txid and wtxid should be different
    assert_ne!(txid, wtxid);
    
    // Both should be valid 32-byte hashes
    assert_eq!(txid.len(), 32);
    assert_eq!(wtxid.len(), 32);
}

#[test]
fn test_legacy_transaction_ids_equal() {
    // Create a legacy transaction (no witness data)
    let tx = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: [4; 32],
                vout: 0,
            },
            script_sig: Script(vec![0x76, 0xa9]),
            sequence: 0xffffffff,
            witness: Vec::new(), // No witness data
        }],
        output: vec![
            TxOut {
                value: 1000000,
                script_pubkey: Script(vec![0x76, 0xa9, 0x14]),
            },
        ],
    };

    let txid = tx.txid();
    let wtxid = tx.wtxid();
    
    // For legacy transactions, txid and wtxid should be the same
    assert_eq!(txid, wtxid);
}

#[test]
fn test_outpoint_null() {
    let null_outpoint = OutPoint::null();
    assert!(null_outpoint.is_null());
    assert_eq!(null_outpoint.txid, [0; 32]);
    assert_eq!(null_outpoint.vout, 0xffffffff);
    
    let normal_outpoint = OutPoint::new([1; 32], 0);
    assert!(!normal_outpoint.is_null());
}

#[test]
fn test_script_operations() {
    let script = Script::new();
    assert!(script.is_empty());
    assert_eq!(script.len(), 0);
    
    let script_with_data = Script::from_bytes(vec![0x76, 0xa9, 0x14]);
    assert!(!script_with_data.is_empty());
    assert_eq!(script_with_data.len(), 3);
    assert_eq!(script_with_data.as_bytes(), &[0x76, 0xa9, 0x14]);
}

// Tests for witness encoding/decoding are internal implementation details
// and are tested through the transaction encode/decode tests above
