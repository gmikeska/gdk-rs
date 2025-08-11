//! Comprehensive unit tests for transaction builder functionality

use gdk_rs::transaction_builder::*;
use gdk_rs::primitives::transaction::*;
use gdk_rs::primitives::script::Script;
use gdk_rs::primitives::address::Network;

#[test]
fn test_transaction_builder_new() {
    let builder = TransactionBuilder::new(Network::Mainnet);
    
    assert_eq!(builder.network(), Network::Mainnet);
    assert_eq!(builder.inputs().len(), 0);
    assert_eq!(builder.outputs().len(), 0);
    assert!(builder.fee_rate().is_none());
}

#[test]
fn test_transaction_builder_add_input() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    
    builder.add_input(outpoint, script_sig.clone());
    
    assert_eq!(builder.inputs().len(), 1);
    assert_eq!(builder.inputs()[0].previous_output, outpoint);
    assert_eq!(builder.inputs()[0].script_sig, script_sig);
    assert_eq!(builder.inputs()[0].sequence, 0xffffffff);
}

#[test]
fn test_transaction_builder_add_input_with_sequence() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    let sequence = 0x12345678;
    
    builder.add_input_with_sequence(outpoint, script_sig.clone(), sequence);
    
    assert_eq!(builder.inputs().len(), 1);
    assert_eq!(builder.inputs()[0].sequence, sequence);
}

#[test]
fn test_transaction_builder_add_output() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    
    builder.add_output(value, script_pubkey.clone());
    
    assert_eq!(builder.outputs().len(), 1);
    assert_eq!(builder.outputs()[0].value, value);
    assert_eq!(builder.outputs()[0].script_pubkey, script_pubkey);
}

#[test]
fn test_transaction_builder_set_fee_rate() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    let fee_rate = 10; // sat/vbyte
    builder.set_fee_rate(fee_rate);
    
    assert_eq!(builder.fee_rate(), Some(fee_rate));
}

#[test]
fn test_transaction_builder_set_lock_time() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    let lock_time = 500000;
    builder.set_lock_time(lock_time);
    
    assert_eq!(builder.lock_time(), lock_time);
}

#[test]
fn test_transaction_builder_build_simple() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    // Add output
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    let tx = builder.build().unwrap();
    
    assert_eq!(tx.version, 2);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.lock_time, 0);
}

#[test]
fn test_transaction_builder_build_empty_inputs() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add output but no inputs
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    let result = builder.build();
    assert!(result.is_err());
}

#[test]
fn test_transaction_builder_build_empty_outputs() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input but no outputs
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let result = builder.build();
    assert!(result.is_err());
}

#[test]
fn test_transaction_builder_multiple_inputs_outputs() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add multiple inputs
    for i in 0..3 {
        let mut txid = [0; 32];
        txid[0] = i as u8;
        let outpoint = OutPoint::new(txid, i);
        let script_sig = Script::new();
        builder.add_input(outpoint, script_sig);
    }
    
    // Add multiple outputs
    for i in 0..2 {
        let value = 50000 + (i as u64 * 10000);
        let mut hash = [0; 20];
        hash[0] = i as u8;
        let script_pubkey = Script::new_p2pkh(&hash);
        builder.add_output(value, script_pubkey);
    }
    
    let tx = builder.build().unwrap();
    
    assert_eq!(tx.input.len(), 3);
    assert_eq!(tx.output.len(), 2);
    
    // Verify input ordering is preserved
    for i in 0..3 {
        assert_eq!(tx.input[i].previous_output.vout, i);
    }
    
    // Verify output values
    assert_eq!(tx.output[0].value, 50000);
    assert_eq!(tx.output[1].value, 60000);
}

#[test]
fn test_transaction_builder_with_witness() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input with witness data
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new(); // Empty for witness input
    builder.add_input(outpoint, script_sig);
    
    // Add witness data
    let witness_data = vec![
        vec![0x30, 0x44], // Signature
        vec![0x03, 0x21], // Public key
    ];
    builder.add_witness(0, witness_data.clone()).unwrap();
    
    // Add output
    let value = 100000;
    let script_pubkey = Script::new_p2wpkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    let tx = builder.build().unwrap();
    
    assert!(tx.has_witness());
    assert_eq!(tx.input[0].witness, witness_data);
}

#[test]
fn test_transaction_builder_add_witness_invalid_index() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    let witness_data = vec![vec![0x30, 0x44]];
    let result = builder.add_witness(0, witness_data);
    
    // Should fail because no inputs exist yet
    assert!(result.is_err());
}

#[test]
fn test_transaction_builder_clear() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add some data
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    builder.set_fee_rate(10);
    builder.set_lock_time(500000);
    
    // Clear everything
    builder.clear();
    
    assert_eq!(builder.inputs().len(), 0);
    assert_eq!(builder.outputs().len(), 0);
    assert!(builder.fee_rate().is_none());
    assert_eq!(builder.lock_time(), 0);
}

#[test]
fn test_transaction_builder_estimate_size() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add P2PKH input (estimated size)
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    // Add P2PKH output
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    let estimated_size = builder.estimate_size();
    
    // P2PKH transaction should be around 192 bytes
    assert!(estimated_size > 180);
    assert!(estimated_size < 220);
}

#[test]
fn test_transaction_builder_estimate_fee() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input and output
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    // Set fee rate
    let fee_rate = 10; // sat/vbyte
    builder.set_fee_rate(fee_rate);
    
    let estimated_fee = builder.estimate_fee().unwrap();
    let estimated_size = builder.estimate_size();
    
    // Fee should be approximately size * fee_rate
    let expected_fee = estimated_size * fee_rate;
    assert!((estimated_fee as i64 - expected_fee as i64).abs() < 100);
}

#[test]
fn test_transaction_builder_estimate_fee_no_rate() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input and output but no fee rate
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    let result = builder.estimate_fee();
    assert!(result.is_err());
}

#[test]
fn test_transaction_builder_different_script_types() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    // Add different output types
    builder.add_output(25000, Script::new_p2pkh(&[1; 20]));           // P2PKH
    builder.add_output(25000, Script::new_p2sh(&[2; 20]));            // P2SH
    builder.add_output(25000, Script::new_p2wpkh(&[3; 20]));          // P2WPKH
    builder.add_output(25000, Script::new_p2wsh(&[4; 32]));           // P2WSH
    
    let tx = builder.build().unwrap();
    
    assert_eq!(tx.output.len(), 4);
    assert!(tx.output[0].script_pubkey.is_p2pkh());
    assert!(tx.output[1].script_pubkey.is_p2sh());
    assert!(tx.output[2].script_pubkey.is_p2wpkh());
    assert!(tx.output[3].script_pubkey.is_p2wsh());
}

#[test]
fn test_transaction_builder_version_setting() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add minimal transaction
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    // Test different versions
    builder.set_version(1);
    let tx_v1 = builder.build().unwrap();
    assert_eq!(tx_v1.version, 1);
    
    builder.set_version(2);
    let tx_v2 = builder.build().unwrap();
    assert_eq!(tx_v2.version, 2);
}

#[test]
fn test_transaction_builder_rbf_signaling() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input with RBF sequence
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    let rbf_sequence = 0xfffffffd; // Signals RBF
    builder.add_input_with_sequence(outpoint, script_sig, rbf_sequence);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    let tx = builder.build().unwrap();
    
    assert_eq!(tx.input[0].sequence, rbf_sequence);
    assert!(tx.is_rbf_signaling());
}

#[test]
fn test_transaction_builder_timelock() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    // Set timelock
    let lock_time = 500000; // Block height
    builder.set_lock_time(lock_time);
    
    let tx = builder.build().unwrap();
    
    assert_eq!(tx.lock_time, lock_time);
}

#[test]
fn test_transaction_builder_dust_output() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    // Add dust output (very small value)
    let dust_value = 1; // 1 satoshi
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(dust_value, script_pubkey);
    
    // Should still build (dust checking is policy, not consensus)
    let tx = builder.build().unwrap();
    assert_eq!(tx.output[0].value, dust_value);
}

#[test]
fn test_transaction_builder_large_transaction() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add many inputs
    for i in 0..100 {
        let mut txid = [0; 32];
        txid[0] = (i % 256) as u8;
        txid[1] = (i / 256) as u8;
        let outpoint = OutPoint::new(txid, i % 4);
        let script_sig = Script::new();
        builder.add_input(outpoint, script_sig);
    }
    
    // Add many outputs
    for i in 0..50 {
        let value = 1000 + i as u64;
        let mut hash = [0; 20];
        hash[0] = (i % 256) as u8;
        let script_pubkey = Script::new_p2pkh(&hash);
        builder.add_output(value, script_pubkey);
    }
    
    let tx = builder.build().unwrap();
    
    assert_eq!(tx.input.len(), 100);
    assert_eq!(tx.output.len(), 50);
    
    // Verify the transaction is quite large
    let estimated_size = builder.estimate_size();
    assert!(estimated_size > 10000); // Should be over 10KB
}

#[test]
fn test_transaction_builder_zero_value_output() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add input
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    // Add zero-value output (OP_RETURN)
    let zero_value = 0;
    let op_return_script = Script::new_op_return(b"Hello, Bitcoin!");
    builder.add_output(zero_value, op_return_script);
    
    let tx = builder.build().unwrap();
    assert_eq!(tx.output[0].value, 0);
    assert!(tx.output[0].script_pubkey.is_op_return());
}

#[test]
fn test_transaction_builder_witness_size_estimation() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add witness input
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    // Add witness data
    let witness_data = vec![
        vec![0; 72], // Signature (72 bytes)
        vec![0; 33], // Public key (33 bytes)
    ];
    builder.add_witness(0, witness_data).unwrap();
    
    // Add output
    let value = 100000;
    let script_pubkey = Script::new_p2wpkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    let estimated_size = builder.estimate_size();
    let estimated_vsize = builder.estimate_vsize();
    
    // Witness transaction should have different size vs vsize
    assert!(estimated_vsize <= estimated_size);
    assert!(estimated_vsize > 0);
}

#[test]
fn test_transaction_builder_reset() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Build up a transaction
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    builder.set_fee_rate(10);
    builder.set_lock_time(500000);
    
    // Reset to different network
    builder.reset(Network::Testnet);
    
    assert_eq!(builder.network(), Network::Testnet);
    assert_eq!(builder.inputs().len(), 0);
    assert_eq!(builder.outputs().len(), 0);
    assert!(builder.fee_rate().is_none());
    assert_eq!(builder.lock_time(), 0);
}

#[test]
fn test_transaction_builder_clone() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    // Add some data
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let value = 100000;
    let script_pubkey = Script::new_p2pkh(&[0; 20]);
    builder.add_output(value, script_pubkey);
    
    builder.set_fee_rate(10);
    
    // Clone the builder
    let cloned_builder = builder.clone();
    
    assert_eq!(builder.network(), cloned_builder.network());
    assert_eq!(builder.inputs().len(), cloned_builder.inputs().len());
    assert_eq!(builder.outputs().len(), cloned_builder.outputs().len());
    assert_eq!(builder.fee_rate(), cloned_builder.fee_rate());
}

#[test]
fn test_transaction_builder_debug() {
    let mut builder = TransactionBuilder::new(Network::Mainnet);
    
    let outpoint = OutPoint::new([1; 32], 0);
    let script_sig = Script::new();
    builder.add_input(outpoint, script_sig);
    
    let debug_str = format!("{:?}", builder);
    assert!(debug_str.contains("TransactionBuilder"));
    assert!(debug_str.contains("Mainnet"));
}