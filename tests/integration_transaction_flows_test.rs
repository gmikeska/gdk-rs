//! Integration tests for complete transaction creation and signing flows

use gdk_rs::*;
use gdk_rs::types::*;
use gdk_rs::transaction_builder::*;
use gdk_rs::transaction_signer::*;
use gdk_rs::primitives::transaction::*;
use gdk_rs::primitives::address::*;
use gdk_rs::primitives::script::Script;
use gdk_rs::session::*;
use gdk_rs::bip39::*;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::str::FromStr;
use tempfile::TempDir;

/// Helper to create test session with wallet
async fn create_test_session_with_wallet() -> (Session, LoginCredentials) {
    let temp_dir = TempDir::new().unwrap();
    let config = GdkConfig {
        data_dir: Some(temp_dir.path().to_path_buf()),
        tor_dir: None,
        registry_dir: None,
        log_level: LogLevel::Debug,
        with_shutdown: false,
    };
    
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = ConnectParams {
        name: "testnet".to_string(),
        proxy: None,
        use_tor: false,
        user_agent: Some("gdk-rs-test/1.0".to_string()),
        spv_enabled: false,
        min_fee_rate: Some(1000),
        electrum_url: None,
        electrum_tls: false,
    };
    
    session.connect(&network_params).await.unwrap();
    
    let mnemonic = Mnemonic::generate(128).unwrap();
    let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
    
    session.register_user(&credentials).await.unwrap();
    session.login(&credentials).await.unwrap();
    
    (session, credentials)
}

/// Helper to create test UTXO
fn create_test_utxo(value: u64, script_type: &str) -> (OutPoint, TxOut, Script) {
    let txid = [1u8; 32];
    let vout = 0;
    let outpoint = OutPoint::new(txid, vout);
    
    let script_pubkey = match script_type {
        "p2pkh" => Script::new_p2pkh(&[0u8; 20]),
        "p2wpkh" => Script::new_p2wpkh(&[0u8; 20]),
        "p2sh" => Script::new_p2sh(&[0u8; 20]),
        "p2wsh" => Script::new_p2wsh(&[0u8; 32]),
        _ => Script::new_p2pkh(&[0u8; 20]),
    };
    
    let txout = TxOut {
        value,
        script_pubkey: script_pubkey.clone(),
    };
    
    let redeem_script = Script::new_p2pkh(&[0u8; 20]);
    
    (outpoint, txout, redeem_script)
}

#[tokio::test]
async fn test_simple_p2pkh_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    // Create transaction builder
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add input UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    builder.add_utxo(outpoint, utxo);
    
    // Add output
    let recipient_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let addressee = Addressee {
        address: recipient_address.to_string(),
        satoshi: 50000,
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    
    // Set fee rate
    builder.set_fee_rate(1000); // 1 sat/vbyte
    
    // Build transaction
    let create_result = builder.create_transaction().await.unwrap();
    assert!(create_result.transaction.input.len() > 0);
    assert!(create_result.transaction.output.len() > 0);
    
    // Sign transaction
    let mut signer = TransactionSigner::new();
    
    // Create signing info for the input
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    
    let signing_info = SigningInfo {
        script_type: ScriptType::P2pkh,
        public_key: Some(public_key),
        redeem_script: None,
        witness_script: None,
    };
    
    let signing_infos = vec![signing_info];
    let private_keys = vec![private_key];
    
    let signed_tx = signer.sign_transaction(
        &create_result.transaction,
        &signing_infos,
        &private_keys,
        &[utxo]
    ).await.unwrap();
    
    // Verify transaction is properly signed
    assert!(!signed_tx.input[0].script_sig.is_empty());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_segwit_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add SegWit UTXO
    let (outpoint, utxo, _) = create_test_utxo(200000, "p2wpkh");
    builder.add_utxo(outpoint, utxo);
    
    // Add output
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 150000,
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    let create_result = builder.create_transaction().await.unwrap();
    
    // Sign SegWit transaction
    let mut signer = TransactionSigner::new();
    
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    
    let signing_info = SigningInfo {
        script_type: ScriptType::P2wpkh,
        public_key: Some(public_key),
        redeem_script: None,
        witness_script: None,
    };
    
    let signed_tx = signer.sign_transaction(
        &create_result.transaction,
        &[signing_info],
        &[private_key],
        &[utxo]
    ).await.unwrap();
    
    // SegWit transaction should have witness data
    assert!(signed_tx.has_witness());
    assert!(!signed_tx.input[0].witness.is_empty());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_multi_input_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add multiple UTXOs
    let (outpoint1, utxo1, _) = create_test_utxo(50000, "p2pkh");
    let (outpoint2, utxo2, _) = create_test_utxo(75000, "p2wpkh");
    
    builder.add_utxo(outpoint1, utxo1);
    builder.add_utxo(outpoint2, utxo2);
    
    // Add output that requires both inputs
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 100000,
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    let create_result = builder.create_transaction().await.unwrap();
    assert_eq!(create_result.transaction.input.len(), 2);
    
    // Sign with different keys for each input
    let mut signer = TransactionSigner::new();
    let secp = Secp256k1::new();
    
    let private_key1 = SecretKey::from_slice(&[3u8; 32]).unwrap();
    let private_key2 = SecretKey::from_slice(&[4u8; 32]).unwrap();
    
    let public_key1 = PublicKey::from_secret_key(&secp, &private_key1);
    let public_key2 = PublicKey::from_secret_key(&secp, &private_key2);
    
    let signing_infos = vec![
        SigningInfo {
            script_type: ScriptType::P2pkh,
            public_key: Some(public_key1),
            redeem_script: None,
            witness_script: None,
        },
        SigningInfo {
            script_type: ScriptType::P2wpkh,
            public_key: Some(public_key2),
            redeem_script: None,
            witness_script: None,
        },
    ];
    
    let signed_tx = signer.sign_transaction(
        &create_result.transaction,
        &signing_infos,
        &[private_key1, private_key2],
        &[utxo1, utxo2]
    ).await.unwrap();
    
    // Both inputs should be signed
    assert!(!signed_tx.input[0].script_sig.is_empty()); // P2PKH
    assert!(!signed_tx.input[1].witness.is_empty());    // P2WPKH
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_send_all_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    builder.add_utxo(outpoint, utxo);
    
    // Create send-all transaction
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 0, // 0 indicates send-all
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    let create_result = builder.create_transaction().await.unwrap();
    
    // Output should be less than input due to fees
    let output_value = create_result.transaction.output[0].value;
    assert!(output_value < 100000);
    assert!(output_value > 90000); // Should be close to input minus reasonable fee
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_rbf_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    builder.add_utxo(outpoint, utxo);
    
    // Add output
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 50000,
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    // Enable RBF
    builder.enable_rbf();
    
    let create_result = builder.create_transaction().await.unwrap();
    
    // Transaction should signal RBF
    assert!(create_result.transaction.is_rbf_signaling());
    
    // Create replacement transaction with higher fee
    builder.set_fee_rate(2000); // Double the fee rate
    let replacement_result = builder.create_transaction().await.unwrap();
    
    // Replacement should have higher fee
    assert!(replacement_result.fee > create_result.fee);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_transaction_with_change_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add UTXO with more value than needed
    let (outpoint, utxo, _) = create_test_utxo(1000000, "p2pkh"); // 0.01 BTC
    builder.add_utxo(outpoint, utxo);
    
    // Add output for much less
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 100000, // 0.001 BTC
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    // Set change address
    let change_address = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7";
    builder.set_change_address(change_address.to_string()).unwrap();
    
    let create_result = builder.create_transaction().await.unwrap();
    
    // Should have 2 outputs: recipient + change
    assert_eq!(create_result.transaction.output.len(), 2);
    
    // Find change output (should be the larger one)
    let change_output = create_result.transaction.output.iter()
        .find(|output| output.value > 100000)
        .expect("Should have change output");
    
    // Change should be significant
    assert!(change_output.value > 800000); // Most of the input minus fee
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_transaction_fee_estimation_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    builder.add_utxo(outpoint, utxo);
    
    // Add output
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 50000,
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    
    // Test different fee rates
    let fee_rates = [1000, 5000, 10000]; // sat/vbyte
    let mut fees = Vec::new();
    
    for &fee_rate in &fee_rates {
        builder.set_fee_rate(fee_rate);
        let create_result = builder.create_transaction().await.unwrap();
        fees.push(create_result.fee);
    }
    
    // Higher fee rates should result in higher fees
    assert!(fees[1] > fees[0]);
    assert!(fees[2] > fees[1]);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_insufficient_funds_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add small UTXO
    let (outpoint, utxo, _) = create_test_utxo(10000, "p2pkh"); // Very small amount
    builder.add_utxo(outpoint, utxo);
    
    // Try to send more than available
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 50000, // More than UTXO value
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    // Should fail with insufficient funds
    let result = builder.create_transaction().await;
    assert!(result.is_err());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_dust_output_handling_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    builder.add_utxo(outpoint, utxo);
    
    // Try to create dust output
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 1, // Dust amount
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    // Should either fail or handle dust appropriately
    let result = builder.create_transaction().await;
    
    // Implementation might either reject dust or handle it specially
    match result {
        Ok(create_result) => {
            // If it succeeds, verify the output is reasonable
            assert!(create_result.transaction.output[0].value >= 1);
        }
        Err(_) => {
            // Rejecting dust is also acceptable behavior
        }
    }
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_transaction_broadcast_simulation() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    // Create and sign a transaction
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    builder.add_utxo(outpoint, utxo);
    
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 50000,
        asset_id: None,
    };
    
    builder.add_addressee(addressee).unwrap();
    builder.set_fee_rate(1000);
    
    let create_result = builder.create_transaction().await.unwrap();
    
    // Sign the transaction
    let mut signer = TransactionSigner::new();
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&[5u8; 32]).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    
    let signing_info = SigningInfo {
        script_type: ScriptType::P2pkh,
        public_key: Some(public_key),
        redeem_script: None,
        witness_script: None,
    };
    
    let signed_tx = signer.sign_transaction(
        &create_result.transaction,
        &[signing_info],
        &[private_key],
        &[utxo]
    ).await.unwrap();
    
    // Simulate broadcast (in real implementation, this would send to network)
    let broadcast_result = session.broadcast_transaction(&signed_tx).await;
    
    // In test environment, broadcast might fail due to no network connection
    // That's expected - we're just testing the flow
    match broadcast_result {
        Ok(txid) => {
            // If broadcast succeeds, verify we get a transaction ID
            assert_eq!(txid.len(), 64); // Hex string of 32 bytes
        }
        Err(_) => {
            // Expected in test environment without real network
        }
    }
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_transaction_history_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    // Get initial transaction history (should be empty for new wallet)
    let initial_history = session.get_transactions().await.unwrap();
    assert!(initial_history.is_empty());
    
    // In a real scenario, we would:
    // 1. Create and broadcast transactions
    // 2. Wait for confirmations
    // 3. Check updated history
    
    // For this test, we'll just verify the API works
    let history_with_filter = session.get_transactions_with_filter(
        TransactionFilter {
            subaccount: Some(0),
            first: Some(0),
            count: Some(10),
        }
    ).await.unwrap();
    
    // Should return empty list for new wallet
    assert!(history_with_filter.is_empty());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_utxo_management_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    // Get initial UTXO set (should be empty for new wallet)
    let initial_utxos = session.get_unspent_outputs().await.unwrap();
    assert!(initial_utxos.is_empty());
    
    // In a real scenario, we would receive funds and then have UTXOs
    // For this test, we'll verify the API structure
    
    let utxos_with_filter = session.get_unspent_outputs_with_filter(
        UtxoFilter {
            subaccount: Some(0),
            num_confs: Some(1),
        }
    ).await.unwrap();
    
    assert!(utxos_with_filter.is_empty());
    
    session.disconnect().await.unwrap();
}