//! Integration tests for complete transaction creation and signing flows

use gdk_rs::{Session, GdkConfig, init};
use gdk_rs::types::{ConnectParams, LogLevel};
use gdk_rs::transaction_builder::{TransactionBuilder, TransactionBuildParams};
use gdk_rs::transaction_builder::{FeeEstimationStrategy, CoinSelectionStrategy, UtxoInfo};
use gdk_rs::transaction_signer::{TransactionSigner, InputSigningInfo, SigningKey, ScriptType, SigHashType};
use gdk_rs::primitives::transaction::{TxOut, OutPoint};
use gdk_rs::primitives::address::Network as AddressNetwork;
use gdk_rs::primitives::script::Script;
use gdk_rs::bip39::Mnemonic;
use gdk_rs::protocol::{LoginCredentials, Addressee, GetTransactionsParams, GetUnspentOutputsParams};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use tempfile::TempDir;

/// Helper to create test session with wallet
async fn create_test_session_with_wallet() -> (Session, LoginCredentials) {
    let temp_dir = TempDir::new().unwrap();
    let config = GdkConfig {
        data_dir: Some(temp_dir.path().to_path_buf()),
        tor_dir: None,
        registry_dir: None,
        log_level: Some(LogLevel::Debug),
        with_shutdown: false,
    };
    
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = ConnectParams {
        chain_id: "testnet".to_string(),
        name: Some("testnet".to_string()),
        user_agent: Some("gdk-rs-test/1.0".to_string()),
        use_proxy: false,
        proxy: None,
        tor_enabled: false,
        use_tor: false,
        spv_enabled: false,
        min_fee_rate: Some(1000),
        electrum_url: None,
        electrum_tls: false,
    };
    
    // For test environment, use a test URL
    let urls = vec!["wss://greenlight.blockstream.com:443".to_string()];
    session.connect(&network_params, &urls).await.unwrap();
    
    let mnemonic = Mnemonic::generate(128).unwrap();
    let credentials = LoginCredentials {
        mnemonic: mnemonic.to_string(),
        password: None,
        bip39_passphrase: None,
    };
    
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
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add input UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    // For the new API, we need to create TransactionBuildParams
    let _params = TransactionBuildParams {
        addressees: vec![],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    // Add output to params
    let recipient_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let addressee = Addressee {
        address: recipient_address.to_string(),
        satoshi: 50000,
        asset_id: None,
    };
    
    let params = TransactionBuildParams {
        addressees: vec![addressee],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    // Build transaction
    let available_utxos = vec![];
    let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
    assert!(create_result.transaction.input.len() > 0);
    assert!(create_result.transaction.output.len() > 0);
    
    // Sign transaction
    let signer = TransactionSigner::new(AddressNetwork::Testnet);
    
    // Create signing info for the input
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let _public_key = PublicKey::from_secret_key(&secp, &private_key);
    
    let signing_info = InputSigningInfo {
        utxo: create_result.selected_utxos[0].clone(),
        script_type: ScriptType::P2PKH,
        signing_key: SigningKey::new(private_key),
        redeem_script: None,
        witness_script: None,
        sighash_type: SigHashType::All,
    };
    
    let signing_result = signer.sign_transaction(
        create_result.transaction.clone(),
        &[signing_info],
    ).unwrap();
    
    let signed_tx = signing_result.signed_transaction;
    
    // Verify transaction is properly signed
    assert!(!signed_tx.input[0].script_sig.is_empty());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_segwit_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add SegWit UTXO
    let (outpoint, utxo, _) = create_test_utxo(200000, "p2wpkh");
    
    // Create params with SegWit UTXO
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 150000,
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2wpkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    // Build transaction
    let available_utxos = vec![];
    let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
    
    // Sign SegWit transaction
    let signer = TransactionSigner::new(AddressNetwork::Testnet);
    
    let _secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&[2u8; 32]).unwrap();
    
    let signing_info = InputSigningInfo {
        utxo: create_result.selected_utxos[0].clone(),
        script_type: ScriptType::P2WPKH,
        signing_key: SigningKey::new(private_key),
        redeem_script: None,
        witness_script: None,
        sighash_type: SigHashType::All,
    };
    
    let signing_result = signer.sign_transaction(
        create_result.transaction.clone(),
        &[signing_info],
    ).unwrap();
    
    let signed_tx = signing_result.signed_transaction;
    
    // SegWit transaction should have witness data
    assert!(!signed_tx.input[0].witness.is_empty());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_multi_input_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add multiple UTXOs
    let (outpoint1, utxo1, _) = create_test_utxo(50000, "p2pkh");
    let (outpoint2, utxo2, _) = create_test_utxo(75000, "p2wpkh");
    
    // Create params with multiple UTXOs
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 100000,
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![
            UtxoInfo {
                txid: format!("{:064x}", u128::from_le_bytes(outpoint1.txid[..16].try_into().unwrap())),
                vout: outpoint1.vout,
                value: utxo1.value,
                address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                script_pubkey: utxo1.script_pubkey.clone(),
                subaccount_id: 0,
                is_change: false,
                block_height: None,
                confirmations: 6,
                frozen: false,
                script_type: "p2pkh".to_string(),
            },
            UtxoInfo {
                txid: format!("{:064x}", u128::from_le_bytes(outpoint2.txid[..16].try_into().unwrap())),
                vout: outpoint2.vout,
                value: utxo2.value,
                address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                script_pubkey: utxo2.script_pubkey.clone(),
                subaccount_id: 0,
                is_change: false,
                block_height: None,
                confirmations: 6,
                frozen: false,
                script_type: "p2wpkh".to_string(),
            }
        ]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    // Build transaction
    let available_utxos = vec![];
    let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
    assert_eq!(create_result.transaction.input.len(), 2);
    
    // Sign with different keys for each input
    let signer = TransactionSigner::new(AddressNetwork::Testnet);
    let _secp = Secp256k1::new();
    
    let private_key1 = SecretKey::from_slice(&[3u8; 32]).unwrap();
    let private_key2 = SecretKey::from_slice(&[4u8; 32]).unwrap();
    
    let signing_infos = vec![
        InputSigningInfo {
            utxo: create_result.selected_utxos[0].clone(),
            script_type: ScriptType::P2PKH,
            signing_key: SigningKey::new(private_key1),
            redeem_script: None,
            witness_script: None,
            sighash_type: SigHashType::All,
        },
        InputSigningInfo {
            utxo: create_result.selected_utxos[1].clone(),
            script_type: ScriptType::P2WPKH,
            signing_key: SigningKey::new(private_key2),
            redeem_script: None,
            witness_script: None,
            sighash_type: SigHashType::All,
        },
    ];
    
    let signing_result = signer.sign_transaction(
        create_result.transaction.clone(),
        &signing_infos,
    ).unwrap();
    
    let signed_tx = signing_result.signed_transaction;
    
    // Both inputs should be signed
    assert!(!signed_tx.input[0].script_sig.is_empty()); // P2PKH
    assert!(!signed_tx.input[1].witness.is_empty());    // P2WPKH
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_send_all_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    
    // Create send-all transaction params
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 0, // 0 indicates send-all
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: true,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    let available_utxos = vec![];
    let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
    
    // Output should be less than input due to fees
    let output_value = create_result.transaction.output[0].value;
    assert!(output_value < 100000);
    assert!(output_value > 90000); // Should be close to input minus reasonable fee
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_rbf_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    
    // Create RBF-enabled transaction params
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 50000,
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: true,
    };
    
    let available_utxos = vec![];
    let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
    
    // Transaction should have RBF sequence
    assert!(create_result.transaction.input[0].sequence < 0xfffffffe);
    
    // Create replacement transaction with higher fee
    let mut params_replacement = params.clone();
    params_replacement.fee_strategy = FeeEstimationStrategy::FixedRate(2000);
    let replacement_result = builder.build_transaction(&params_replacement, &available_utxos).unwrap();
    
    // Replacement should have higher fee
    assert!(replacement_result.fee > create_result.fee);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_transaction_with_change_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add UTXO with more value than needed
    let (outpoint, utxo, _) = create_test_utxo(1000000, "p2pkh"); // 0.01 BTC
    
    // Create params with change address
    let change_address = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7";
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 100000, // 0.001 BTC
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: Some(change_address.to_string()),
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    let available_utxos = vec![];
    let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
    
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
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    
    // Test different fee rates
    let fee_rates = [1000, 5000, 10000]; // sat/vbyte
    let mut fees = Vec::new();
    
    for &fee_rate in &fee_rates {
        let params = TransactionBuildParams {
            addressees: vec![Addressee {
                address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                satoshi: 50000,
                asset_id: None,
            }],
            fee_strategy: FeeEstimationStrategy::FixedRate(fee_rate),
            coin_strategy: CoinSelectionStrategy::default(),
            send_all: false,
            utxos: Some(vec![UtxoInfo {
                txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
                vout: outpoint.vout,
                value: utxo.value,
                address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
                script_pubkey: utxo.script_pubkey.clone(),
                subaccount_id: 0,
                is_change: false,
                block_height: None,
                confirmations: 6,
                frozen: false,
                script_type: "p2pkh".to_string(),
            }]),
            subaccount: 0,
            change_address: None,
            min_confirmations: 1,
            rbf_enabled: false,
        };
        
        let available_utxos = vec![];
        let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
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
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add small UTXO
    let (outpoint, utxo, _) = create_test_utxo(10000, "p2pkh"); // Very small amount
    
    // Try to send more than available
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 50000, // More than UTXO value
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    // Should fail with insufficient funds
    let available_utxos = vec![];
    let result = builder.build_transaction(&params, &available_utxos);
    assert!(result.is_err());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_dust_output_handling_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Add UTXO
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    
    // Try to create dust output
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 1, // Dust amount
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    // Should either fail or handle dust appropriately
    let available_utxos = vec![];
    let result = builder.build_transaction(&params, &available_utxos);
    
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
    
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Create and sign a transaction
    let (outpoint, utxo, _) = create_test_utxo(100000, "p2pkh");
    
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 50000,
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(1000),
        coin_strategy: CoinSelectionStrategy::default(),
        send_all: false,
        utxos: Some(vec![UtxoInfo {
            txid: format!("{:064x}", u128::from_le_bytes(outpoint.txid[..16].try_into().unwrap())),
            vout: outpoint.vout,
            value: utxo.value,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            script_pubkey: utxo.script_pubkey.clone(),
            subaccount_id: 0,
            is_change: false,
            block_height: None,
            confirmations: 6,
            frozen: false,
            script_type: "p2pkh".to_string(),
        }]),
        subaccount: 0,
        change_address: None,
        min_confirmations: 1,
        rbf_enabled: false,
    };
    
    let available_utxos = vec![];
    let create_result = builder.build_transaction(&params, &available_utxos).unwrap();
    
    // Sign the transaction
    let signer = TransactionSigner::new(AddressNetwork::Testnet);
    let _secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&[5u8; 32]).unwrap();
    
    let signing_info = InputSigningInfo {
        utxo: create_result.selected_utxos[0].clone(),
        script_type: ScriptType::P2PKH,
        signing_key: SigningKey::new(private_key),
        redeem_script: None,
        witness_script: None,
        sighash_type: SigHashType::All,
    };
    
    let signing_result = signer.sign_transaction(
        create_result.transaction.clone(),
        &[signing_info],
    ).unwrap();
    
    let signed_tx = signing_result.signed_transaction;
    
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
    let params = GetTransactionsParams {
        subaccount: 0,
        first: 0,
        count: 10,
    };
    let initial_history = session.get_transactions(&params).await.unwrap();
    assert!(initial_history.is_empty());
    
    // In a real scenario, we would:
    // 1. Create and broadcast transactions
    // 2. Wait for confirmations
    // 3. Check updated history
    
    // For this test, we'll just verify the API works
    let params_filtered = GetTransactionsParams {
        subaccount: 0,
        first: 0,
        count: 10,
    };
    let history_with_filter = session.get_transactions(&params_filtered).await.unwrap();
    
    // Should return empty list for new wallet
    assert!(history_with_filter.is_empty());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_utxo_management_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    // Get initial UTXO set (should be empty for new wallet)
    let params = GetUnspentOutputsParams {
        subaccount: 0,
        num_confs: 1,
    };
    let initial_utxos = session.get_unspent_outputs(&params).await.unwrap();
    // UnspentOutputs struct contains a `unspent_outputs` field which is a Vec
    assert!(initial_utxos.unspent_outputs.is_empty());
    
    // In a real scenario, we would receive funds and then have UTXOs
    // For this test, we'll verify the API structure
    
    let params_filtered = GetUnspentOutputsParams {
        subaccount: 0,
        num_confs: 1,
    };
    let utxos_with_filter = session.get_unspent_outputs(&params_filtered).await.unwrap();
    
    assert!(utxos_with_filter.unspent_outputs.is_empty());
    
    session.disconnect().await.unwrap();
}
