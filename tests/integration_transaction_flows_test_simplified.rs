//! Simplified integration tests for transaction flows

use gdk_rs::*;
use gdk_rs::types::*;
use gdk_rs::transaction_builder::*;
use gdk_rs::transaction_signer::*;
use gdk_rs::primitives::transaction::*;
use gdk_rs::primitives::address::Network as AddressNetwork;
use gdk_rs::primitives::script::Script;
use gdk_rs::session::Session;
use gdk_rs::bip39::*;
use gdk_rs::protocol::{
    LoginCredentials as ProtocolLoginCredentials, 
    Addressee, 
    GetTransactionsParams, 
    GetUnspentOutputsParams,
};
use secp256k1::{Secp256k1, SecretKey};
use tempfile::TempDir;

/// Helper to create test session with wallet
async fn create_test_session_with_wallet() -> (Session, ProtocolLoginCredentials) {
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
        name: Some("testnet".to_string()),
        proxy: None,
        use_tor: false,
        tor_enabled: false,
        use_proxy: false,
        user_agent: Some("gdk-rs-test/1.0".to_string()),
        spv_enabled: false,
        min_fee_rate: Some(1000),
        electrum_url: None,
        electrum_tls: false,
        chain_id: "bitcoin".to_string(),
    };
    
    // For test environment, use empty URLs
    let urls: Vec<String> = vec![];
    session.connect(&network_params, &urls).await.unwrap();
    
    let mnemonic = Mnemonic::generate(128).unwrap();
    let credentials = ProtocolLoginCredentials {
        mnemonic: mnemonic.to_string(),
        password: None,
        bip39_passphrase: None,
    };
    
    session.register_user(&credentials).await.unwrap();
    session.login(&credentials).await.unwrap();
    
    (session, credentials)
}

/// Helper to create test UTXO
fn create_test_utxo(value: u64, script_type: &str) -> (OutPoint, TxOut, UtxoInfo) {
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
    
    let utxo_info = UtxoInfo {
        txid: hex::encode(txid),
        vout,
        value,
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        script_pubkey: script_pubkey.clone(),
        subaccount_id: 0,
        is_change: false,
        block_height: None,
        confirmations: 6,
        frozen: false,
        script_type: script_type.to_string(),
    };
    
    (outpoint, txout, utxo_info)
}

#[tokio::test]
async fn test_simple_p2pkh_transaction_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    // Create transaction builder
    let builder = TransactionBuilder::new(AddressNetwork::Testnet);
    
    // Create test UTXO
    let (_, _, utxo_info) = create_test_utxo(100000, "p2pkh");
    
    // Create transaction parameters
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
        utxos: Some(vec![utxo_info.clone()]),
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
    let _secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&[1u8; 32]).unwrap();
    
    let signing_info = InputSigningInfo {
        utxo: utxo_info,
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
async fn test_transaction_history_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    // Get initial transaction history using the proper method signature
    let params = GetTransactionsParams {
        subaccount: 0,
        first: 0,
        count: 10,
    };
    let _initial_history = session.get_transactions(&params).await.unwrap();
    
    // Check if the transaction list is empty
    // The actual structure depends on what get_transactions returns
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_utxo_management_flow() {
    let (mut session, _credentials) = create_test_session_with_wallet().await;
    
    // Get initial UTXO set with proper parameters
    let params = GetUnspentOutputsParams {
        subaccount: 0,
        num_confs: 1,
    };
    let initial_utxos = session.get_unspent_outputs(&params).await.unwrap();
    
    // Check if UTXOs are empty (UnspentOutputs contains a HashMap)
    assert!(initial_utxos.unspent_outputs.is_empty());
    
    session.disconnect().await.unwrap();
}
