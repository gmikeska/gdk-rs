use gdk_rs::transaction_builder::*;
use gdk_rs::primitives::address::{Network, Address};
use gdk_rs::primitives::script::Script;
use gdk_rs::protocol::Addressee;
use std::str::FromStr;

fn create_test_utxo(value: u64, script_type: &str, network: Network) -> UtxoInfo {
    // Create appropriate address for the network
    let address_str = match network {
        Network::Mainnet => "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        Network::Testnet => "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        Network::Regtest => "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        Network::Signet => "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
    };
    
    let address = Address::from_str(address_str).unwrap();
    
    UtxoInfo {
        txid: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        vout: 0,
        value,
        address: address_str.to_string(),
        script_pubkey: address.script_pubkey(),
        subaccount_id: 0,
        is_change: false,
        block_height: Some(100),
        confirmations: 6,
        frozen: false,
        script_type: script_type.to_string(),
    }
}

#[test]
fn test_transaction_builder_creation() {
    let builder = TransactionBuilder::new(Network::Testnet);
    // Test that we can get fee estimates
    let estimates = builder.get_fee_estimates();
    assert!(estimates.fee_rates.len() > 0);
}

#[test]
fn test_build_simple_transaction() {
    let builder = TransactionBuilder::new(Network::Testnet);
    let utxos = vec![
        create_test_utxo(100000, "p2pkh", Network::Testnet),
    ];
    
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".to_string(),
            satoshi: 50000,
            asset_id: None,
        }],
        fee_strategy: FeeEstimationStrategy::FixedRate(10),
        ..Default::default()
    };

    let result = builder.build_transaction(&params, &utxos).unwrap();
    assert_eq!(result.selected_utxos.len(), 1);
    assert_eq!(result.input_value, 100000);
    assert!(result.fee > 0);
    assert_eq!(result.fee_rate, 10);
}

#[test]
fn test_send_all_transaction() {
    let builder = TransactionBuilder::new(Network::Testnet);
    let utxos = vec![
        create_test_utxo(100000, "p2pkh", Network::Testnet),
        create_test_utxo(50000, "p2pkh", Network::Testnet),
    ];
    
    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".to_string(),
            satoshi: 0, // Will be ignored with send_all
            asset_id: None,
        }],
        send_all: true,
        fee_strategy: FeeEstimationStrategy::FixedRate(10),
        ..Default::default()
    };

    let result = builder.build_transaction(&params, &utxos).unwrap();
    assert_eq!(result.selected_utxos.len(), 2);
    assert_eq!(result.input_value, 150000);
    assert!(result.fee > 0);
    assert_eq!(result.output_value + result.fee, result.input_value);
}

#[test]
fn test_update_fee_estimates() {
    let mut builder = TransactionBuilder::new(Network::Testnet);
    
    let mut new_estimates = FeeEstimate::default();
    new_estimates.fee_rates.insert(1, 50);
    new_estimates.min_relay_fee = 2;
    
    builder.update_fee_estimates(new_estimates);
    
    let estimates = builder.get_fee_estimates();
    assert_eq!(estimates.fee_rates.get(&1), Some(&50));
    assert_eq!(estimates.min_relay_fee, 2);
}

#[test]
fn test_insufficient_funds() {
    let builder = TransactionBuilder::new(Network::Testnet);
    let utxos = vec![create_test_utxo(1000, "p2pkh", Network::Testnet)];

    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".to_string(),
            satoshi: 50000, // More than available
            asset_id: None,
        }],
        ..Default::default()
    };

    let result = builder.build_transaction(&params, &utxos);
    assert!(result.is_err());
}

#[test]
fn test_empty_addressees_error() {
    let builder = TransactionBuilder::new(Network::Testnet);
    let utxos = vec![create_test_utxo(100000, "p2pkh", Network::Testnet)];
    
    // Test empty addressees without send_all
    let params = TransactionBuildParams::default();
    let result = builder.build_transaction(&params, &utxos);
    assert!(result.is_err());
}

#[test]
fn test_network_mismatch() {
    let builder = TransactionBuilder::new(Network::Testnet);
    let utxos = vec![create_test_utxo(100000, "p2pkh", Network::Testnet)];

    let params = TransactionBuildParams {
        addressees: vec![Addressee {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), // Mainnet address
            satoshi: 50000,
            asset_id: None,
        }],
        ..Default::default()
    };

    let result = builder.build_transaction(&params, &utxos);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("network mismatch"));
}
