use gdk_rs::primitives::address::{Address, Network};
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::str::FromStr;

#[test]
fn test_address_functionality() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = SecretKey::from_str(private_key_hex).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);

    // Test P2PKH address
    let p2pkh_addr = Address::p2pkh(&public_key, Network::Mainnet);
    assert_eq!(p2pkh_addr.address_type(), "p2pkh");
    assert!(!p2pkh_addr.is_segwit());
    
    // Test address string conversion and parsing
    let addr_str = p2pkh_addr.to_string();
    let parsed_addr = Address::from_str(&addr_str).unwrap();
    assert_eq!(p2pkh_addr, parsed_addr);

    // Test P2WPKH address
    let p2wpkh_addr = Address::p2wpkh(&public_key, Network::Mainnet);
    assert_eq!(p2wpkh_addr.address_type(), "p2wpkh");
    assert!(p2wpkh_addr.is_segwit());
    
    // Test Bech32 address string conversion and parsing
    let bech32_str = p2wpkh_addr.to_string();
    assert!(bech32_str.starts_with("bc1"));
    let parsed_bech32 = Address::from_str(&bech32_str).unwrap();
    assert_eq!(p2wpkh_addr, parsed_bech32);

    println!("All address tests passed!");
}