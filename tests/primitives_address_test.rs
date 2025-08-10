use gdk_rs::primitives::address::*;
use gdk_rs::primitives::script::Script;
use secp256k1::Secp256k1;
use std::str::FromStr;

#[test]
fn test_p2pkh_address_compressed() {
    // Test vector from mastering bitcoin (compressed pubkey)
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let address = Address::p2pkh(&public_key, Network::Mainnet);
    assert_eq!(address.address_type(), "p2pkh");
    assert!(!address.is_segwit());
    assert_eq!(address.network, Network::Mainnet);
    
    // Verify roundtrip
    let addr_str = address.to_string();
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2pkh_address_uncompressed() {
    // Test vector from mastering bitcoin (uncompressed pubkey)
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let address = Address::p2pkh_uncompressed(&public_key, Network::Mainnet);
    assert_eq!(address.to_string(), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
    assert_eq!(address.address_type(), "p2pkh");
    assert!(!address.is_segwit());
}

#[test]
fn test_p2pkh_testnet() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let address = Address::p2pkh(&public_key, Network::Testnet);
    assert_eq!(address.network, Network::Testnet);
    
    let addr_str = address.to_string();
    assert!(addr_str.starts_with('m') || addr_str.starts_with('n'));
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2sh_address() {
    // Create a simple P2SH address from a script
    let script = Script::new_p2pkh(&[0u8; 20]);
    let address = Address::p2sh(&script, Network::Mainnet);
    
    assert_eq!(address.address_type(), "p2sh");
    assert!(!address.is_segwit());
    assert_eq!(address.network, Network::Mainnet);
    
    let addr_str = address.to_string();
    assert!(addr_str.starts_with('3'));
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2sh_testnet() {
    let script = Script::new_p2pkh(&[0u8; 20]);
    let address = Address::p2sh(&script, Network::Testnet);
    
    assert_eq!(address.network, Network::Testnet);
    let addr_str = address.to_string();
    assert!(addr_str.starts_with('2'));
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2wpkh_address() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let address = Address::p2wpkh(&public_key, Network::Mainnet);
    assert_eq!(address.address_type(), "p2wpkh");
    assert!(address.is_segwit());
    assert_eq!(address.network, Network::Mainnet);
    
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("bc1"));
    assert_eq!(addr_str.len(), 42); // P2WPKH addresses are 42 characters
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2wpkh_testnet() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let address = Address::p2wpkh(&public_key, Network::Testnet);
    assert_eq!(address.network, Network::Testnet);
    
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("tb1"));
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2wsh_address() {
    let script = Script::new_p2pkh(&[0u8; 20]);
    let address = Address::p2wsh(&script, Network::Mainnet);
    
    assert_eq!(address.address_type(), "p2wsh");
    assert!(address.is_segwit());
    assert_eq!(address.network, Network::Mainnet);
    
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("bc1"));
    assert_eq!(addr_str.len(), 62); // P2WSH addresses are 62 characters
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2wsh_testnet() {
    let script = Script::new_p2pkh(&[0u8; 20]);
    let address = Address::p2wsh(&script, Network::Testnet);
    
    assert_eq!(address.network, Network::Testnet);
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("tb1"));
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_p2tr_address() {
    let output_key = [0x12u8; 32];
    let address = Address::p2tr(output_key, Network::Mainnet);
    
    assert_eq!(address.address_type(), "p2tr");
    assert!(address.is_segwit());
    assert_eq!(address.network, Network::Mainnet);
    
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("bc1p"));
    assert_eq!(addr_str.len(), 62); // P2TR addresses are 62 characters
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
}

#[test]
fn test_address_validation() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    // Valid addresses should validate
    let p2pkh = Address::p2pkh(&public_key, Network::Mainnet);
    assert!(p2pkh.validate().is_ok());

    let p2wpkh = Address::p2wpkh(&public_key, Network::Mainnet);
    assert!(p2wpkh.validate().is_ok());

    let script = Script::new_p2pkh(&[0u8; 20]);
    let p2wsh = Address::p2wsh(&script, Network::Mainnet);
    assert!(p2wsh.validate().is_ok());
}

#[test]
fn test_network_validation() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let mainnet_addr = Address::p2pkh(&public_key, Network::Mainnet);
    let testnet_addr = Address::p2pkh(&public_key, Network::Testnet);

    let mainnet_str = mainnet_addr.to_string();
    let testnet_str = testnet_addr.to_string();

    // Addresses should be valid for their respective networks
    assert!(Address::is_valid_for_network(&mainnet_str, Network::Mainnet));
    assert!(!Address::is_valid_for_network(&mainnet_str, Network::Testnet));
    
    assert!(Address::is_valid_for_network(&testnet_str, Network::Testnet));
    assert!(!Address::is_valid_for_network(&testnet_str, Network::Mainnet));
}

#[test]
fn test_script_pubkey_generation() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    // Test P2PKH script pubkey
    let p2pkh_addr = Address::p2pkh(&public_key, Network::Mainnet);
    let p2pkh_script = p2pkh_addr.script_pubkey();
    assert!(p2pkh_script.is_p2pkh());

    // Test P2WPKH script pubkey
    let p2wpkh_addr = Address::p2wpkh(&public_key, Network::Mainnet);
    let p2wpkh_script = p2wpkh_addr.script_pubkey();
    assert!(p2wpkh_script.is_p2wpkh());

    // Test P2WSH script pubkey
    let script = Script::new_p2pkh(&[0u8; 20]);
    let p2wsh_addr = Address::p2wsh(&script, Network::Mainnet);
    let p2wsh_script = p2wsh_addr.script_pubkey();
    assert!(p2wsh_script.is_p2wsh());
}

#[test]
fn test_invalid_addresses() {
    // Invalid Base58Check
    assert!(Address::from_str("invalid").is_err());
    assert!(Address::from_str("1234567890").is_err());
    
    // Invalid Bech32
    assert!(Address::from_str("bc1invalid").is_err());
    assert!(Address::from_str("tb1toolong1234567890123456789012345678901234567890").is_err());
    
    // Wrong network prefix
    assert!(Address::from_str("ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty").is_err());
}

#[test]
fn test_address_string_validation() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let address = Address::p2pkh(&public_key, Network::Mainnet);
    let addr_str = address.to_string();

    // Valid address should return correct network
    let network = Address::validate_address_string(&addr_str).unwrap();
    assert_eq!(network, Network::Mainnet);

    // Invalid address should return error
    assert!(Address::validate_address_string("invalid").is_err());
}

#[test]
fn test_regtest_addresses() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    // Test regtest P2WPKH
    let address = Address::p2wpkh(&public_key, Network::Regtest);
    let addr_str = address.to_string();
    assert!(addr_str.starts_with("bcrt1"));
    
    // Verify roundtrip
    let parsed = Address::from_str(&addr_str).unwrap();
    assert_eq!(address, parsed);
    assert_eq!(parsed.network, Network::Regtest);
}

#[test]
fn test_all_address_types_roundtrip() {
    let secp = Secp256k1::new();
    let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
    let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

    let networks = [Network::Mainnet, Network::Testnet, Network::Regtest];
    
    for network in networks {
        // Test P2PKH
        let p2pkh = Address::p2pkh(&public_key, network);
        let p2pkh_str = p2pkh.to_string();
        let p2pkh_parsed = Address::from_str(&p2pkh_str).unwrap();
        assert_eq!(p2pkh, p2pkh_parsed);

        // Test P2WPKH
        let p2wpkh = Address::p2wpkh(&public_key, network);
        let p2wpkh_str = p2wpkh.to_string();
        let p2wpkh_parsed = Address::from_str(&p2wpkh_str).unwrap();
        assert_eq!(p2wpkh, p2wpkh_parsed);

        // Test P2SH
        let script = Script::new_p2pkh(&[0u8; 20]);
        let p2sh = Address::p2sh(&script, network);
        let p2sh_str = p2sh.to_string();
        let p2sh_parsed = Address::from_str(&p2sh_str).unwrap();
        assert_eq!(p2sh, p2sh_parsed);

        // Test P2WSH
        let p2wsh = Address::p2wsh(&script, network);
        let p2wsh_str = p2wsh.to_string();
        let p2wsh_parsed = Address::from_str(&p2wsh_str).unwrap();
        assert_eq!(p2wsh, p2wsh_parsed);
    }
}
