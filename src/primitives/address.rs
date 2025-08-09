//! Bitcoin addresses with comprehensive support for all address types.

use crate::primitives::hash::{hash160, sha256, Hash160, Hash256};
use crate::primitives::script::Script;
use crate::{Result, GdkError};
use secp256k1::PublicKey;
use base58check::{ToBase58Check, FromBase58Check};
use bech32::{self, ToBase32, FromBase32, Variant};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Bitcoin network types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin regtest
    Regtest,
    /// Bitcoin signet
    Signet,
}

impl Network {
    /// Get the human-readable part for Bech32 addresses
    pub fn bech32_hrp(&self) -> &'static str {
        match self {
            Network::Mainnet => "bc",
            Network::Testnet => "tb",
            Network::Regtest => "bcrt",
            Network::Signet => "tb",
        }
    }

    /// Get the P2PKH version byte
    pub fn p2pkh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x00,
            Network::Testnet | Network::Regtest | Network::Signet => 0x6f,
        }
    }

    /// Get the P2SH version byte
    pub fn p2sh_version(&self) -> u8 {
        match self {
            Network::Mainnet => 0x05,
            Network::Testnet | Network::Regtest | Network::Signet => 0xc4,
        }
    }
}

/// Address payload types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressPayload {
    /// Pay-to-Pubkey-Hash (P2PKH)
    P2PKH(Hash160),
    /// Pay-to-Script-Hash (P2SH)
    P2SH(Hash160),
    /// Pay-to-Witness-Pubkey-Hash (P2WPKH)
    P2WPKH(Hash160),
    /// Pay-to-Witness-Script-Hash (P2WSH)
    P2WSH(Hash256),
    /// Pay-to-Taproot (P2TR) - for future use
    P2TR([u8; 32]),
}

/// Bitcoin address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Address {
    pub network: Network,
    pub payload: AddressPayload,
}

impl Address {
    /// Create a P2PKH address from a public key
    pub fn p2pkh(pubkey: &PublicKey, network: Network) -> Self {
        let pubkey_bytes = pubkey.serialize();
        let hash = hash160(&pubkey_bytes);
        Address {
            network,
            payload: AddressPayload::P2PKH(hash),
        }
    }

    /// Create a P2PKH address from an uncompressed public key (for legacy compatibility)
    pub fn p2pkh_uncompressed(pubkey: &PublicKey, network: Network) -> Self {
        let pubkey_bytes = pubkey.serialize_uncompressed();
        let hash = hash160(&pubkey_bytes);
        Address {
            network,
            payload: AddressPayload::P2PKH(hash),
        }
    }

    /// Create a P2SH address from a script
    pub fn p2sh(script: &Script, network: Network) -> Self {
        let hash = hash160(script.as_bytes());
        Address {
            network,
            payload: AddressPayload::P2SH(hash),
        }
    }

    /// Create a P2SH address from a script hash
    pub fn p2sh_from_hash(hash: Hash160, network: Network) -> Self {
        Address {
            network,
            payload: AddressPayload::P2SH(hash),
        }
    }

    /// Create a P2WPKH address from a public key
    pub fn p2wpkh(pubkey: &PublicKey, network: Network) -> Self {
        let pubkey_bytes = pubkey.serialize();
        let hash = hash160(&pubkey_bytes);
        Address {
            network,
            payload: AddressPayload::P2WPKH(hash),
        }
    }

    /// Create a P2WPKH address from a hash160
    pub fn p2wpkh_from_hash(hash: Hash160, network: Network) -> Self {
        Address {
            network,
            payload: AddressPayload::P2WPKH(hash),
        }
    }

    /// Create a P2WSH address from a script
    pub fn p2wsh(script: &Script, network: Network) -> Self {
        let hash = sha256(script.as_bytes());
        Address {
            network,
            payload: AddressPayload::P2WSH(hash),
        }
    }

    /// Create a P2WSH address from a script hash
    pub fn p2wsh_from_hash(hash: Hash256, network: Network) -> Self {
        Address {
            network,
            payload: AddressPayload::P2WSH(hash),
        }
    }

    /// Create a P2TR address from a taproot output key
    pub fn p2tr(output_key: [u8; 32], network: Network) -> Self {
        Address {
            network,
            payload: AddressPayload::P2TR(output_key),
        }
    }

    /// Get the script pubkey for this address
    pub fn script_pubkey(&self) -> Script {
        match &self.payload {
            AddressPayload::P2PKH(hash) => Script::new_p2pkh(hash),
            AddressPayload::P2SH(hash) => Script::new_p2sh(hash),
            AddressPayload::P2WPKH(hash) => Script::new_p2wpkh(hash),
            AddressPayload::P2WSH(hash) => Script::new_p2wsh(hash),
            AddressPayload::P2TR(key) => {
                let mut script = Vec::with_capacity(34);
                script.push(0x51); // OP_1
                script.push(0x20); // Push 32 bytes
                script.extend_from_slice(key);
                Script::from_bytes(script)
            }
        }
    }

    /// Get the address type as a string
    pub fn address_type(&self) -> &'static str {
        match self.payload {
            AddressPayload::P2PKH(_) => "p2pkh",
            AddressPayload::P2SH(_) => "p2sh",
            AddressPayload::P2WPKH(_) => "p2wpkh",
            AddressPayload::P2WSH(_) => "p2wsh",
            AddressPayload::P2TR(_) => "p2tr",
        }
    }

    /// Check if this is a SegWit address
    pub fn is_segwit(&self) -> bool {
        matches!(self.payload, AddressPayload::P2WPKH(_) | AddressPayload::P2WSH(_) | AddressPayload::P2TR(_))
    }

    /// Validate the address format and network consistency
    pub fn validate(&self) -> Result<()> {
        match &self.payload {
            AddressPayload::P2PKH(hash) | AddressPayload::P2SH(hash) | 
            AddressPayload::P2WPKH(hash) => {
                if hash.len() != 20 {
                    return Err(GdkError::InvalidInput("Invalid hash160 length".to_string()));
                }
            }
            AddressPayload::P2WSH(hash) => {
                if hash.len() != 32 {
                    return Err(GdkError::InvalidInput("Invalid hash256 length".to_string()));
                }
            }
            AddressPayload::P2TR(_) => {
                // P2TR key is always 32 bytes by definition
            }
        }
        Ok(())
    }

    /// Convert to Bech32 string (for SegWit addresses)
    fn to_bech32(&self) -> Result<String> {
        let hrp = self.network.bech32_hrp();
        
        match &self.payload {
            AddressPayload::P2WPKH(hash) => {
                let mut data = vec![bech32::u5::try_from_u8(0).unwrap()]; // witness version 0
                data.extend_from_slice(&hash.to_base32());
                bech32::encode(hrp, data, Variant::Bech32)
                    .map_err(|e| GdkError::InvalidInput(format!("Bech32 encoding error: {}", e)))
            }
            AddressPayload::P2WSH(hash) => {
                let mut data = vec![bech32::u5::try_from_u8(0).unwrap()]; // witness version 0
                data.extend_from_slice(&hash.to_base32());
                bech32::encode(hrp, data, Variant::Bech32)
                    .map_err(|e| GdkError::InvalidInput(format!("Bech32 encoding error: {}", e)))
            }
            AddressPayload::P2TR(key) => {
                let mut data = vec![bech32::u5::try_from_u8(1).unwrap()]; // witness version 1
                data.extend_from_slice(&key.to_base32());
                bech32::encode(hrp, data, Variant::Bech32m)
                    .map_err(|e| GdkError::InvalidInput(format!("Bech32m encoding error: {}", e)))
            }
            _ => Err(GdkError::InvalidInput("Not a SegWit address".to_string())),
        }
    }

    /// Parse a Bech32 address string
    fn from_bech32(s: &str) -> Result<Self> {
        let (hrp, data, variant) = bech32::decode(s)
            .map_err(|e| GdkError::InvalidInput(format!("Bech32 decode error: {}", e)))?;

        let network = match hrp.as_str() {
            "bc" => Network::Mainnet,
            "tb" => Network::Testnet,
            "bcrt" => Network::Regtest,
            _ => return Err(GdkError::InvalidInput(format!("Unknown HRP: {}", hrp))),
        };

        if data.is_empty() {
            return Err(GdkError::InvalidInput("Empty witness program".to_string()));
        }

        let witness_version = data[0];
        let program = Vec::<u8>::from_base32(&data[1..])
            .map_err(|e| GdkError::InvalidInput(format!("Base32 decode error: {}", e)))?;

        let witness_version_u8 = witness_version.to_u8();
        match (witness_version_u8, program.len(), variant) {
            (0, 20, Variant::Bech32) => {
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&program);
                Ok(Address {
                    network,
                    payload: AddressPayload::P2WPKH(hash),
                })
            }
            (0, 32, Variant::Bech32) => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&program);
                Ok(Address {
                    network,
                    payload: AddressPayload::P2WSH(hash),
                })
            }
            (1, 32, Variant::Bech32m) => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&program);
                Ok(Address {
                    network,
                    payload: AddressPayload::P2TR(key),
                })
            }
            _ => Err(GdkError::InvalidInput(format!(
                "Invalid witness program: version={}, length={}, variant={:?}",
                witness_version_u8, program.len(), variant
            ))),
        }
    }

    /// Parse a Base58Check address string
    fn from_base58check(s: &str) -> Result<Self> {
        let (version, payload) = s.from_base58check()
            .map_err(|e| GdkError::InvalidInput(format!("Base58Check decode error: {:?}", e)))?;

        if payload.len() != 20 {
            return Err(GdkError::InvalidInput("Invalid address payload length".to_string()));
        }

        let mut hash = [0u8; 20];
        hash.copy_from_slice(&payload);

        match version {
            0x00 => Ok(Address {
                network: Network::Mainnet,
                payload: AddressPayload::P2PKH(hash),
            }),
            0x05 => Ok(Address {
                network: Network::Mainnet,
                payload: AddressPayload::P2SH(hash),
            }),
            0x6f => Ok(Address {
                network: Network::Testnet,
                payload: AddressPayload::P2PKH(hash),
            }),
            0xc4 => Ok(Address {
                network: Network::Testnet,
                payload: AddressPayload::P2SH(hash),
            }),
            _ => Err(GdkError::InvalidInput(format!("Unknown address version: {:#x}", version))),
        }
    }

    /// Validate an address string and return the network if valid
    pub fn validate_address_string(s: &str) -> Result<Network> {
        let address = Address::from_str(s)?;
        address.validate()?;
        Ok(address.network)
    }

    /// Check if an address string is valid for the given network
    pub fn is_valid_for_network(s: &str, expected_network: Network) -> bool {
        match Address::from_str(s) {
            Ok(address) => address.network == expected_network && address.validate().is_ok(),
            Err(_) => false,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self.payload {
            AddressPayload::P2PKH(hash) => {
                let version = self.network.p2pkh_version();
                write!(f, "{}", hash.to_base58check(version))
            }
            AddressPayload::P2SH(hash) => {
                let version = self.network.p2sh_version();
                write!(f, "{}", hash.to_base58check(version))
            }
            AddressPayload::P2WPKH(_) | AddressPayload::P2WSH(_) | AddressPayload::P2TR(_) => {
                match self.to_bech32() {
                    Ok(addr) => write!(f, "{}", addr),
                    Err(_) => write!(f, "<invalid_address>"),
                }
            }
        }
    }
}

impl FromStr for Address {
    type Err = GdkError;

    fn from_str(s: &str) -> Result<Self> {
        // Try Bech32 first (starts with known HRPs)
        if s.starts_with("bc1") || s.starts_with("tb1") || s.starts_with("bcrt1") {
            return Self::from_bech32(s);
        }

        // Try Base58Check
        Self::from_base58check(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
