//! BIP32 Hierarchical Deterministic Keys.

use crate::{GdkError, Result};
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use ripemd::Ripemd160;
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::str::FromStr;

const BIP32_MASTER_KEY: &[u8] = b"Bitcoin seed";
const BIP32_HARDENED_KEY_LIMIT: u32 = 0x80000000;

// Version bytes for extended keys
const MAINNET_PRIVATE_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4]; // xprv
const MAINNET_PUBLIC_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];  // xpub
const TESTNET_PRIVATE_VERSION: [u8; 4] = [0x04, 0x35, 0x83, 0x94]; // tprv
const TESTNET_PUBLIC_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];  // tpub

/// Network type for key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Network {
    Bitcoin,
    Testnet,
}

impl Network {
    pub fn private_version_bytes(&self) -> [u8; 4] {
        match self {
            Network::Bitcoin => MAINNET_PRIVATE_VERSION,
            Network::Testnet => TESTNET_PRIVATE_VERSION,
        }
    }

    pub fn public_version_bytes(&self) -> [u8; 4] {
        match self {
            Network::Bitcoin => MAINNET_PUBLIC_VERSION,
            Network::Testnet => TESTNET_PUBLIC_VERSION,
        }
    }
}

/// Chain code for BIP32 key derivation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChainCode(pub [u8; 32]);

impl ChainCode {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Key fingerprint (first 4 bytes of HASH160 of public key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Fingerprint(pub [u8; 4]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Calculate fingerprint from public key
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let pubkey_bytes = public_key.serialize();
        let hash = Sha256::digest(&pubkey_bytes);
        let ripemd = Ripemd160::digest(&hash);
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&ripemd[0..4]);
        Fingerprint(fingerprint)
    }
}

/// Derivation path for BIP32 key derivation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationPath {
    path: Vec<u32>,
}

impl DerivationPath {
    /// Create a new derivation path
    pub fn new(path: Vec<u32>) -> Self {
        DerivationPath { path }
    }

    /// Create master path (empty)
    pub fn master() -> Self {
        DerivationPath { path: Vec::new() }
    }

    /// Get the path components
    pub fn path(&self) -> &[u32] {
        &self.path
    }

    /// Check if a child number is hardened
    pub fn is_hardened(child_number: u32) -> bool {
        child_number >= BIP32_HARDENED_KEY_LIMIT
    }

    /// Create hardened child number
    pub fn hardened(index: u32) -> u32 {
        index + BIP32_HARDENED_KEY_LIMIT
    }

    /// Get the depth of the path
    pub fn depth(&self) -> u8 {
        self.path.len() as u8
    }

    /// Get the last child number, or 0 for master
    pub fn child_number(&self) -> u32 {
        self.path.last().copied().unwrap_or(0)
    }

    /// Get parent path
    pub fn parent(&self) -> Option<DerivationPath> {
        if self.path.is_empty() {
            None
        } else {
            let mut parent_path = self.path.clone();
            parent_path.pop();
            Some(DerivationPath::new(parent_path))
        }
    }

    /// Extend path with child
    pub fn child(&self, child_number: u32) -> DerivationPath {
        let mut new_path = self.path.clone();
        new_path.push(child_number);
        DerivationPath::new(new_path)
    }
}

impl FromStr for DerivationPath {
    type Err = GdkError;

    fn from_str(s: &str) -> Result<Self> {
        if s == "m" {
            return Ok(DerivationPath::master());
        }

        if !s.starts_with("m/") {
            return Err(GdkError::InvalidInput(
                "Derivation path must start with 'm' or 'm/'".to_string(),
            ));
        }

        let path_str = &s[2..]; // Remove "m/"
        if path_str.is_empty() {
            return Ok(DerivationPath::master());
        }

        let mut path = Vec::new();
        for component in path_str.split('/') {
            if component.is_empty() {
                return Err(GdkError::InvalidInput(
                    "Empty path component".to_string(),
                ));
            }

            let (index_str, is_hardened) = if component.ends_with('\'') || component.ends_with('h') {
                (&component[..component.len() - 1], true)
            } else {
                (component, false)
            };

            let index: u32 = index_str.parse().map_err(|_| {
                GdkError::InvalidInput(format!("Invalid path component: {}", component))
            })?;

            if index >= BIP32_HARDENED_KEY_LIMIT {
                return Err(GdkError::InvalidInput(format!(
                    "Path component index too large: {}",
                    index
                )));
            }

            let child_number = if is_hardened {
                DerivationPath::hardened(index)
            } else {
                index
            };

            path.push(child_number);
        }

        Ok(DerivationPath::new(path))
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "m")
        } else {
            write!(f, "m")?;
            for &child_number in &self.path {
                if DerivationPath::is_hardened(child_number) {
                    write!(f, "/{}'", child_number - BIP32_HARDENED_KEY_LIMIT)?;
                } else {
                    write!(f, "/{}", child_number)?;
                }
            }
            Ok(())
        }
    }
}

/// Extended private key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivateKey {
    pub network: Network,
    pub depth: u8,
    pub parent_fingerprint: Fingerprint,
    pub child_number: u32,
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

impl ExtendedPrivateKey {
    /// Create a new master key from a seed
    pub fn new_master_from_seed(seed: &[u8], network: Network) -> Result<Self> {
        let mut mac = Hmac::<Sha512>::new_from_slice(BIP32_MASTER_KEY).unwrap();
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let (key_bytes, chain_code_bytes) = result.split_at(32);

        let private_key = SecretKey::from_slice(key_bytes)
            .map_err(|e| GdkError::InvalidInput(format!("Invalid private key from seed: {}", e)))?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(chain_code_bytes);

        Ok(ExtendedPrivateKey {
            network,
            depth: 0,
            parent_fingerprint: Fingerprint([0; 4]),
            child_number: 0,
            private_key,
            chain_code: ChainCode(chain_code),
        })
    }

    /// Derive a child private key
    pub fn derive_child(&self, child_number: u32) -> Result<ExtendedPrivateKey> {
        let secp = Secp256k1::new();
        let public_key = self.private_key.public_key(&secp);

        let mut mac = Hmac::<Sha512>::new_from_slice(&self.chain_code.0).unwrap();

        if DerivationPath::is_hardened(child_number) {
            // Hardened derivation: use private key
            mac.update(&[0]);
            mac.update(&self.private_key.secret_bytes());
        } else {
            // Non-hardened derivation: use public key
            mac.update(&public_key.serialize());
        }

        mac.update(&child_number.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let (key_bytes, chain_code_bytes) = result.split_at(32);

        // Use secp256k1 to properly handle scalar addition modulo curve order
        let scalar = SecretKey::from_slice(key_bytes)
            .map_err(|e| GdkError::InvalidInput(format!("Invalid scalar: {}", e)))?;
        
        let child_private_key = self.private_key.add_tweak(&secp256k1::Scalar::from(scalar))
            .map_err(|e| GdkError::InvalidInput(format!("Invalid child private key: {}", e)))?;

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(chain_code_bytes);

        let parent_fingerprint = Fingerprint::from_public_key(&public_key);

        Ok(ExtendedPrivateKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
            private_key: child_private_key,
            chain_code: ChainCode(child_chain_code),
        })
    }

    /// Derive a key from a derivation path
    pub fn derive_path(&self, path: &DerivationPath) -> Result<ExtendedPrivateKey> {
        let mut current_key = self.clone();
        for &child_number in path.path() {
            current_key = current_key.derive_child(child_number)?;
        }
        Ok(current_key)
    }

    /// Get the corresponding extended public key
    pub fn extended_public_key(&self) -> ExtendedPublicKey {
        let secp = Secp256k1::new();
        let public_key = self.private_key.public_key(&secp);

        ExtendedPublicKey {
            network: self.network,
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            public_key,
            chain_code: self.chain_code,
        }
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Fingerprint {
        let secp = Secp256k1::new();
        let public_key = self.private_key.public_key(&secp);
        Fingerprint::from_public_key(&public_key)
    }

    /// Serialize to extended private key format (xprv/tprv)
    pub fn to_string(&self) -> String {
        let mut data = Vec::with_capacity(78);

        // Version (4 bytes)
        data.extend_from_slice(&self.network.private_version_bytes());

        // Depth (1 byte)
        data.push(self.depth);

        // Parent fingerprint (4 bytes)
        data.extend_from_slice(self.parent_fingerprint.as_bytes());

        // Child number (4 bytes)
        data.extend_from_slice(&self.child_number.to_be_bytes());

        // Chain code (32 bytes)
        data.extend_from_slice(self.chain_code.as_bytes());

        // Private key (33 bytes with 0x00 prefix)
        data.push(0x00);
        data.extend_from_slice(&self.private_key.secret_bytes());

        // Add checksum and encode to base58
        let checksum = Sha256::digest(&Sha256::digest(&data));
        data.extend_from_slice(&checksum[..4]);
        
        // Manual base58 encoding
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut encoded = Vec::new();
        let mut num = data.iter().fold(num_bigint::BigUint::from(0u32), |acc, &byte| {
            (acc << 8) + num_bigint::BigUint::from(byte)
        });
        
        while num > num_bigint::BigUint::from(0u32) {
            let remainder = &num % 58u32;
            let digit = remainder.to_u32_digits().first().copied().unwrap_or(0);
            encoded.push(ALPHABET[digit as usize]);
            num /= 58u32;
        }
        
        // Add leading '1's for leading zero bytes
        for &byte in data.iter() {
            if byte == 0 {
                encoded.push(b'1');
            } else {
                break;
            }
        }
        
        encoded.reverse();
        String::from_utf8(encoded).unwrap()
    }
}

impl FromStr for ExtendedPrivateKey {
    type Err = GdkError;

    fn from_str(s: &str) -> Result<Self> {
        // Manual base58 decoding
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut num = num_bigint::BigUint::from(0u32);
        
        for &ch in s.as_bytes() {
            let digit = ALPHABET.iter().position(|&c| c == ch)
                .ok_or_else(|| GdkError::InvalidInput("Invalid base58 character".to_string()))?;
            num = num * 58u32 + num_bigint::BigUint::from(digit);
        }
        
        let mut bytes = if num == num_bigint::BigUint::from(0u32) {
            vec![]
        } else {
            num.to_bytes_be()
        };
        
        // Add leading zeros for leading '1's
        for &ch in s.as_bytes() {
            if ch == b'1' {
                bytes.insert(0, 0);
            } else {
                break;
            }
        }
        
        let data = bytes;

        if data.len() != 82 {
            return Err(GdkError::InvalidInput(
                format!("Invalid extended private key length: {} expected 82", data.len()),
            ));
        }
        
        // Verify checksum
        let (payload, checksum) = data.split_at(78);
        let computed_checksum = Sha256::digest(&Sha256::digest(payload));
        if checksum != &computed_checksum[..4] {
            return Err(GdkError::InvalidInput(
                "Invalid checksum".to_string(),
            ));
        }
        
        let data = payload.to_vec();

        // Parse version
        let version = [data[0], data[1], data[2], data[3]];
        let network = match version {
            MAINNET_PRIVATE_VERSION => Network::Bitcoin,
            TESTNET_PRIVATE_VERSION => Network::Testnet,
            _ => return Err(GdkError::InvalidInput("Invalid version bytes".to_string())),
        };

        // Parse depth
        let depth = data[4];

        // Parse parent fingerprint
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        // Parse child number
        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

        // Parse chain code
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        // Parse private key (skip the 0x00 prefix)
        if data[45] != 0x00 {
            return Err(GdkError::InvalidInput(
                "Invalid private key prefix".to_string(),
            ));
        }

        let private_key = SecretKey::from_slice(&data[46..78])
            .map_err(|e| GdkError::InvalidInput(format!("Invalid private key: {}", e)))?;

        Ok(ExtendedPrivateKey {
            network,
            depth,
            parent_fingerprint: Fingerprint(parent_fingerprint),
            child_number,
            private_key,
            chain_code: ChainCode(chain_code),
        })
    }
}

impl fmt::Display for ExtendedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Extended public key
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExtendedPublicKey {
    pub network: Network,
    pub depth: u8,
    pub parent_fingerprint: Fingerprint,
    pub child_number: u32,
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
}

impl ExtendedPublicKey {
    /// Derive a child public key (non-hardened only)
    pub fn derive_child(&self, child_number: u32) -> Result<ExtendedPublicKey> {
        if DerivationPath::is_hardened(child_number) {
            return Err(GdkError::InvalidInput(
                "Cannot derive hardened child from public key".to_string(),
            ));
        }

        let secp = Secp256k1::new();
        let mut mac = Hmac::<Sha512>::new_from_slice(&self.chain_code.0).unwrap();

        // Non-hardened derivation: use public key
        mac.update(&self.public_key.serialize());
        mac.update(&child_number.to_be_bytes());
        let result = mac.finalize().into_bytes();

        let (key_bytes, chain_code_bytes) = result.split_at(32);

        // Create a secret key from the derived bytes and add it to the public key
        let derived_secret = SecretKey::from_slice(key_bytes)
            .map_err(|e| GdkError::InvalidInput(format!("Invalid derived key: {}", e)))?;

        let derived_public = derived_secret.public_key(&secp);
        let child_public_key = self.public_key.combine(&derived_public)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to combine public keys: {}", e)))?;

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(chain_code_bytes);

        let parent_fingerprint = Fingerprint::from_public_key(&self.public_key);

        Ok(ExtendedPublicKey {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint,
            child_number,
            public_key: child_public_key,
            chain_code: ChainCode(child_chain_code),
        })
    }

    /// Get the fingerprint of this key
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_public_key(&self.public_key)
    }

    /// Serialize to extended public key format (xpub/tpub)
    pub fn to_string(&self) -> String {
        let mut data = Vec::with_capacity(78);

        // Version (4 bytes)
        data.extend_from_slice(&self.network.public_version_bytes());

        // Depth (1 byte)
        data.push(self.depth);

        // Parent fingerprint (4 bytes)
        data.extend_from_slice(self.parent_fingerprint.as_bytes());

        // Child number (4 bytes)
        data.extend_from_slice(&self.child_number.to_be_bytes());

        // Chain code (32 bytes)
        data.extend_from_slice(self.chain_code.as_bytes());

        // Public key (33 bytes compressed)
        data.extend_from_slice(&self.public_key.serialize());

        // Add checksum and encode to base58
        let checksum = Sha256::digest(&Sha256::digest(&data));
        data.extend_from_slice(&checksum[..4]);
        
        // Manual base58 encoding
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut encoded = Vec::new();
        let mut num = data.iter().fold(num_bigint::BigUint::from(0u32), |acc, &byte| {
            (acc << 8) + num_bigint::BigUint::from(byte)
        });
        
        while num > num_bigint::BigUint::from(0u32) {
            let remainder = &num % 58u32;
            let digit = remainder.to_u32_digits().first().copied().unwrap_or(0);
            encoded.push(ALPHABET[digit as usize]);
            num /= 58u32;
        }
        
        // Add leading '1's for leading zero bytes
        for &byte in data.iter() {
            if byte == 0 {
                encoded.push(b'1');
            } else {
                break;
            }
        }
        
        encoded.reverse();
        String::from_utf8(encoded).unwrap()
    }
}

impl FromStr for ExtendedPublicKey {
    type Err = GdkError;

    fn from_str(s: &str) -> Result<Self> {
        // Manual base58 decoding
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut num = num_bigint::BigUint::from(0u32);
        
        for &ch in s.as_bytes() {
            let digit = ALPHABET.iter().position(|&c| c == ch)
                .ok_or_else(|| GdkError::InvalidInput("Invalid base58 character".to_string()))?;
            num = num * 58u32 + num_bigint::BigUint::from(digit);
        }
        
        let mut bytes = if num == num_bigint::BigUint::from(0u32) {
            vec![]
        } else {
            num.to_bytes_be()
        };
        
        // Add leading zeros for leading '1's
        for &ch in s.as_bytes() {
            if ch == b'1' {
                bytes.insert(0, 0);
            } else {
                break;
            }
        }
        
        let data = bytes;

        if data.len() != 82 {
            return Err(GdkError::InvalidInput(
                format!("Invalid extended public key length: {} expected 82", data.len()),
            ));
        }
        
        // Verify checksum
        let (payload, checksum) = data.split_at(78);
        let computed_checksum = Sha256::digest(&Sha256::digest(payload));
        if checksum != &computed_checksum[..4] {
            return Err(GdkError::InvalidInput(
                "Invalid checksum".to_string(),
            ));
        }
        
        let data = payload.to_vec();

        // Parse version
        let version = [data[0], data[1], data[2], data[3]];
        let network = match version {
            MAINNET_PUBLIC_VERSION => Network::Bitcoin,
            TESTNET_PUBLIC_VERSION => Network::Testnet,
            _ => return Err(GdkError::InvalidInput("Invalid version bytes".to_string())),
        };

        // Parse depth
        let depth = data[4];

        // Parse parent fingerprint
        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        // Parse child number
        let child_number = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);

        // Parse chain code
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        // Parse public key
        let public_key = PublicKey::from_slice(&data[45..78])
            .map_err(|e| GdkError::InvalidInput(format!("Invalid public key: {}", e)))?;

        Ok(ExtendedPublicKey {
            network,
            depth,
            parent_fingerprint: Fingerprint(parent_fingerprint),
            child_number,
            public_key,
            chain_code: ChainCode(chain_code),
        })
    }
}

impl fmt::Display for ExtendedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// Legacy type aliases for compatibility
pub type ExtendedPrivKey = ExtendedPrivateKey;
pub type ExtendedPubKey = ExtendedPublicKey;

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_bip32_master_from_seed() {
        // BIP32 test vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let xprv = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();

        let expected_key_hex = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        let expected_chain_code_hex = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

        assert_eq!(hex::encode(xprv.private_key.secret_bytes()), expected_key_hex);
        assert_eq!(hex::encode(xprv.chain_code.0), expected_chain_code_hex);
        assert_eq!(xprv.depth, 0);
        assert_eq!(xprv.child_number, 0);
        assert_eq!(xprv.parent_fingerprint.0, [0; 4]);
    }

    #[test]
    fn test_derivation_path_parsing() {
        // Test master path
        let path = DerivationPath::from_str("m").unwrap();
        assert_eq!(path.path(), &[] as &[u32]);
        assert_eq!(path.to_string(), "m");

        // Test simple path
        let path = DerivationPath::from_str("m/0").unwrap();
        assert_eq!(path.path(), &[0]);
        assert_eq!(path.to_string(), "m/0");

        // Test hardened path with apostrophe
        let path = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        assert_eq!(path.path(), &[
            DerivationPath::hardened(44),
            DerivationPath::hardened(0),
            DerivationPath::hardened(0)
        ]);
        assert_eq!(path.to_string(), "m/44'/0'/0'");

        // Test hardened path with 'h'
        let path = DerivationPath::from_str("m/44h/0h/0h").unwrap();
        assert_eq!(path.path(), &[
            DerivationPath::hardened(44),
            DerivationPath::hardened(0),
            DerivationPath::hardened(0)
        ]);
        assert_eq!(path.to_string(), "m/44'/0'/0'");

        // Test mixed path
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        assert_eq!(path.path(), &[
            DerivationPath::hardened(44),
            DerivationPath::hardened(0),
            DerivationPath::hardened(0),
            0,
            0
        ]);
        assert_eq!(path.to_string(), "m/44'/0'/0'/0/0");
    }

    #[test]
    fn test_derivation_path_errors() {
        // Invalid start
        assert!(DerivationPath::from_str("n/0").is_err());
        
        // Empty component
        assert!(DerivationPath::from_str("m//0").is_err());
        
        // Invalid number
        assert!(DerivationPath::from_str("m/abc").is_err());
        
        // Too large index
        let large_index = format!("m/{}", BIP32_HARDENED_KEY_LIMIT);
        assert!(DerivationPath::from_str(&large_index).is_err());
    }

    #[test]
    fn test_derivation_path_methods() {
        let path = DerivationPath::from_str("m/44'/0'/0'/0/5").unwrap();
        
        assert_eq!(path.depth(), 5);
        assert_eq!(path.child_number(), 5);
        
        let parent = path.parent().unwrap();
        assert_eq!(parent.to_string(), "m/44'/0'/0'/0");
        
        let child = path.child(10);
        assert_eq!(child.to_string(), "m/44'/0'/0'/0/5/10");
        
        assert!(DerivationPath::is_hardened(DerivationPath::hardened(44)));
        assert!(!DerivationPath::is_hardened(44));
    }

    #[test]
    fn test_child_key_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();

        // Test hardened derivation
        let child = master.derive_child(DerivationPath::hardened(0)).unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.child_number, DerivationPath::hardened(0));
        assert_ne!(child.private_key.secret_bytes(), master.private_key.secret_bytes());

        // Test non-hardened derivation
        let child2 = child.derive_child(1).unwrap();
        assert_eq!(child2.depth, 2);
        assert_eq!(child2.child_number, 1);
    }

    #[test]
    fn test_path_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();

        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let derived = master.derive_path(&path).unwrap();

        assert_eq!(derived.depth, 5);
        assert_eq!(derived.child_number, 0);

        // Test that step-by-step derivation gives same result
        let step1 = master.derive_child(DerivationPath::hardened(44)).unwrap();
        let step2 = step1.derive_child(DerivationPath::hardened(0)).unwrap();
        let step3 = step2.derive_child(DerivationPath::hardened(0)).unwrap();
        let step4 = step3.derive_child(0).unwrap();
        let step5 = step4.derive_child(0).unwrap();

        assert_eq!(derived.private_key.secret_bytes(), step5.private_key.secret_bytes());
        assert_eq!(derived.chain_code.0, step5.chain_code.0);
    }

    #[test]
    fn test_extended_public_key() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();
        let master_pub = master_priv.extended_public_key();

        assert_eq!(master_pub.depth, master_priv.depth);
        assert_eq!(master_pub.child_number, master_priv.child_number);
        assert_eq!(master_pub.chain_code.0, master_priv.chain_code.0);
        assert_eq!(master_pub.network, master_priv.network);

        // Test public key derivation (non-hardened only)
        let child_priv = master_priv.derive_child(0).unwrap();
        let child_pub_from_priv = child_priv.extended_public_key();
        let child_pub_from_pub = master_pub.derive_child(0).unwrap();

        assert_eq!(child_pub_from_priv.public_key.serialize(), child_pub_from_pub.public_key.serialize());
        assert_eq!(child_pub_from_priv.chain_code.0, child_pub_from_pub.chain_code.0);
    }

    #[test]
    fn test_public_key_hardened_derivation_fails() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master_priv = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();
        let master_pub = master_priv.extended_public_key();

        // Should fail for hardened derivation
        let result = master_pub.derive_child(DerivationPath::hardened(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_fingerprint_calculation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();
        let child = master.derive_child(0).unwrap();

        let master_fingerprint = master.fingerprint();
        assert_eq!(child.parent_fingerprint.0, master_fingerprint.0);
    }

    #[test]
    fn test_extended_key_serialization() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();

        // Test private key serialization
        let serialized = master.to_string();
        assert!(serialized.starts_with("xprv"));

        let deserialized = ExtendedPrivateKey::from_str(&serialized).unwrap();
        assert_eq!(master.private_key.secret_bytes(), deserialized.private_key.secret_bytes());
        assert_eq!(master.chain_code.0, deserialized.chain_code.0);
        assert_eq!(master.depth, deserialized.depth);
        assert_eq!(master.child_number, deserialized.child_number);

        // Test public key serialization
        let master_pub = master.extended_public_key();
        let pub_serialized = master_pub.to_string();
        assert!(pub_serialized.starts_with("xpub"));

        let pub_deserialized = ExtendedPublicKey::from_str(&pub_serialized).unwrap();
        assert_eq!(master_pub.public_key.serialize(), pub_deserialized.public_key.serialize());
        assert_eq!(master_pub.chain_code.0, pub_deserialized.chain_code.0);
    }

    #[test]
    fn test_testnet_keys() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Testnet).unwrap();

        let serialized = master.to_string();
        assert!(serialized.starts_with("tprv"));

        let master_pub = master.extended_public_key();
        let pub_serialized = master_pub.to_string();
        assert!(pub_serialized.starts_with("tpub"));
    }

    #[test]
    fn test_network_version_bytes() {
        assert_eq!(Network::Bitcoin.private_version_bytes(), MAINNET_PRIVATE_VERSION);
        assert_eq!(Network::Bitcoin.public_version_bytes(), MAINNET_PUBLIC_VERSION);
        assert_eq!(Network::Testnet.private_version_bytes(), TESTNET_PRIVATE_VERSION);
        assert_eq!(Network::Testnet.public_version_bytes(), TESTNET_PUBLIC_VERSION);
    }

    #[test]
    fn test_invalid_extended_key_deserialization() {
        // Invalid base58
        assert!(ExtendedPrivateKey::from_str("invalid").is_err());
        
        // Wrong length
        let short_key = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert!(ExtendedPrivateKey::from_str(&short_key[..short_key.len()-10]).is_err());
        
        // Invalid version
        let mut invalid_version = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        assert!(ExtendedPrivateKey::from_str(invalid_version).is_err());
    }

    #[test]
    fn test_bip32_test_vectors() {
        // BIP32 test vector 1 - more comprehensive test
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();

        // Test master key
        assert_eq!(
            master.to_string(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );

        let master_pub = master.extended_public_key();
        assert_eq!(
            master_pub.to_string(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
    }

    #[test]
    fn test_chain_code_and_fingerprint_methods() {
        let chain_code = ChainCode([42u8; 32]);
        assert_eq!(chain_code.as_bytes(), &[42u8; 32]);

        let fingerprint = Fingerprint([1, 2, 3, 4]);
        assert_eq!(fingerprint.as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_legacy_type_aliases() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let _master: ExtendedPrivKey = ExtendedPrivateKey::new_master_from_seed(&seed, Network::Bitcoin).unwrap();
        let _master_pub: ExtendedPubKey = _master.extended_public_key();
    }
}
