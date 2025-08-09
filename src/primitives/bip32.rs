//! BIP32 Hierarchical Deterministic Keys.

use crate::Result;
use hmac::{Hmac, Mac};
use sha2::Sha512;
use secp256k1::{SecretKey, PublicKey};

const BIP32_MASTER_KEY: &[u8] = b"Bitcoin seed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainCode(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
    // other fields: depth, parent_fingerprint, child_number, network
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedPubKey {
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
    // other fields
}

impl ExtendedPrivKey {
    /// Create a new master key from a seed.
    pub fn new_master_from_seed(seed: &[u8]) -> Result<Self> {
        let mut mac = Hmac::<Sha512>::new_from_slice(BIP32_MASTER_KEY).unwrap();
        mac.update(seed);
        let result = mac.finalize().into_bytes();

        let (key, chain_code_bytes) = result.split_at(32);

        let private_key = SecretKey::from_slice(key)
            .map_err(|e| crate::GdkError::InvalidInput(format!("Invalid private key from seed: {}", e)))?;

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(chain_code_bytes);

        Ok(ExtendedPrivKey {
            private_key,
            chain_code: ChainCode(chain_code),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_bip32_master_from_seed() {
        // BIP32 test vector 1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let xprv = ExtendedPrivKey::new_master_from_seed(&seed).unwrap();

        let expected_key_hex = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        let expected_chain_code_hex = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

        assert_eq!(hex::encode(xprv.private_key.secret_bytes()), expected_key_hex);
        assert_eq!(hex::encode(xprv.chain_code.0), expected_chain_code_hex);
    }
}
