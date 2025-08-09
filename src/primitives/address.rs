//! Bitcoin addresses.

use crate::primitives::hash::hash160;
use secp256k1::PublicKey;
use base58check::ToBase58Check;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressPayload {
    /// Pay-to-Pubkey-Hash
    P2PKH(Vec<u8>), // 20-byte hash
    /// Pay-to-Script-Hash
    P2SH(Vec<u8>), // 20-byte hash
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub network: Network,
    pub payload: AddressPayload,
}

impl Address {
    pub fn p2pkh(pubkey: &PublicKey, network: Network) -> Self {
        // The test vector from Mastering Bitcoin uses an uncompressed pubkey
        let uncompressed_pubkey = pubkey.serialize_uncompressed();
        let payload = hash160(&uncompressed_pubkey);
        Address {
            network,
            payload: AddressPayload::P2PKH(payload.to_vec()),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let version = match self.network {
            Network::Mainnet => match self.payload {
                AddressPayload::P2PKH(_) => 0x00,
                AddressPayload::P2SH(_) => 0x05,
            },
            Network::Testnet => match self.payload {
                AddressPayload::P2PKH(_) => 0x6f,
                AddressPayload::P2SH(_) => 0xc4,
            },
        };

        let payload_bytes = match &self.payload {
            AddressPayload::P2PKH(p) => p.as_slice(),
            AddressPayload::P2SH(p) => p.as_slice(),
        };

        write!(f, "{}", payload_bytes.to_base58check(version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;
    use std::str::FromStr;

    #[test]
    fn test_p2pkh_address() {
        // Test vector from mastering bitcoin
        let secp = Secp256k1::new();
        let private_key_hex = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725";
        let private_key = secp256k1::SecretKey::from_str(private_key_hex).unwrap();
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &private_key);

        let address = Address::p2pkh(&public_key, Network::Mainnet);
        assert_eq!(address.to_string(), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
    }
}
