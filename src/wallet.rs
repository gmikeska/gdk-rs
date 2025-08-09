//! Wallet logic, including key management and signing.

use crate::bip39::{Mnemonic, Seed};
use crate::primitives::bip32::ExtendedPrivKey;
use crate::Result;

pub struct Wallet {
    master_key: ExtendedPrivKey,
}

impl Wallet {
    pub fn from_mnemonic(mnemonic_str: &str) -> Result<Self> {
        let mnemonic = Mnemonic::from_phrase(mnemonic_str)?;
        let seed = Seed::new(&mnemonic, "");
        let master_key = ExtendedPrivKey::new_master_from_seed(&seed.0)?;
        Ok(Wallet { master_key })
    }
}
