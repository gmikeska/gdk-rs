//! Partially Signed Bitcoin Transactions (BIP 174).

use crate::primitives::transaction::Transaction;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Using Vec<u8> for keys and values for simplicity.
// A full implementation would use typed keys.
type Key = Vec<u8>;
type Value = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtGlobal {
    pub unsigned_tx: Option<Transaction>,
    pub xpub: BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>, // xpub -> (fingerprint, path)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtInput {
    pub non_witness_utxo: Option<Transaction>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PsbtOutput {
    // output fields...
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PartiallySignedTransaction {
    pub global: PsbtGlobal,
    pub inputs: Vec<PsbtInput>,
    pub outputs: Vec<PsbtOutput>,
}
