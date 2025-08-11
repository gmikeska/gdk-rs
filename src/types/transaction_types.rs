//! Additional transaction-related types needed by the tests

use serde::{Deserialize, Serialize};
use secp256k1::PublicKey;
use crate::primitives::script::Script;
use crate::transaction_signer::ScriptType;

/// Signing information for a transaction input
#[derive(Debug, Clone)]
pub struct SigningInfo {
    pub script_type: ScriptType,
    pub public_key: Option<PublicKey>,
    pub redeem_script: Option<Script>,
    pub witness_script: Option<Script>,
}

/// Filter for transaction queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionFilter {
    pub subaccount: Option<u32>,
    pub count: Option<u32>,
    pub first: Option<u32>,
    pub after_txhash: Option<String>,
}

/// Filter for UTXO queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoFilter {
    pub subaccount: Option<u32>,
    pub num_confs: Option<u32>,
    pub dust_limit: Option<u64>,
}
