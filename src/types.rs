use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use secp256k1::PublicKey;
use crate::primitives::script::Script;
use crate::transaction_signer::ScriptType;

// Re-export authentication types
pub use crate::auth::{LoginCredentials, PinData, RegisterLoginResult, AuthManager};

// Re-export protocol types
pub use crate::protocol::Addressee;

// Re-export logging types
pub use crate::utils::logging::LogLevel;

/// Main configuration for the GDK session, mirroring GA_init's JSON config.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GdkConfig {
    /// Directory to store persistent data. If None, session is in-memory only.
    #[serde(rename = "datadir")]
    pub data_dir: Option<PathBuf>,
    /// Directory for Tor data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor_dir: Option<PathBuf>,
    /// Directory for asset registry data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_dir: Option<PathBuf>,
    /// Log level for the session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<LogLevel>,
    /// Whether to handle shutdown signals
    #[serde(default)]
    pub with_shutdown: bool,
}

/// Represents a network definition passed to GA_register_network.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Network {
    pub name: String,
    pub network: String, // "mainnet", "testnet", "liquid", "regtest"
    #[serde(default)]
    pub spv_enabled: bool,
}

/// Represents the `connect_params` for GA_connect
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConnectParams {
    pub chain_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub use_proxy: bool,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub tor_enabled: bool,
    #[serde(default)]
    pub use_tor: bool,
    #[serde(default)]
    pub spv_enabled: bool,
    #[serde(default)]
    pub min_fee_rate: Option<u64>,
    #[serde(default)]
    pub electrum_url: Option<String>,
    #[serde(default)]
    pub electrum_tls: bool,
}

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
