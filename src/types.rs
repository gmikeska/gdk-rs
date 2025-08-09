use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Re-export authentication types
pub use crate::auth::{LoginCredentials, PinData, RegisterLoginResult, AuthManager};

/// Main configuration for the GDK session, mirroring GA_init's JSON config.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GdkConfig {
    /// Directory to store persistent data. If None, session is in-memory only.
    #[serde(rename = "datadir")]
    pub data_dir: Option<PathBuf>,
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
    pub user_agent: Option<String>,
    #[serde(default)]
    pub use_proxy: bool,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub tor_enabled: bool,
}
