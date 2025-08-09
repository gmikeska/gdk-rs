//! This module defines the Rust structs that map to the GDK JSON API.
//! These are used for serialization/deserialization in communications
//! with the Green backend.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use uuid::Uuid;

// Represents a generic call that can be sent to the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MethodCall {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginCredentials {
    pub mnemonic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip39_passphrase: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterLoginResult {
    pub wallet_hash_id: String,
    pub xpub_hash_id: String,
    pub warnings: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Subaccount {
    pub pointer: u32,
    #[serde(rename = "type")]
    pub account_type: String,
    pub name: String,
    pub hidden: bool,
    #[serde(default)]
    pub receiving_id: String,
    #[serde(default)]
    pub core_descriptors: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetSubaccountsParams {
    pub refresh: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SubaccountsList {
    pub subaccounts: Vec<Subaccount>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetTransactionsParams {
    pub subaccount: u32,
    pub first: u32,
    pub count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionListItem {
    pub block_height: u32,
    pub created_at_ts: u64,
    pub fee: u64,
    pub fee_rate: u64,
    pub inputs: Vec<TxIo>,
    pub outputs: Vec<TxIo>,
    pub satoshi: HashMap<String, i64>,
    pub txhash: String,
    #[serde(rename = "type")]
    pub type_str: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxIo {
    pub address: String,
    pub satoshi: u64,
    pub subaccount: u32,
    pub is_relevant: bool,
    pub is_internal: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetUnspentOutputsParams {
    pub subaccount: u32,
    pub num_confs: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnspentOutput {
    pub address: String,
    pub txhash: String,
    pub pt_idx: u32,
    pub satoshi: u64,
    pub subaccount: u32,
    pub address_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnspentOutputs {
    // The key is the asset_id, "btc" for bitcoin.
    pub unspent_outputs: HashMap<String, Vec<UnspentOutput>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetAssetsParams {
    pub details: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetInfo {
    pub asset_id: String,
    pub name: String,
    pub ticker: String,
    pub precision: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Assets {
   pub assets: HashMap<String, AssetInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Addressee {
    pub address: String,
    pub satoshi: u64,
    pub asset_id: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateTransactionParams {
    pub addressees: Vec<Addressee>,
    pub fee_rate: u64,
    pub subaccount: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlockNotification {
    pub block_hash: String,
    pub block_height: u32,
    pub timestamp: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkStatusNotification {
    pub connected: bool,
    pub login_required: bool,
    pub elapsed: u64,
    pub limit: bool,
    pub blocks: u32,
    pub verified: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TwoFactorNotification {
    pub method: String,
    pub action: String,
    pub device: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FeeEstimateNotification {
    pub fees: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SettingsNotification {
    pub event: String,
    pub settings: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetsNotification {
    pub assets_updated: bool,
    pub icons_updated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "event")]
#[serde(rename_all = "snake_case")]
pub enum Notification {
    Block(BlockNotification),
    Transaction(TransactionListItem),
    Network(NetworkStatusNotification),
    TwoFactor(TwoFactorNotification),
    FeeEstimate(FeeEstimateNotification),
    Settings(SettingsNotification),
    Assets(AssetsNotification),
}

/// Notification filter for subscription management
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NotificationFilter {
    pub block_notifications: bool,
    pub transaction_notifications: bool,
    pub network_notifications: bool,
    pub two_factor_notifications: bool,
    pub fee_estimate_notifications: bool,
    pub settings_notifications: bool,
    pub assets_notifications: bool,
    pub subaccount_filter: Option<Vec<u32>>, // Filter by specific subaccounts
}

impl Default for NotificationFilter {
    fn default() -> Self {
        Self {
            block_notifications: true,
            transaction_notifications: true,
            network_notifications: true,
            two_factor_notifications: true,
            fee_estimate_notifications: true,
            settings_notifications: true,
            assets_notifications: true,
            subaccount_filter: None,
        }
    }
}

impl NotificationFilter {
    pub fn should_include(&self, notification: &Notification) -> bool {
        match notification {
            Notification::Block(_) => self.block_notifications,
            Notification::Transaction(tx) => {
                if !self.transaction_notifications {
                    return false;
                }
                // Check subaccount filter
                if let Some(ref filter_subaccounts) = self.subaccount_filter {
                    // Check if any of the transaction's inputs or outputs match the filter
                    let has_matching_subaccount = tx.inputs.iter().any(|input| filter_subaccounts.contains(&input.subaccount))
                        || tx.outputs.iter().any(|output| filter_subaccounts.contains(&output.subaccount));
                    has_matching_subaccount
                } else {
                    true
                }
            }
            Notification::Network(_) => self.network_notifications,
            Notification::TwoFactor(_) => self.two_factor_notifications,
            Notification::FeeEstimate(_) => self.fee_estimate_notifications,
            Notification::Settings(_) => self.settings_notifications,
            Notification::Assets(_) => self.assets_notifications,
        }
    }
}
