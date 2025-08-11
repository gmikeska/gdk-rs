//! This module defines the Rust structs that map to the GDK JSON API.
//! These are used for serialization/deserialization in communications
//! with the Green backend.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::error::GdkError;
use crate::Result;

use uuid::Uuid;

/// JSON-RPC 2.0 version constant
pub const JSONRPC_VERSION: &str = "2.0";

/// JSON-RPC 2.0 Request
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    pub fn new(method: String, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method,
            params,
            id: Some(serde_json::Value::String(Uuid::new_v4().to_string())),
        }
    }

    pub fn new_notification(method: String, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method,
            params,
            id: None, // Notifications don't have IDs
        }
    }

    pub fn with_id(method: String, params: Option<serde_json::Value>, id: serde_json::Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method,
            params,
            id: Some(id),
        }
    }
}

/// JSON-RPC 2.0 Response
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    pub fn success(result: serde_json::Value, id: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(error: JsonRpcError, id: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// JSON-RPC 2.0 Error
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    // Standard JSON-RPC 2.0 error codes
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    pub fn parse_error() -> Self {
        Self {
            code: Self::PARSE_ERROR,
            message: "Parse error".to_string(),
            data: None,
        }
    }

    pub fn invalid_request() -> Self {
        Self {
            code: Self::INVALID_REQUEST,
            message: "Invalid Request".to_string(),
            data: None,
        }
    }

    pub fn method_not_found() -> Self {
        Self {
            code: Self::METHOD_NOT_FOUND,
            message: "Method not found".to_string(),
            data: None,
        }
    }

    pub fn invalid_params() -> Self {
        Self {
            code: Self::INVALID_PARAMS,
            message: "Invalid params".to_string(),
            data: None,
        }
    }

    pub fn internal_error() -> Self {
        Self {
            code: Self::INTERNAL_ERROR,
            message: "Internal error".to_string(),
            data: None,
        }
    }

    pub fn custom(code: i32, message: String, data: Option<serde_json::Value>) -> Self {
        Self { code, message, data }
    }
}

impl From<JsonRpcError> for GdkError {
    fn from(error: JsonRpcError) -> Self {
        GdkError::network_simple(format!("JSON-RPC Error {}: {}", error.code, error.message))
    }
}

/// Batch request containing multiple JSON-RPC requests
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcBatchRequest(pub Vec<JsonRpcRequest>);

impl JsonRpcBatchRequest {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn add_request(&mut self, request: JsonRpcRequest) {
        self.0.push(request);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Batch response containing multiple JSON-RPC responses
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcBatchResponse(pub Vec<JsonRpcResponse>);

/// Request tracking information for timeout and correlation
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub id: serde_json::Value,
    pub method: String,
    pub created_at: Instant,
    pub timeout: Duration,
}

impl PendingRequest {
    pub fn new(id: serde_json::Value, method: String, timeout: Duration) -> Self {
        Self {
            id,
            method,
            created_at: Instant::now(),
            timeout,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.timeout
    }
}

/// JSON-RPC method validation
pub struct MethodValidator;

impl MethodValidator {
    /// Validate method name according to JSON-RPC 2.0 specification
    pub fn validate_method_name(method: &str) -> Result<()> {
        if method.is_empty() {
            return Err(GdkError::invalid_input_simple("Method name cannot be empty".to_string()));
        }

        if method.starts_with("rpc.") {
            return Err(GdkError::invalid_input_simple("Method names starting with 'rpc.' are reserved".to_string()));
        }

        // Check for valid characters (alphanumeric, underscore, dot, hyphen)
        if !method.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-') {
            return Err(GdkError::invalid_input_simple("Method name contains invalid characters".to_string()));
        }

        Ok(())
    }

    /// Validate request parameters
    pub fn validate_params(params: &Option<serde_json::Value>) -> Result<()> {
        if let Some(params) = params {
            match params {
                serde_json::Value::Object(_) | serde_json::Value::Array(_) => Ok(()),
                _ => Err(GdkError::invalid_input_simple("Parameters must be an Object or Array".to_string())),
            }
        } else {
            Ok(())
        }
    }
}

// Represents a generic call that can be sent to the server (legacy compatibility).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MethodCall {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub method: String,
    pub params: serde_json::Value,
}

impl From<MethodCall> for JsonRpcRequest {
    fn from(call: MethodCall) -> Self {
        JsonRpcRequest::with_id(
            call.method,
            Some(call.params),
            serde_json::Value::String(call.id.to_string()),
        )
    }
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
