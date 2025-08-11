//! Transaction broadcasting and tracking functionality.

use crate::error::GdkError;
use crate::primitives::encode::Encodable;
use crate::primitives::transaction::Transaction;
use crate::protocol::{Notification, TransactionListItem};
use crate::{Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, RwLock, Mutex};

/// Trait for network connections that can be used by the transaction broadcaster
#[async_trait]
pub trait NetworkConnection: Send + Sync {
    /// Make a JSON-RPC call to the network
    async fn call(&self, method: &str, params: Value) -> Result<Value>;
}

/// Transaction broadcast status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BroadcastStatus {
    /// Transaction is pending broadcast
    Pending,
    /// Transaction has been broadcast to the network
    Broadcast,
    /// Transaction has been confirmed in a block
    Confirmed { block_height: u32, confirmations: u32 },
    /// Transaction broadcast failed
    Failed { error: String, retry_count: u32 },
    /// Transaction was replaced (RBF)
    Replaced { replacement_txid: String },
    /// Transaction was rejected by the network
    Rejected { reason: String },
}

/// Transaction status tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionStatus {
    /// Transaction ID
    pub txid: String,
    /// Current broadcast status
    pub status: BroadcastStatus,
    /// Transaction hex data
    pub transaction_hex: String,
    /// Fee rate in sat/vbyte
    pub fee_rate: u64,
    /// Total fee in satoshis
    pub fee: u64,
    /// Timestamp when transaction was created
    pub created_at: u64,
    /// Timestamp when transaction was broadcast
    pub broadcast_at: Option<u64>,
    /// Timestamp when transaction was confirmed
    pub confirmed_at: Option<u64>,
    /// Number of broadcast attempts
    pub broadcast_attempts: u32,
    /// Last error message (if any)
    pub last_error: Option<String>,
    /// Whether RBF is enabled for this transaction
    pub rbf_enabled: bool,
    /// Parent transaction ID (for RBF replacements)
    pub replaces_txid: Option<String>,
}

impl TransactionStatus {
    pub fn new(txid: String, transaction_hex: String, fee_rate: u64, fee: u64, rbf_enabled: bool) -> Self {
        Self {
            txid,
            status: BroadcastStatus::Pending,
            transaction_hex,
            fee_rate,
            fee,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            broadcast_at: None,
            confirmed_at: None,
            broadcast_attempts: 0,
            last_error: None,
            rbf_enabled,
            replaces_txid: None,
        }
    }

    pub fn is_final(&self) -> bool {
        matches!(
            self.status,
            BroadcastStatus::Confirmed { .. } | BroadcastStatus::Replaced { .. } | BroadcastStatus::Rejected { .. }
        )
    }

    pub fn can_retry(&self) -> bool {
        matches!(self.status, BroadcastStatus::Failed { .. }) && self.broadcast_attempts < 5
    }
}

/// RBF (Replace-By-Fee) transaction parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbfParams {
    /// Original transaction ID to replace
    pub original_txid: String,
    /// New fee rate (must be higher than original)
    pub new_fee_rate: u64,
    /// Optional new recipients (if changing outputs)
    pub new_addressees: Option<Vec<crate::protocol::Addressee>>,
    /// Whether to increase fee by adding to existing fee or replacing entirely
    pub fee_bump_type: FeeBumpType,
}

/// Type of fee bump for RBF
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeBumpType {
    /// Add the specified amount to the existing fee
    Additive,
    /// Replace the fee entirely with the new amount
    Absolute,
}

/// Broadcast retry configuration
#[derive(Debug, Clone)]
pub struct BroadcastRetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub backoff_multiplier: f64,
    pub retry_on_errors: Vec<String>,
}

impl Default for BroadcastRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            retry_on_errors: vec![
                "network error".to_string(),
                "timeout".to_string(),
                "connection failed".to_string(),
                "temporary failure".to_string(),
            ],
        }
    }
}

/// Transaction broadcaster and tracker
pub struct TransactionBroadcaster {
    /// Network connection for broadcasting
    connection: Arc<dyn NetworkConnection>,
    /// Tracked transactions
    tracked_transactions: Arc<RwLock<HashMap<String, TransactionStatus>>>,
    /// Notification sender for transaction updates
    notification_sender: broadcast::Sender<Notification>,
    /// Retry configuration
    retry_config: BroadcastRetryConfig,
    /// Background task handles
    task_handles: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl TransactionBroadcaster {
    /// Create a new transaction broadcaster
    pub fn new(
        connection: Arc<dyn NetworkConnection>,
        notification_sender: broadcast::Sender<Notification>,
    ) -> Self {
        Self {
            connection,
            tracked_transactions: Arc::new(RwLock::new(HashMap::new())),
            notification_sender,
            retry_config: BroadcastRetryConfig::default(),
            task_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a broadcaster with custom retry configuration
    pub fn with_retry_config(
        connection: Arc<dyn NetworkConnection>,
        notification_sender: broadcast::Sender<Notification>,
        retry_config: BroadcastRetryConfig,
    ) -> Self {
        Self {
            connection,
            tracked_transactions: Arc::new(RwLock::new(HashMap::new())),
            notification_sender,
            retry_config,
            task_handles: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&self, transaction: &Transaction) -> Result<String> {
        let transaction_hex = hex::encode(transaction.consensus_encode_to_vec()?);
        let txid = hex::encode(transaction.txid());

        log::info!("Broadcasting transaction: {}", txid);

        // Create transaction status
        let fee = self.calculate_transaction_fee(transaction).await?;
        let fee_rate = self.calculate_fee_rate(transaction, fee).await?;
        let rbf_enabled = self.is_rbf_enabled(transaction);

        let status = TransactionStatus::new(
            txid.clone(),
            transaction_hex.clone(),
            fee_rate,
            fee,
            rbf_enabled,
        );

        // Add to tracking
        {
            let mut tracked = self.tracked_transactions.write().await;
            tracked.insert(txid.clone(), status);
        }

        // Start broadcast task
        self.start_broadcast_task(txid.clone(), transaction_hex).await;

        Ok(txid)
    }

    /// Replace a transaction using RBF
    pub async fn replace_transaction(
        &self,
        rbf_params: &RbfParams,
        new_transaction: &Transaction,
    ) -> Result<String> {
        let original_status = {
            let tracked = self.tracked_transactions.read().await;
            tracked.get(&rbf_params.original_txid).cloned()
        };

        let original_status = original_status
            .ok_or_else(|| GdkError::invalid_input_simple("Original transaction not found".to_string()))?;

        // Validate RBF conditions
        if !original_status.rbf_enabled {
            return Err(GdkError::invalid_input_simple("Original transaction does not support RBF".to_string()));
        }

        if original_status.is_final() {
            return Err(GdkError::invalid_input_simple("Cannot replace finalized transaction".to_string()));
        }

        if rbf_params.new_fee_rate <= original_status.fee_rate {
            return Err(GdkError::invalid_input_simple("New fee rate must be higher than original".to_string()));
        }

        let new_txid = hex::encode(new_transaction.txid());
        let transaction_hex = hex::encode(new_transaction.consensus_encode_to_vec()?);

        log::info!("Replacing transaction {} with {}", rbf_params.original_txid, new_txid);

        // Create new transaction status
        let fee = self.calculate_transaction_fee(new_transaction).await?;
        let fee_rate = self.calculate_fee_rate(new_transaction, fee).await?;

        let mut new_status = TransactionStatus::new(
            new_txid.clone(),
            transaction_hex.clone(),
            fee_rate,
            fee,
            true, // RBF replacements are always RBF-enabled
        );
        new_status.replaces_txid = Some(rbf_params.original_txid.clone());

        // Update original transaction status
        {
            let mut tracked = self.tracked_transactions.write().await;
            
            // Mark original as replaced
            if let Some(original) = tracked.get_mut(&rbf_params.original_txid) {
                original.status = BroadcastStatus::Replaced {
                    replacement_txid: new_txid.clone(),
                };
            }

            // Add new transaction
            tracked.insert(new_txid.clone(), new_status);
        }

        // Start broadcast task for replacement
        self.start_broadcast_task(new_txid.clone(), transaction_hex).await;

        // Send notification about replacement
        self.send_replacement_notification(&rbf_params.original_txid, &new_txid).await;

        Ok(new_txid)
    }

    /// Get the status of a tracked transaction
    pub async fn get_transaction_status(&self, txid: &str) -> Option<TransactionStatus> {
        let tracked = self.tracked_transactions.read().await;
        tracked.get(txid).cloned()
    }

    /// Get all tracked transactions
    pub async fn get_all_tracked_transactions(&self) -> HashMap<String, TransactionStatus> {
        let tracked = self.tracked_transactions.read().await;
        tracked.clone()
    }

    /// Remove a transaction from tracking
    pub async fn stop_tracking(&self, txid: &str) -> Result<()> {
        let mut tracked = self.tracked_transactions.write().await;
        tracked.remove(txid);
        log::debug!("Stopped tracking transaction: {}", txid);
        Ok(())
    }

    /// Start monitoring for transaction confirmations
    pub async fn start_confirmation_monitoring(&self) {
        let tracked_transactions = self.tracked_transactions.clone();
        let connection = self.connection.clone();
        let notification_sender = self.notification_sender.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let txids: Vec<String> = {
                    let tracked = tracked_transactions.read().await;
                    tracked
                        .iter()
                        .filter(|(_, status)| {
                            matches!(status.status, BroadcastStatus::Broadcast)
                        })
                        .map(|(txid, _)| txid.clone())
                        .collect()
                };

                for txid in txids {
                    if let Err(e) = Self::check_transaction_confirmation(
                        &txid,
                        &connection,
                        &tracked_transactions,
                        &notification_sender,
                    ).await {
                        log::warn!("Failed to check confirmation for {}: {}", txid, e);
                    }
                }
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(handle);
    }

    /// Start a background task to broadcast a transaction with retry logic
    async fn start_broadcast_task(&self, txid: String, transaction_hex: String) {
        let connection = self.connection.clone();
        let tracked_transactions = self.tracked_transactions.clone();
        let notification_sender = self.notification_sender.clone();
        let retry_config = self.retry_config.clone();

        let handle = tokio::spawn(async move {
            let mut attempt = 0;
            let mut delay = retry_config.initial_delay;

            loop {
                attempt += 1;

                // Update attempt count
                {
                    let mut tracked = tracked_transactions.write().await;
                    if let Some(status) = tracked.get_mut(&txid) {
                        status.broadcast_attempts = attempt;
                    }
                }

                match Self::broadcast_transaction_once(&connection, &transaction_hex).await {
                    Ok(()) => {
                        log::info!("Successfully broadcast transaction: {}", txid);
                        
                        // Update status to broadcast
                        {
                            let mut tracked = tracked_transactions.write().await;
                            if let Some(status) = tracked.get_mut(&txid) {
                                status.status = BroadcastStatus::Broadcast;
                                status.broadcast_at = Some(
                                    std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs(),
                                );
                                status.last_error = None;
                            }
                        }

                        // Send notification
                        Self::send_broadcast_notification(&notification_sender, &txid, true, None).await;
                        break;
                    }
                    Err(e) => {
                        log::warn!("Failed to broadcast transaction {} (attempt {}): {}", txid, attempt, e);

                        let error_msg = e.to_string();
                        let should_retry = attempt < retry_config.max_attempts
                            && retry_config.retry_on_errors.iter().any(|retry_error| {
                                error_msg.to_lowercase().contains(&retry_error.to_lowercase())
                            });

                        // Update status
                        {
                            let mut tracked = tracked_transactions.write().await;
                            if let Some(status) = tracked.get_mut(&txid) {
                                status.last_error = Some(error_msg.clone());
                                if should_retry {
                                    status.status = BroadcastStatus::Failed {
                                        error: error_msg.clone(),
                                        retry_count: attempt,
                                    };
                                } else {
                                    status.status = BroadcastStatus::Rejected {
                                        reason: error_msg.clone(),
                                    };
                                }
                            }
                        }

                        if should_retry {
                            log::info!("Retrying broadcast for {} in {:?}", txid, delay);
                            tokio::time::sleep(delay).await;
                            
                            // Exponential backoff
                            delay = std::cmp::min(
                                Duration::from_millis(
                                    (delay.as_millis() as f64 * retry_config.backoff_multiplier) as u64
                                ),
                                retry_config.max_delay,
                            );
                        } else {
                            log::error!("Giving up on broadcasting transaction {}: {}", txid, error_msg);
                            Self::send_broadcast_notification(&notification_sender, &txid, false, Some(error_msg)).await;
                            break;
                        }
                    }
                }
            }
        });

        let mut handles = self.task_handles.lock().await;
        handles.push(handle);
    }

    /// Broadcast a transaction once (single attempt)
    async fn broadcast_transaction_once(
        connection: &Arc<dyn NetworkConnection>,
        transaction_hex: &str,
    ) -> Result<()> {
        let params = serde_json::json!({
            "tx": transaction_hex
        });

        let _result: serde_json::Value = connection.call("broadcast_transaction", params).await?;
        Ok(())
    }

    /// Check if a transaction has been confirmed
    async fn check_transaction_confirmation(
        txid: &str,
        connection: &Arc<dyn NetworkConnection>,
        tracked_transactions: &Arc<RwLock<HashMap<String, TransactionStatus>>>,
        notification_sender: &broadcast::Sender<Notification>,
    ) -> Result<()> {
        let params = serde_json::json!({
            "txhash": txid
        });

        match connection.call("get_transaction", params).await {
            Ok(result) => {
                if let Ok(tx_info) = serde_json::from_value::<TransactionListItem>(result) {
                    if tx_info.block_height > 0 {
                        // Transaction is confirmed
                        let confirmations = Self::calculate_confirmations(tx_info.block_height).await;
                        
                        {
                            let mut tracked = tracked_transactions.write().await;
                            if let Some(status) = tracked.get_mut(txid) {
                                if !matches!(status.status, BroadcastStatus::Confirmed { .. }) {
                                    status.status = BroadcastStatus::Confirmed {
                                        block_height: tx_info.block_height,
                                        confirmations,
                                    };
                                    status.confirmed_at = Some(
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs(),
                                    );

                                    // Send confirmation notification
                                    Self::send_confirmation_notification(
                                        notification_sender,
                                        txid,
                                        tx_info.block_height,
                                        confirmations,
                                    ).await;
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Transaction not found or other error - this is normal for unconfirmed transactions
            }
        }

        Ok(())
    }

    /// Calculate the number of confirmations for a transaction
    async fn calculate_confirmations(block_height: u32) -> u32 {
        // In a real implementation, this would get the current block height from the network
        // For now, we'll assume a reasonable number
        let current_height = block_height + 1; // Simplified
        if current_height > block_height {
            current_height - block_height + 1
        } else {
            0
        }
    }

    /// Send a broadcast notification
    async fn send_broadcast_notification(
        notification_sender: &broadcast::Sender<Notification>,
        txid: &str,
        success: bool,
        error: Option<String>,
    ) {
        // Create a transaction notification
        let notification = if success {
            log::info!("Transaction {} broadcast successfully", txid);
            // In a real implementation, we'd create a proper transaction notification
            return;
        } else {
            log::error!("Transaction {} broadcast failed: {:?}", txid, error);
            return;
        };
    }

    /// Send a confirmation notification
    async fn send_confirmation_notification(
        notification_sender: &broadcast::Sender<Notification>,
        txid: &str,
        block_height: u32,
        confirmations: u32,
    ) {
        log::info!(
            "Transaction {} confirmed in block {} with {} confirmations",
            txid, block_height, confirmations
        );
        // In a real implementation, we'd create a proper confirmation notification
    }

    /// Send a replacement notification
    async fn send_replacement_notification(&self, original_txid: &str, new_txid: &str) {
        log::info!("Transaction {} replaced by {}", original_txid, new_txid);
        // In a real implementation, we'd create a proper replacement notification
    }

    /// Calculate transaction fee (simplified implementation)
    async fn calculate_transaction_fee(&self, transaction: &Transaction) -> Result<u64> {
        // In a real implementation, this would calculate the actual fee
        // by looking up input values and subtracting output values
        Ok(1000) // Placeholder
    }

    /// Calculate fee rate in sat/vbyte
    async fn calculate_fee_rate(&self, transaction: &Transaction, fee: u64) -> Result<u64> {
        let tx_size = transaction.consensus_encode_to_vec()?.len() as u64;
        let vsize = self.calculate_virtual_size(transaction).await?;
        Ok(fee / vsize.max(1))
    }

    /// Calculate virtual size for fee rate calculation
    async fn calculate_virtual_size(&self, transaction: &Transaction) -> Result<u64> {
        // Simplified vsize calculation
        let base_size = transaction.consensus_encode_to_vec()?.len() as u64;
        let witness_size: u64 = transaction
            .input
            .iter()
            .map(|input| input.witness.iter().map(|w| w.len() as u64).sum::<u64>())
            .sum();
        
        // BIP141 weight calculation: (base_size * 3 + total_size) / 4
        let weight = base_size * 3 + base_size + witness_size;
        Ok((weight + 3) / 4) // Round up
    }

    /// Check if RBF is enabled for a transaction
    fn is_rbf_enabled(&self, transaction: &Transaction) -> bool {
        // RBF is signaled by having at least one input with sequence < 0xfffffffe
        transaction.input.iter().any(|input| input.sequence < 0xfffffffe)
    }

    /// Shutdown the broadcaster and clean up background tasks
    pub async fn shutdown(&self) {
        let mut handles = self.task_handles.lock().await;
        for handle in handles.drain(..) {
            handle.abort();
        }
        log::info!("Transaction broadcaster shutdown complete");
    }
}

impl Drop for TransactionBroadcaster {
    fn drop(&mut self) {
        // Note: This is not async, so we can't properly wait for tasks to finish
        // In a real implementation, you'd want to call shutdown() explicitly
        log::debug!("TransactionBroadcaster dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::transaction::{TxIn, TxOut, OutPoint};
    use crate::primitives::script::Script;

    fn create_test_transaction() -> Transaction {
        let mut tx = Transaction::new();
        tx.version = 2;
        
        // Add a test input with RBF sequence
        let outpoint = OutPoint::new([1u8; 32], 0);
        let input = TxIn::new(outpoint, Script::new(), 0xfffffffd); // RBF enabled
        tx.input.push(input);
        
        // Add a test output
        let output = TxOut::new(50000, Script::new());
        tx.output.push(output);
        
        tx
    }

    #[tokio::test]
    async fn test_transaction_status_creation() {
        let status = TransactionStatus::new(
            "test_txid".to_string(),
            "test_hex".to_string(),
            10,
            1000,
            true,
        );

        assert_eq!(status.txid, "test_txid");
        assert_eq!(status.status, BroadcastStatus::Pending);
        assert_eq!(status.fee_rate, 10);
        assert_eq!(status.fee, 1000);
        assert!(status.rbf_enabled);
        assert!(!status.is_final());
    }

    #[test]
    fn test_broadcast_status_final() {
        assert!(matches!(
            BroadcastStatus::Confirmed { block_height: 100, confirmations: 1 },
            status if matches!(status, BroadcastStatus::Confirmed { .. })
        ));
        
        let status = TransactionStatus {
            txid: "test".to_string(),
            status: BroadcastStatus::Confirmed { block_height: 100, confirmations: 1 },
            transaction_hex: "".to_string(),
            fee_rate: 0,
            fee: 0,
            created_at: 0,
            broadcast_at: None,
            confirmed_at: None,
            broadcast_attempts: 0,
            last_error: None,
            rbf_enabled: false,
            replaces_txid: None,
        };
        
        assert!(status.is_final());
    }

    #[test]
    #[ignore] // Incomplete test - needs mock connection implementation
    fn test_rbf_detection() {
        let tx = create_test_transaction();
        
        // Mock broadcaster for testing
        // let (notification_tx, _) = broadcast::channel(10);
        // let connection = Arc::new(
        //     // This would need a mock connection in a real test
        //     // For now, we'll skip this test
        // );
        
        // Test would verify RBF detection logic
        // assert!(broadcaster.is_rbf_enabled(&tx));
    }

    #[test]
    fn test_fee_bump_type() {
        assert_eq!(FeeBumpType::Additive, FeeBumpType::Additive);
        assert_ne!(FeeBumpType::Additive, FeeBumpType::Absolute);
    }

    #[test]
    fn test_retry_config_defaults() {
        let config = BroadcastRetryConfig::default();
        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_delay, Duration::from_secs(1));
        assert!(!config.retry_on_errors.is_empty());
    }
}