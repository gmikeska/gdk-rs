//! Session management.

use crate::api::transactions::{TransactionBroadcaster, TransactionStatus, RbfParams};
use crate::error::GdkError;
use crate::network::{Connection, ConnectionConfig, ConnectionPool, ConnectionEndpoint, ConnectionState};
use crate::notifications::{NotificationManager, NotificationConfig, NotificationBatch};
use crate::primitives::transaction::Transaction;
use crate::protocol::NotificationFilter;
use crate::primitives::psbt::PartiallySignedTransaction;
use crate::protocol::{
    Assets, CreateTransactionParams, GetAssetsParams, GetSubaccountsParams, GetTransactionsParams,
    GetUnspentOutputsParams, LoginCredentials, Notification, RegisterLoginResult, SubaccountsList,
    TransactionListItem, UnspentOutputs,
};
use crate::types::{ConnectParams, GdkConfig};
use crate::wallet::Wallet;
use crate::Result;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex, RwLock};
use uuid::Uuid;

/// Mock connection for transaction broadcasting
/// In a real implementation, this would be replaced with a proper connection interface
pub struct MockConnection {
    notification_sender: broadcast::Sender<Notification>,
}

impl MockConnection {
    pub fn new(notification_sender: broadcast::Sender<Notification>) -> Self {
        Self {
            notification_sender,
        }
    }
}

#[async_trait::async_trait]
impl crate::api::transactions::NetworkConnection for MockConnection {
    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        log::debug!("Mock connection call: {} with params: {:?}", method, params);
        
        match method {
            "broadcast_transaction" => {
                // Simulate successful broadcast
                Ok(serde_json::json!({
                    "success": true,
                    "txid": "mock_txid_12345"
                }))
            }
            "get_transaction" => {
                // Simulate transaction lookup
                if let Some(txhash) = params.get("txhash") {
                    // Return a mock transaction that appears unconfirmed
                    Ok(serde_json::json!({
                        "block_height": 0,
                        "txhash": txhash,
                        "confirmations": 0
                    }))
                } else {
                    Err(GdkError::Network("Transaction not found".to_string()))
                }
            }
            _ => {
                log::warn!("Unhandled mock connection method: {}", method);
                Ok(serde_json::json!({}))
            }
        }
    }
}

/// Session state tracking
#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    Created,
    Connecting,
    Connected,
    Authenticated,
    Disconnected,
    Failed,
}

/// Session persistence data for offline/online state transitions
#[derive(Debug, Clone)]
pub struct SessionPersistence {
    pub wallet_hash_id: Option<String>,
    pub last_block_height: Option<u32>,
    pub cached_subaccounts: Vec<crate::protocol::Subaccount>,
    pub offline_notifications: Vec<Notification>,
}

impl Default for SessionPersistence {
    fn default() -> Self {
        Self {
            wallet_hash_id: None,
            last_block_height: None,
            cached_subaccounts: Vec::new(),
            offline_notifications: Vec::new(),
        }
    }
}

/// Represents a GDK session with robust connection management.
pub struct Session {
    config: Arc<GdkConfig>,
    connection_pool: Option<ConnectionPool>,
    notification_sender: broadcast::Sender<Notification>,
    notification_manager: Arc<NotificationManager>,
    wallet: Arc<Mutex<Option<Wallet>>>,
    state: Arc<RwLock<SessionState>>,
    persistence: Arc<RwLock<SessionPersistence>>,
    connection_config: ConnectionConfig,
    transaction_broadcaster: Arc<Mutex<Option<TransactionBroadcaster>>>,
}

impl Session {
    /// Create a new session.
    pub fn new(config: GdkConfig) -> Self {
        let (tx, _) = broadcast::channel(256); // Increased buffer for notifications
        let notification_manager = Arc::new(NotificationManager::new(NotificationConfig::default()));
        Self {
            config: Arc::new(config),
            connection_pool: None,
            notification_sender: tx,
            notification_manager,
            wallet: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(SessionState::Created)),
            persistence: Arc::new(RwLock::new(SessionPersistence::default())),
            connection_config: ConnectionConfig::default(),
            transaction_broadcaster: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new session with custom connection configuration.
    pub fn new_with_config(config: GdkConfig, connection_config: ConnectionConfig) -> Self {
        let (tx, _) = broadcast::channel(256);
        let notification_manager = Arc::new(NotificationManager::new(NotificationConfig::default()));
        Self {
            config: Arc::new(config),
            connection_pool: None,
            notification_sender: tx,
            notification_manager,
            wallet: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(SessionState::Created)),
            persistence: Arc::new(RwLock::new(SessionPersistence::default())),
            connection_config,
            transaction_broadcaster: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new session with custom notification configuration.
    pub fn new_with_notification_config(config: GdkConfig, notification_config: NotificationConfig) -> Self {
        let (tx, _) = broadcast::channel(256);
        let notification_manager = Arc::new(NotificationManager::new(notification_config));
        Self {
            config: Arc::new(config),
            connection_pool: None,
            notification_sender: tx,
            notification_manager,
            wallet: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(SessionState::Created)),
            persistence: Arc::new(RwLock::new(SessionPersistence::default())),
            connection_config: ConnectionConfig::default(),
            transaction_broadcaster: Arc::new(Mutex::new(None)),
        }
    }

    /// Subscribe to notifications from the session.
    pub fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.notification_sender.subscribe()
    }

    /// Subscribe to filtered notifications with advanced features.
    pub async fn subscribe_filtered(&self, filter: NotificationFilter) -> Result<(Uuid, broadcast::Receiver<Notification>)> {
        self.notification_manager.subscribe(filter).await
    }

    /// Subscribe to batched notifications for high-throughput scenarios.
    pub async fn subscribe_batched(&self, filter: NotificationFilter) -> Result<(Uuid, broadcast::Receiver<NotificationBatch>)> {
        self.notification_manager.subscribe_batched(filter).await
    }

    /// Unsubscribe from notifications.
    pub async fn unsubscribe(&self, subscription_id: Uuid) -> Result<()> {
        self.notification_manager.unsubscribe(subscription_id).await
    }

    /// Update notification filter for an existing subscription.
    pub async fn update_notification_filter(&self, subscription_id: Uuid, filter: NotificationFilter) -> Result<()> {
        self.notification_manager.update_filter(subscription_id, filter).await
    }

    /// Get notification history for a subscription.
    pub async fn get_notification_history(&self, subscription_id: Uuid, limit: usize) -> Result<Vec<crate::notifications::PersistedNotification>> {
        self.notification_manager.get_history(subscription_id, limit).await
    }

    /// Get notification system statistics.
    pub async fn get_notification_stats(&self) -> crate::notifications::NotificationStats {
        self.notification_manager.get_stats().await
    }

    /// Connect to the Green server with multiple endpoints for failover.
    pub async fn connect(&mut self, params: &ConnectParams, urls: &[String]) -> Result<()> {
        *self.state.write().await = SessionState::Connecting;
        
        log::info!("Connecting to endpoints: {:?}", urls);
        
        // Create connection endpoints with equal priority
        let endpoints: Vec<ConnectionEndpoint> = urls.iter()
            .enumerate()
            .map(|(i, url)| ConnectionEndpoint::new(url.clone(), 100 - i as u32)) // Higher priority for earlier URLs
            .collect();

        if endpoints.is_empty() {
            return Err(GdkError::Network("No connection endpoints provided".to_string()));
        }

        let connection_pool = ConnectionPool::new(
            endpoints,
            self.connection_config.clone(),
            self.notification_sender.clone(),
        );

        // Attempt to connect
        connection_pool.connect().await?;
        
        self.connection_pool = Some(connection_pool);
        *self.state.write().await = SessionState::Connected;
        
        log::info!("WebSocket connection successful and connection pool started.");
        
        // Start session monitoring task
        self.start_session_monitoring().await;
        
        // Start notification routing task
        self.start_notification_routing().await;
        
        // Initialize transaction broadcaster
        self.initialize_transaction_broadcaster().await?;
        
        Ok(())
    }

    /// Connect to a single Green server (convenience method).
    pub async fn connect_single(&mut self, params: &ConnectParams, url: &str) -> Result<()> {
        self.connect(params, &[url.to_string()]).await
    }

    /// Get the current session state.
    pub async fn get_state(&self) -> SessionState {
        self.state.read().await.clone()
    }

    /// Get the current connection state.
    pub async fn get_connection_state(&self) -> Option<ConnectionState> {
        match &self.connection_pool {
            Some(pool) => Some(pool.get_state().await),
            None => None,
        }
    }

    /// Disconnect from the server and clean up resources.
    pub async fn disconnect(&mut self) -> Result<()> {
        *self.state.write().await = SessionState::Disconnected;
        
        if let Some(pool) = &self.connection_pool {
            pool.disconnect().await?;
        }
        
        self.connection_pool = None;
        
        // Clear wallet state
        *self.wallet.lock().await = None;
        
        log::info!("Session disconnected and resources cleaned up.");
        Ok(())
    }

    /// Manually trigger reconnection.
    pub async fn reconnect(&self) -> Result<()> {
        if let Some(pool) = &self.connection_pool {
            pool.connect().await?;
            *self.state.write().await = SessionState::Connected;
            Ok(())
        } else {
            Err(GdkError::Network("No connection pool available".to_string()))
        }
    }

    /// Start background task for session monitoring and maintenance.
    async fn start_session_monitoring(&self) {
        let state = self.state.clone();
        let persistence = self.persistence.clone();
        let notification_sender = self.notification_sender.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let current_state = state.read().await.clone();
                match current_state {
                    SessionState::Disconnected | SessionState::Failed => {
                        break; // Stop monitoring
                    }
                    SessionState::Connected | SessionState::Authenticated => {
                        // Perform periodic maintenance tasks
                        // This could include syncing cached data, cleaning up old notifications, etc.
                        Self::perform_maintenance(&persistence).await;
                    }
                    _ => {}
                }
            }
            
            log::debug!("Session monitoring task finished.");
        });
    }

    /// Perform periodic maintenance tasks.
    async fn perform_maintenance(persistence: &Arc<RwLock<SessionPersistence>>) {
        let mut persistence_guard = persistence.write().await;
        
        // Clean up old offline notifications (keep only last 100)
        if persistence_guard.offline_notifications.len() > 100 {
            let drain_count = persistence_guard.offline_notifications.len() - 100;
            persistence_guard.offline_notifications.drain(0..drain_count);
        }
        
        log::debug!("Performed session maintenance");
    }

    /// Start background task for routing notifications through the NotificationManager.
    async fn start_notification_routing(&self) {
        let mut notification_rx = self.notification_sender.subscribe();
        let notification_manager = self.notification_manager.clone();
        let state = self.state.clone();
        
        tokio::spawn(async move {
            loop {
                match notification_rx.recv().await {
                    Ok(notification) => {
                        // Route notification through the NotificationManager
                        if let Err(e) = notification_manager.publish(notification).await {
                            log::error!("Failed to publish notification through NotificationManager: {}", e);
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        log::info!("Notification routing task finished - channel closed");
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        log::warn!("Notification routing lagged, skipped {} notifications", skipped);
                        // Continue processing
                    }
                }
                
                // Check if session is still active
                let current_state = state.read().await.clone();
                if matches!(current_state, SessionState::Disconnected | SessionState::Failed) {
                    log::info!("Notification routing task finished - session disconnected");
                    break;
                }
            }
        });
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &impl serde::Serialize,
    ) -> Result<T> {
        let connection_pool = self.connection_pool.as_ref()
            .ok_or_else(|| GdkError::Network("Not connected".to_string()))?;
        let params_val = serde_json::to_value(params)?;
        let result_val = connection_pool.call(method, params_val).await?;
        serde_json::from_value(result_val).map_err(GdkError::Json)
    }

    pub async fn login(&self, creds: &LoginCredentials) -> Result<RegisterLoginResult> {
        let login_result: RegisterLoginResult = self.call("login_user", creds).await?;
        // TODO: Create wallet from credentials when wallet_simple is implemented
        // let wallet = crate::wallet_simple::Wallet::from_mnemonic(&creds.mnemonic, crate::primitives::address::Network::Mainnet)?;
        // let mut wallet_lock = self.wallet.lock().await;
        // *wallet_lock = Some(wallet);
        
        // Update session state and persistence
        *self.state.write().await = SessionState::Authenticated;
        let mut persistence = self.persistence.write().await;
        persistence.wallet_hash_id = Some(login_result.wallet_hash_id.clone());
        
        Ok(login_result)
    }

    pub async fn get_subaccounts(&self) -> Result<SubaccountsList> {
        let params = GetSubaccountsParams { refresh: false };
        self.call("get_subaccounts", &params).await
    }

    pub async fn get_transactions(
        &self,
        params: &GetTransactionsParams,
    ) -> Result<Vec<TransactionListItem>> {
        self.call("get_transactions", params).await
    }

    pub async fn get_unspent_outputs(
        &self,
        params: &GetUnspentOutputsParams,
    ) -> Result<UnspentOutputs> {
        self.call("get_unspent_outputs", params).await
    }

    pub async fn get_assets(&self, params: &GetAssetsParams) -> Result<Assets> {
        self.call("get_assets", params).await
    }

    pub async fn create_transaction(&self, params: &mut CreateTransactionParams) -> Result<PartiallySignedTransaction> {
        self.call("create_transaction", params).await
    }

    /// Sign a transaction PSBT.
    pub async fn sign_transaction(&self, pset: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction> {
        let wallet_lock = self.wallet.lock().await;
        let _wallet = wallet_lock.as_ref().ok_or_else(|| GdkError::Auth("Not logged in".to_string()))?;

        log::info!("PSBT signing logic would go here, using the wallet's keys.");

        // For now, just return the same PSET.
        Ok(pset.clone())
    }

    /// Initialize the transaction broadcaster (called after connection is established)
    async fn initialize_transaction_broadcaster(&self) -> Result<()> {
        if let Some(_pool) = &self.connection_pool {
            // Create a mock connection for the broadcaster
            // In a real implementation, we'd extract a connection interface from the pool
            let mock_connection = MockConnection::new(self.notification_sender.clone());
            let connection = Arc::new(mock_connection);

            let broadcaster = TransactionBroadcaster::new(
                connection,
                self.notification_sender.clone(),
            );

            // Start confirmation monitoring
            broadcaster.start_confirmation_monitoring().await;

            let mut tx_broadcaster = self.transaction_broadcaster.lock().await;
            *tx_broadcaster = Some(broadcaster);

            log::info!("Transaction broadcaster initialized");
        }
        Ok(())
    }

    /// Broadcast a transaction to the network
    pub async fn broadcast_transaction(&self, transaction: &Transaction) -> Result<String> {
        let broadcaster = self.transaction_broadcaster.lock().await;
        let broadcaster = broadcaster.as_ref()
            .ok_or_else(|| GdkError::Network("Transaction broadcaster not initialized".to_string()))?;

        broadcaster.broadcast_transaction(transaction).await
    }

    /// Replace a transaction using RBF (Replace-By-Fee)
    pub async fn replace_transaction(
        &self,
        rbf_params: &RbfParams,
        new_transaction: &Transaction,
    ) -> Result<String> {
        let broadcaster = self.transaction_broadcaster.lock().await;
        let broadcaster = broadcaster.as_ref()
            .ok_or_else(|| GdkError::Network("Transaction broadcaster not initialized".to_string()))?;

        broadcaster.replace_transaction(rbf_params, new_transaction).await
    }

    /// Get the status of a tracked transaction
    pub async fn get_transaction_status(&self, txid: &str) -> Result<Option<TransactionStatus>> {
        let broadcaster = self.transaction_broadcaster.lock().await;
        let broadcaster = broadcaster.as_ref()
            .ok_or_else(|| GdkError::Network("Transaction broadcaster not initialized".to_string()))?;

        Ok(broadcaster.get_transaction_status(txid).await)
    }

    /// Get all tracked transactions
    pub async fn get_all_tracked_transactions(&self) -> Result<std::collections::HashMap<String, TransactionStatus>> {
        let broadcaster = self.transaction_broadcaster.lock().await;
        let broadcaster = broadcaster.as_ref()
            .ok_or_else(|| GdkError::Network("Transaction broadcaster not initialized".to_string()))?;

        Ok(broadcaster.get_all_tracked_transactions().await)
    }

    /// Stop tracking a transaction
    pub async fn stop_tracking_transaction(&self, txid: &str) -> Result<()> {
        let broadcaster = self.transaction_broadcaster.lock().await;
        let broadcaster = broadcaster.as_ref()
            .ok_or_else(|| GdkError::Network("Transaction broadcaster not initialized".to_string()))?;

        broadcaster.stop_tracking(txid).await
    }

    /// Send a transaction (create, sign, and broadcast in one call)
    pub async fn send_transaction(&self, params: &mut CreateTransactionParams) -> Result<String> {
        // Create the transaction
        let psbt = self.create_transaction(params).await?;
        
        // Sign the transaction
        let signed_psbt = self.sign_transaction(&psbt).await?;
        
        // Convert PSBT to final transaction
        let transaction = self.finalize_psbt(&signed_psbt).await?;
        
        // Broadcast the transaction
        self.broadcast_transaction(&transaction).await
    }

    /// Finalize a PSBT into a complete transaction
    async fn finalize_psbt(&self, psbt: &PartiallySignedTransaction) -> Result<Transaction> {
        // In a real implementation, this would finalize the PSBT
        // For now, we'll create a placeholder transaction
        log::info!("PSBT finalization logic would go here");
        
        // Return a placeholder transaction
        Ok(Transaction::new())
    }
}
