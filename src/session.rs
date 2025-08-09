//! Session management.

use crate::error::GdkError;
use crate::network::Connection;
use crate::primitives::psbt::PartiallySignedTransaction;
use crate::protocol::{
    Assets, CreateTransactionParams, GetAssetsParams, GetSubaccountsParams, GetTransactionsParams,
    GetUnspentOutputsParams, LoginCredentials, Notification, RegisterLoginResult, SubaccountsList,
    TransactionListItem, UnspentOutputs,
};
use crate::types::{ConnectParams, GdkConfig};
use crate::wallet::Wallet;
use crate::Result;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// Represents a GDK session.
pub struct Session {
    config: Arc<GdkConfig>,
    connection: Option<Connection>,
    notification_sender: broadcast::Sender<Notification>,
    wallet: Arc<Mutex<Option<Wallet>>>,
}

impl Session {
    /// Create a new session.
    pub fn new(config: GdkConfig) -> Self {
        let (tx, _) = broadcast::channel(32);
        Self {
            config: Arc::new(config),
            connection: None,
            notification_sender: tx,
            wallet: Arc::new(Mutex::new(None)),
        }
    }

    /// Subscribe to notifications from the session.
    pub fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.notification_sender.subscribe()
    }

    /// Connect to the Green server and start the notification loop.
    pub async fn connect(&mut self, _params: &ConnectParams, url: &str) -> Result<()> {
        log::info!("Connecting to {}", url);
        let connection = Connection::new(url, self.notification_sender.clone()).await?;
        self.connection = Some(connection);
        log::info!("WebSocket connection successful and connection task started.");
        Ok(())
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: &impl serde::Serialize,
    ) -> Result<T> {
        let connection = self.connection.as_ref().ok_or_else(|| GdkError::Network("Not connected".to_string()))?;
        let params_val = serde_json::to_value(params)?;
        let result_val = connection.call(method, params_val).await?;
        serde_json::from_value(result_val).map_err(GdkError::Json)
    }

    pub async fn login(&self, creds: &LoginCredentials) -> Result<RegisterLoginResult> {
        let login_result = self.call("login_user", creds).await?;
        let wallet = Wallet::from_mnemonic(&creds.mnemonic)?;
        let mut wallet_lock = self.wallet.lock().await;
        *wallet_lock = Some(wallet);
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
}
