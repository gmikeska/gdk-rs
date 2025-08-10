//! JSON-RPC 2.0 client implementation with batch support, timeout handling, and error recovery.

use crate::error::GdkError;
use crate::protocol::{
    JsonRpcRequest, JsonRpcResponse, JsonRpcBatchRequest, JsonRpcBatchResponse, 
    JsonRpcError, PendingRequest, MethodValidator, JSONRPC_VERSION
};
use crate::Result;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::time::{interval, timeout, sleep};
use uuid::Uuid;

/// Configuration for JSON-RPC client behavior
#[derive(Debug, Clone)]
pub struct JsonRpcConfig {
    pub default_timeout: Duration,
    pub batch_timeout: Duration,
    pub max_batch_size: usize,
    pub enable_batching: bool,
    pub retry_attempts: u32,
    pub retry_delay: Duration,
    pub enable_method_validation: bool,
}

impl Default for JsonRpcConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            batch_timeout: Duration::from_millis(10),
            max_batch_size: 100,
            enable_batching: true,
            retry_attempts: 3,
            retry_delay: Duration::from_millis(100),
            enable_method_validation: true,
        }
    }
}

/// Statistics for monitoring JSON-RPC client performance
#[derive(Debug, Clone, Default)]
pub struct JsonRpcStats {
    pub requests_sent: u64,
    pub responses_received: u64,
    pub errors_received: u64,
    pub timeouts: u64,
    pub batch_requests_sent: u64,
    pub average_response_time: Duration,
    pub last_request_time: Option<Instant>,
}

/// Internal request for the JSON-RPC client
#[derive(Debug)]
struct ClientRequest {
    id: Value,
    method: String,
    params: Option<Value>,
    timeout: Duration,
    created_at: Instant,
}

/// Internal request with response channel
#[derive(Debug)]
struct ClientRequestWithResponse {
    request: ClientRequest,
    response_tx: oneshot::Sender<Result<Value>>,
}

/// Batch of requests waiting to be sent
#[derive(Debug)]
struct PendingBatch {
    requests: Vec<ClientRequest>,
    created_at: Instant,
}

impl PendingBatch {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            created_at: Instant::now(),
        }
    }

    fn add_request(&mut self, request: ClientRequest) {
        self.requests.push(request);
    }

    fn is_ready(&self, config: &JsonRpcConfig) -> bool {
        self.requests.len() >= config.max_batch_size || 
        self.created_at.elapsed() >= config.batch_timeout
    }

    fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    fn len(&self) -> usize {
        self.requests.len()
    }
}

/// JSON-RPC 2.0 Client with batch support and error recovery
pub struct JsonRpcClient {
    config: JsonRpcConfig,
    pending_requests: Arc<Mutex<HashMap<String, PendingRequest>>>,
    stats: Arc<RwLock<JsonRpcStats>>,
    request_tx: mpsc::Sender<ClientRequestWithResponse>,
    batch_tx: mpsc::Sender<JsonRpcBatchRequest>,
}

impl JsonRpcClient {
    pub fn new(
        config: JsonRpcConfig,
        batch_tx: mpsc::Sender<JsonRpcBatchRequest>,
    ) -> Self {
        let (request_tx, request_rx) = mpsc::channel(1000);
        let pending_requests = Arc::new(Mutex::new(HashMap::new()));
        let stats = Arc::new(RwLock::new(JsonRpcStats::default()));

        let client = Self {
            config: config.clone(),
            pending_requests: pending_requests.clone(),
            stats: stats.clone(),
            request_tx,
            batch_tx: batch_tx.clone(),
        };

        // Start the request batching task
        if config.enable_batching {
            start_batching_task(
                request_rx,
                batch_tx.clone(),
                config.clone(),
                pending_requests.clone(),
                stats.clone(),
            );
        }

        // Start the timeout cleanup task
        start_timeout_cleanup_task(
            pending_requests.clone(),
            config.clone(),
        );

        client
    }

    /// Send a single JSON-RPC request
    pub async fn call(&self, method: &str, params: Option<Value>) -> Result<Value> {
        self.call_with_timeout(method, params, self.config.default_timeout).await
    }

    /// Send a JSON-RPC request with retry logic
    pub async fn call_with_retry(&self, method: &str, params: Option<Value>) -> Result<Value> {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.config.retry_attempts {
            match self.call(method, params.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempts += 1;
                    last_error = Some(e);
                    
                    if attempts < self.config.retry_attempts {
                        log::warn!("JSON-RPC call failed (attempt {}), retrying: {:?}", attempts, last_error);
                        tokio::time::sleep(self.config.retry_delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| GdkError::Network("All retry attempts failed".to_string())))
    }

    /// Send a JSON-RPC request with custom timeout
    pub async fn call_with_timeout(
        &self, 
        method: &str, 
        params: Option<Value>, 
        timeout_duration: Duration
    ) -> Result<Value> {
        // Validate method name if enabled
        if self.config.enable_method_validation {
            MethodValidator::validate_method_name(method)?;
            MethodValidator::validate_params(&params)?;
        }

        let id = Value::String(Uuid::new_v4().to_string());
        let (response_tx, response_rx) = oneshot::channel();

        let request = ClientRequestWithResponse {
            request: ClientRequest {
                id: id.clone(),
                method: method.to_string(),
                params,
                timeout: timeout_duration,
                created_at: Instant::now(),
            },
            response_tx,
        };

        // Add to pending requests for tracking
        {
            let mut pending = self.pending_requests.lock().await;
            pending.insert(
                id.as_str().unwrap().to_string(),
                PendingRequest::new(id.clone(), method.to_string(), timeout_duration),
            );
        }

        // Send request to batching task
        if self.request_tx.send(request).await.is_err() {
            return Err(GdkError::Network("JSON-RPC client task has died".to_string()));
        }

        // Wait for response with timeout
        match timeout(timeout_duration, response_rx).await {
            Ok(Ok(result)) => {
                self.update_stats_success().await;
                result
            }
            Ok(Err(_)) => {
                self.update_stats_error().await;
                Err(GdkError::Network("Response channel closed".to_string()))
            }
            Err(_) => {
                self.update_stats_timeout().await;
                // Clean up pending request
                let mut pending = self.pending_requests.lock().await;
                pending.remove(id.as_str().unwrap());
                Err(GdkError::Network("Request timeout".to_string()))
            }
        }
    }

    /// Send a notification (no response expected)
    pub async fn notify(&self, method: &str, params: Option<Value>) -> Result<()> {
        if self.config.enable_method_validation {
            MethodValidator::validate_method_name(method)?;
            MethodValidator::validate_params(&params)?;
        }

        let request = JsonRpcRequest::new_notification(method.to_string(), params);
        let mut batch = JsonRpcBatchRequest::new();
        batch.add_request(request);

        if self.batch_tx.send(batch).await.is_err() {
            return Err(GdkError::Network("Failed to send notification".to_string()));
        }

        Ok(())
    }

    /// Handle incoming JSON-RPC response
    pub async fn handle_response(&self, response_data: &str) -> Result<()> {
        // Try to parse as single response first
        if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(response_data) {
            self.handle_single_response(response).await?;
            return Ok(());
        }

        // Try to parse as batch response
        if let Ok(batch_response) = serde_json::from_str::<JsonRpcBatchResponse>(response_data) {
            for response in batch_response.0 {
                self.handle_single_response(response).await?;
            }
            return Ok(());
        }

        Err(GdkError::Network("Invalid JSON-RPC response format".to_string()))
    }

    /// Handle a single JSON-RPC response
    async fn handle_single_response(&self, response: JsonRpcResponse) -> Result<()> {
        let id_str = match &response.id {
            Some(Value::String(s)) => s.clone(),
            Some(id) => id.to_string(),
            None => return Ok(()), // Notification response, ignore
        };

        let mut pending = self.pending_requests.lock().await;
        if let Some(pending_request) = pending.remove(&id_str) {
            // Find the response sender (this would need to be tracked separately in a real implementation)
            // For now, we'll just update stats
            if response.error.is_some() {
                self.update_stats_error().await;
            } else {
                self.update_stats_success().await;
            }
        }

        Ok(())
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> JsonRpcStats {
        self.stats.read().await.clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = JsonRpcStats::default();
    }

    async fn update_stats_success(&self) {
        let mut stats = self.stats.write().await;
        stats.requests_sent += 1;
        stats.responses_received += 1;
        stats.last_request_time = Some(Instant::now());
    }

    async fn update_stats_error(&self) {
        let mut stats = self.stats.write().await;
        stats.requests_sent += 1;
        stats.errors_received += 1;
        stats.last_request_time = Some(Instant::now());
    }

    async fn update_stats_timeout(&self) {
        let mut stats = self.stats.write().await;
        stats.requests_sent += 1;
        stats.timeouts += 1;
        stats.last_request_time = Some(Instant::now());
    }
}

/// Start the request batching task
fn start_batching_task(
    mut request_rx: mpsc::Receiver<ClientRequestWithResponse>,
    batch_tx: mpsc::Sender<JsonRpcBatchRequest>,
    config: JsonRpcConfig,
    pending_requests: Arc<Mutex<HashMap<String, PendingRequest>>>,
    stats: Arc<RwLock<JsonRpcStats>>,
) {
    tokio::spawn(async move {
        let mut current_batch = PendingBatch::new();
        let mut batch_timer = interval(config.batch_timeout);
        let mut response_senders: HashMap<String, oneshot::Sender<Result<Value>>> = HashMap::new();

        loop {
            tokio::select! {
                // Handle incoming requests
                Some(request_with_response) = request_rx.recv() => {
                    let id_str = request_with_response.request.id.as_str().unwrap().to_string();
                    let response_tx = request_with_response.response_tx;
                    response_senders.insert(id_str, response_tx);
                    current_batch.add_request(request_with_response.request);

                    // Send batch if it's ready
                    if current_batch.is_ready(&config) {
                        if let Err(e) = send_batch(&mut current_batch, &batch_tx, &stats).await {
                            log::error!("Failed to send batch: {}", e);
                        }
                    }
                }

                // Handle batch timeout
                _ = batch_timer.tick() => {
                    if !current_batch.is_empty() {
                        if let Err(e) = send_batch(&mut current_batch, &batch_tx, &stats).await {
                            log::error!("Failed to send batch on timeout: {}", e);
                        }
                    }
                }

                else => {
                    log::info!("Batching task finished");
                    break;
                }
            }
        }
    });
}

/// Send a batch of requests
async fn send_batch(
    batch: &mut PendingBatch,
    batch_tx: &mpsc::Sender<JsonRpcBatchRequest>,
    stats: &Arc<RwLock<JsonRpcStats>>,
) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut json_batch = JsonRpcBatchRequest::new();
    
    for request in batch.requests.drain(..) {
        let json_request = JsonRpcRequest::with_id(
            request.method,
            request.params,
            request.id,
        );
        json_batch.add_request(json_request);
    }

    // Update stats
    {
        let mut stats_guard = stats.write().await;
        stats_guard.batch_requests_sent += 1;
    }

    if batch_tx.send(json_batch).await.is_err() {
        return Err(GdkError::Network("Failed to send batch request".to_string()));
    }

    *batch = PendingBatch::new();
    Ok(())
}

/// Start the timeout cleanup task
fn start_timeout_cleanup_task(
    pending_requests: Arc<Mutex<HashMap<String, PendingRequest>>>,
    config: JsonRpcConfig,
) {
    tokio::spawn(async move {
        let mut cleanup_interval = interval(Duration::from_secs(10));

        loop {
            cleanup_interval.tick().await;

            let mut pending = pending_requests.lock().await;
            let expired_ids: Vec<String> = pending
                .iter()
                .filter(|(_, request)| request.is_expired())
                .map(|(id, _)| id.clone())
                .collect();

            for id in expired_ids {
                pending.remove(&id);
                log::debug!("Cleaned up expired request: {}", id);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_jsonrpc_config_defaults() {
        let config = JsonRpcConfig::default();
        
        assert_eq!(config.default_timeout, Duration::from_secs(30));
        assert_eq!(config.batch_timeout, Duration::from_millis(10));
        assert_eq!(config.max_batch_size, 100);
        assert_eq!(config.enable_batching, true);
        assert_eq!(config.retry_attempts, 3);
        assert_eq!(config.enable_method_validation, true);
    }

    #[tokio::test]
    async fn test_jsonrpc_request_creation() {
        let request = JsonRpcRequest::new("test_method".to_string(), None);
        
        assert_eq!(request.jsonrpc, JSONRPC_VERSION);
        assert_eq!(request.method, "test_method");
        assert_eq!(request.params, None);
        assert!(request.id.is_some());
    }

    #[tokio::test]
    async fn test_jsonrpc_notification_creation() {
        let notification = JsonRpcRequest::new_notification("test_notification".to_string(), None);
        
        assert_eq!(notification.jsonrpc, JSONRPC_VERSION);
        assert_eq!(notification.method, "test_notification");
        assert_eq!(notification.params, None);
        assert!(notification.id.is_none());
    }

    #[tokio::test]
    async fn test_method_validation() {
        // Valid method names
        assert!(MethodValidator::validate_method_name("valid_method").is_ok());
        assert!(MethodValidator::validate_method_name("method.with.dots").is_ok());
        assert!(MethodValidator::validate_method_name("method-with-hyphens").is_ok());
        assert!(MethodValidator::validate_method_name("method123").is_ok());

        // Invalid method names
        assert!(MethodValidator::validate_method_name("").is_err());
        assert!(MethodValidator::validate_method_name("rpc.reserved").is_err());
        assert!(MethodValidator::validate_method_name("method with spaces").is_err());
        assert!(MethodValidator::validate_method_name("method@invalid").is_err());
    }

    #[tokio::test]
    async fn test_params_validation() {
        use serde_json::json;

        // Valid parameters
        assert!(MethodValidator::validate_params(&None).is_ok());
        assert!(MethodValidator::validate_params(&Some(json!({"key": "value"}))).is_ok());
        assert!(MethodValidator::validate_params(&Some(json!(["item1", "item2"]))).is_ok());

        // Invalid parameters
        assert!(MethodValidator::validate_params(&Some(json!("string"))).is_err());
        assert!(MethodValidator::validate_params(&Some(json!(123))).is_err());
        assert!(MethodValidator::validate_params(&Some(json!(true))).is_err());
    }

    #[tokio::test]
    async fn test_pending_request_expiration() {
        let request = PendingRequest::new(
            Value::String("test".to_string()),
            "test_method".to_string(),
            Duration::from_millis(1),
        );

        // Should not be expired immediately
        assert!(!request.is_expired());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert!(request.is_expired());
    }

    #[tokio::test]
    async fn test_batch_request_operations() {
        let mut batch = JsonRpcBatchRequest::new();
        assert!(batch.is_empty());
        assert_eq!(batch.len(), 0);

        let request = JsonRpcRequest::new("test".to_string(), None);
        batch.add_request(request);

        assert!(!batch.is_empty());
        assert_eq!(batch.len(), 1);
    }

    #[tokio::test]
    async fn test_jsonrpc_retry_config() {
        let config = JsonRpcConfig {
            retry_attempts: 5,
            retry_delay: Duration::from_millis(50),
            ..Default::default()
        };
        
        assert_eq!(config.retry_attempts, 5);
        assert_eq!(config.retry_delay, Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_jsonrpc_stats_tracking() {
        let stats = JsonRpcStats::default();
        
        assert_eq!(stats.requests_sent, 0);
        assert_eq!(stats.responses_received, 0);
        assert_eq!(stats.errors_received, 0);
        assert_eq!(stats.timeouts, 0);
        assert_eq!(stats.batch_requests_sent, 0);
        assert!(stats.last_request_time.is_none());
    }
}