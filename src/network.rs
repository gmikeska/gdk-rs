//! Network connection management with robust WebSocket communication.
//!
//! This module provides comprehensive WebSocket communication capabilities including:
//! - TLS support for secure connections
//! - Message queuing with delivery guarantees
//! - Connection pooling for multiple endpoints
//! - Message compression and optimization
//! - Comprehensive error handling and recovery

use crate::error::GdkError;
use crate::protocol::{MethodCall, Notification};
use crate::Result;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock, Semaphore};
use tokio::time::{interval, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{WebSocketStream, connect_async, connect_async_tls_with_config};
use tokio::net::TcpStream;
use uuid::Uuid;

#[cfg(feature = "compression")]
use flate2::{Compression, write::GzEncoder, read::GzDecoder};
#[cfg(feature = "compression")]
use std::io::{Write, Read};

pub type WsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;
type ResponseMap = Arc<Mutex<HashMap<Uuid, oneshot::Sender<Result<Value>>>>>;

/// TLS configuration for secure WebSocket connections
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub accept_invalid_certs: bool,
    pub accept_invalid_hostnames: bool,
    pub root_cert_store: Option<Vec<u8>>,
    pub client_cert: Option<Vec<u8>>,
    pub client_key: Option<Vec<u8>>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            accept_invalid_certs: false,
            accept_invalid_hostnames: false,
            root_cert_store: None,
            client_cert: None,
            client_key: None,
        }
    }
}

/// Message delivery guarantee levels
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryGuarantee {
    /// Fire and forget - no delivery confirmation
    AtMostOnce,
    /// Guaranteed delivery with acknowledgment
    AtLeastOnce,
    /// Exactly once delivery (not implemented yet)
    ExactlyOnce,
}

/// Queued message with delivery tracking
#[derive(Debug)]
pub struct QueuedMessage {
    pub id: Uuid,
    pub content: String,
    pub created_at: Instant,
    pub attempts: u32,
    pub max_attempts: u32,
    pub guarantee: DeliveryGuarantee,
    pub ack_tx: Option<oneshot::Sender<Result<()>>>,
}

impl QueuedMessage {
    pub fn new(content: String, guarantee: DeliveryGuarantee) -> Self {
        Self {
            id: Uuid::new_v4(),
            content,
            created_at: Instant::now(),
            attempts: 0,
            max_attempts: 3,
            guarantee,
            ack_tx: None,
        }
    }

    pub fn with_ack_channel(mut self, ack_tx: oneshot::Sender<Result<()>>) -> Self {
        self.ack_tx = Some(ack_tx);
        self
    }

    pub fn should_retry(&self) -> bool {
        self.attempts < self.max_attempts && self.guarantee != DeliveryGuarantee::AtMostOnce
    }

    pub fn increment_attempts(&mut self) {
        self.attempts += 1;
    }
}

/// Message queue with delivery guarantees
#[derive(Debug)]
pub struct MessageQueue {
    pending: Arc<Mutex<VecDeque<QueuedMessage>>>,
    in_flight: Arc<Mutex<HashMap<Uuid, QueuedMessage>>>,
    max_queue_size: usize,
    semaphore: Arc<Semaphore>,
}

impl MessageQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            pending: Arc::new(Mutex::new(VecDeque::new())),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            max_queue_size: max_size,
            semaphore: Arc::new(Semaphore::new(max_size)),
        }
    }

    pub async fn enqueue(&self, message: QueuedMessage) -> Result<()> {
        // Acquire semaphore permit to enforce queue size limit
        let _permit = self.semaphore.acquire().await
            .map_err(|_| GdkError::network_simple("Message queue semaphore closed".to_string()))?;

        let mut pending = self.pending.lock().await;
        if pending.len() >= self.max_queue_size {
            return Err(GdkError::network_simple("Message queue is full".to_string()));
        }
        
        pending.push_back(message);
        Ok(())
    }

    pub async fn dequeue(&self) -> Option<QueuedMessage> {
        let mut pending = self.pending.lock().await;
        pending.pop_front()
    }

    pub async fn mark_in_flight(&self, message: QueuedMessage) {
        let mut in_flight = self.in_flight.lock().await;
        in_flight.insert(message.id, message);
    }

    pub async fn acknowledge(&self, message_id: Uuid) -> Option<QueuedMessage> {
        let mut in_flight = self.in_flight.lock().await;
        in_flight.remove(&message_id)
    }

    pub async fn requeue_failed(&self, message_id: Uuid) -> Result<()> {
        let mut in_flight = self.in_flight.lock().await;
        if let Some(mut message) = in_flight.remove(&message_id) {
            message.increment_attempts();
            
            if message.should_retry() {
                drop(in_flight);
                let mut pending = self.pending.lock().await;
                pending.push_front(message); // Prioritize retries
                Ok(())
            } else {
                // Max attempts reached, notify failure
                if let Some(ack_tx) = message.ack_tx {
                    let _ = ack_tx.send(Err(GdkError::network_simple("Max delivery attempts exceeded".to_string())));
                }
                Err(GdkError::network_simple("Message delivery failed after max attempts".to_string()))
            }
        } else {
            Err(GdkError::network_simple("Message not found in flight queue".to_string()))
        }
    }

    pub async fn get_queue_stats(&self) -> QueueStats {
        let pending = self.pending.lock().await;
        let in_flight = self.in_flight.lock().await;
        
        QueueStats {
            pending_count: pending.len(),
            in_flight_count: in_flight.len(),
            available_permits: self.semaphore.available_permits(),
            max_queue_size: self.max_queue_size,
        }
    }
}

/// Statistics for message queue monitoring
#[derive(Debug, Clone)]
pub struct QueueStats {
    pub pending_count: usize,
    pub in_flight_count: usize,
    pub available_permits: usize,
    pub max_queue_size: usize,
}

/// Connection state tracking
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// Connection health status
#[derive(Debug, Clone)]
pub struct ConnectionHealth {
    pub last_ping: Option<Instant>,
    pub last_pong: Option<Instant>,
    pub ping_failures: u32,
    pub is_healthy: bool,
}

impl Default for ConnectionHealth {
    fn default() -> Self {
        Self {
            last_ping: None,
            last_pong: None,
            ping_failures: 0,
            is_healthy: true,
        }
    }
}

/// Configuration for connection behavior
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
    pub max_ping_failures: u32,
    pub initial_reconnect_delay: Duration,
    pub max_reconnect_delay: Duration,
    pub reconnect_backoff_multiplier: f64,
    pub max_reconnect_attempts: Option<u32>,
    pub enable_compression: bool,
    pub compression_threshold: usize, // Minimum message size to compress
    pub message_queue_size: usize,
    pub batch_timeout: Duration, // Time to wait for batching messages
    pub tls_config: TlsConfig,
    pub default_delivery_guarantee: DeliveryGuarantee,
    pub message_timeout: Duration,
    pub enable_message_batching: bool,
    pub max_batch_size: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            max_ping_failures: 3,
            initial_reconnect_delay: Duration::from_millis(500),
            max_reconnect_delay: Duration::from_secs(30),
            reconnect_backoff_multiplier: 2.0,
            max_reconnect_attempts: None, // Infinite retries
            enable_compression: true,
            compression_threshold: 1024, // Compress messages larger than 1KB
            message_queue_size: 100,
            batch_timeout: Duration::from_millis(10),
            tls_config: TlsConfig::default(),
            default_delivery_guarantee: DeliveryGuarantee::AtLeastOnce,
            message_timeout: Duration::from_secs(30),
            enable_message_batching: true,
            max_batch_size: 10,
        }
    }
}

// Internal message used to send requests to the connection task.
struct ConnectionRequest {
    id: Uuid,
    method: String,
    params: Value,
    response_tx: oneshot::Sender<Result<Value>>,
}

// Batch of requests for optimization
struct RequestBatch {
    requests: Vec<ConnectionRequest>,
    created_at: Instant,
}

// Internal control messages for the connection task
#[derive(Debug)]
enum ConnectionControl {
    Reconnect,
    Disconnect,
    Ping,
}

/// Connection endpoint information
#[derive(Debug, Clone)]
pub struct ConnectionEndpoint {
    pub url: String,
    pub priority: u32,
    pub last_success: Option<Instant>,
    pub failure_count: u32,
}

impl ConnectionEndpoint {
    pub fn new(url: String, priority: u32) -> Self {
        Self {
            url,
            priority,
            last_success: None,
            failure_count: 0,
        }
    }
}

/// Connection pool for managing multiple endpoints
pub struct ConnectionPool {
    endpoints: Arc<RwLock<Vec<ConnectionEndpoint>>>,
    active_connection: Arc<RwLock<Option<Connection>>>,
    config: ConnectionConfig,
    notification_tx: broadcast::Sender<Notification>,
}

impl ConnectionPool {
    pub fn new(
        endpoints: Vec<ConnectionEndpoint>,
        config: ConnectionConfig,
        notification_tx: broadcast::Sender<Notification>,
    ) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(endpoints)),
            active_connection: Arc::new(RwLock::new(None)),
            config,
            notification_tx,
        }
    }

    pub async fn connect(&self) -> Result<()> {
        let endpoints = self.endpoints.read().await;
        let mut sorted_endpoints = endpoints.clone();
        
        // Sort by priority (higher priority first) and then by failure count (lower first)
        sorted_endpoints.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| a.failure_count.cmp(&b.failure_count))
        });

        for endpoint in sorted_endpoints {
            match Connection::new(&endpoint.url, self.notification_tx.clone(), self.config.clone()).await {
                Ok(connection) => {
                    *self.active_connection.write().await = Some(connection);
                    // Update endpoint success
                    let mut endpoints_write = self.endpoints.write().await;
                    if let Some(ep) = endpoints_write.iter_mut().find(|e| e.url == endpoint.url) {
                        ep.last_success = Some(Instant::now());
                        ep.failure_count = 0;
                    }
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("Failed to connect to {}: {}", endpoint.url, e);
                    // Update endpoint failure
                    let mut endpoints_write = self.endpoints.write().await;
                    if let Some(ep) = endpoints_write.iter_mut().find(|e| e.url == endpoint.url) {
                        ep.failure_count += 1;
                    }
                }
            }
        }

        Err(GdkError::network_simple("Failed to connect to any endpoint".to_string()))
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let connection = self.active_connection.read().await;
        match connection.as_ref() {
            Some(conn) => conn.call(method, params).await,
            None => Err(GdkError::network_simple("No active connection".to_string())),
        }
    }

    pub async fn disconnect(&self) -> Result<()> {
        let mut connection = self.active_connection.write().await;
        if let Some(conn) = connection.take() {
            conn.disconnect().await?;
        }
        Ok(())
    }

    pub async fn get_state(&self) -> ConnectionState {
        let connection = self.active_connection.read().await;
        match connection.as_ref() {
            Some(conn) => conn.get_state().await,
            None => ConnectionState::Disconnected,
        }
    }
}

/// Manages the WebSocket connection, handling requests, responses, and notifications.
#[derive(Clone)]
pub struct Connection {
    request_tx: mpsc::Sender<ConnectionRequest>,
    control_tx: mpsc::Sender<ConnectionControl>,
    state: Arc<RwLock<ConnectionState>>,
    health: Arc<RwLock<ConnectionHealth>>,
    config: ConnectionConfig,
    message_queue: Arc<MessageQueue>,
    stats: Arc<RwLock<ConnectionStats>>,
}

/// Connection statistics for monitoring and debugging
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub reconnection_count: u32,
    pub last_error: Option<String>,
    pub uptime: Duration,
    pub connection_established_at: Option<Instant>,
}

impl Connection {
    pub async fn new(
        url: &str, 
        notification_tx: broadcast::Sender<Notification>,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let state = Arc::new(RwLock::new(ConnectionState::Connecting));
        let health = Arc::new(RwLock::new(ConnectionHealth::default()));
        let message_queue = Arc::new(MessageQueue::new(config.message_queue_size));
        let stats = Arc::new(RwLock::new(ConnectionStats::default()));
        
        let (request_tx, request_rx) = mpsc::channel(32);
        let (control_tx, control_rx) = mpsc::channel(16);

        let connection = Self {
            request_tx,
            control_tx,
            state: state.clone(),
            health: health.clone(),
            config: config.clone(),
            message_queue: message_queue.clone(),
            stats: stats.clone(),
        };

        // Start the connection task with reconnection logic
        start_connection_manager(
            url.to_string(),
            request_rx,
            control_rx,
            notification_tx,
            state.clone(),
            health,
            config,
            message_queue,
            stats,
        );

        // Wait for connection to be established
        let mut attempts = 0;
        let max_attempts = 100; // 10 seconds with 100ms intervals
        loop {
            let current_state = state.read().await.clone();
            log::trace!("Connection state check #{}: {:?}", attempts, current_state);
            match current_state {
                ConnectionState::Connected => {
                    log::debug!("Connection established successfully");
                    break;
                }
                ConnectionState::Failed => {
                    return Err(GdkError::network_simple("Connection failed".to_string()));
                }
                _ => {
                    if attempts >= max_attempts {
                        log::error!("Connection timeout after {} attempts, final state: {:?}", attempts, current_state);
                        return Err(GdkError::network_simple("Connection timeout".to_string()));
                    }
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }

        Ok(connection)
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        // Check if we're connected
        let state = self.state.read().await;
        if *state != ConnectionState::Connected {
            return Err(GdkError::network_simple(format!("Connection not ready, state: {:?}", *state)));
        }
        drop(state);

        let id = Uuid::new_v4();
        let (response_tx, response_rx) = oneshot::channel();

        let request = ConnectionRequest {
            id,
            method: method.to_string(),
            params,
            response_tx,
        };

        if self.request_tx.send(request).await.is_err() {
            return Err(GdkError::network_simple("Connection task has died".to_string()));
        }

        // Add timeout for the response
        match timeout(Duration::from_secs(30), response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(GdkError::network_simple("Connection task dropped the response sender".to_string())),
            Err(_) => Err(GdkError::network_simple("Request timeout".to_string())),
        }
    }

    pub async fn disconnect(&self) -> Result<()> {
        if self.control_tx.send(ConnectionControl::Disconnect).await.is_err() {
            return Err(GdkError::network_simple("Connection control task has died".to_string()));
        }
        Ok(())
    }

    pub async fn reconnect(&self) -> Result<()> {
        if self.control_tx.send(ConnectionControl::Reconnect).await.is_err() {
            return Err(GdkError::network_simple("Connection control task has died".to_string()));
        }
        Ok(())
    }

    pub async fn get_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    pub async fn get_health(&self) -> ConnectionHealth {
        self.health.read().await.clone()
    }

    pub async fn is_healthy(&self) -> bool {
        let health = self.health.read().await;
        health.is_healthy && health.ping_failures < self.config.max_ping_failures
    }
}

fn start_connection_manager(
    url: String,
    mut request_rx: mpsc::Receiver<ConnectionRequest>,
    mut control_rx: mpsc::Receiver<ConnectionControl>,
    notification_tx: broadcast::Sender<Notification>,
    state: Arc<RwLock<ConnectionState>>,
    health: Arc<RwLock<ConnectionHealth>>,
    config: ConnectionConfig,
    message_queue: Arc<MessageQueue>,
    stats: Arc<RwLock<ConnectionStats>>,
) {
    tokio::spawn(async move {
        let mut reconnect_attempts = 0u32;
        let mut reconnect_delay = config.initial_reconnect_delay;
        let should_reconnect = true;

        while should_reconnect {
            // Update state to connecting
            *state.write().await = ConnectionState::Connecting;

            match establish_connection(&url).await {
                Ok(ws_stream) => {
                    log::info!("Connected to {}", url);
                    *state.write().await = ConnectionState::Connected;
                    reconnect_attempts = 0;
                    reconnect_delay = config.initial_reconnect_delay;

                    // Reset health status
                    {
                        let mut health_guard = health.write().await;
                        *health_guard = ConnectionHealth::default();
                    }

                    // Run the connection until it fails or is disconnected
                    let disconnect_requested = run_connection(
                        ws_stream,
                        &mut request_rx,
                        &mut control_rx,
                        &notification_tx,
                        &state,
                        &health,
                        &config,
                    ).await;

                    if disconnect_requested {
                        *state.write().await = ConnectionState::Disconnected;
                        break;
                    }

                    // Connection failed, prepare for reconnection
                    *state.write().await = ConnectionState::Reconnecting;
                    log::warn!("Connection lost, attempting to reconnect...");
                }
                Err(e) => {
                    log::error!("Failed to connect to {}: {}", url, e);
                    *state.write().await = ConnectionState::Failed;
                    
                    reconnect_attempts += 1;
                    if let Some(max_attempts) = config.max_reconnect_attempts {
                        if reconnect_attempts >= max_attempts {
                            log::error!("Max reconnection attempts ({}) reached, giving up", max_attempts);
                                break;
                        }
                    }
                }
            }

            if should_reconnect {
                log::info!("Waiting {:?} before reconnection attempt {}", reconnect_delay, reconnect_attempts + 1);
                sleep(reconnect_delay).await;
                
                // Exponential backoff
                reconnect_delay = std::cmp::min(
                    Duration::from_millis((reconnect_delay.as_millis() as f64 * config.reconnect_backoff_multiplier) as u64),
                    config.max_reconnect_delay,
                );
            }
        }

        // Clean up any pending requests
        while let Ok(request) = request_rx.try_recv() {
            let _ = request.response_tx.send(Err(GdkError::network_simple("Connection closed".to_string())));
        }

        log::info!("Connection manager finished.");
    });
}

/// Enhanced connection establishment with TLS support and comprehensive error handling
async fn establish_connection(url: &str) -> Result<WsStream> {
    establish_connection_with_config(url, &TlsConfig::default()).await
}

/// Establish WebSocket connection with custom TLS configuration
async fn establish_connection_with_config(url: &str, tls_config: &TlsConfig) -> Result<WsStream> {
    log::debug!("Establishing WebSocket connection to: {}", url);
    
    // Parse URL to determine if TLS is required
    let is_secure = url.starts_with("wss://");
    
    if is_secure {
        // For secure connections, we need to configure TLS
        let connector = create_tls_connector(tls_config)?;
        
        match connect_async_tls_with_config(url, None, false, Some(connector)).await {
            Ok((stream, response)) => {
                log::debug!("Secure WebSocket connection established. Response status: {:?}", response.status());
                Ok(stream)
            }
            Err(e) => {
                log::error!("Failed to establish secure WebSocket connection: {}", e);
                Err(map_websocket_error(e))
            }
        }
    } else {
        // For non-secure connections, use standard connection
        match connect_async(url).await {
            Ok((stream, response)) => {
                log::debug!("WebSocket connection established. Response status: {:?}", response.status());
                Ok(stream)
            }
            Err(e) => {
                log::error!("Failed to establish WebSocket connection: {}", e);
                Err(map_websocket_error(e))
            }
        }
    }
}

/// Create TLS connector with custom configuration
fn create_tls_connector(tls_config: &TlsConfig) -> Result<tokio_tungstenite::Connector> {
    use tokio_tungstenite::Connector;
    
    // For now, return the default connector
    // In a full implementation, we would configure the TLS connector based on tls_config
    // This would involve setting up custom certificate stores, client certificates, etc.
    Ok(Connector::NativeTls(native_tls::TlsConnector::new()
        .map_err(|e| GdkError::network_simple(format!("Failed to create TLS connector: {}", e)))?))
}

/// Map WebSocket errors to GdkError with detailed context
fn map_websocket_error(error: tokio_tungstenite::tungstenite::Error) -> GdkError {
    use tokio_tungstenite::tungstenite::Error as WsError;
    
    match error {
        WsError::ConnectionClosed => {
            GdkError::network_simple("WebSocket connection was closed".to_string())
        }
        WsError::AlreadyClosed => {
            GdkError::network_simple("WebSocket connection is already closed".to_string())
        }
        WsError::Io(io_err) => {
            GdkError::network_simple(format!("WebSocket I/O error: {}", io_err))
        }
        WsError::Tls(tls_err) => {
            GdkError::network_simple(format!("WebSocket TLS error: {}", tls_err))
        }
        WsError::Capacity(cap_err) => {
            GdkError::network_simple(format!("WebSocket capacity error: {}", cap_err))
        }
        WsError::Protocol(protocol_err) => {
            GdkError::network_simple(format!("WebSocket protocol error: {}", protocol_err))
        }
        WsError::Utf8 => {
            GdkError::network_simple("WebSocket UTF-8 encoding error".to_string())
        }
        WsError::Url(url_err) => {
            GdkError::network_simple(format!("WebSocket URL error: {}", url_err))
        }
        WsError::Http(response) => {
            GdkError::network_simple(format!("WebSocket HTTP error: {}", response.status()))
        }
        WsError::HttpFormat(http_err) => {
            GdkError::network_simple(format!("WebSocket HTTP format error: {}", http_err))
        }
        _ => {
            GdkError::network_simple(format!("WebSocket error: {}", error))
        }
    }
}

async fn run_connection(
    ws_stream: WsStream,
    request_rx: &mut mpsc::Receiver<ConnectionRequest>,
    control_rx: &mut mpsc::Receiver<ConnectionControl>,
    notification_tx: &broadcast::Sender<Notification>,
    state: &Arc<RwLock<ConnectionState>>,
    health: &Arc<RwLock<ConnectionHealth>>,
    config: &ConnectionConfig,
) -> bool {
    let (mut ws_tx, mut ws_rx) = ws_stream.split();
    let responses: ResponseMap = Arc::new(Mutex::new(HashMap::new()));
    
    // Start health monitoring
    let mut ping_interval = interval(config.ping_interval);
    let mut pending_pings: HashMap<Uuid, Instant> = HashMap::new();

    loop {
        tokio::select! {
            // Handle control messages
            Some(control) = control_rx.recv() => {
                match control {
                    ConnectionControl::Disconnect => {
                        log::info!("Disconnect requested");
                        // Send a proper close frame before closing
                        let _ = ws_tx.send(Message::Close(None)).await;
                        let _ = ws_tx.close().await;
                        return true; // Disconnect requested
                    }
                    ConnectionControl::Reconnect => {
                        log::info!("Reconnect requested");
                        let _ = ws_tx.close().await;
                        return false; // Reconnect requested
                    }
                    ConnectionControl::Ping => {
                        if let Err(e) = send_ping(&mut ws_tx, &mut pending_pings, health).await {
                            log::error!("Failed to send ping: {}", e);
                            return false; // Connection failed
                        }
                    }
                }
            }

            // Handle periodic pings
            _ = ping_interval.tick() => {
                if let Err(e) = send_ping(&mut ws_tx, &mut pending_pings, health).await {
                    log::error!("Failed to send periodic ping: {}", e);
                    return false; // Connection failed
                }
            }

            // Handle outgoing requests from the session
            Some(request) = request_rx.recv() => {
                let call = MethodCall {
                    id: request.id,
                    method: request.method,
                    params: request.params,
                };
                
                let msg = match serde_json::to_string(&call) {
                    Ok(msg) => msg,
                    Err(e) => {
                        let _ = request.response_tx.send(Err(GdkError::json_simple(e.to_string())));
                        continue;
                    }
                };

                responses.lock().await.insert(request.id, request.response_tx);

                if let Err(e) = send_compressed_message(&mut ws_tx, &msg, config).await {
                    log::error!("WebSocket connection closed while sending request: {}", e);
                    return false; // Connection failed
                }
            }

            // Handle incoming messages from the server
            Some(message_result) = ws_rx.next() => {
                match message_result {
                    Ok(message) => {
                        if !handle_message(message, &responses, notification_tx, &mut pending_pings, health).await {
                            return false; // Connection failed
                        }
                    }
                    Err(e) => {
                        log::error!("WebSocket error: {}", e);
                        return false; // Connection failed
                    }
                }
            }

            else => {
                log::info!("All channels closed, ending connection");
                return false; // Connection ended
            }
        }
    }
}

async fn send_ping(
    ws_tx: &mut futures_util::stream::SplitSink<WsStream, Message>,
    pending_pings: &mut HashMap<Uuid, Instant>,
    health: &Arc<RwLock<ConnectionHealth>>,
) -> Result<()> {
    let ping_id = Uuid::new_v4();
    let ping_data = ping_id.as_bytes().to_vec();
    
    pending_pings.insert(ping_id, Instant::now());
    
    {
        let mut health_guard = health.write().await;
        health_guard.last_ping = Some(Instant::now());
    }

    ws_tx.send(Message::Ping(ping_data)).await
        .map_err(|e| GdkError::network_simple(e.to_string()))
}

/// Compress message if it exceeds threshold and compression is enabled
#[cfg(feature = "compression")]
fn compress_message(data: &str, config: &ConnectionConfig) -> Result<Vec<u8>> {
    if !config.enable_compression || data.len() < config.compression_threshold {
        return Ok(data.as_bytes().to_vec());
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data.as_bytes())
        .map_err(|e| GdkError::network_simple(format!("Compression failed: {}", e)))?;
    encoder.finish()
        .map_err(|e| GdkError::network_simple(format!("Compression finalization failed: {}", e)))
}

#[cfg(not(feature = "compression"))]
fn compress_message(data: &str, _config: &ConnectionConfig) -> Result<Vec<u8>> {
    Ok(data.as_bytes().to_vec())
}

/// Decompress message if it was compressed
#[cfg(feature = "compression")]
fn decompress_message(data: &[u8]) -> Result<String> {
    // Try to decompress first, if it fails assume it's uncompressed
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = String::new();
    
    match decoder.read_to_string(&mut decompressed) {
        Ok(_) => Ok(decompressed),
        Err(_) => {
            // Assume it's uncompressed text
            String::from_utf8(data.to_vec())
                .map_err(|e| GdkError::network_simple(format!("Invalid UTF-8: {}", e)))
        }
    }
}

#[cfg(not(feature = "compression"))]
fn decompress_message(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec())
        .map_err(|e| GdkError::network_simple(format!("Invalid UTF-8: {}", e)))
}

/// Send a message with optional compression
async fn send_compressed_message(
    ws_tx: &mut futures_util::stream::SplitSink<WsStream, Message>,
    message: &str,
    config: &ConnectionConfig,
) -> Result<()> {
    let compressed_data = compress_message(message, config)?;
    
    // Use binary message if compressed, text if not
    let ws_message = if config.enable_compression && compressed_data.len() < message.len() {
        Message::Binary(compressed_data)
    } else {
        Message::Text(message.to_string())
    };

    ws_tx.send(ws_message).await
        .map_err(|e| GdkError::network_simple(e.to_string()))
}

async fn handle_message(
    message: Message,
    responses: &ResponseMap,
    notification_tx: &broadcast::Sender<Notification>,
    pending_pings: &mut HashMap<Uuid, Instant>,
    health: &Arc<RwLock<ConnectionHealth>>,
) -> bool {
    match message {
        Message::Text(text) => {
            let value: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    log::warn!("Received invalid JSON message: {}", text);
                    return true; // Continue processing
                }
            };

            // Check if it's a response to a call
            if let Some(id_val) = value.get("id") {
                if let Ok(id) = serde_json::from_value::<Uuid>(id_val.clone()) {
                    if let Some(tx) = responses.lock().await.remove(&id) {
                        // Extract the "result" field from the response object
                        if let Some(result_val) = value.get("result").cloned() {
                            let _ = tx.send(Ok(result_val));
                        } else if let Some(error_val) = value.get("error").cloned() {
                            let err_msg = error_val.as_str().unwrap_or("Unknown error").to_string();
                            let _ = tx.send(Err(GdkError::network_simple(err_msg)));
                        } else {
                            let _ = tx.send(Err(GdkError::network_simple("Invalid response format".to_string())));
                        }
                        return true; // Continue processing
                    }
                }
            }

            // Otherwise, assume it's a notification
            if let Ok(notification) = serde_json::from_value::<Notification>(value) {
                let _ = notification_tx.send(notification);
            } else {
                log::warn!("Received message that was not a response or a valid notification: {}", text);
            }
        }
        Message::Pong(data) => {
            // Handle pong response
            if data.len() == 16 {
                if let Ok(ping_id) = Uuid::from_slice(&data) {
                    if let Some(ping_time) = pending_pings.remove(&ping_id) {
                        let rtt = ping_time.elapsed();
                        log::debug!("Received pong, RTT: {:?}", rtt);
                        
                        let mut health_guard = health.write().await;
                        health_guard.last_pong = Some(Instant::now());
                        health_guard.ping_failures = 0;
                        health_guard.is_healthy = true;
                    }
                }
            }
        }
        Message::Ping(data) => {
            // Server sent us a ping, we should respond with pong
            // This would be handled automatically by the WebSocket implementation
            log::debug!("Received ping from server");
        }
        Message::Close(_) => {
            log::info!("Received close message from server");
            return false; // Connection closed
        }
        Message::Binary(data) => {
            // Try to decompress and handle as JSON
            match decompress_message(&data) {
                Ok(text) => {
                    let value: Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(_) => {
                            log::warn!("Received invalid JSON in binary message: {}", text);
                            return true; // Continue processing
                        }
                    };

                    // Check if it's a response to a call
                    if let Some(id_val) = value.get("id") {
                        if let Ok(id) = serde_json::from_value::<Uuid>(id_val.clone()) {
                            if let Some(tx) = responses.lock().await.remove(&id) {
                                // Extract the "result" field from the response object
                                if let Some(result_val) = value.get("result").cloned() {
                                    let _ = tx.send(Ok(result_val));
                                } else if let Some(error_val) = value.get("error").cloned() {
                                    let err_msg = error_val.as_str().unwrap_or("Unknown error").to_string();
                                    let _ = tx.send(Err(GdkError::network_simple(err_msg)));
                                } else {
                                    let _ = tx.send(Err(GdkError::network_simple("Invalid response format".to_string())));
                                }
                                return true; // Continue processing
                            }
                        }
                    }

                    // Otherwise, assume it's a notification
                    if let Ok(notification) = serde_json::from_value::<Notification>(value) {
                        let _ = notification_tx.send(notification);
                    } else {
                        log::warn!("Received binary message that was not a response or a valid notification: {}", text);
                    }
                }
                Err(e) => {
                    log::warn!("Failed to decompress binary message: {}", e);
                }
            }
        }
        Message::Frame(_) => {
            log::debug!("Received raw frame");
        }
    }
    
    true // Continue processing
}
