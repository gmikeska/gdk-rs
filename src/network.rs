//! Network connection management.

use crate::error::GdkError;
use crate::protocol::{MethodCall, Notification};
use crate::Result;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, RwLock};
use tokio::time::{interval, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio::net::TcpStream;
use uuid::Uuid;

pub type WsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;
type ResponseMap = Arc<Mutex<HashMap<Uuid, oneshot::Sender<Result<Value>>>>>;

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

        Err(GdkError::Network("Failed to connect to any endpoint".to_string()))
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let connection = self.active_connection.read().await;
        match connection.as_ref() {
            Some(conn) => conn.call(method, params).await,
            None => Err(GdkError::Network("No active connection".to_string())),
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
}

impl Connection {
    pub async fn new(
        url: &str, 
        notification_tx: broadcast::Sender<Notification>,
        config: ConnectionConfig,
    ) -> Result<Self> {
        let state = Arc::new(RwLock::new(ConnectionState::Connecting));
        let health = Arc::new(RwLock::new(ConnectionHealth::default()));
        
        let (request_tx, request_rx) = mpsc::channel(32);
        let (control_tx, control_rx) = mpsc::channel(16);

        let connection = Self {
            request_tx,
            control_tx,
            state: state.clone(),
            health: health.clone(),
            config: config.clone(),
        };

        // Start the connection task with reconnection logic
        start_connection_manager(
            url.to_string(),
            request_rx,
            control_rx,
            notification_tx,
            state,
            health,
            config,
        );

        Ok(connection)
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        // Check if we're connected
        let state = self.state.read().await;
        if *state != ConnectionState::Connected {
            return Err(GdkError::Network(format!("Connection not ready, state: {:?}", *state)));
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
            return Err(GdkError::Network("Connection task has died".to_string()));
        }

        // Add timeout for the response
        match timeout(Duration::from_secs(30), response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(GdkError::Network("Connection task dropped the response sender".to_string())),
            Err(_) => Err(GdkError::Network("Request timeout".to_string())),
        }
    }

    pub async fn disconnect(&self) -> Result<()> {
        if self.control_tx.send(ConnectionControl::Disconnect).await.is_err() {
            return Err(GdkError::Network("Connection control task has died".to_string()));
        }
        Ok(())
    }

    pub async fn reconnect(&self) -> Result<()> {
        if self.control_tx.send(ConnectionControl::Reconnect).await.is_err() {
            return Err(GdkError::Network("Connection control task has died".to_string()));
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
) {
    tokio::spawn(async move {
        let mut reconnect_attempts = 0u32;
        let mut reconnect_delay = config.initial_reconnect_delay;
        let mut should_reconnect = true;

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
                        should_reconnect = false;
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
                            should_reconnect = false;
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
            let _ = request.response_tx.send(Err(GdkError::Network("Connection closed".to_string())));
        }

        log::info!("Connection manager finished.");
    });
}

async fn establish_connection(url: &str) -> Result<WsStream> {
    tokio_tungstenite::connect_async(url)
        .await
        .map(|(stream, _)| stream)
        .map_err(|e| GdkError::Network(e.to_string()))
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
                        let _ = request.response_tx.send(Err(GdkError::Json(e)));
                        continue;
                    }
                };

                responses.lock().await.insert(request.id, request.response_tx);

                if let Err(e) = ws_tx.send(Message::Text(msg)).await {
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
        .map_err(|e| GdkError::Network(e.to_string()))
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
                            let _ = tx.send(Err(GdkError::Network(err_msg)));
                        } else {
                            let _ = tx.send(Err(GdkError::Network("Invalid response format".to_string())));
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
        Message::Binary(_) => {
            log::warn!("Received unexpected binary message");
        }
        Message::Frame(_) => {
            log::debug!("Received raw frame");
        }
    }
    
    true // Continue processing
}
