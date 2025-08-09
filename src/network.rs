//! Network connection management.

use crate::error::GdkError;
use crate::protocol::{MethodCall, Notification};
use crate::Result;
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tokio::net::TcpStream;
use uuid::Uuid;

pub type WsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>;
type ResponseMap = Arc<Mutex<HashMap<Uuid, oneshot::Sender<Result<Value>>>>>;

// Internal message used to send requests to the connection task.
struct ConnectionRequest {
    id: Uuid,
    method: String,
    params: Value,
    response_tx: oneshot::Sender<Result<Value>>,
}

/// Manages the WebSocket connection, handling requests, responses, and notifications.
#[derive(Clone)]
pub struct Connection {
    request_tx: mpsc::Sender<ConnectionRequest>,
}

impl Connection {
    pub async fn new(url: &str, notification_tx: broadcast::Sender<Notification>) -> Result<Self> {
        let (ws_stream, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| GdkError::Network(e.to_string()))?;

        let (request_tx, request_rx) = mpsc::channel(32);

        start_connection_task(ws_stream, request_rx, notification_tx);

        Ok(Self { request_tx })
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
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

        response_rx.await.map_err(|_| GdkError::Network("Connection task dropped the response sender".to_string()))?
    }
}

fn start_connection_task(
    ws_stream: WsStream,
    mut request_rx: mpsc::Receiver<ConnectionRequest>,
    notification_tx: broadcast::Sender<Notification>,
) {
    let (mut ws_tx, mut ws_rx) = ws_stream.split();
    let responses: ResponseMap = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        loop {
            tokio::select! {
                // Handle outgoing requests from the session
                Some(request) = request_rx.recv() => {
                    let call = MethodCall {
                        id: request.id,
                        method: request.method,
                        params: request.params,
                    };
                    let msg = serde_json::to_string(&call).unwrap();

                    responses.lock().await.insert(request.id, request.response_tx);

                    if ws_tx.send(Message::Text(msg)).await.is_err() {
                        log::error!("WebSocket connection closed while sending request.");
                        break;
                    }
                },

                // Handle incoming messages from the server
                Some(Ok(message)) = ws_rx.next() => {
                    if let Message::Text(text) = message {
                        let value: Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(_) => {
                                log::warn!("Received invalid JSON message: {}", text);
                                continue;
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
                                    continue;
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
                },
                else => break,
            }
        }
        log::info!("Connection task finished.");
    });
}
