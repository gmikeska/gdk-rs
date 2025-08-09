use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
    routing::get,
    Router,
};
use gdk_rs::primitives::psbt::PartiallySignedTransaction;
use gdk_rs::protocol::{MethodCall, RegisterLoginResult};
use serde_json::Value;
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn start_mock_server() -> SocketAddr {
    let app = Router::new().route("/v2/ws", get(websocket_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[axum::debug_handler]
async fn websocket_handler(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_socket)
}

fn build_response(id: &str, result: Value) -> Value {
    serde_json::json!({
        "id": id,
        "result": result,
    })
}

async fn handle_socket(mut socket: WebSocket) {
    if let Some(Ok(Message::Text(text))) = socket.recv().await {
        let call: Result<MethodCall, _> = serde_json::from_str(&text);

        if let Ok(call) = call {
            let result_body = match call.method.as_str() {
                "login_user" => {
                    let res = RegisterLoginResult {
                        wallet_hash_id: "mock_wallet_hash_id".to_string(),
                        xpub_hash_id: "mock_xpub_hash_id".to_string(),
                        warnings: vec![],
                    };
                    serde_json::to_value(res).unwrap()
                }
                "get_subaccounts" => {
                    let res = gdk_rs::protocol::SubaccountsList {
                        subaccounts: vec![],
                    };
                    serde_json::to_value(res).unwrap()
                }
                "get_transactions" => {
                    let res: Vec<gdk_rs::protocol::TransactionListItem> = vec![];
                    serde_json::to_value(res).unwrap()
                }
                "get_unspent_outputs" => {
                    let res = gdk_rs::protocol::UnspentOutputs {
                        unspent_outputs: std::collections::HashMap::new(),
                    };
                    serde_json::to_value(res).unwrap()
                }
                "get_assets" => {
                    let mut assets = std::collections::HashMap::new();
                    let lbtc_id = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d".to_string();
                    assets.insert(lbtc_id.clone(), gdk_rs::protocol::AssetInfo {
                        asset_id: lbtc_id,
                        name: "L-BTC".to_string(),
                        ticker: "L-BTC".to_string(),
                        precision: 8,
                    });
                    let res = gdk_rs::protocol::Assets { assets };
                    serde_json::to_value(res).unwrap()
                }
                "create_transaction" => {
                    let pset = PartiallySignedTransaction::default();
                    serde_json::to_value(pset).unwrap()
                }
                _ => {
                    serde_json::json!({ "error": "Unknown method" })
                }
            };
            let response = build_response(&call.id.to_string(), result_body);
            let response_json = serde_json::to_string(&response).unwrap();
            let _ = socket.send(Message::Text(response_json)).await;
        }
    }
}
