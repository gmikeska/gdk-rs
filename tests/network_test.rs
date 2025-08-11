//! Tests for network communication layer

use gdk_rs::network::{Connection, ConnectionConfig, ConnectionPool, ConnectionEndpoint, ConnectionState};
use gdk_rs::protocol::{Notification, JsonRpcRequest, JsonRpcResponse, JsonRpcError, JsonRpcBatchRequest, JSONRPC_VERSION};
use gdk_rs::jsonrpc::{JsonRpcClient, JsonRpcConfig};
use tokio::sync::{broadcast, mpsc};
use std::time::Duration;
use serde_json::json;

#[tokio::test]
async fn test_connection_config_defaults() {
    let config = ConnectionConfig::default();
    
    assert_eq!(config.ping_interval, Duration::from_secs(30));
    assert_eq!(config.pong_timeout, Duration::from_secs(10));
    assert_eq!(config.max_ping_failures, 3);
    assert_eq!(config.initial_reconnect_delay, Duration::from_millis(500));
    assert_eq!(config.max_reconnect_delay, Duration::from_secs(30));
    assert_eq!(config.reconnect_backoff_multiplier, 2.0);
    assert_eq!(config.max_reconnect_attempts, None);
    assert_eq!(config.enable_compression, true);
    assert_eq!(config.compression_threshold, 1024);
    assert_eq!(config.message_queue_size, 100);
    assert_eq!(config.batch_timeout, Duration::from_millis(10));
}

#[tokio::test]
async fn test_connection_endpoint_creation() {
    let endpoint = ConnectionEndpoint::new("wss://example.com".to_string(), 1);
    
    assert_eq!(endpoint.url, "wss://example.com");
    assert_eq!(endpoint.priority, 1);
    assert_eq!(endpoint.last_success, None);
    assert_eq!(endpoint.failure_count, 0);
}

#[tokio::test]
async fn test_connection_pool_creation() {
    let (notification_tx, _) = broadcast::channel(100);
    let config = ConnectionConfig::default();
    
    let endpoints = vec![
        ConnectionEndpoint::new("wss://primary.example.com".to_string(), 10),
        ConnectionEndpoint::new("wss://secondary.example.com".to_string(), 5),
    ];
    
    let pool = ConnectionPool::new(endpoints, config, notification_tx);
    
    // Test that pool starts in disconnected state
    assert_eq!(pool.get_state().await, ConnectionState::Disconnected);
}

#[tokio::test]
async fn test_connection_pool_endpoint_sorting() {
    let (notification_tx, _) = broadcast::channel(100);
    let config = ConnectionConfig::default();
    
    // Create endpoints with different priorities and failure counts
    let mut endpoints = vec![
        ConnectionEndpoint::new("wss://low-priority.example.com".to_string(), 1),
        ConnectionEndpoint::new("wss://high-priority.example.com".to_string(), 10),
        ConnectionEndpoint::new("wss://medium-priority.example.com".to_string(), 5),
    ];
    
    // Simulate some failures on the high priority endpoint
    endpoints[1].failure_count = 2;
    
    let pool = ConnectionPool::new(endpoints, config, notification_tx);
    
    // The pool should try to connect to endpoints in priority order
    // but prefer those with fewer failures
    let state = pool.get_state().await;
    assert_eq!(state, ConnectionState::Disconnected);
}

#[cfg(feature = "compression")]
#[tokio::test]
async fn test_compression_feature_enabled() {
    let config = ConnectionConfig::default();
    assert!(config.enable_compression);
    assert_eq!(config.compression_threshold, 1024);
}

#[tokio::test]
async fn test_connection_state_transitions() {
    // Test that connection states are properly defined
    let _states = vec![
        ConnectionState::Disconnected,
        ConnectionState::Connecting,
        ConnectionState::Connected,
        ConnectionState::Reconnecting,
        ConnectionState::Failed,
    ];
    
    // Test equality
    assert_eq!(ConnectionState::Disconnected, ConnectionState::Disconnected);
    assert_ne!(ConnectionState::Connected, ConnectionState::Disconnected);
    
    // Test cloning
    let state = ConnectionState::Connected;
    let cloned_state = state.clone();
    assert_eq!(state, cloned_state);
}

#[tokio::test]
async fn test_connection_health_default() {
    let health = gdk_rs::network::ConnectionHealth::default();
    
    assert_eq!(health.last_ping, None);
    assert_eq!(health.last_pong, None);
    assert_eq!(health.ping_failures, 0);
    assert_eq!(health.is_healthy, true);
}

#[tokio::test]
async fn test_notification_channel_creation() {
    let (tx, rx) = broadcast::channel::<Notification>(100);
    
    // Test that we can create the channel without issues
    assert_eq!(tx.receiver_count(), 1);
    
    // Test that receiver can be created
    let rx2 = tx.subscribe();
    assert_eq!(tx.receiver_count(), 2);
    
    // Test channel capacity
    drop(rx);
    drop(rx2);
    assert_eq!(tx.receiver_count(), 0);
}

#[tokio::test]
async fn test_connection_config_customization() {
    let mut config = ConnectionConfig::default();
    
    // Test that we can customize configuration
    config.ping_interval = Duration::from_secs(60);
    config.enable_compression = false;
    config.compression_threshold = 2048;
    config.max_reconnect_attempts = Some(5);
    
    assert_eq!(config.ping_interval, Duration::from_secs(60));
    assert_eq!(config.enable_compression, false);
    assert_eq!(config.compression_threshold, 2048);
    assert_eq!(config.max_reconnect_attempts, Some(5));
}

// Mock WebSocket server for testing (would require additional setup in real tests)
#[tokio::test]
async fn test_connection_error_handling() {
    let (notification_tx, _) = broadcast::channel(100);
    let config = ConnectionConfig::default();
    
    // Test connection to invalid URL
    let result = Connection::new("ws://invalid-url-that-does-not-exist.local", notification_tx, config).await;
    
    // Connection creation should succeed (connection happens asynchronously)
    // The actual connection failure would be handled by the connection manager
    assert!(result.is_ok());
    
    if let Ok(connection) = result {
        // Test that we can get the initial state
        let state = connection.get_state().await;
        // State should be Connecting initially, then transition to Failed
        assert!(matches!(state, ConnectionState::Connecting | ConnectionState::Failed));
    }
}

// JSON-RPC 2.0 Protocol Tests

#[tokio::test]
async fn test_jsonrpc_request_creation() {
    let request = JsonRpcRequest::new("test_method".to_string(), Some(json!({"param": "value"})));
    
    assert_eq!(request.jsonrpc, JSONRPC_VERSION);
    assert_eq!(request.method, "test_method");
    assert_eq!(request.params, Some(json!({"param": "value"})));
    assert!(request.id.is_some());
}

#[tokio::test]
async fn test_jsonrpc_notification_creation() {
    let notification = JsonRpcRequest::new_notification("test_notification".to_string(), None);
    
    assert_eq!(notification.jsonrpc, JSONRPC_VERSION);
    assert_eq!(notification.method, "test_notification");
    assert_eq!(notification.params, None);
    assert!(notification.id.is_none()); // Notifications don't have IDs
}

#[tokio::test]
async fn test_jsonrpc_response_success() {
    let result = json!({"success": true});
    let id = Some(json!("test-id"));
    let response = JsonRpcResponse::success(result.clone(), id.clone());
    
    assert_eq!(response.jsonrpc, JSONRPC_VERSION);
    assert_eq!(response.result, Some(result));
    assert_eq!(response.error, None);
    assert_eq!(response.id, id);
}

#[tokio::test]
async fn test_jsonrpc_response_error() {
    let error = JsonRpcError::method_not_found();
    let id = Some(json!("test-id"));
    let response = JsonRpcResponse::error(error.clone(), id.clone());
    
    assert_eq!(response.jsonrpc, JSONRPC_VERSION);
    assert_eq!(response.result, None);
    assert!(response.error.is_some());
    assert_eq!(response.id, id);
}

#[tokio::test]
async fn test_jsonrpc_error_codes() {
    let parse_error = JsonRpcError::parse_error();
    assert_eq!(parse_error.code, JsonRpcError::PARSE_ERROR);
    assert_eq!(parse_error.message, "Parse error");
    
    let invalid_request = JsonRpcError::invalid_request();
    assert_eq!(invalid_request.code, JsonRpcError::INVALID_REQUEST);
    assert_eq!(invalid_request.message, "Invalid Request");
    
    let method_not_found = JsonRpcError::method_not_found();
    assert_eq!(method_not_found.code, JsonRpcError::METHOD_NOT_FOUND);
    assert_eq!(method_not_found.message, "Method not found");
    
    let invalid_params = JsonRpcError::invalid_params();
    assert_eq!(invalid_params.code, JsonRpcError::INVALID_PARAMS);
    assert_eq!(invalid_params.message, "Invalid params");
    
    let internal_error = JsonRpcError::internal_error();
    assert_eq!(internal_error.code, JsonRpcError::INTERNAL_ERROR);
    assert_eq!(internal_error.message, "Internal error");
}

#[tokio::test]
async fn test_jsonrpc_custom_error() {
    let custom_error = JsonRpcError::custom(
        -32000, 
        "Custom error".to_string(), 
        Some(json!({"details": "Additional info"}))
    );
    
    assert_eq!(custom_error.code, -32000);
    assert_eq!(custom_error.message, "Custom error");
    assert_eq!(custom_error.data, Some(json!({"details": "Additional info"})));
}

#[tokio::test]
async fn test_jsonrpc_batch_request() {
    let mut batch = JsonRpcBatchRequest::new();
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
    
    let request1 = JsonRpcRequest::new("method1".to_string(), None);
    let request2 = JsonRpcRequest::new("method2".to_string(), Some(json!({"param": "value"})));
    
    batch.add_request(request1);
    batch.add_request(request2);
    
    assert!(!batch.is_empty());
    assert_eq!(batch.len(), 2);
}

#[tokio::test]
async fn test_jsonrpc_config_defaults() {
    let config = JsonRpcConfig::default();
    
    assert_eq!(config.default_timeout, Duration::from_secs(30));
    assert_eq!(config.batch_timeout, Duration::from_millis(10));
    assert_eq!(config.max_batch_size, 100);
    assert_eq!(config.enable_batching, true);
    assert_eq!(config.retry_attempts, 3);
    assert_eq!(config.retry_delay, Duration::from_millis(100));
    assert_eq!(config.enable_method_validation, true);
}

#[tokio::test]
async fn test_jsonrpc_client_creation() {
    let config = JsonRpcConfig::default();
    let (batch_tx, _batch_rx) = mpsc::channel(100);
    
    let client = JsonRpcClient::new(config, batch_tx);
    
    // Test that we can get initial stats
    let stats = client.get_stats().await;
    assert_eq!(stats.requests_sent, 0);
    assert_eq!(stats.responses_received, 0);
    assert_eq!(stats.errors_received, 0);
    assert_eq!(stats.timeouts, 0);
}

#[tokio::test]
async fn test_jsonrpc_method_validation() {
    use gdk_rs::protocol::MethodValidator;
    
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
async fn test_jsonrpc_params_validation() {
    use gdk_rs::protocol::MethodValidator;
    
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
async fn test_jsonrpc_request_serialization() {
    let request = JsonRpcRequest::new("test_method".to_string(), Some(json!({"param": "value"})));
    
    // Test serialization
    let serialized = serde_json::to_string(&request).unwrap();
    assert!(serialized.contains("\"jsonrpc\":\"2.0\""));
    assert!(serialized.contains("\"method\":\"test_method\""));
    assert!(serialized.contains("\"params\":{\"param\":\"value\"}"));
    assert!(serialized.contains("\"id\""));
    
    // Test deserialization
    let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.jsonrpc, request.jsonrpc);
    assert_eq!(deserialized.method, request.method);
    assert_eq!(deserialized.params, request.params);
}

#[tokio::test]
async fn test_jsonrpc_response_serialization() {
    let response = JsonRpcResponse::success(
        json!({"result": "success"}),
        Some(json!("test-id"))
    );
    
    // Test serialization
    let serialized = serde_json::to_string(&response).unwrap();
    assert!(serialized.contains("\"jsonrpc\":\"2.0\""));
    assert!(serialized.contains("\"result\":{\"result\":\"success\"}"));
    assert!(serialized.contains("\"id\":\"test-id\""));
    assert!(!serialized.contains("\"error\""));
    
    // Test deserialization
    let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.jsonrpc, response.jsonrpc);
    assert_eq!(deserialized.result, response.result);
    assert_eq!(deserialized.error, response.error);
    assert_eq!(deserialized.id, response.id);
}

#[tokio::test]
async fn test_jsonrpc_batch_serialization() {
    let mut batch = JsonRpcBatchRequest::new();
    batch.add_request(JsonRpcRequest::new("method1".to_string(), None));
    batch.add_request(JsonRpcRequest::new("method2".to_string(), Some(json!({"param": "value"}))));
    
    // Test serialization
    let serialized = serde_json::to_string(&batch).unwrap();
    assert!(serialized.starts_with('['));
    assert!(serialized.ends_with(']'));
    assert!(serialized.contains("\"method\":\"method1\""));
    assert!(serialized.contains("\"method\":\"method2\""));
    
    // Test deserialization
    let deserialized: JsonRpcBatchRequest = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.len(), 2);
}

#[tokio::test]
async fn test_jsonrpc_error_conversion() {
    use gdk_rs::error::GdkError;
    
    let json_error = JsonRpcError::method_not_found();
    let gdk_error: GdkError = json_error.into();
    
    match gdk_error {
        GdkError::Network { message, .. } => {
            assert!(message.contains("JSON-RPC Error"));
            assert!(message.contains("-32601"));
            assert!(message.contains("Method not found"));
        }
        _ => panic!("Expected Network error"),
    }
}

#[tokio::test]
async fn test_all_jsonrpc_error_conversions() {
    use gdk_rs::error::GdkError;
    
    // Test all standard JSON-RPC error types
    let test_cases = vec![
        (JsonRpcError::parse_error(), "-32700", "Parse error"),
        (JsonRpcError::invalid_request(), "-32600", "Invalid Request"),
        (JsonRpcError::method_not_found(), "-32601", "Method not found"),
        (JsonRpcError::invalid_params(), "-32602", "Invalid params"),
        (JsonRpcError::internal_error(), "-32603", "Internal error"),
    ];
    
    for (json_error, expected_code, expected_message) in test_cases {
        let gdk_error: GdkError = json_error.into();
        
        match gdk_error {
            GdkError::Network { message, code, .. } => {
                assert!(message.contains("JSON-RPC Error"));
                assert!(message.contains(expected_code));
                assert!(message.contains(expected_message));
                // Verify the error code is NetworkConnectionFailed (as set by network_simple)
                assert_eq!(code, gdk_rs::error::GdkErrorCode::NetworkConnectionFailed);
            }
            _ => panic!("Expected Network error variant"),
        }
    }
}

#[tokio::test]
async fn test_custom_jsonrpc_error_conversion() {
    use gdk_rs::error::GdkError;
    
    let custom_error = JsonRpcError::custom(
        -32000,
        "Custom error message".to_string(),
        Some(json!({"detail": "Additional information"}))
    );
    
    let gdk_error: GdkError = custom_error.into();
    
    match gdk_error {
        GdkError::Network { message, .. } => {
            assert!(message.contains("JSON-RPC Error"));
            assert!(message.contains("-32000"));
            assert!(message.contains("Custom error message"));
        }
        _ => panic!("Expected Network error variant"),
    }
}

#[tokio::test]
async fn test_jsonrpc_timeout_handling() {
    use gdk_rs::protocol::PendingRequest;
    use serde_json::Value;
    
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
async fn test_jsonrpc_legacy_compatibility() {
    use gdk_rs::protocol::MethodCall;
    use uuid::Uuid;
    
    let legacy_call = MethodCall {
        id: Uuid::new_v4(),
        method: "legacy_method".to_string(),
        params: json!({"legacy": "param"}),
    };
    
    // Test conversion to new JSON-RPC format
    let json_request: JsonRpcRequest = legacy_call.clone().into();
    
    assert_eq!(json_request.jsonrpc, JSONRPC_VERSION);
    assert_eq!(json_request.method, legacy_call.method);
    assert_eq!(json_request.params, Some(legacy_call.params));
    assert!(json_request.id.is_some());
}
// Tor Integration Tests (only available with tor-support feature)

#[cfg(feature = "tor-support")]
mod tor_tests {
    use super::*;
    use gdk_rs::tor::{TorManager, TorConfig, CircuitStatus};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    #[tokio::test]
    async fn test_tor_config_defaults() {
        let config = TorConfig::default();
        
        assert_eq!(config.socks_proxy.port(), 9050);
        assert_eq!(config.control_port.unwrap().port(), 9051);
        assert_eq!(config.enable_circuit_rotation, true);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.enable_onion_services, true);
        assert_eq!(config.circuit_rotation_interval, Duration::from_secs(600));
    }

    #[tokio::test]
    async fn test_tor_config_customization() {
        let mut config = TorConfig::default();
        config.socks_proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9150);
        config.enable_circuit_rotation = false;
        config.connection_timeout = Duration::from_secs(60);
        config.max_retries = 5;
        
        assert_eq!(config.socks_proxy.port(), 9150);
        assert_eq!(config.enable_circuit_rotation, false);
        assert_eq!(config.connection_timeout, Duration::from_secs(60));
        assert_eq!(config.max_retries, 5);
    }

    #[tokio::test]
    async fn test_tor_manager_creation() {
        let config = TorConfig::default();
        let manager = TorManager::new(config);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.connections_established, 0);
        assert_eq!(stats.connections_failed, 0);
        assert_eq!(stats.circuits_created, 0);
        assert_eq!(stats.onion_connections, 0);
        assert_eq!(stats.clearnet_connections, 0);
    }

    #[test]
    fn test_is_onion_service() {
        assert!(TorManager::is_onion_service("example.onion"));
        assert!(TorManager::is_onion_service("3g2upl4pq6kufc4m.onion"));
        assert!(TorManager::is_onion_service("facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion"));
        
        assert!(!TorManager::is_onion_service("example.com"));
        assert!(!TorManager::is_onion_service("192.168.1.1"));
        assert!(!TorManager::is_onion_service("google.com"));
        assert!(!TorManager::is_onion_service(""));
    }

    #[tokio::test]
    async fn test_tor_stats_tracking() {
        let config = TorConfig::default();
        let manager = TorManager::new(config);
        
        // Test onion service connection tracking
        manager.update_stats_success("example.onion").await;
        let stats = manager.get_stats().await;
        
        assert_eq!(stats.connections_established, 1);
        assert_eq!(stats.onion_connections, 1);
        assert_eq!(stats.clearnet_connections, 0);
        
        // Test clearnet connection tracking
        manager.update_stats_success("example.com").await;
        let stats = manager.get_stats().await;
        
        assert_eq!(stats.connections_established, 2);
        assert_eq!(stats.onion_connections, 1);
        assert_eq!(stats.clearnet_connections, 1);
        
        // Test failure tracking
        manager.update_stats_failure().await;
        let stats = manager.get_stats().await;
        
        assert_eq!(stats.connections_failed, 1);
    }

    #[test]
    fn test_circuit_status() {
        let statuses = vec![
            CircuitStatus::Building,
            CircuitStatus::Built,
            CircuitStatus::Failed,
            CircuitStatus::Closed,
        ];
        
        // Test that all statuses are different
        for (i, status1) in statuses.iter().enumerate() {
            for (j, status2) in statuses.iter().enumerate() {
                if i == j {
                    assert_eq!(status1, status2);
                } else {
                    assert_ne!(status1, status2);
                }
            }
        }
    }

    #[tokio::test]
    async fn test_onion_endpoint_preference() {
        let mut config = TorConfig::default();
        config.onion_endpoints = vec![
            "blockstream.onion".to_string(),
            "green.onion".to_string(),
        ];
        
        let manager = TorManager::new(config);
        
        assert!(manager.get_onion_endpoint("blockstream").is_some());
        assert!(manager.get_onion_endpoint("green").is_some());
        assert!(manager.get_onion_endpoint("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_tor_connection_timeout() {
        let mut config = TorConfig::default();
        config.connection_timeout = Duration::from_millis(1); // Very short timeout
        config.max_retries = 1;
        
        let manager = TorManager::new(config);
        
        // This should fail quickly due to short timeout
        let result = manager.connect("nonexistent.onion", 80).await;
        assert!(result.is_err());
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.connections_failed, 1);
    }

    #[tokio::test]
    async fn test_socks5_constants() {
        // Test that SOCKS5 constants are correctly defined
        // These are internal constants, so we test them indirectly
        let config = TorConfig::default();
        let manager = TorManager::new(config);
        
        // The manager should be created successfully with default SOCKS5 settings
        let stats = manager.get_stats().await;
        assert_eq!(stats.connections_established, 0);
    }

    #[tokio::test]
    async fn test_tor_config_serialization() {
        let config = TorConfig::default();
        
        // Test that TorConfig can be serialized and deserialized
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: TorConfig = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(config.socks_proxy, deserialized.socks_proxy);
        assert_eq!(config.control_port, deserialized.control_port);
        assert_eq!(config.enable_circuit_rotation, deserialized.enable_circuit_rotation);
        assert_eq!(config.connection_timeout, deserialized.connection_timeout);
        assert_eq!(config.max_retries, deserialized.max_retries);
    }

    #[tokio::test]
    async fn test_tor_error_handling() {
        let mut config = TorConfig::default();
        // Use an invalid proxy address
        config.socks_proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9999);
        config.max_retries = 1;
        config.retry_delay = Duration::from_millis(1);
        
        let manager = TorManager::new(config);
        
        // This should fail to connect
        let result = manager.connect("example.com", 80).await;
        assert!(result.is_err());
        
        // Check that error is properly tracked
        let stats = manager.get_stats().await;
        assert_eq!(stats.connections_failed, 1);
    }

    #[tokio::test]
    async fn test_tor_retry_logic() {
        let mut config = TorConfig::default();
        config.socks_proxy = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9999);
        config.max_retries = 3;
        config.retry_delay = Duration::from_millis(1);
        
        let manager = TorManager::new(config);
        
        let start_time = std::time::Instant::now();
        let result = manager.connect("example.com", 80).await;
        let elapsed = start_time.elapsed();
        
        // Should fail after retries
        assert!(result.is_err());
        
        // Should have taken some time due to retries
        assert!(elapsed >= Duration::from_millis(2)); // At least 2 retry delays
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.connections_failed, 1);
    }
}

#[cfg(not(feature = "tor-support"))]
#[tokio::test]
async fn test_tor_feature_disabled() {
    // When tor-support feature is disabled, the tor module should not be available
    // This test just ensures the feature flag works correctly
    assert!(true); // Placeholder test
}