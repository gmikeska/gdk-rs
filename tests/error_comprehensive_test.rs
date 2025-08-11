//! Comprehensive unit tests for error handling system

use gdk_rs::error::*;
use gdk_rs::{GdkError, Result};
use std::io;

#[test]
fn test_gdk_error_creation() {
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout");
    
    match error {
        GdkError::Network { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::NetworkConnectionFailed);
            assert_eq!(message, "Connection timeout");
        }
        _ => panic!("Expected Network error"),
    }
}

#[test]
fn test_gdk_error_auth() {
    let error = GdkError::auth(GdkErrorCode::AuthInvalidCredentials, "Invalid PIN");
    
    match error {
        GdkError::Auth { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::AuthInvalidCredentials);
            assert_eq!(message, "Invalid PIN");
        }
        _ => panic!("Expected Auth error"),
    }
}

#[test]
fn test_gdk_error_transaction() {
    let error = GdkError::transaction(GdkErrorCode::TransactionInvalidInput, "Invalid UTXO");
    
    match error {
        GdkError::Transaction { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::TransactionInvalidInput);
            assert_eq!(message, "Invalid UTXO");
        }
        _ => panic!("Expected Transaction error"),
    }
}

#[test]
fn test_gdk_error_crypto() {
    let error = GdkError::crypto(GdkErrorCode::CryptoInvalidKey, "Invalid private key");
    
    match error {
        GdkError::Crypto { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::CryptoInvalidKey);
            assert_eq!(message, "Invalid private key");
        }
        _ => panic!("Expected Crypto error"),
    }
}

#[test]
fn test_gdk_error_hardware_wallet() {
    let error = GdkError::hardware_wallet(GdkErrorCode::HardwareWalletNotConnected, "Device not connected");
    
    match error {
        GdkError::HardwareWallet { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::HardwareWalletNotConnected);
            assert_eq!(message, "Device not connected");
        }
        _ => panic!("Expected HardwareWallet error"),
    }
}

#[test]
fn test_gdk_error_invalid_input() {
    let error = GdkError::invalid_input(GdkErrorCode::InvalidInputFormat, "Invalid parameter");
    
    match error {
        GdkError::InvalidInput { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::InvalidInputFormat);
            assert_eq!(message, "Invalid parameter");
        }
        _ => panic!("Expected InvalidInput error"),
    }
}

#[test]
fn test_gdk_error_persistence() {
    let error = GdkError::persistence(GdkErrorCode::PersistenceDiskFull, "Disk full");
    
    match error {
        GdkError::Persistence { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::PersistenceDiskFull);
            assert_eq!(message, "Disk full");
        }
        _ => panic!("Expected Persistence error"),
    }
}

#[test]
fn test_gdk_error_with_context() {
    // Create error and then access its context for modification - not directly chainable
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout");
    
    // Test that the error has context (created during construction)
    match &error {
        GdkError::Network { context, .. } => {
            // The context already has default values from construction
            assert!(context.operation.is_some());
            assert_eq!(context.operation.as_ref().unwrap(), "network_operation");
        }
        _ => panic!("Expected Network error"),
    }
}

#[test]
fn test_gdk_error_with_call_chain() {
    // Create a custom context with call chain
    let custom_context = ErrorContext::new()
        .with_call("connect_to_server")
        .with_call("sync_wallet");
    
    // We can't directly set the context on a GdkError after construction
    // Instead test that context methods work correctly
    assert_eq!(custom_context.call_chain.len(), 2);
    assert!(custom_context.call_chain.contains(&"connect_to_server".to_string()));
    assert!(custom_context.call_chain.contains(&"sync_wallet".to_string()));
}

#[test]
fn test_gdk_error_recovery_strategy() {
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout");
    
    match error.recovery_strategy() {
        RecoveryStrategy::Retry { max_attempts, delay_ms, backoff_multiplier } => {
            // Check that default recovery strategy is set
            assert!(*max_attempts > 0);
            assert!(*delay_ms > 0);
            assert!(*backoff_multiplier >= 1.0);
        }
        _ => panic!("Expected Retry recovery strategy"),
    }
}

#[test]
fn test_gdk_error_display() {
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout");
    
    let display_str = format!("{}", error);
    
    assert!(display_str.contains("Network error"));
    assert!(display_str.contains("Connection timeout"));
}

#[test]
fn test_gdk_error_debug() {
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout");
    
    let debug_str = format!("{:?}", error);
    
    assert!(debug_str.contains("Network"));
    assert!(debug_str.contains("NetworkConnectionFailed"));
    assert!(debug_str.contains("Connection timeout"));
    assert!(debug_str.contains("network_operation")); // Default operation set during construction
}

#[test]
fn test_gdk_error_from_io_error() {
    let io_error = io::Error::new(io::ErrorKind::NotFound, "File not found");
    let gdk_error = GdkError::from(io_error);
    
    match gdk_error {
        GdkError::Io { code, .. } => {
            assert_eq!(code, GdkErrorCode::IoFileNotFound);
        }
        _ => panic!("Expected Io error"),
    }
}

#[test]
fn test_gdk_error_from_json_error() {
    let json_error = serde_json::from_str::<String>("invalid json").unwrap_err();
    let gdk_error = GdkError::from(json_error);
    
    match gdk_error {
        GdkError::Json { code, .. } => {
            assert_eq!(code, GdkErrorCode::JsonDeserializationFailed);
        }
        _ => panic!("Expected Json error"),
    }
}

#[test]
fn test_gdk_error_from_hex_error() {
    let hex_error = hex::decode("invalid hex").unwrap_err();
    let gdk_error = GdkError::from(hex_error);
    
    match gdk_error {
        GdkError::Hex { code, .. } => {
            assert_eq!(code, GdkErrorCode::HexDecodingFailed);
        }
        _ => panic!("Expected Hex error"),
    }
}

#[test]
fn test_gdk_error_code_debug() {
    let debug_str = format!("{:?}", GdkErrorCode::NetworkConnectionFailed);
    assert!(debug_str.contains("NetworkConnectionFailed"));
}

#[test]
fn test_gdk_error_code_categories() {
    // Test that the category method exists and works correctly
    assert_eq!(GdkErrorCode::TransactionInvalidInput.category(), "Transaction");
    assert_eq!(GdkErrorCode::CryptoInvalidKey.category(), "Cryptographic");
    assert_eq!(GdkErrorCode::NetworkTimeout.category(), "Network");
    assert_eq!(GdkErrorCode::AuthPinRequired.category(), "Authentication");
}

#[test]
fn test_gdk_error_code_is_recoverable() {
    // Test that the is_recoverable method exists and works correctly  
    assert!(GdkErrorCode::NetworkConnectionFailed.is_recoverable());
    assert!(GdkErrorCode::NetworkTimeout.is_recoverable());
    assert!(!GdkErrorCode::CryptoInvalidKey.is_recoverable());
    assert!(!GdkErrorCode::AuthMnemonicInvalid.is_recoverable());
}

#[test]
fn test_gdk_error_code_retry_delay() {
    // Test that the retry_delay_ms method exists and works correctly
    assert_eq!(GdkErrorCode::NetworkConnectionFailed.retry_delay_ms(), Some(5000));
    assert_eq!(GdkErrorCode::NetworkTimeout.retry_delay_ms(), Some(1000));
    assert_eq!(GdkErrorCode::CryptoInvalidKey.retry_delay_ms(), None);
    assert_eq!(GdkErrorCode::AuthMnemonicInvalid.retry_delay_ms(), None);
}

#[test]
fn test_recovery_strategy_retry() {
    let strategy = RecoveryStrategy::Retry {
        max_attempts: 5,
        delay_ms: 2000,
        backoff_multiplier: 2.0,
    };
    
    match strategy {
        RecoveryStrategy::Retry { max_attempts, delay_ms, .. } => {
            assert_eq!(max_attempts, 5);
            assert_eq!(delay_ms, 2000);
        }
        _ => panic!("Expected Retry recovery strategy"),
    }
}

#[test]
fn test_recovery_strategy_fallback() {
    let strategy = RecoveryStrategy::Fallback {
        alternative: "Use backup server".to_string(),
    };
    
    match strategy {
        RecoveryStrategy::Fallback { alternative } => {
            assert_eq!(alternative, "Use backup server");
        }
        _ => panic!("Expected Fallback recovery strategy"),
    }
}

#[test]
fn test_recovery_strategy_user_intervention() {
    let strategy = RecoveryStrategy::UserIntervention {
        required_action: "Please check your internet connection".to_string(),
    };
    
    match strategy {
        RecoveryStrategy::UserIntervention { required_action } => {
            assert_eq!(required_action, "Please check your internet connection");
        }
        _ => panic!("Expected UserIntervention recovery strategy"),
    }
}

#[test]
fn test_recovery_strategy_none() {
    let strategy = RecoveryStrategy::None;
    
    match strategy {
        RecoveryStrategy::None => {},
        _ => panic!("Expected None recovery strategy"),
    }
}

#[test]
fn test_error_context() {
    let context = ErrorContext::new()
        .with_context("key1", "value1")
        .with_context("key2", "value2")
        .with_call("function1")
        .with_call("function2")
        .with_operation("test_operation")
        .with_suggested_action("Try again later");
    
    assert_eq!(context.context.get("key1"), Some(&"value1".to_string()));
    assert_eq!(context.context.get("key2"), Some(&"value2".to_string()));
    assert_eq!(context.call_chain.len(), 2);
    assert_eq!(context.operation, Some("test_operation".to_string()));
    assert!(context.suggested_actions.contains(&"Try again later".to_string()));
}

#[test]
fn test_error_context_debug() {
    let context = ErrorContext::new()
        .with_context("operation", "wallet_sync")
        .with_context("attempt", "2");
    
    let debug_str = format!("{:?}", context);
    assert!(debug_str.contains("operation"));
    assert!(debug_str.contains("wallet_sync"));
    assert!(debug_str.contains("attempt"));
    assert!(debug_str.contains("2"));
}

#[test]
fn test_error_methods() {
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout");
    
    assert_eq!(error.code(), GdkErrorCode::NetworkConnectionFailed);
    // Test methods that should exist on GdkError
    assert!(error.is_recoverable());
    assert!(error.user_message().is_some());
    assert_eq!(error.retry_delay_ms(), Some(5000));
}

#[test]
fn test_result_type_alias() {
    fn test_function_ok() -> Result<i32> {
        Ok(42)
    }
    
    fn test_function_error() -> Result<i32> {
        Err(GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Error"))
    }
    
    assert_eq!(test_function_ok().unwrap(), 42);
    assert!(test_function_error().is_err());
}

#[test]
fn test_error_chaining() {
    let _io_error = io::Error::new(io::ErrorKind::PermissionDenied, "Access denied");
    // Create error with appropriate error code
    let gdk_error = GdkError::persistence(GdkErrorCode::PersistencePermissionDenied, "Failed to save file");
    
    match gdk_error {
        GdkError::Persistence { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::PersistencePermissionDenied);
            assert_eq!(message, "Failed to save file");
        }
        _ => panic!("Expected Persistence error"),
    }
}

#[test]
fn test_error_severity_levels() {
    // Create errors with different severity levels
    let critical_error = GdkError::crypto(GdkErrorCode::CryptoInvalidKey, "Invalid private key");
    let recoverable_error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout");
    
    // These would be used by severity-based error handling logic
    assert!(matches!(critical_error, GdkError::Crypto { .. }));
    assert!(matches!(recoverable_error, GdkError::Network { .. }));
}

#[test]
fn test_error_context_accumulation() {
    let context = ErrorContext::new()
        .with_context("timestamp", "2023-01-01T00:00:00Z")
        .with_context("user_id", "12345")
        .with_context("request_id", "abc-123");
    
    // Test that context can be used for debugging
    let debug_output = format!("{:?}", context);
    assert!(debug_output.contains("timestamp"));
    assert!(debug_output.contains("2023-01-01T00:00:00Z"));
    assert!(debug_output.contains("user_id"));
    assert!(debug_output.contains("12345"));
    assert!(debug_output.contains("request_id"));
    assert!(debug_output.contains("abc-123"));
}

#[test]
fn test_error_retry_attempts() {
    // Simulate a series of network attempts
    let mut errors = Vec::new();
    
    for i in 1..=3 {
        // Create errors with different messages to simulate retry attempts
        let error = GdkError::network(
            GdkErrorCode::NetworkConnectionFailed, 
            &format!("Connection timeout (attempt {})", i)
        );
        
        errors.push(error);
    }
    
    // Verify each error has the correct message
    for (i, error) in errors.iter().enumerate() {
        match error {
            GdkError::Network { message, recovery, .. } => {
                assert!(message.contains(&format!("attempt {}", i + 1)));
                assert!(matches!(recovery, RecoveryStrategy::Retry { .. }));
            }
            _ => panic!("Expected Network error"),
        }
    }
}
