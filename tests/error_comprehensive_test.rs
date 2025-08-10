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
            assert_eq!(code, GdkErrorCode::HardwareWalletNotConnect
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
    let error = GdkError::persistence(GdkErrorCode::PersistenceFileNotFound, "Disk full");
    
    match error {
        GdkError::Persistence { code, message, .. } => {
            assert_eq!(code, GdkErrorCode::PersistenceFileNotFound);
            assert_eq!(message, "Disk full");
        }
        _ => panic!("Expected Persistence error"),
    }
}

#[test]
fn test_gdk_error_with_context() {
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout")
        .with_context("operation", "wallet_sync")
        .with_context("retry_count", "3");
    
    match error {
        GdkError::Network { context, .. } => {
            assert_eq!(context.context.get("operation"), Some(&"wallet_sync".to_str
            assert_eq!(context.context.get("retry_count"), Some(&"3".to_str
        }
        _ => panic!("Expected Network error"),
    }
}

#[test]
fn test_gdk_error_with_call_chain() {
    let error = GdkError::network(GdkErrorCode::NetworkConnectionFailed, "Connection timeout")
        .with_call("connect_to_server")
    ");
    
    match error {
        GdkError::Network { context, 
            assert_eq!(context.call_chain.len(), 2);
            assert!(context.call_chain.contains(
            assert!(context.call_chain.containsng()));
        }
        _ => panic!("Expected Network error"),
    }
}

#[test]
f{
");
    
    match error.recovery_stragy() {
        RecoveryStrategy::Retry { max_attempts, delay_ms, .. } => {
            assert_eq!(*max_attempts, 3);
    0);
        }
        _ => panic!("Expected Retry recovery strategy"),
 
}

#[test]
fn test_gdk_error_display() {
    let error = GdkError::network(GdkErrorC);
    
    
    "));
    assert!(display_str.contains("Connectio
}

#[test]
fn test_gdk_error_debug() {
 t")

    
    let debug_str = format!("{:?}",error);
    
    assert!(debug_str.contains("Network"));
    
    assert!(debug_str"));
    assert!(debug_str.contains));
    assert!(debug_str.contains("sync"));
}

#[tes]
f() {
;
    leto();
    
    match gdk_error {
        GdkError::Io { code, .. } => {
    d);
        }
        _ => panic!("Expected 
    }
}

#[tes
f) {

    letto();
    
    match gdk_error {
        GdkError::Json { code, .. } => {
    
        }
        _ => panic!("Expectedrror"),
    }
}

#[tes]
f) {
rr();
    let();
    
    match gdk_error {
        GdkError::Hex { code, .. } => {
            assert_eq!(code, GdkErrorCode::HexDecodingFailed);
 
ror"),
    }
}

#[test]
f
");
    ass");
    assert_eq!(format!("{}", GdkErr");
}

#[test]
fn test_gdk_error_code_debug() {
    let debug_str = format!("{:?}", GdkEiled);
    assert_eq!(debug_str, "NetworkConne
}

#[tes]
f {
);
    asson");
    assert_eq!(GdkErrorCode::Transacti
    assert_eq!(GdkErrorCode::CryptoInvalidKey.category(), "Cryptographic");
}

#[test]
fn test_gdk_error_code_is_recoverable() {
    asser;
    assert!(GdkErrorCode::NetworkConnectionFailed.
    a
 e());


#[test]
fn test_gdk_error_code_retry_delay() {
    );
    assert_eq!(GdkEr));
    assert_eq!(GdkErrorCode::CryptoInvalidKey.retry_delay_ms(one);
}

#[test]
fn te {
 2000);
 
    mat
        RecoveryStrategy::Retry { 
            assert_eq!(max_attempts, 5);
    2000);
            assert_e);
        }
        _ => panic!("E,
    }
}

#

    let;
    
    match strategy {
    > {
            assert_eq!(alternativer");
        }
    "),
    }
}

#[te
fn test_recovery_strate
    let strategy = RecoveryStrategy::ut");
    
 
> {
       
        }
        _ => panic!("Expected UserInterven
    }
}

#[test]
fn test_recovery_strategy_none() {
    let strategy = RecoveryStrategy::None;
    
    match strategy {
 

       
        _ => panic!("Expected egy"),
    }
}

test]
fn test
    let context = ErrorContext::n
        .with_context("key1", "value1")
        .with_context("key2", "value2")
    
        .with_call("functio)
        .with_operation("test_operation")
 e")
n 1")
       ;
    
    assert_eq!(context.context.get("key1"), ));
    )));
    assert_eq!(context.call_chain.len(), 2);
    assert_eq!(context.operation, Some("test_operation".to_string()));
    ));
    assert_eq!(context.sugge);
}

#[test]
f{
ew()
       _sync")
        .with_context("attempt", "2")
    
    ;
    assert!(debug_str.contains("operation"));
    assert!(debug_str.contains("wallet_sync"));
    );
    assert!(debug_str.contai);
}

#[test]
fn test_error_methods() {
    
    
    assert_eq!(error.code(), GdkErrorCode::NetFailed);
    assert!(error.is_recoverable());
    asser));
    assert!(error.user_message().is_some());
    a());
}

#[test]
fn test_result_type_alias() {
    fn te> {
        Ok(42)
    }
  
 {
       "))
    }
    
    , 42);
    assert!(test_function_error().is_err());
}

#[test]
fn tning() {
    let io_error = iodenied");
    let gdk_error = GdkError::persistence(
        .with_context("underlying_error", &for;
 
error {
       > {
            assert!(context.co;
        }
        _ => panic!("Expected Persistence er"),
   }


#[test]
fn test_error_severity_levels() {
    rity
    let critical_error = GdkError::crypt key");
    let recoverable_error = GdkErroe");
    
    
    // These would be used by se
    assert!(matches!(critical_;
    assert!(matches!(recoverab
    . }));
}

#st]
{
    let
        .with_context("timestamp00:00Z")
        .with_context("user_id", "12345")
    ");
    
    // Test that context can bgging
    let debug_output = format!("{:?}", contet);
    );
    assert!(debug_out
    assert!(debug_output.contains("user_id")
    assert!(debug_output.contains("2345"));
 on"));
);
}

#[test]
fn t
    // Simulate a series of nempts
    let mut errors = Vec::new(;
    
     {
        let error = GdkError::network(
            GdkErrorCode::NetworkConnectionFailed, 
 t"

       
        
        errors.push(error);
    }
    
    t context
    for (i, error) in errors.iter().enumerate() {
        match error {
     => {
    ));
                assert!(matches!(recovery, Re;
            }
 rror"),
      }
    }
}