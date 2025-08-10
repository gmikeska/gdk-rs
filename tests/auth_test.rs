use gdk_rs::auth::*;
use gdk_rs::types::LoginCredentials;

#[test]
fn test_pin_data_creation_and_decryption() {
    let pin = "1234";
    let credentials = b"test mnemonic phrase";
    
    let mut pin_data = PinData::new(pin, credentials).unwrap();
    let decrypted = pin_data.decrypt_with_pin(pin).unwrap();
    
    assert_eq!(decrypted, credentials);
}

#[test]
fn test_pin_validation_failure() {
    let pin = "1234";
    let wrong_pin = "5678";
    let credentials = b"test mnemonic phrase";
    
    let mut pin_data = PinData::new(pin, credentials).unwrap();
    let result = pin_data.decrypt_with_pin(wrong_pin);
    
    assert!(result.is_err());
    assert_eq!(pin_data.failed_attempts, 1);
}

#[test]
fn test_pin_lockout() {
    let pin = "1234";
    let wrong_pin = "5678";
    let credentials = b"test mnemonic phrase";
    
    let mut pin_data = PinData::new(pin, credentials).unwrap();
    
    // Fail 3 times
    for _ in 0..3 {
        let _ = pin_data.decrypt_with_pin(wrong_pin);
    }
    
    assert!(pin_data.is_locked_out());
    
    // Should fail even with correct PIN when locked out
    let result = pin_data.decrypt_with_pin(pin);
    assert!(result.is_err());
}

#[test]
fn test_pin_change() {
    let old_pin = "1234";
    let new_pin = "5678";
    let credentials = b"test mnemonic phrase";
    
    let mut pin_data = PinData::new(old_pin, credentials).unwrap();
    pin_data.change_pin(old_pin, new_pin).unwrap();
    
    // Should fail with old PIN
    let result = pin_data.decrypt_with_pin(old_pin);
    assert!(result.is_err());
    
    // Should work with new PIN
    let decrypted = pin_data.decrypt_with_pin(new_pin).unwrap();
    assert_eq!(decrypted, credentials);
}

#[tokio::test]
async fn test_auth_manager_register_mnemonic() {
    let mut auth_manager = AuthManager::new();
    let credentials = LoginCredentials::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        None
    );
    
    let result = auth_manager.register_user(&credentials).await.unwrap();
    assert!(!result.watch_only);
    assert!(result.available_auth_methods.contains(&"mnemonic".to_string()));
}

#[tokio::test]
async fn test_auth_manager_register_watch_only() {
    let mut auth_manager = AuthManager::new();
    let credentials = LoginCredentials::from_watch_only_user(
        "testuser".to_string(),
        "testpass".to_string()
    );
    
    let result = auth_manager.register_user(&credentials).await.unwrap();
    assert!(result.watch_only);
    assert!(result.available_auth_methods.contains(&"watch_only_user".to_string()));
}

// PIN and xpub validation functions are private implementation details
// Their behavior is tested through the public API tests above
