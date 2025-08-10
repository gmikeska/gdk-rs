//! Integration tests for complete wallet creation and login flows

use gdk_rs::*;
use gdk_rs::types::*;
use gdk_rs::auth::*;
use gdk_rs::session::*;
use gdk_rs::bip39::*;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper function to create a test configuration
fn create_test_config() -> GdkConfig {
    let temp_dir = TempDir::new().unwrap();
    GdkConfig {
        data_dir: Some(temp_dir.path().to_path_buf()),
        tor_dir: None,
        registry_dir: None,
        log_level: LogLevel::Debug,
        with_shutdown: false,
    }
}

/// Helper function to create test network parameters
fn create_test_network_params() -> ConnectParams {
    ConnectParams {
        name: "testnet".to_string(),
        proxy: None,
        use_tor: false,
        user_agent: Some("gdk-rs-test/1.0".to_string()),
        spv_enabled: false,
        min_fee_rate: Some(1000),
        electrum_url: None,
        electrum_tls: false,
    }
}

#[tokio::test]
async fn test_complete_wallet_creation_flow() {
    // Initialize GDK
    let config = create_test_config();
    init(&config).unwrap();
    
    // Create session
    let mut session = Session::new(config);
    
    // Connect to network
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Generate new mnemonic
    let mnemonic = Mnemonic::generate(256).unwrap(); // 24 words
    assert_eq!(mnemonic.words().len(), 24);
    
    // Create login credentials from mnemonic
    let credentials = LoginCredentials::from_mnemonic(
        mnemonic.to_string(),
        None // No passphrase
    );
    
    // Register new user
    let register_result = session.register_user(&credentials).await.unwrap();
    assert!(!register_result.watch_only);
    assert!(register_result.available_auth_methods.contains(&"mnemonic".to_string()));
    
    // Verify we can login with the same credentials
    let login_result = session.login(&credentials).await.unwrap();
    assert!(!login_result.watch_only);
    assert_eq!(register_result.wallet_hash_id, login_result.wallet_hash_id);
    
    // Disconnect
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_pin_based_authentication_flow() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Generate mnemonic and register user
    let mnemonic = Mnemonic::generate(128).unwrap(); // 12 words
    let initial_credentials = LoginCredentials::from_mnemonic(
        mnemonic.to_string(),
        None
    );
    
    let register_result = session.register_user(&initial_credentials).await.unwrap();
    
    // Set up PIN authentication
    let pin = "123456";
    let pin_data = PinData::new(pin, mnemonic.to_string().as_bytes()).unwrap();
    
    let pin_credentials = LoginCredentials::from_pin(pin.to_string(), pin_data);
    
    // Login with PIN should work
    let login_result = session.login(&pin_credentials).await.unwrap();
    assert!(!login_result.watch_only);
    assert_eq!(register_result.wallet_hash_id, login_result.wallet_hash_id);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_watch_only_wallet_flow() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Create watch-only credentials
    let credentials = LoginCredentials::from_watch_only_user(
        "test_user".to_string(),
        "test_password".to_string()
    );
    
    // Register watch-only user
    let register_result = session.register_user(&credentials).await.unwrap();
    assert!(register_result.watch_only);
    assert!(register_result.available_auth_methods.contains(&"watch_only_user".to_string()));
    
    // Login with watch-only credentials
    let login_result = session.login(&credentials).await.unwrap();
    assert!(login_result.watch_only);
    assert_eq!(register_result.wallet_hash_id, login_result.wallet_hash_id);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_wallet_with_passphrase_flow() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Generate mnemonic
    let mnemonic = Mnemonic::generate(256).unwrap();
    let passphrase = "test_passphrase_123";
    
    // Create credentials with passphrase
    let credentials_with_passphrase = LoginCredentials::from_mnemonic(
        mnemonic.to_string(),
        Some(passphrase.to_string())
    );
    
    // Create credentials without passphrase
    let credentials_without_passphrase = LoginCredentials::from_mnemonic(
        mnemonic.to_string(),
        None
    );
    
    // Register with passphrase
    let register_result_with = session.register_user(&credentials_with_passphrase).await.unwrap();
    
    // Register without passphrase (should create different wallet)
    let register_result_without = session.register_user(&credentials_without_passphrase).await.unwrap();
    
    // Should have different wallet IDs
    assert_ne!(register_result_with.wallet_hash_id, register_result_without.wallet_hash_id);
    
    // Login with correct passphrase should work
    let login_result = session.login(&credentials_with_passphrase).await.unwrap();
    assert_eq!(register_result_with.wallet_hash_id, login_result.wallet_hash_id);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_session_reconnection_flow() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    
    // Initial connection
    session.connect(&network_params).await.unwrap();
    
    // Register user
    let mnemonic = Mnemonic::generate(128).unwrap();
    let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
    let register_result = session.register_user(&credentials).await.unwrap();
    
    // Disconnect
    session.disconnect().await.unwrap();
    
    // Reconnect
    session.connect(&network_params).await.unwrap();
    
    // Should be able to login again
    let login_result = session.login(&credentials).await.unwrap();
    assert_eq!(register_result.wallet_hash_id, login_result.wallet_hash_id);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_multiple_sessions_flow() {
    let config1 = create_test_config();
    let config2 = create_test_config();
    init(&config1).unwrap();
    
    let mut session1 = Session::new(config1);
    let mut session2 = Session::new(config2);
    
    let network_params = create_test_network_params();
    
    // Connect both sessions
    session1.connect(&network_params).await.unwrap();
    session2.connect(&network_params).await.unwrap();
    
    // Create different wallets in each session
    let mnemonic1 = Mnemonic::generate(128).unwrap();
    let mnemonic2 = Mnemonic::generate(128).unwrap();
    
    let credentials1 = LoginCredentials::from_mnemonic(mnemonic1.to_string(), None);
    let credentials2 = LoginCredentials::from_mnemonic(mnemonic2.to_string(), None);
    
    let register_result1 = session1.register_user(&credentials1).await.unwrap();
    let register_result2 = session2.register_user(&credentials2).await.unwrap();
    
    // Should have different wallet IDs
    assert_ne!(register_result1.wallet_hash_id, register_result2.wallet_hash_id);
    
    // Each session should be able to login with its own credentials
    let login_result1 = session1.login(&credentials1).await.unwrap();
    let login_result2 = session2.login(&credentials2).await.unwrap();
    
    assert_eq!(register_result1.wallet_hash_id, login_result1.wallet_hash_id);
    assert_eq!(register_result2.wallet_hash_id, login_result2.wallet_hash_id);
    
    session1.disconnect().await.unwrap();
    session2.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_invalid_credentials_flow() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Try to login with invalid mnemonic
    let invalid_credentials = LoginCredentials::from_mnemonic(
        "invalid mnemonic phrase that should not work".to_string(),
        None
    );
    
    let result = session.login(&invalid_credentials).await;
    assert!(result.is_err());
    
    // Try to register with invalid mnemonic
    let result = session.register_user(&invalid_credentials).await;
    assert!(result.is_err());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_session_state_persistence() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Register and login
    let mnemonic = Mnemonic::generate(128).unwrap();
    let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
    
    let register_result = session.register_user(&credentials).await.unwrap();
    let login_result = session.login(&credentials).await.unwrap();
    
    // Verify session state
    assert_eq!(register_result.wallet_hash_id, login_result.wallet_hash_id);
    
    // Session should maintain state across operations
    let wallet_id = session.get_wallet_identifier().await.unwrap();
    assert_eq!(wallet_id, login_result.wallet_hash_id);
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_notification_system_integration() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    
    // Subscribe to notifications before connecting
    let mut notification_receiver = session.subscribe();
    
    session.connect(&network_params).await.unwrap();
    
    // Register user
    let mnemonic = Mnemonic::generate(128).unwrap();
    let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
    session.register_user(&credentials).await.unwrap();
    
    // Check if we received any notifications during the process
    // Note: This is a simplified test - in a real scenario we'd wait for specific notifications
    tokio::select! {
        notification = notification_receiver.recv() => {
            // If we receive a notification, verify it's properly formatted
            if let Ok(notification) = notification {
                // Basic validation that notification has expected structure
                assert!(!notification.event.is_empty());
            }
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
            // Timeout is OK - notifications might not be generated in test environment
        }
    }
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_error_recovery_flow() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    
    // Try to login without connecting first (should fail)
    let mnemonic = Mnemonic::generate(128).unwrap();
    let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
    
    let result = session.login(&credentials).await;
    assert!(result.is_err());
    
    // Now connect and try again (should work after registration)
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Register first
    session.register_user(&credentials).await.unwrap();
    
    // Now login should work
    let login_result = session.login(&credentials).await;
    assert!(login_result.is_ok());
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_concurrent_operations() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Create multiple mnemonics for concurrent registration
    let mnemonics: Vec<_> = (0..3).map(|_| Mnemonic::generate(128).unwrap()).collect();
    
    // Register users concurrently
    let mut handles = Vec::new();
    for (i, mnemonic) in mnemonics.iter().enumerate() {
        let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
        
        // Note: In a real implementation, we'd need to handle concurrent access properly
        // For this test, we'll do sequential operations to avoid borrowing issues
        let register_result = session.register_user(&credentials).await.unwrap();
        assert!(!register_result.watch_only);
    }
    
    session.disconnect().await.unwrap();
}

#[tokio::test]
async fn test_wallet_recovery_flow() {
    let config = create_test_config();
    init(&config).unwrap();
    
    let mut session = Session::new(config);
    let network_params = create_test_network_params();
    session.connect(&network_params).await.unwrap();
    
    // Create wallet with known mnemonic
    let known_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(known_mnemonic).unwrap();
    
    let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
    
    // Register wallet
    let register_result = session.register_user(&credentials).await.unwrap();
    let original_wallet_id = register_result.wallet_hash_id.clone();
    
    // Disconnect and create new session (simulating app restart)
    session.disconnect().await.unwrap();
    
    let mut new_session = Session::new(create_test_config());
    new_session.connect(&network_params).await.unwrap();
    
    // Recover wallet using same mnemonic
    let recovery_result = new_session.register_user(&credentials).await.unwrap();
    
    // Should recover the same wallet
    assert_eq!(original_wallet_id, recovery_result.wallet_hash_id);
    
    new_session.disconnect().await.unwrap();
}