#![cfg(feature = "hardware-wallets")]

use gdk_rs::*;
use gdk_rs::hw::*;
use std::time::Duration;
use std::str::FromStr;

#[tokio::test]
async fn test_hardware_wallet_manager_creation() {
    let manager = HardwareWalletManager::new();
    assert_eq!(manager.list_connected_devices().len(), 0);
    assert_eq!(manager.list_active_sessions().len(), 0);
}

#[tokio::test]
async fn test_device_discovery() {
    let manager = HardwareWalletManager::new();
    let devices = manager.discover_devices().await.unwrap();
    
    // Should discover at least the mock devices
    assert!(!devices.is_empty());
    
    // Check that we have both Ledger and Trezor mock devices
    let ledger_found = devices.iter().any(|d| d.device_type == HardwareWalletType::Ledger);
    let trezor_found = devices.iter().any(|d| d.device_type == HardwareWalletType::Trezor);
    
    assert!(ledger_found);
    assert!(trezor_found);
}

#[tokio::test]
async fn test_device_connection_and_disconnection() {
    let manager = HardwareWalletManager::new();
    
    // Connect to a mock device
    let result = manager.connect_device("ledger_001").await;
    assert!(result.is_ok());
    
    // Verify device is connected
    let connected_devices = manager.list_connected_devices();
    assert!(connected_devices.contains(&"ledger_001".to_string()));
    
    // Disconnect the device
    let result = manager.disconnect_device("ledger_001").await;
    assert!(result.is_ok());
    
    // Verify device is disconnected
    let connected_devices = manager.list_connected_devices();
    assert!(!connected_devices.contains(&"ledger_001".to_string()));
}

#[tokio::test]
async fn test_session_management() {
    let manager = HardwareWalletManager::new();
    
    // Create a session
    let session_id = manager.create_session("test_device").unwrap();
    assert!(!session_id.is_empty());
    
    // Verify session exists and is active
    let session = manager.get_session(&session_id).unwrap();
    assert_eq!(session.device_id, "test_device");
    assert_eq!(session.state, SessionState::Active);
    
    // Update session activity
    let result = manager.update_session_activity(&session_id);
    assert!(result.is_ok());
    
    // List active sessions
    let active_sessions = manager.list_active_sessions();
    assert_eq!(active_sessions.len(), 1);
    assert_eq!(active_sessions[0].session_id, session_id);
    
    // Terminate session
    let result = manager.terminate_session(&session_id);
    assert!(result.is_ok());
    
    // Verify session is terminated
    let session = manager.get_session(&session_id).unwrap();
    assert_eq!(session.state, SessionState::Terminated);
}

#[tokio::test]
async fn test_ledger_device_connection() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string()],
    };
    
    let mut device = LedgerDevice::new(info);
    
    assert!(!device.is_connected());
    assert_eq!(device.get_status(), ConnectionStatus::Disconnected);
    
    device.connect().await.unwrap();
    
    assert!(device.is_connected());
    assert_eq!(device.get_status(), ConnectionStatus::Connected);
    
    device.disconnect().await.unwrap();
    
    assert!(!device.is_connected());
    assert_eq!(device.get_status(), ConnectionStatus::Disconnected);
}

#[tokio::test]
async fn test_trezor_device_capabilities() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Trezor,
        model: "Test Trezor".to_string(),
        firmware_version: "2.0.0".to_string(),
        device_id: "test_trezor".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "message_signing".to_string()],
    };
    
    let device = TrezorDevice::new(info);
    let capabilities = device.get_capabilities().await.unwrap();
    
    assert!(capabilities.bitcoin_support);
    assert!(!capabilities.liquid_support); // Trezor mock doesn't support Liquid
    assert!(capabilities.psbt_support);
    assert!(capabilities.address_display);
    assert!(capabilities.message_signing);
}

#[tokio::test]
async fn test_device_authentication_when_disconnected() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string()],
    };
    
    let device = LedgerDevice::new(info);
    
    // Should fail when device is not connected
    let result = device.get_auth_credentials().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Device not connected"));
}

#[tokio::test]
async fn test_device_authentication_when_connected() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string()],
    };
    
    let mut device = LedgerDevice::new(info.clone());
    device.connect().await.unwrap();
    
    // Should succeed when device is connected
    let result = device.get_auth_credentials().await;
    assert!(result.is_ok());
    
    let credentials = result.unwrap();
    assert_eq!(credentials.device_info.device_id, info.device_id);
    assert_eq!(credentials.device_info.device_type, info.device_type);
}

#[tokio::test]
async fn test_device_verification() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Trezor,
        model: "Test Trezor".to_string(),
        firmware_version: "2.0.0".to_string(),
        device_id: "test_trezor".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string()],
    };
    
    let mut device = TrezorDevice::new(info);
    
    // Should fail when disconnected
    let result = device.verify_device().await;
    assert!(result.is_err());
    
    // Should succeed when connected
    device.connect().await.unwrap();
    let result = device.verify_device().await;
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[tokio::test]
async fn test_address_display() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "address_display".to_string()],
    };
    
    let mut device = LedgerDevice::new(info);
    device.connect().await.unwrap();
    
    // Mock derivation path
    use gdk_rs::primitives::bip32::DerivationPath;
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    
    let result = device.display_address(&path).await;
    assert!(result.is_ok());
    assert!(result.unwrap()); // Mock implementation returns true
}

#[tokio::test]
async fn test_message_signing_support() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Trezor,
        model: "Test Trezor".to_string(),
        firmware_version: "2.0.0".to_string(),
        device_id: "test_trezor".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "message_signing".to_string()],
    };
    
    let mut device = TrezorDevice::new(info);
    device.connect().await.unwrap();
    
    use gdk_rs::primitives::bip32::DerivationPath;
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    let message = b"test message";
    
    let result = device.sign_message(&path, message).await;
    assert!(result.is_ok());
    
    let signature = result.unwrap();
    assert_eq!(signature.len(), 64); // Mock signature length
}

#[tokio::test]
async fn test_message_signing_not_supported() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string()],
    };
    
    let mut device = LedgerDevice::new(info);
    device.connect().await.unwrap();
    
    use gdk_rs::primitives::bip32::DerivationPath;
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    let message = b"test message";
    
    let result = device.sign_message(&path, message).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Message signing not supported"));
}

#[tokio::test]
async fn test_hardware_wallet_error_recovery() {
    let manager = HardwareWalletManager::new();
    
    // Test connection recovery
    let result = HardwareWalletErrorRecovery::recover_connection("nonexistent_device", &manager).await;
    assert!(result.is_err()); // Should fail for nonexistent device
    
    // Test device busy handling with short timeout
    let result = HardwareWalletErrorRecovery::handle_device_busy("test_device", Duration::from_millis(100)).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("remained busy"));
}

#[tokio::test]
async fn test_error_guidance() {
    let not_connected_error = GdkError::auth_simple("Device not connected".to_string());
    let guidance = HardwareWalletErrorRecovery::get_error_guidance(&not_connected_error);
    assert!(guidance.contains("ensure your hardware wallet is connected"));
    
    let locked_error = GdkError::auth_simple("Device locked out".to_string());
    let guidance = HardwareWalletErrorRecovery::get_error_guidance(&locked_error);
    assert!(guidance.contains("locked"));
    
    let busy_error = GdkError::auth_simple("Device is busy".to_string());
    let guidance = HardwareWalletErrorRecovery::get_error_guidance(&busy_error);
    assert!(guidance.contains("busy"));
    
    let generic_error = GdkError::network_simple("Connection failed".to_string());
    let guidance = HardwareWalletErrorRecovery::get_error_guidance(&generic_error);
    assert!(guidance.contains("check your hardware wallet connection"));
}

#[tokio::test]
async fn test_device_types_and_capabilities() {
    // Test all device types can be created and have expected capabilities
    let device_types = vec![
        (HardwareWalletType::Ledger, true, true, false),   // bitcoin, liquid, no message signing
        (HardwareWalletType::Trezor, true, false, true),   // bitcoin, no liquid, message signing
        (HardwareWalletType::Coldcard, true, false, true), // bitcoin, no liquid, message signing
        (HardwareWalletType::BitBox, true, false, true),   // bitcoin, no liquid, message signing
        (HardwareWalletType::KeepKey, true, false, true),  // bitcoin, no liquid, message signing
        (HardwareWalletType::Jade, true, true, false),     // bitcoin, liquid, no message signing
    ];
    
    for (device_type, bitcoin_support, liquid_support, message_signing) in device_types {
        let info = HardwareWalletInfo {
            device_type,
            model: format!("Test {:?}", device_type),
            firmware_version: "1.0.0".to_string(),
            device_id: format!("test_{:?}", device_type).to_lowercase(),
            initialized: true,
            features: vec!["bitcoin".to_string()],
        };
        
        let manager = HardwareWalletManager::new();
        let device = manager.create_device_instance(&info).unwrap();
        let capabilities = device.get_capabilities().await.unwrap();
        
        assert_eq!(capabilities.bitcoin_support, bitcoin_support);
        assert_eq!(capabilities.liquid_support, liquid_support);
        assert_eq!(capabilities.message_signing, message_signing);
        assert!(capabilities.psbt_support); // All devices support PSBT
        assert!(capabilities.address_display); // All devices support address display
    }
}

#[tokio::test]
async fn test_session_cleanup() {
    let mut manager = HardwareWalletManager::new();
    
    // Create a session
    let session_id = manager.create_session("test_device").unwrap();
    
    // Verify session exists
    assert!(manager.get_session(&session_id).is_some());
    
    // Manually trigger cleanup (in real scenario this would happen automatically)
    let result = manager.cleanup_expired().await;
    assert!(result.is_ok());
    
    // Stop cleanup task to avoid resource leaks in tests
    manager.stop_cleanup_task();
}

#[tokio::test]
async fn test_connection_retry_logic() {
    let manager = HardwareWalletManager::new();
    
    // Try to connect to a nonexistent device - should fail after retries
    let result = manager.connect_device("nonexistent_device").await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn test_device_info_serialization() {
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Nano S Plus".to_string(),
        firmware_version: "1.1.0".to_string(),
        device_id: "ledger_001".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "liquid".to_string()],
    };
    
    // Test serialization
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("Ledger"));
    assert!(json.contains("Nano S Plus"));
    
    // Test deserialization
    let deserialized: HardwareWalletInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.device_type, HardwareWalletType::Ledger);
    assert_eq!(deserialized.model, "Nano S Plus");
    assert_eq!(deserialized.device_id, "ledger_001");
}

// Hardware wallet transaction signing tests

#[tokio::test]
async fn test_psbt_signing_ledger() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut device = LedgerDevice::new(info);
    device.connect().await.unwrap();
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test PSBT signing
    let result = device.sign_psbt(&psbt).await;
    assert!(result.is_ok());
    
    let signed_psbt = result.unwrap();
    assert_eq!(signed_psbt.inputs.len(), psbt.inputs.len());
    assert_eq!(signed_psbt.outputs.len(), psbt.outputs.len());
}

#[tokio::test]
async fn test_psbt_signing_trezor() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Trezor,
        model: "Test Trezor".to_string(),
        firmware_version: "2.0.0".to_string(),
        device_id: "test_trezor".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut device = TrezorDevice::new(info);
    device.connect().await.unwrap();
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test PSBT signing
    let result = device.sign_psbt(&psbt).await;
    assert!(result.is_ok());
    
    let signed_psbt = result.unwrap();
    assert_eq!(signed_psbt.inputs.len(), psbt.inputs.len());
    assert_eq!(signed_psbt.outputs.len(), psbt.outputs.len());
}

#[tokio::test]
async fn test_psbt_signing_when_disconnected() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let device = LedgerDevice::new(info);
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Should fail when device is not connected
    let result = device.sign_psbt(&psbt).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Device not connected"));
}

#[tokio::test]
async fn test_psbt_input_signing() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut device = LedgerDevice::new(info);
    device.connect().await.unwrap();
    
    // Create a mock PSBT with multiple inputs
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint { txid: [1u8; 32], vout: 1 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
        ],
        output: vec![
            TxOut {
                value: 100000,
                script_pubkey: Script::new(),
            }
        ],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test signing specific inputs
    let input_indices = vec![0, 1];
    let result = device.sign_psbt_inputs(&psbt, &input_indices).await;
    assert!(result.is_ok());
    
    // Test signing with invalid input index
    let invalid_indices = vec![5];
    let result = device.sign_psbt_inputs(&psbt, &invalid_indices).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("out of bounds"));
}

#[tokio::test]
async fn test_transaction_display() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Trezor,
        model: "Test Trezor".to_string(),
        firmware_version: "2.0.0".to_string(),
        device_id: "test_trezor".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut device = TrezorDevice::new(info);
    device.connect().await.unwrap();
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test transaction display
    let result = device.display_transaction(&psbt).await;
    assert!(result.is_ok());
    assert!(result.unwrap()); // Mock implementation returns true
}

#[tokio::test]
async fn test_signing_capabilities_analysis() {
    use gdk_rs::primitives::psbt::{PartiallySignedTransaction, PsbtInput, Bip32Derivation};
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    use gdk_rs::primitives::bip32::{DerivationPath, Fingerprint};
    use secp256k1::PublicKey;
    use std::collections::BTreeMap;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut device = LedgerDevice::new(info);
    device.connect().await.unwrap();
    
    // Create a mock PSBT with mixed signable/unsignable inputs
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint { txid: [1u8; 32], vout: 1 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
        ],
        output: vec![],
    };
    
    let mut psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Add BIP32 derivation info to first input (making it signable)
    let pubkey_bytes = [2u8; 33]; // Mock compressed public key
    let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
    let mut bip32_derivation = BTreeMap::new();
    bip32_derivation.insert(pubkey, Bip32Derivation {
        fingerprint: Fingerprint([0u8; 4]),
        path: DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap(),
    });
    
    psbt.inputs[0].bip32_derivation = bip32_derivation;
    // Leave second input without BIP32 derivation (making it unsignable)
    
    // Test signing capabilities analysis
    let result = device.get_signing_capabilities(&psbt).await;
    assert!(result.is_ok());
    
    let capabilities = result.unwrap();
    assert!(!capabilities.can_sign_all); // Not all inputs can be signed
    assert_eq!(capabilities.signable_inputs, vec![0]); // Only first input is signable
    assert_eq!(capabilities.unsignable_inputs, vec![1]); // Second input is not signable
    assert!(capabilities.unsignable_reasons.contains_key(&1));
    assert!(capabilities.requires_confirmation);
    assert!(capabilities.estimated_time_seconds > 0);
}

#[tokio::test]
async fn test_multi_device_signing_coordination() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    
    // Create multiple devices
    let ledger_info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let trezor_info = HardwareWalletInfo {
        device_type: HardwareWalletType::Trezor,
        model: "Test Trezor".to_string(),
        firmware_version: "2.0.0".to_string(),
        device_id: "test_trezor".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut ledger_device = LedgerDevice::new(ledger_info);
    let mut trezor_device = TrezorDevice::new(trezor_info);
    
    ledger_device.connect().await.unwrap();
    trezor_device.connect().await.unwrap();
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test that both devices can sign the same PSBT
    let ledger_result = ledger_device.sign_psbt(&psbt).await;
    let trezor_result = trezor_device.sign_psbt(&psbt).await;
    
    assert!(ledger_result.is_ok());
    assert!(trezor_result.is_ok());
    
    // In a real implementation, you would combine the signatures from both devices
    let ledger_signed = ledger_result.unwrap();
    let trezor_signed = trezor_result.unwrap();
    
    // Both should have the same structure
    assert_eq!(ledger_signed.inputs.len(), trezor_signed.inputs.len());
    assert_eq!(ledger_signed.outputs.len(), trezor_signed.outputs.len());
}

#[tokio::test]
async fn test_hardware_wallet_manager_psbt_operations() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    
    let manager = HardwareWalletManager::new();
    
    // Connect to a device
    let result = manager.connect_device("ledger_001").await;
    assert!(result.is_ok());
    
    // Create a session
    let session_id = manager.create_session("ledger_001").unwrap();
    
    // Update session activity (simulating PSBT signing activity)
    let result = manager.update_session_activity(&session_id);
    assert!(result.is_ok());
    
    // Verify session is still active
    let session = manager.get_session(&session_id).unwrap();
    assert_eq!(session.state, SessionState::Active);
    
    // Clean up
    let result = manager.disconnect_device("ledger_001").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_hardware_wallet_error_handling_during_signing() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let device = LedgerDevice::new(info); // Not connected
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test all signing operations fail when device is not connected
    let sign_result = device.sign_psbt(&psbt).await;
    assert!(sign_result.is_err());
    
    let sign_inputs_result = device.sign_psbt_inputs(&psbt, &[]).await;
    assert!(sign_inputs_result.is_err());
    
    let display_result = device.display_transaction(&psbt).await;
    assert!(display_result.is_err());
    
    let capabilities_result = device.get_signing_capabilities(&psbt).await;
    assert!(capabilities_result.is_err());
    
    // All should return the same "Device not connected" error
    assert!(sign_result.unwrap_err().to_string().contains("Device not connected"));
    assert!(sign_inputs_result.unwrap_err().to_string().contains("Device not connected"));
    assert!(display_result.unwrap_err().to_string().contains("Device not connected"));
    assert!(capabilities_result.unwrap_err().to_string().contains("Device not connected"));
}
// Additional tests for hardware wallet transaction signing functionality

#[tokio::test]
async fn test_hardware_wallet_signing_coordinator() {
    use gdk_rs::hw::{HardwareWalletSigningCoordinator, SigningStatus};
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    use std::sync::Arc;
    
    let manager = Arc::new(HardwareWalletManager::new());
    let coordinator = HardwareWalletSigningCoordinator::new(manager);
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test starting a multi-device signing session with non-connected devices
    let device_ids = vec!["device1".to_string(), "device2".to_string()];
    let result = coordinator.start_multi_device_signing(psbt, device_ids, None).await;
    
    // Should fail because devices are not connected
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Device not connected"));
}

#[tokio::test]
async fn test_hardware_wallet_signature_verifier() {
    use gdk_rs::hw::HardwareWalletSignatureVerifier;
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }
        ],
        output: vec![
            TxOut {
                value: 100000,
                script_pubkey: Script::new(),
            }
        ],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test signature verification on empty PSBT
    let result = HardwareWalletSignatureVerifier::verify_psbt_signatures(&psbt);
    assert!(result.is_ok());
    
    let verification_result = result.unwrap();
    assert!(!verification_result.all_verified); // No signatures to verify
    assert_eq!(verification_result.verified_inputs.len(), 0);
    assert_eq!(verification_result.failed_inputs.len(), 1); // One input with no signatures
}

#[tokio::test]
async fn test_hardware_wallet_signing_error_types() {
    use gdk_rs::hw::{HardwareWalletSigningError, SigningErrorType};
    
    // Test different error types and their guidance
    let error_types = vec![
        (SigningErrorType::DeviceNotConnected, true, "connect your hardware wallet"),
        (SigningErrorType::UserRejected, true, "rejected on the hardware wallet"),
        (SigningErrorType::DeviceTimeout, true, "did not respond in time"),
        (SigningErrorType::UnsupportedTransaction, false, "not supported by your hardware wallet"),
        (SigningErrorType::InsufficientPermissions, true, "does not have permission"),
        (SigningErrorType::DeviceError, true, "error occurred on the hardware wallet"),
        (SigningErrorType::CommunicationError, true, "Failed to communicate"),
        (SigningErrorType::InvalidPsbt, false, "transaction data is invalid"),
        (SigningErrorType::UnknownError, true, "unknown error occurred"),
    ];
    
    for (error_type, expected_retry, expected_guidance_contains) in error_types {
        let error = HardwareWalletSigningError::new(
            error_type,
            "test_device".to_string(),
            "Test error message".to_string(),
        );
        
        assert_eq!(error.retry_possible, expected_retry);
        assert!(error.user_guidance.to_lowercase().contains(expected_guidance_contains));
        assert!(!error.suggested_actions.is_empty());
    }
}

#[tokio::test]
async fn test_hardware_wallet_signing_error_from_gdk_error() {
    use gdk_rs::hw::{HardwareWalletSigningError, SigningErrorType};
    
    // Test conversion from different GdkError types
    let test_cases = vec![
        (GdkError::auth_simple("Device not connected".to_string()), SigningErrorType::DeviceNotConnected),
        (GdkError::auth_simple("User rejected transaction".to_string()), SigningErrorType::UserRejected),
        (GdkError::hardware_wallet_simple("Device timeout".to_string()), SigningErrorType::DeviceTimeout),
        (GdkError::hardware_wallet_simple("Unsupported transaction".to_string()), SigningErrorType::UnsupportedTransaction),
        (GdkError::invalid_input_simple("Invalid PSBT".to_string()), SigningErrorType::InvalidPsbt),
        (GdkError::hardware_wallet_simple("Device error".to_string()), SigningErrorType::DeviceError),
        (GdkError::network_simple("Connection failed".to_string()), SigningErrorType::CommunicationError),
        (GdkError::unknown(GdkErrorCode::Unknown, "Unknown error"), SigningErrorType::UnknownError),
    ];
    
    for (gdk_error, expected_error_type) in test_cases {
        let signing_error = HardwareWalletSigningError::from_gdk_error(gdk_error, "test_device".to_string());
        assert_eq!(signing_error.error_type, expected_error_type);
        assert_eq!(signing_error.device_id, "test_device");
    }
}

#[tokio::test]
async fn test_hardware_wallet_transaction_signer() {
    use gdk_rs::hw::HardwareWalletTransactionSigner;
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    use std::sync::Arc;
    
    let manager = Arc::new(HardwareWalletManager::new());
    let signer = HardwareWalletTransactionSigner::new(manager);
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test signing with non-connected device
    let result = signer.sign_transaction("nonexistent_device", &psbt).await;
    assert!(result.is_err());
    
    let error = result.unwrap_err();
    assert_eq!(error.error_type, gdk_rs::hw::SigningErrorType::DeviceNotConnected);
    assert_eq!(error.device_id, "nonexistent_device");
    assert!(error.retry_possible);
}

#[tokio::test]
async fn test_hardware_wallet_transaction_signer_multi_device() {
    use gdk_rs::hw::HardwareWalletTransactionSigner;
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    use std::sync::Arc;
    
    let manager = Arc::new(HardwareWalletManager::new());
    let signer = HardwareWalletTransactionSigner::new(manager);
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test multi-device signing with non-connected devices
    let device_ids = vec!["device1".to_string(), "device2".to_string()];
    let result = signer.sign_transaction_multi_device(device_ids, &psbt, None).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.device_id, "multi-device");
}

#[tokio::test]
async fn test_hardware_wallet_transaction_signer_input_signing() {
    use gdk_rs::hw::HardwareWalletTransactionSigner;
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    use std::sync::Arc;
    
    let manager = Arc::new(HardwareWalletManager::new());
    let signer = HardwareWalletTransactionSigner::new(manager);
    
    // Create a mock PSBT with multiple inputs
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint { txid: [1u8; 32], vout: 1 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
        ],
        output: vec![
            TxOut {
                value: 100000,
                script_pubkey: Script::new(),
            }
        ],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test signing specific inputs with non-connected device
    let input_indices = vec![0, 1];
    let result = signer.sign_transaction_inputs("nonexistent_device", &psbt, &input_indices).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, gdk_rs::hw::SigningErrorType::DeviceNotConnected);
}

#[tokio::test]
async fn test_hardware_wallet_transaction_signer_capabilities() {
    use gdk_rs::hw::HardwareWalletTransactionSigner;
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    use std::sync::Arc;
    
    let manager = Arc::new(HardwareWalletManager::new());
    let signer = HardwareWalletTransactionSigner::new(manager);
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![],
        output: vec![],
    };
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test getting capabilities for non-connected device
    let result = signer.get_signing_capabilities("nonexistent_device", &psbt).await;
    
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert_eq!(error.error_type, gdk_rs::hw::SigningErrorType::DeviceNotConnected);
}

#[tokio::test]
async fn test_hardware_wallet_transaction_signer_signature_verification() {
    use gdk_rs::hw::HardwareWalletTransactionSigner;
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    use std::sync::Arc;
    
    let manager = Arc::new(HardwareWalletManager::new());
    let signer = HardwareWalletTransactionSigner::new(manager);
    
    // Create a mock PSBT
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            }
        ],
        output: vec![
            TxOut {
                value: 100000,
                script_pubkey: Script::new(),
            }
        ],
    };
    
    let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Test signature verification
    let result = signer.verify_signatures(&psbt);
    assert!(result.is_ok());
    
    let verification_result = result.unwrap();
    assert!(!verification_result.all_verified); // No signatures to verify
    assert_eq!(verification_result.verified_inputs.len(), 0);
    assert_eq!(verification_result.failed_inputs.len(), 1);
}

#[tokio::test]
async fn test_device_signing_capability_verification() {
    use gdk_rs::hw::HardwareWalletSignatureVerifier;
    use gdk_rs::primitives::psbt::{PartiallySignedTransaction, PsbtInput, Bip32Derivation};
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    use gdk_rs::primitives::bip32::{DerivationPath, Fingerprint};
    use secp256k1::PublicKey;
    use std::collections::BTreeMap;
    
    let info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut device = LedgerDevice::new(info);
    device.connect().await.unwrap();
    
    // Create a mock PSBT with mixed signable/unsignable inputs
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint { txid: [1u8; 32], vout: 1 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
        ],
        output: vec![],
    };
    
    let mut psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Add BIP32 derivation info to first input only
    let pubkey_bytes = [2u8; 33];
    let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
    let mut bip32_derivation = BTreeMap::new();
    bip32_derivation.insert(pubkey, Bip32Derivation {
        fingerprint: Fingerprint([0u8; 4]),
        path: DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap(),
    });
    
    psbt.inputs[0].bip32_derivation = bip32_derivation;
    
    // Test device capability verification for specific inputs
    let input_indices = vec![0, 1];
    let result = HardwareWalletSignatureVerifier::verify_device_can_sign(
        &device as &dyn HardwareWallet,
        &psbt,
        &input_indices,
    ).await;
    
    assert!(result.is_ok());
    let capability_result = result.unwrap();
    
    assert!(!capability_result.can_sign_all); // Not all inputs can be signed
    assert_eq!(capability_result.can_sign, vec![0]); // Only first input
    assert_eq!(capability_result.cannot_sign, vec![1]); // Second input cannot be signed
    assert!(capability_result.reasons.contains_key(&1));
    assert!(capability_result.estimated_time > 0);
}

#[tokio::test]
async fn test_signing_session_management() {
    use gdk_rs::hw::{HardwareWalletSigningCoordinator, SigningStatus};
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::Transaction;
    use std::sync::Arc;
    use std::time::Duration;
    
    let manager = Arc::new(HardwareWalletManager::new());
    let coordinator = HardwareWalletSigningCoordinator::new(manager);
    
    // Test session cleanup
    coordinator.cleanup_sessions();
    
    // Test listing active sessions (should be empty)
    let active_sessions = coordinator.list_active_sessions();
    assert_eq!(active_sessions.len(), 0);
    
    // Test getting non-existent session
    let session = coordinator.get_signing_session("nonexistent");
    assert!(session.is_none());
    
    // Test cancelling non-existent session
    let result = coordinator.cancel_signing_session("nonexistent");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_comprehensive_device_signing_flow() {
    use gdk_rs::primitives::psbt::PartiallySignedTransaction;
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    
    // Test the complete signing flow for each device type
    let device_types = vec![
        HardwareWalletType::Ledger,
        HardwareWalletType::Trezor,
        HardwareWalletType::Coldcard,
        HardwareWalletType::BitBox,
        HardwareWalletType::KeepKey,
        HardwareWalletType::Jade,
    ];
    
    for device_type in device_types {
        let info = HardwareWalletInfo {
            device_type,
            model: format!("Test {:?}", device_type),
            firmware_version: "1.0.0".to_string(),
            device_id: format!("test_{:?}", device_type).to_lowercase(),
            initialized: true,
            features: vec!["bitcoin".to_string(), "psbt".to_string()],
        };
        
        let manager = HardwareWalletManager::new();
        let mut device = manager.create_device_instance(&info).unwrap();
        
        // Connect device
        device.connect().await.unwrap();
        assert!(device.is_connected());
        
        // Create a mock PSBT
        let unsigned_tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                TxIn {
                    previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                    script_sig: Script::new(),
                    sequence: 0xffffffff,
                    witness: vec![],
                }
            ],
            output: vec![
                TxOut {
                    value: 100000,
                    script_pubkey: Script::new(),
                }
            ],
        };
        
        let psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
        
        // Test complete signing flow
        
        // 1. Get signing capabilities
        let capabilities = device.get_signing_capabilities(&psbt).await.unwrap();
        assert!(capabilities.estimated_time_seconds > 0);
        
        // 2. Display transaction
        let display_result = device.display_transaction(&psbt).await.unwrap();
        assert!(display_result); // Mock implementation returns true
        
        // 3. Sign PSBT
        let signed_psbt = device.sign_psbt(&psbt).await.unwrap();
        assert_eq!(signed_psbt.inputs.len(), psbt.inputs.len());
        assert_eq!(signed_psbt.outputs.len(), psbt.outputs.len());
        
        // 4. Sign specific inputs
        let input_indices = vec![0];
        let signed_inputs_psbt = device.sign_psbt_inputs(&psbt, &input_indices).await.unwrap();
        assert_eq!(signed_inputs_psbt.inputs.len(), psbt.inputs.len());
        
        // 5. Verify device
        let verification_result = device.verify_device().await.unwrap();
        assert!(verification_result);
        
        // 6. Get auth credentials
        let credentials = device.get_auth_credentials().await.unwrap();
        assert_eq!(credentials.device_info.device_type, device_type);
        
        // Disconnect device
        device.disconnect().await.unwrap();
        assert!(!device.is_connected());
    }
}

#[tokio::test]
async fn test_psbt_combination_in_multi_device_scenario() {
    use gdk_rs::primitives::psbt::{PartiallySignedTransaction, PsbtInput, Bip32Derivation};
    use gdk_rs::primitives::transaction::{Transaction, TxIn, TxOut};
    use gdk_rs::primitives::transaction::OutPoint;
    use gdk_rs::primitives::script::Script;
    use gdk_rs::primitives::bip32::{DerivationPath, Fingerprint};
    use secp256k1::PublicKey;
    use std::collections::BTreeMap;
    
    // Create two devices
    let ledger_info = HardwareWalletInfo {
        device_type: HardwareWalletType::Ledger,
        model: "Test Ledger".to_string(),
        firmware_version: "1.0.0".to_string(),
        device_id: "test_ledger".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let trezor_info = HardwareWalletInfo {
        device_type: HardwareWalletType::Trezor,
        model: "Test Trezor".to_string(),
        firmware_version: "2.0.0".to_string(),
        device_id: "test_trezor".to_string(),
        initialized: true,
        features: vec!["bitcoin".to_string(), "psbt".to_string()],
    };
    
    let mut ledger_device = LedgerDevice::new(ledger_info);
    let mut trezor_device = TrezorDevice::new(trezor_info);
    
    ledger_device.connect().await.unwrap();
    trezor_device.connect().await.unwrap();
    
    // Create a mock PSBT with multiple inputs
    let unsigned_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![
            TxIn {
                previous_output: OutPoint { txid: [0u8; 32], vout: 0 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
            TxIn {
                previous_output: OutPoint { txid: [1u8; 32], vout: 1 },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: vec![],
            },
        ],
        output: vec![
            TxOut {
                value: 100000,
                script_pubkey: Script::new(),
            }
        ],
    };
    
    let mut psbt = PartiallySignedTransaction::new(unsigned_tx).unwrap();
    
    // Add different BIP32 derivation info to each input (simulating different devices owning different inputs)
    let pubkey1_bytes = [2u8; 33];
    let pubkey1 = PublicKey::from_slice(&pubkey1_bytes).unwrap();
    let mut bip32_derivation1 = BTreeMap::new();
    bip32_derivation1.insert(pubkey1, Bip32Derivation {
        fingerprint: Fingerprint([1u8; 4]),
        path: DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap(),
    });
    
    let pubkey2_bytes = [3u8; 33];
    let pubkey2 = PublicKey::from_slice(&pubkey2_bytes).unwrap();
    let mut bip32_derivation2 = BTreeMap::new();
    bip32_derivation2.insert(pubkey2, Bip32Derivation {
        fingerprint: Fingerprint([2u8; 4]),
        path: DerivationPath::from_str("m/44'/0'/0'/0/1").unwrap(),
    });
    
    psbt.inputs[0].bip32_derivation = bip32_derivation1;
    psbt.inputs[1].bip32_derivation = bip32_derivation2;
    
    // Sign with both devices
    let ledger_signed = ledger_device.sign_psbt(&psbt).await.unwrap();
    let trezor_signed = trezor_device.sign_psbt(&psbt).await.unwrap();
    
    // Combine the PSBTs
    let mut combined_psbt = ledger_signed.clone();
    let combine_result = combined_psbt.combine(&trezor_signed);
    assert!(combine_result.is_ok());
    
    // The combined PSBT should have the same structure
    assert_eq!(combined_psbt.inputs.len(), psbt.inputs.len());
    assert_eq!(combined_psbt.outputs.len(), psbt.outputs.len());
    
    // Both devices should have contributed their BIP32 derivation information
    assert!(!combined_psbt.inputs[0].bip32_derivation.is_empty());
    assert!(!combined_psbt.inputs[1].bip32_derivation.is_empty());
}

#[tokio::test]
async fn test_hardware_wallet_feature_support_utility_functions() {
    use gdk_rs::hw::{device_supports_feature, get_recommended_devices_for_feature};
    
    // Test device feature support
    assert!(device_supports_feature(HardwareWalletType::Ledger, "bitcoin"));
    assert!(device_supports_feature(HardwareWalletType::Ledger, "liquid"));
    assert!(!device_supports_feature(HardwareWalletType::Ledger, "message_signing"));
    
    assert!(device_supports_feature(HardwareWalletType::Trezor, "bitcoin"));
    assert!(!device_supports_feature(HardwareWalletType::Trezor, "liquid"));
    assert!(device_supports_feature(HardwareWalletType::Trezor, "message_signing"));
    
    assert!(device_supports_feature(HardwareWalletType::Jade, "bitcoin"));
    assert!(device_supports_feature(HardwareWalletType::Jade, "liquid"));
    assert!(!device_supports_feature(HardwareWalletType::Jade, "message_signing"));
    
    // Test recommended devices for features
    let liquid_devices = get_recommended_devices_for_feature("liquid");
    assert!(liquid_devices.contains(&HardwareWalletType::Ledger));
    assert!(liquid_devices.contains(&HardwareWalletType::Jade));
    assert!(!liquid_devices.contains(&HardwareWalletType::Trezor));
    
    let message_signing_devices = get_recommended_devices_for_feature("message_signing");
    assert!(message_signing_devices.contains(&HardwareWalletType::Trezor));
    assert!(message_signing_devices.contains(&HardwareWalletType::Coldcard));
    assert!(!message_signing_devices.contains(&HardwareWalletType::Ledger));
    
    let bitcoin_devices = get_recommended_devices_for_feature("bitcoin");
    assert_eq!(bitcoin_devices.len(), 6); // All devices support Bitcoin
    
    let unknown_feature_devices = get_recommended_devices_for_feature("unknown_feature");
    assert_eq!(unknown_feature_devices.len(), 0);
}