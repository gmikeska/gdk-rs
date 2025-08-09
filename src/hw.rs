use crate::error::GdkError;
use crate::primitives::bip32::{ExtendedPublicKey, DerivationPath};
use crate::primitives::address::Address;
use crate::primitives::psbt::PartiallySignedTransaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Hardware wallet device types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareWalletType {
    Ledger,
    Trezor,
    Coldcard,
    BitBox,
    KeepKey,
    Jade,
}

/// Hardware wallet connection status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    Disconnected,
    Connected,
    Busy,
    Error(String),
}

/// Hardware wallet device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWalletInfo {
    /// Device type
    pub device_type: HardwareWalletType,
    /// Device model name
    pub model: String,
    /// Firmware version
    pub firmware_version: String,
    /// Device serial number or identifier
    pub device_id: String,
    /// Whether device is initialized
    pub initialized: bool,
    /// Supported features
    pub features: Vec<String>,
}

/// Hardware wallet capabilities
#[derive(Debug, Clone)]
pub struct HardwareWalletCapabilities {
    /// Supports Bitcoin transactions
    pub bitcoin_support: bool,
    /// Supports Liquid transactions
    pub liquid_support: bool,
    /// Supports PSBT signing
    pub psbt_support: bool,
    /// Supports address display verification
    pub address_display: bool,
    /// Supports message signing
    pub message_signing: bool,
    /// Maximum derivation path depth
    pub max_derivation_depth: u32,
}

/// Hardware wallet authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWalletCredentials {
    /// Device information
    pub device_info: HardwareWalletInfo,
    /// Master extended public key
    pub master_xpub: Option<String>,
    /// Device-specific authentication data
    pub auth_data: HashMap<String, String>,
}

/// Hardware wallet trait for device-agnostic operations
#[async_trait::async_trait]
pub trait HardwareWallet: Send + Sync {
    /// Get device information
    async fn get_device_info(&self) -> Result<HardwareWalletInfo, GdkError>;
    
    /// Get device capabilities
    async fn get_capabilities(&self) -> Result<HardwareWalletCapabilities, GdkError>;
    
    /// Connect to the hardware wallet device
    async fn connect(&mut self) -> Result<(), GdkError>;
    
    /// Disconnect from the hardware wallet device
    async fn disconnect(&mut self) -> Result<(), GdkError>;
    
    /// Check if device is connected
    fn is_connected(&self) -> bool;
    
    /// Get connection status
    fn get_status(&self) -> ConnectionStatus;
    
    /// Get master extended public key
    async fn get_master_xpub(&self) -> Result<ExtendedPublicKey, GdkError>;
    
    /// Get extended public key for a specific derivation path
    async fn get_xpub(&self, derivation_path: &DerivationPath) -> Result<ExtendedPublicKey, GdkError>;
    
    /// Get address for a specific derivation path
    async fn get_address(&self, derivation_path: &DerivationPath) -> Result<Address, GdkError>;
    
    /// Display address on device for verification
    async fn display_address(&self, derivation_path: &DerivationPath) -> Result<bool, GdkError>;
    
    /// Sign a PSBT (Partially Signed Bitcoin Transaction)
    async fn sign_psbt(&self, psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, GdkError>;
    
    /// Sign a message with a specific key
    async fn sign_message(&self, derivation_path: &DerivationPath, message: &[u8]) -> Result<Vec<u8>, GdkError>;
    
    /// Verify device authenticity (if supported)
    async fn verify_device(&self) -> Result<bool, GdkError>;
    
    /// Get device-specific authentication credentials
    async fn get_auth_credentials(&self) -> Result<HardwareWalletCredentials, GdkError>;
}

/// Hardware wallet device manager
pub struct HardwareWalletManager {
    /// Connected devices
    devices: Arc<Mutex<HashMap<String, Box<dyn HardwareWallet>>>>,
    /// Device discovery timeout
    discovery_timeout: Duration,
    /// Connection retry attempts
    max_retry_attempts: u32,
}

impl HardwareWalletManager {
    /// Create a new hardware wallet manager
    pub fn new() -> Self {
        Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            discovery_timeout: Duration::from_secs(30),
            max_retry_attempts: 3,
        }
    }
    
    /// Set discovery timeout
    pub fn set_discovery_timeout(&mut self, timeout: Duration) {
        self.discovery_timeout = timeout;
    }
    
    /// Set maximum retry attempts
    pub fn set_max_retry_attempts(&mut self, attempts: u32) {
        self.max_retry_attempts = attempts;
    }
    
    /// Discover available hardware wallet devices
    pub async fn discover_devices(&self) -> Result<Vec<HardwareWalletInfo>, GdkError> {
        let mut discovered_devices = Vec::new();
        
        // Discover Ledger devices
        if let Ok(ledger_devices) = self.discover_ledger_devices().await {
            discovered_devices.extend(ledger_devices);
        }
        
        // Discover Trezor devices
        if let Ok(trezor_devices) = self.discover_trezor_devices().await {
            discovered_devices.extend(trezor_devices);
        }
        
        // Discover other device types
        if let Ok(other_devices) = self.discover_other_devices().await {
            discovered_devices.extend(other_devices);
        }
        
        Ok(discovered_devices)
    }
    
    /// Connect to a specific hardware wallet device
    pub async fn connect_device(&self, device_id: &str) -> Result<Box<dyn HardwareWallet>, GdkError> {
        // First try to find the device
        let device_info = self.find_device_by_id(device_id).await?;
        
        // Create appropriate device implementation
        let mut device = self.create_device_instance(&device_info)?;
        
        // Attempt connection with retries
        let mut attempts = 0;
        while attempts < self.max_retry_attempts {
            match device.connect().await {
                Ok(()) => {
                    // Store the connected device
                    let mut devices = self.devices.lock().unwrap();
                    devices.insert(device_id.to_string(), device);
                    return Ok(devices.get(device_id).unwrap().as_ref().into());
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= self.max_retry_attempts {
                        return Err(GdkError::Auth(format!(
                            "Failed to connect to hardware wallet after {} attempts: {}",
                            attempts, e
                        )));
                    }
                    // Wait before retry
                    tokio::time::sleep(Duration::from_millis(1000)).await;
                }
            }
        }
        
        Err(GdkError::Auth("Failed to connect to hardware wallet".to_string()))
    }
    
    /// Disconnect from a hardware wallet device
    pub async fn disconnect_device(&self, device_id: &str) -> Result<(), GdkError> {
        let mut devices = self.devices.lock().unwrap();
        if let Some(mut device) = devices.remove(device_id) {
            device.disconnect().await?;
        }
        Ok(())
    }
    
    /// Get connected device
    pub fn get_device(&self, device_id: &str) -> Option<Box<dyn HardwareWallet>> {
        let devices = self.devices.lock().unwrap();
        devices.get(device_id).map(|d| d.as_ref().into())
    }
    
    /// List all connected devices
    pub fn list_connected_devices(&self) -> Vec<String> {
        let devices = self.devices.lock().unwrap();
        devices.keys().cloned().collect()
    }
    
    /// Authenticate with hardware wallet
    pub async fn authenticate_device(&self, device_id: &str) -> Result<HardwareWalletCredentials, GdkError> {
        let devices = self.devices.lock().unwrap();
        if let Some(device) = devices.get(device_id) {
            device.get_auth_credentials().await
        } else {
            Err(GdkError::Auth("Hardware wallet device not connected".to_string()))
        }
    }
    
    /// Verify device authenticity
    pub async fn verify_device_authenticity(&self, device_id: &str) -> Result<bool, GdkError> {
        let devices = self.devices.lock().unwrap();
        if let Some(device) = devices.get(device_id) {
            device.verify_device().await
        } else {
            Err(GdkError::Auth("Hardware wallet device not connected".to_string()))
        }
    }
    
    // Private helper methods
    
    async fn discover_ledger_devices(&self) -> Result<Vec<HardwareWalletInfo>, GdkError> {
        // Mock implementation - in real implementation this would use Ledger's HID/USB communication
        Ok(vec![
            HardwareWalletInfo {
                device_type: HardwareWalletType::Ledger,
                model: "Nano S Plus".to_string(),
                firmware_version: "1.1.0".to_string(),
                device_id: "ledger_001".to_string(),
                initialized: true,
                features: vec![
                    "bitcoin".to_string(),
                    "liquid".to_string(),
                    "psbt".to_string(),
                    "address_display".to_string(),
                ],
            }
        ])
    }
    
    async fn discover_trezor_devices(&self) -> Result<Vec<HardwareWalletInfo>, GdkError> {
        // Mock implementation - in real implementation this would use Trezor's USB communication
        Ok(vec![
            HardwareWalletInfo {
                device_type: HardwareWalletType::Trezor,
                model: "Model T".to_string(),
                firmware_version: "2.5.3".to_string(),
                device_id: "trezor_001".to_string(),
                initialized: true,
                features: vec![
                    "bitcoin".to_string(),
                    "psbt".to_string(),
                    "address_display".to_string(),
                    "message_signing".to_string(),
                ],
            }
        ])
    }
    
    async fn discover_other_devices(&self) -> Result<Vec<HardwareWalletInfo>, GdkError> {
        // Mock implementation for other device types
        Ok(vec![])
    }
    
    async fn find_device_by_id(&self, device_id: &str) -> Result<HardwareWalletInfo, GdkError> {
        let devices = self.discover_devices().await?;
        devices.into_iter()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| GdkError::Auth(format!("Hardware wallet device not found: {}", device_id)))
    }
    
    fn create_device_instance(&self, device_info: &HardwareWalletInfo) -> Result<Box<dyn HardwareWallet>, GdkError> {
        match device_info.device_type {
            HardwareWalletType::Ledger => Ok(Box::new(LedgerDevice::new(device_info.clone()))),
            HardwareWalletType::Trezor => Ok(Box::new(TrezorDevice::new(device_info.clone()))),
            HardwareWalletType::Coldcard => Ok(Box::new(ColdcardDevice::new(device_info.clone()))),
            HardwareWalletType::BitBox => Ok(Box::new(BitBoxDevice::new(device_info.clone()))),
            HardwareWalletType::KeepKey => Ok(Box::new(KeepKeyDevice::new(device_info.clone()))),
            HardwareWalletType::Jade => Ok(Box::new(JadeDevice::new(device_info.clone()))),
        }
    }
}

/// Mock Ledger device implementation
pub struct LedgerDevice {
    info: HardwareWalletInfo,
    connected: bool,
    status: ConnectionStatus,
}

impl LedgerDevice {
    pub fn new(info: HardwareWalletInfo) -> Self {
        Self {
            info,
            connected: false,
            status: ConnectionStatus::Disconnected,
        }
    }
}

#[async_trait::async_trait]
impl HardwareWallet for LedgerDevice {
    async fn get_device_info(&self) -> Result<HardwareWalletInfo, GdkError> {
        Ok(self.info.clone())
    }
    
    async fn get_capabilities(&self) -> Result<HardwareWalletCapabilities, GdkError> {
        Ok(HardwareWalletCapabilities {
            bitcoin_support: true,
            liquid_support: true,
            psbt_support: true,
            address_display: true,
            message_signing: false,
            max_derivation_depth: 5,
        })
    }
    
    async fn connect(&mut self) -> Result<(), GdkError> {
        // Mock connection logic
        self.connected = true;
        self.status = ConnectionStatus::Connected;
        Ok(())
    }
    
    async fn disconnect(&mut self) -> Result<(), GdkError> {
        self.connected = false;
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn get_status(&self) -> ConnectionStatus {
        self.status.clone()
    }
    
    async fn get_master_xpub(&self) -> Result<ExtendedPublicKey, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock implementation - would communicate with actual device
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn get_xpub(&self, _derivation_path: &DerivationPath) -> Result<ExtendedPublicKey, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock implementation
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn get_address(&self, _derivation_path: &DerivationPath) -> Result<Address, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock implementation
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn display_address(&self, _derivation_path: &DerivationPath) -> Result<bool, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock implementation - would show address on device screen
        Ok(true)
    }
    
    async fn sign_psbt(&self, _psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock implementation
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn sign_message(&self, _derivation_path: &DerivationPath, _message: &[u8]) -> Result<Vec<u8>, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Ledger doesn't support message signing in this mock
        Err(GdkError::Auth("Message signing not supported on this device".to_string()))
    }
    
    async fn verify_device(&self) -> Result<bool, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock verification - would check device authenticity
        Ok(true)
    }
    
    async fn get_auth_credentials(&self) -> Result<HardwareWalletCredentials, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        Ok(HardwareWalletCredentials {
            device_info: self.info.clone(),
            master_xpub: None, // Would be populated with actual xpub
            auth_data: HashMap::new(),
        })
    }
}

// Mock implementations for other device types
pub struct TrezorDevice {
    info: HardwareWalletInfo,
    connected: bool,
    status: ConnectionStatus,
}

impl TrezorDevice {
    pub fn new(info: HardwareWalletInfo) -> Self {
        Self {
            info,
            connected: false,
            status: ConnectionStatus::Disconnected,
        }
    }
}

#[async_trait::async_trait]
impl HardwareWallet for TrezorDevice {
    async fn get_device_info(&self) -> Result<HardwareWalletInfo, GdkError> {
        Ok(self.info.clone())
    }
    
    async fn get_capabilities(&self) -> Result<HardwareWalletCapabilities, GdkError> {
        Ok(HardwareWalletCapabilities {
            bitcoin_support: true,
            liquid_support: false, // Trezor doesn't support Liquid in this mock
            psbt_support: true,
            address_display: true,
            message_signing: true,
            max_derivation_depth: 10,
        })
    }
    
    async fn connect(&mut self) -> Result<(), GdkError> {
        self.connected = true;
        self.status = ConnectionStatus::Connected;
        Ok(())
    }
    
    async fn disconnect(&mut self) -> Result<(), GdkError> {
        self.connected = false;
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }
    
    fn is_connected(&self) -> bool {
        self.connected
    }
    
    fn get_status(&self) -> ConnectionStatus {
        self.status.clone()
    }
    
    async fn get_master_xpub(&self) -> Result<ExtendedPublicKey, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn get_xpub(&self, _derivation_path: &DerivationPath) -> Result<ExtendedPublicKey, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn get_address(&self, _derivation_path: &DerivationPath) -> Result<Address, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn display_address(&self, _derivation_path: &DerivationPath) -> Result<bool, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        Ok(true)
    }
    
    async fn sign_psbt(&self, _psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
    }
    
    async fn sign_message(&self, _derivation_path: &DerivationPath, _message: &[u8]) -> Result<Vec<u8>, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        // Mock message signing
        Ok(vec![0u8; 64]) // Mock signature
    }
    
    async fn verify_device(&self) -> Result<bool, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        Ok(true)
    }
    
    async fn get_auth_credentials(&self) -> Result<HardwareWalletCredentials, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        Ok(HardwareWalletCredentials {
            device_info: self.info.clone(),
            master_xpub: None,
            auth_data: HashMap::new(),
        })
    }
}

// Placeholder implementations for other device types
macro_rules! impl_mock_device {
    ($device_name:ident, $device_type:expr, $bitcoin_support:expr, $liquid_support:expr, $message_signing:expr) => {
        pub struct $device_name {
            info: HardwareWalletInfo,
            connected: bool,
            status: ConnectionStatus,
        }
        
        impl $device_name {
            pub fn new(info: HardwareWalletInfo) -> Self {
                Self {
                    info,
                    connected: false,
                    status: ConnectionStatus::Disconnected,
                }
            }
        }
        
        #[async_trait::async_trait]
        impl HardwareWallet for $device_name {
            async fn get_device_info(&self) -> Result<HardwareWalletInfo, GdkError> {
                Ok(self.info.clone())
            }
            
            async fn get_capabilities(&self) -> Result<HardwareWalletCapabilities, GdkError> {
                Ok(HardwareWalletCapabilities {
                    bitcoin_support: $bitcoin_support,
                    liquid_support: $liquid_support,
                    psbt_support: true,
                    address_display: true,
                    message_signing: $message_signing,
                    max_derivation_depth: 5,
                })
            }
            
            async fn connect(&mut self) -> Result<(), GdkError> {
                self.connected = true;
                self.status = ConnectionStatus::Connected;
                Ok(())
            }
            
            async fn disconnect(&mut self) -> Result<(), GdkError> {
                self.connected = false;
                self.status = ConnectionStatus::Disconnected;
                Ok(())
            }
            
            fn is_connected(&self) -> bool {
                self.connected
            }
            
            fn get_status(&self) -> ConnectionStatus {
                self.status.clone()
            }
            
            async fn get_master_xpub(&self) -> Result<ExtendedPublicKey, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
            }
            
            async fn get_xpub(&self, _derivation_path: &DerivationPath) -> Result<ExtendedPublicKey, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
            }
            
            async fn get_address(&self, _derivation_path: &DerivationPath) -> Result<Address, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
            }
            
            async fn display_address(&self, _derivation_path: &DerivationPath) -> Result<bool, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                Ok(true)
            }
            
            async fn sign_psbt(&self, _psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                Err(GdkError::Auth("Mock implementation - not yet implemented".to_string()))
            }
            
            async fn sign_message(&self, _derivation_path: &DerivationPath, _message: &[u8]) -> Result<Vec<u8>, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                if $message_signing {
                    Ok(vec![0u8; 64])
                } else {
                    Err(GdkError::Auth("Message signing not supported on this device".to_string()))
                }
            }
            
            async fn verify_device(&self) -> Result<bool, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                Ok(true)
            }
            
            async fn get_auth_credentials(&self) -> Result<HardwareWalletCredentials, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                
                Ok(HardwareWalletCredentials {
                    device_info: self.info.clone(),
                    master_xpub: None,
                    auth_data: HashMap::new(),
                })
            }
        }
    };
}

impl_mock_device!(ColdcardDevice, HardwareWalletType::Coldcard, true, false, true);
impl_mock_device!(BitBoxDevice, HardwareWalletType::BitBox, true, false, true);
impl_mock_device!(KeepKeyDevice, HardwareWalletType::KeepKey, true, false, true);
impl_mock_device!(JadeDevice, HardwareWalletType::Jade, true, true, false);

/// Hardware wallet error recovery strategies
pub struct HardwareWalletErrorRecovery;

impl HardwareWalletErrorRecovery {
    /// Attempt to recover from connection errors
    pub async fn recover_connection(device_id: &str, manager: &HardwareWalletManager) -> Result<(), GdkError> {
        // Disconnect and reconnect
        let _ = manager.disconnect_device(device_id).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        manager.connect_device(device_id).await?;
        Ok(())
    }
    
    /// Handle device busy errors
    pub async fn handle_device_busy(device_id: &str, max_wait: Duration) -> Result<(), GdkError> {
        let start = Instant::now();
        while start.elapsed() < max_wait {
            tokio::time::sleep(Duration::from_millis(500)).await;
            // In real implementation, would check device status
        }
        Err(GdkError::Auth("Device remained busy for too long".to_string()))
    }
    
    /// Provide user guidance for common errors
    pub fn get_error_guidance(error: &GdkError) -> String {
        match error {
            GdkError::Auth(msg) if msg.contains("not connected") => {
                "Please ensure your hardware wallet is connected and unlocked.".to_string()
            }
            GdkError::Auth(msg) if msg.contains("locked out") => {
                "Your hardware wallet is locked. Please unlock it and try again.".to_string()
            }
            GdkError::Auth(msg) if msg.contains("busy") => {
                "Your hardware wallet is busy. Please wait for the current operation to complete.".to_string()
            }
            _ => "Please check your hardware wallet connection and try again.".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_hardware_wallet_manager_creation() {
        let manager = HardwareWalletManager::new();
        assert_eq!(manager.list_connected_devices().len(), 0);
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
        assert!(result.unwrap_err().to_string().contains("not connected"));
    }
    
    #[test]
    fn test_error_recovery_guidance() {
        let not_connected_error = GdkError::Auth("Device not connected".to_string());
        let guidance = HardwareWalletErrorRecovery::get_error_guidance(&not_connected_error);
        assert!(guidance.contains("connected and unlocked"));
        
        let busy_error = GdkError::Auth("Device is busy".to_string());
        let guidance = HardwareWalletErrorRecovery::get_error_guidance(&busy_error);
        assert!(guidance.contains("busy"));
    }
}