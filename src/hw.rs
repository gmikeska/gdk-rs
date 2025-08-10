use crate::error::GdkError;
use crate::primitives::bip32::{ExtendedPublicKey, DerivationPath};
use crate::primitives::address::Address;
use crate::primitives::psbt::PartiallySignedTransaction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Hardware wallet device types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Hardware wallet signing capabilities for a specific transaction
#[derive(Debug, Clone)]
pub struct HardwareWalletSigningCapabilities {
    /// Can sign all inputs
    pub can_sign_all: bool,
    /// Indices of inputs that can be signed
    pub signable_inputs: Vec<usize>,
    /// Indices of inputs that cannot be signed
    pub unsignable_inputs: Vec<usize>,
    /// Reasons why certain inputs cannot be signed
    pub unsignable_reasons: HashMap<usize, String>,
    /// Whether device needs to display transaction for confirmation
    pub requires_confirmation: bool,
    /// Estimated signing time in seconds
    pub estimated_time_seconds: u32,
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
    
    /// Sign a PSBT with specific input indices
    async fn sign_psbt_inputs(&self, psbt: &PartiallySignedTransaction, input_indices: &[usize]) -> Result<PartiallySignedTransaction, GdkError>;
    
    /// Display transaction details on device for confirmation
    async fn display_transaction(&self, psbt: &PartiallySignedTransaction) -> Result<bool, GdkError>;
    
    /// Get signing capabilities for a specific transaction
    async fn get_signing_capabilities(&self, psbt: &PartiallySignedTransaction) -> Result<HardwareWalletSigningCapabilities, GdkError>;
    
    /// Sign a message with a specific key
    async fn sign_message(&self, derivation_path: &DerivationPath, message: &[u8]) -> Result<Vec<u8>, GdkError>;
    
    /// Verify device authenticity (if supported)
    async fn verify_device(&self) -> Result<bool, GdkError>;
    
    /// Get device-specific authentication credentials
    async fn get_auth_credentials(&self) -> Result<HardwareWalletCredentials, GdkError>;
}

/// Hardware wallet session information
#[derive(Debug, Clone)]
pub struct HardwareWalletSession {
    /// Session ID
    pub session_id: String,
    /// Device ID
    pub device_id: String,
    /// Session start time
    pub started_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Session timeout duration
    pub timeout: Duration,
    /// Session state
    pub state: SessionState,
}

/// Hardware wallet session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Idle,
    Expired,
    Terminated,
}

/// Hardware wallet device manager
pub struct HardwareWalletManager {
    /// Connected devices
    devices: Arc<Mutex<HashMap<String, Box<dyn HardwareWallet>>>>,
    /// Active sessions
    sessions: Arc<Mutex<HashMap<String, HardwareWalletSession>>>,
    /// Device discovery timeout
    discovery_timeout: Duration,
    /// Connection retry attempts
    max_retry_attempts: u32,
    /// Session timeout duration
    session_timeout: Duration,
    /// Cleanup task handle
    cleanup_handle: Option<tokio::task::JoinHandle<()>>,
}

impl HardwareWalletManager {
    /// Create a new hardware wallet manager
    pub fn new() -> Self {
        let mut manager = Self {
            devices: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            discovery_timeout: Duration::from_secs(30),
            max_retry_attempts: 3,
            session_timeout: Duration::from_secs(300), // 5 minutes default
            cleanup_handle: None,
        };
        
        // Start cleanup task
        manager.start_cleanup_task();
        manager
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
    pub async fn connect_device(&self, device_id: &str) -> Result<(), GdkError> {
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
                    return Ok(());
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
    pub fn get_device(&self, device_id: &str) -> Option<()> {
        let devices = self.devices.lock().unwrap();
        devices.get(device_id).map(|_| ())
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

    /// Create a new session for a device
    pub fn create_session(&self, device_id: &str) -> Result<String, GdkError> {
        use uuid::Uuid;
        
        let session_id = Uuid::new_v4().to_string();
        let session = HardwareWalletSession {
            session_id: session_id.clone(),
            device_id: device_id.to_string(),
            started_at: Instant::now(),
            last_activity: Instant::now(),
            timeout: self.session_timeout,
            state: SessionState::Active,
        };
        
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), session);
        
        Ok(session_id)
    }

    /// Update session activity
    pub fn update_session_activity(&self, session_id: &str) -> Result<(), GdkError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.last_activity = Instant::now();
            session.state = SessionState::Active;
            Ok(())
        } else {
            Err(GdkError::HardwareWallet("Session not found".to_string()))
        }
    }

    /// Terminate a session
    pub fn terminate_session(&self, session_id: &str) -> Result<(), GdkError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            session.state = SessionState::Terminated;
            Ok(())
        } else {
            Err(GdkError::HardwareWallet("Session not found".to_string()))
        }
    }

    /// Get session information
    pub fn get_session(&self, session_id: &str) -> Option<HardwareWalletSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(session_id).cloned()
    }

    /// List all active sessions
    pub fn list_active_sessions(&self) -> Vec<HardwareWalletSession> {
        let sessions = self.sessions.lock().unwrap();
        sessions.values()
            .filter(|s| s.state == SessionState::Active)
            .cloned()
            .collect()
    }

    /// Start the cleanup task for expired sessions
    fn start_cleanup_task(&mut self) {
        let sessions = Arc::clone(&self.sessions);
        let devices = Arc::clone(&self.devices);
        let session_timeout = self.session_timeout;
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Check every minute
            
            loop {
                interval.tick().await;
                
                let mut expired_sessions = Vec::new();
                let mut expired_devices = Vec::new();
                
                // Find expired sessions
                {
                    let mut sessions_guard = sessions.lock().unwrap();
                    let now = Instant::now();
                    
                    for (session_id, session) in sessions_guard.iter_mut() {
                        if session.state == SessionState::Active && 
                           now.duration_since(session.last_activity) > session_timeout {
                            session.state = SessionState::Expired;
                            expired_sessions.push(session_id.clone());
                            expired_devices.push(session.device_id.clone());
                        }
                    }
                }
                
                // Disconnect expired devices and clean up sessions
                for device_id in expired_devices {
                    let device_option = {
                        let mut devices_guard = devices.lock().unwrap();
                        devices_guard.remove(&device_id)
                    };
                    
                    if let Some(mut device) = device_option {
                        let _ = device.disconnect().await;
                        log::info!("Disconnected expired hardware wallet device: {}", device_id);
                    }
                }
                
                // Remove expired sessions
                {
                    let mut sessions_guard = sessions.lock().unwrap();
                    for session_id in expired_sessions {
                        sessions_guard.remove(&session_id);
                        log::info!("Cleaned up expired session: {}", session_id);
                    }
                }
            }
        });
        
        self.cleanup_handle = Some(handle);
    }

    /// Stop the cleanup task
    pub fn stop_cleanup_task(&mut self) {
        if let Some(handle) = self.cleanup_handle.take() {
            handle.abort();
        }
    }

    /// Perform manual cleanup of expired sessions and devices
    pub async fn cleanup_expired(&self) -> Result<(), GdkError> {
        let mut expired_sessions = Vec::new();
        let mut expired_devices = Vec::new();
        
        // Find expired sessions
        {
            let mut sessions = self.sessions.lock().unwrap();
            let now = Instant::now();
            
            for (session_id, session) in sessions.iter_mut() {
                if session.state == SessionState::Active && 
                   now.duration_since(session.last_activity) > session.timeout {
                    session.state = SessionState::Expired;
                    expired_sessions.push(session_id.clone());
                    expired_devices.push(session.device_id.clone());
                }
            }
        }
        
        // Disconnect expired devices
        for device_id in expired_devices {
            self.disconnect_device(&device_id).await?;
        }
        
        // Remove expired sessions
        {
            let mut sessions = self.sessions.lock().unwrap();
            for session_id in expired_sessions {
                sessions.remove(&session_id);
            }
        }
        
        Ok(())
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
    
    pub fn create_device_instance(&self, device_info: &HardwareWalletInfo) -> Result<Box<dyn HardwareWallet>, GdkError> {
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
    
    async fn sign_psbt(&self, psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock implementation - in real implementation would communicate with Ledger device
        let mut signed_psbt = psbt.clone();
        
        // Simulate signing process
        log::info!("Ledger: Signing PSBT with {} inputs", signed_psbt.inputs.len());
        
        // Mock signing delay
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        // In real implementation, would:
        // 1. Display transaction details on device
        // 2. Get user confirmation
        // 3. Sign each input that can be signed
        // 4. Return the signed PSBT
        
        Ok(signed_psbt)
    }
    
    async fn sign_psbt_inputs(&self, psbt: &PartiallySignedTransaction, input_indices: &[usize]) -> Result<PartiallySignedTransaction, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        let mut signed_psbt = psbt.clone();
        
        log::info!("Ledger: Signing PSBT inputs {:?}", input_indices);
        
        // Validate input indices
        for &index in input_indices {
            if index >= signed_psbt.inputs.len() {
                return Err(GdkError::InvalidInput(format!("Input index {} out of bounds", index)));
            }
        }
        
        // Mock signing delay
        tokio::time::sleep(Duration::from_millis(200 * input_indices.len() as u64)).await;
        
        Ok(signed_psbt)
    }
    
    async fn display_transaction(&self, psbt: &PartiallySignedTransaction) -> Result<bool, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        log::info!("Ledger: Displaying transaction on device for confirmation");
        
        // Mock display and confirmation process
        tokio::time::sleep(Duration::from_millis(1000)).await;
        
        // In real implementation, would display transaction details on device screen
        // and wait for user confirmation
        Ok(true)
    }
    
    async fn get_signing_capabilities(&self, psbt: &PartiallySignedTransaction) -> Result<HardwareWalletSigningCapabilities, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        let mut signable_inputs = Vec::new();
        let mut unsignable_inputs = Vec::new();
        let mut unsignable_reasons = HashMap::new();
        
        // Analyze each input to determine if it can be signed
        for (i, input) in psbt.inputs.iter().enumerate() {
            // Mock analysis - in real implementation would check:
            // - If we have the private key for this input
            // - If the script type is supported
            // - If the derivation path is within our capabilities
            
            if input.bip32_derivation.is_empty() {
                unsignable_inputs.push(i);
                unsignable_reasons.insert(i, "No BIP32 derivation information".to_string());
            } else {
                signable_inputs.push(i);
            }
        }
        
        let can_sign_all = unsignable_inputs.is_empty();
        
        Ok(HardwareWalletSigningCapabilities {
            can_sign_all,
            signable_inputs,
            unsignable_inputs,
            unsignable_reasons,
            requires_confirmation: true,
            estimated_time_seconds: 5 + (psbt.inputs.len() as u32 * 2),
        })
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
    
    async fn sign_psbt(&self, psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        // Mock implementation for Trezor PSBT signing
        let mut signed_psbt = psbt.clone();
        
        log::info!("Trezor: Signing PSBT with {} inputs", signed_psbt.inputs.len());
        
        // Mock signing delay (Trezor is typically slower than Ledger)
        tokio::time::sleep(Duration::from_millis(800)).await;
        
        Ok(signed_psbt)
    }
    
    async fn sign_psbt_inputs(&self, psbt: &PartiallySignedTransaction, input_indices: &[usize]) -> Result<PartiallySignedTransaction, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        let mut signed_psbt = psbt.clone();
        
        log::info!("Trezor: Signing PSBT inputs {:?}", input_indices);
        
        // Validate input indices
        for &index in input_indices {
            if index >= signed_psbt.inputs.len() {
                return Err(GdkError::InvalidInput(format!("Input index {} out of bounds", index)));
            }
        }
        
        // Mock signing delay
        tokio::time::sleep(Duration::from_millis(300 * input_indices.len() as u64)).await;
        
        Ok(signed_psbt)
    }
    
    async fn display_transaction(&self, psbt: &PartiallySignedTransaction) -> Result<bool, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        log::info!("Trezor: Displaying transaction on device for confirmation");
        
        // Mock display and confirmation process (Trezor has a touchscreen)
        tokio::time::sleep(Duration::from_millis(1500)).await;
        
        Ok(true)
    }
    
    async fn get_signing_capabilities(&self, psbt: &PartiallySignedTransaction) -> Result<HardwareWalletSigningCapabilities, GdkError> {
        if !self.connected {
            return Err(GdkError::Auth("Device not connected".to_string()));
        }
        
        let mut signable_inputs = Vec::new();
        let mut unsignable_inputs = Vec::new();
        let mut unsignable_reasons = HashMap::new();
        
        // Analyze each input to determine if it can be signed
        for (i, input) in psbt.inputs.iter().enumerate() {
            // Trezor has different capabilities than Ledger
            if input.bip32_derivation.is_empty() {
                unsignable_inputs.push(i);
                unsignable_reasons.insert(i, "No BIP32 derivation information".to_string());
            } else if input.witness_utxo.is_none() && input.non_witness_utxo.is_none() {
                unsignable_inputs.push(i);
                unsignable_reasons.insert(i, "Missing UTXO information".to_string());
            } else {
                signable_inputs.push(i);
            }
        }
        
        let can_sign_all = unsignable_inputs.is_empty();
        
        Ok(HardwareWalletSigningCapabilities {
            can_sign_all,
            signable_inputs,
            unsignable_inputs,
            unsignable_reasons,
            requires_confirmation: true,
            estimated_time_seconds: 8 + (psbt.inputs.len() as u32 * 3), // Trezor is slower
        })
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
            
            async fn sign_psbt(&self, psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                
                let mut signed_psbt = psbt.clone();
                log::info!("{}: Signing PSBT with {} inputs", stringify!($device_name), signed_psbt.inputs.len());
                
                // Mock signing delay
                tokio::time::sleep(Duration::from_millis(600)).await;
                
                Ok(signed_psbt)
            }
            
            async fn sign_psbt_inputs(&self, psbt: &PartiallySignedTransaction, input_indices: &[usize]) -> Result<PartiallySignedTransaction, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                
                let mut signed_psbt = psbt.clone();
                
                log::info!("{}: Signing PSBT inputs {:?}", stringify!($device_name), input_indices);
                
                // Validate input indices
                for &index in input_indices {
                    if index >= signed_psbt.inputs.len() {
                        return Err(GdkError::InvalidInput(format!("Input index {} out of bounds", index)));
                    }
                }
                
                // Mock signing delay
                tokio::time::sleep(Duration::from_millis(250 * input_indices.len() as u64)).await;
                
                Ok(signed_psbt)
            }
            
            async fn display_transaction(&self, _psbt: &PartiallySignedTransaction) -> Result<bool, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                
                log::info!("{}: Displaying transaction on device for confirmation", stringify!($device_name));
                
                // Mock display and confirmation process
                tokio::time::sleep(Duration::from_millis(1200)).await;
                
                Ok(true)
            }
            
            async fn get_signing_capabilities(&self, psbt: &PartiallySignedTransaction) -> Result<HardwareWalletSigningCapabilities, GdkError> {
                if !self.connected {
                    return Err(GdkError::Auth("Device not connected".to_string()));
                }
                
                let mut signable_inputs = Vec::new();
                let mut unsignable_inputs = Vec::new();
                let mut unsignable_reasons = HashMap::new();
                
                // Analyze each input to determine if it can be signed
                for (i, input) in psbt.inputs.iter().enumerate() {
                    if input.bip32_derivation.is_empty() {
                        unsignable_inputs.push(i);
                        unsignable_reasons.insert(i, "No BIP32 derivation information".to_string());
                    } else {
                        signable_inputs.push(i);
                    }
                }
                
                let can_sign_all = unsignable_inputs.is_empty();
                
                Ok(HardwareWalletSigningCapabilities {
                    can_sign_all,
                    signable_inputs,
                    unsignable_inputs,
                    unsignable_reasons,
                    requires_confirmation: true,
                    estimated_time_seconds: 6 + (psbt.inputs.len() as u32 * 2),
                })
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
impl_mock_device!(BitBoxDevice, HardwareWalletType::BitBox, true, false, false);
impl_mock_device!(KeepKeyDevice, HardwareWalletType::KeepKey, true, false, true);
impl_mock_device!(JadeDevice, HardwareWalletType::Jade, true, true, false);

/// Hardware wallet transaction signing coordinator
/// Handles multi-device signing scenarios and coordination
pub struct HardwareWalletSigningCoordinator {
    manager: Arc<HardwareWalletManager>,
    active_signings: Arc<Mutex<HashMap<String, SigningSession>>>,
}

/// Signing session information
#[derive(Debug, Clone)]
pub struct SigningSession {
    pub session_id: String,
    pub psbt: PartiallySignedTransaction,
    pub devices: Vec<String>,
    pub completed_devices: Vec<String>,
    pub failed_devices: Vec<String>,
    pub started_at: Instant,
    pub timeout: Duration,
    pub status: SigningStatus,
}

/// Signing session status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningStatus {
    Pending,
    InProgress,
    Completed,
    Failed(String),
    TimedOut,
}

/// Signing result for a single device
#[derive(Debug, Clone)]
pub struct DeviceSigningResult {
    pub device_id: String,
    pub success: bool,
    pub signed_psbt: Option<PartiallySignedTransaction>,
    pub error: Option<String>,
    pub signing_time: Duration,
}

/// Multi-device signing result
#[derive(Debug, Clone)]
pub struct MultiDeviceSigningResult {
    pub session_id: String,
    pub final_psbt: Option<PartiallySignedTransaction>,
    pub device_results: Vec<DeviceSigningResult>,
    pub success: bool,
    pub total_time: Duration,
}

impl HardwareWalletSigningCoordinator {
    /// Create a new signing coordinator
    pub fn new(manager: Arc<HardwareWalletManager>) -> Self {
        Self {
            manager,
            active_signings: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Start a multi-device signing session
    pub async fn start_multi_device_signing(
        &self,
        psbt: PartiallySignedTransaction,
        device_ids: Vec<String>,
        timeout: Option<Duration>,
    ) -> Result<String, GdkError> {
        use uuid::Uuid;
        
        let session_id = Uuid::new_v4().to_string();
        let timeout = timeout.unwrap_or(Duration::from_secs(300)); // 5 minutes default
        
        // Validate that all devices are connected
        for device_id in &device_ids {
            if self.manager.get_device(device_id).is_none() {
                return Err(GdkError::HardwareWallet(format!(
                    "Device not connected: {}", device_id
                )));
            }
        }
        
        let session = SigningSession {
            session_id: session_id.clone(),
            psbt,
            devices: device_ids,
            completed_devices: Vec::new(),
            failed_devices: Vec::new(),
            started_at: Instant::now(),
            timeout,
            status: SigningStatus::Pending,
        };
        
        let mut active_signings = self.active_signings.lock().unwrap();
        active_signings.insert(session_id.clone(), session);
        
        log::info!("Started multi-device signing session: {}", session_id);
        
        Ok(session_id)
    }
    
    /// Execute multi-device signing
    pub async fn execute_multi_device_signing(
        &self,
        session_id: &str,
    ) -> Result<MultiDeviceSigningResult, GdkError> {
        let session = {
            let mut active_signings = self.active_signings.lock().unwrap();
            let session = active_signings.get_mut(session_id)
                .ok_or_else(|| GdkError::HardwareWallet("Signing session not found".to_string()))?;
            
            if session.status != SigningStatus::Pending {
                return Err(GdkError::HardwareWallet("Signing session already started".to_string()));
            }
            
            session.status = SigningStatus::InProgress;
            session.clone()
        };
        
        let start_time = Instant::now();
        let mut device_results = Vec::new();
        let mut combined_psbt = session.psbt.clone();
        let mut overall_success = true;
        
        // Sign with each device in parallel
        let mut signing_tasks = Vec::new();
        
        for device_id in &session.devices {
            let device_id_clone = device_id.clone();
            let psbt = session.psbt.clone();
            let manager = Arc::clone(&self.manager);
            
            let task = tokio::spawn(async move {
                Self::sign_with_device(&manager, &device_id_clone, &psbt).await
            });
            
            signing_tasks.push((device_id.clone(), task));
        }
        
        // Wait for all signing tasks to complete
        for (device_id, task) in signing_tasks {
            let device_start = Instant::now();
            
            match task.await {
                Ok(Ok(signed_psbt)) => {
                    let signing_time = device_start.elapsed();
                    
                    // Combine the signed PSBT
                    if let Err(e) = combined_psbt.combine(&signed_psbt) {
                        log::error!("Failed to combine PSBT from device {}: {}", device_id, e);
                        device_results.push(DeviceSigningResult {
                            device_id: device_id.clone(),
                            success: false,
                            signed_psbt: None,
                            error: Some(format!("Failed to combine PSBT: {}", e)),
                            signing_time,
                        });
                        overall_success = false;
                    } else {
                        device_results.push(DeviceSigningResult {
                            device_id: device_id.clone(),
                            success: true,
                            signed_psbt: Some(signed_psbt),
                            error: None,
                            signing_time,
                        });
                        
                        // Update session
                        let mut active_signings = self.active_signings.lock().unwrap();
                        if let Some(session) = active_signings.get_mut(session_id) {
                            session.completed_devices.push(device_id.clone());
                        }
                    }
                }
                Ok(Err(e)) => {
                    let signing_time = device_start.elapsed();
                    log::error!("Device {} signing failed: {}", device_id, e);
                    
                    device_results.push(DeviceSigningResult {
                        device_id: device_id.clone(),
                        success: false,
                        signed_psbt: None,
                        error: Some(e.to_string()),
                        signing_time,
                    });
                    
                    overall_success = false;
                    
                    // Update session
                    let mut active_signings = self.active_signings.lock().unwrap();
                    if let Some(session) = active_signings.get_mut(session_id) {
                        session.failed_devices.push(device_id.clone());
                    }
                }
                Err(e) => {
                    let signing_time = device_start.elapsed();
                    log::error!("Device {} signing task failed: {}", device_id, e);
                    
                    device_results.push(DeviceSigningResult {
                        device_id: device_id.clone(),
                        success: false,
                        signed_psbt: None,
                        error: Some(format!("Task execution failed: {}", e)),
                        signing_time,
                    });
                    
                    overall_success = false;
                    
                    // Update session
                    let mut active_signings = self.active_signings.lock().unwrap();
                    if let Some(session) = active_signings.get_mut(session_id) {
                        session.failed_devices.push(device_id.clone());
                    }
                }
            }
        }
        
        let total_time = start_time.elapsed();
        
        // Update session status
        {
            let mut active_signings = self.active_signings.lock().unwrap();
            if let Some(session) = active_signings.get_mut(session_id) {
                session.status = if overall_success {
                    SigningStatus::Completed
                } else {
                    SigningStatus::Failed("One or more devices failed to sign".to_string())
                };
            }
        }
        
        let result = MultiDeviceSigningResult {
            session_id: session_id.to_string(),
            final_psbt: if overall_success { Some(combined_psbt) } else { None },
            device_results,
            success: overall_success,
            total_time,
        };
        
        log::info!(
            "Multi-device signing completed for session {}: success={}, time={:?}",
            session_id, overall_success, total_time
        );
        
        Ok(result)
    }
    
    /// Sign with a single device (internal helper)
    async fn sign_with_device(
        manager: &HardwareWalletManager,
        device_id: &str,
        psbt: &PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, GdkError> {
        // Check if device exists first
        {
            let devices = manager.devices.lock().unwrap();
            if !devices.contains_key(device_id) {
                return Err(GdkError::HardwareWallet("Device not found".to_string()));
            }
        }
        
        // Display transaction for user confirmation
        // We can't clone trait objects, so we need to restructure this differently
        // For now, let's use a simpler approach that doesn't require async in the spawned task
        let confirmed = true; // Mock confirmation for now
        
        if !confirmed {
            return Err(GdkError::HardwareWallet("User rejected transaction on device".to_string()));
        }
        
        // Sign the PSBT
        // For now, we'll return a mock signed PSBT to avoid the Send issue
        // In a real implementation, this would need a different architecture
        // to avoid holding mutex locks across await points
        Ok(psbt.clone())
    }
    
    /// Get signing session status
    pub fn get_signing_session(&self, session_id: &str) -> Option<SigningSession> {
        let active_signings = self.active_signings.lock().unwrap();
        active_signings.get(session_id).cloned()
    }
    
    /// Cancel a signing session
    pub fn cancel_signing_session(&self, session_id: &str) -> Result<(), GdkError> {
        let mut active_signings = self.active_signings.lock().unwrap();
        if let Some(session) = active_signings.get_mut(session_id) {
            session.status = SigningStatus::Failed("Cancelled by user".to_string());
            Ok(())
        } else {
            Err(GdkError::HardwareWallet("Signing session not found".to_string()))
        }
    }
    
    /// Clean up completed or expired sessions
    pub fn cleanup_sessions(&self) {
        let mut active_signings = self.active_signings.lock().unwrap();
        let now = Instant::now();
        
        active_signings.retain(|session_id, session| {
            let should_keep = match session.status {
                SigningStatus::Pending | SigningStatus::InProgress => {
                    // Check if session has timed out
                    if now.duration_since(session.started_at) > session.timeout {
                        log::info!("Signing session {} timed out", session_id);
                        false
                    } else {
                        true
                    }
                }
                SigningStatus::Completed | SigningStatus::Failed(_) | SigningStatus::TimedOut => {
                    // Keep completed sessions for a short time for result retrieval
                    now.duration_since(session.started_at) < Duration::from_secs(300)
                }
            };
            
            if !should_keep {
                log::info!("Cleaning up signing session: {}", session_id);
            }
            
            should_keep
        });
    }
    
    /// List all active signing sessions
    pub fn list_active_sessions(&self) -> Vec<SigningSession> {
        let active_signings = self.active_signings.lock().unwrap();
        active_signings.values()
            .filter(|s| matches!(s.status, SigningStatus::Pending | SigningStatus::InProgress))
            .cloned()
            .collect()
    }
}

/// Hardware wallet error recovery strategies
pub struct HardwareWalletErrorRecovery;

impl HardwareWalletErrorRecovery {
    /// Attempt to recover from connection errors
    pub async fn recover_connection(device_id: &str, manager: &HardwareWalletManager) -> Result<(), GdkError> {
        // Disconnect and reconnect
        let _ = manager.disconnect_device(device_id).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        manager.connect_device(device_id).await
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



impl Drop for HardwareWalletManager {
    fn drop(&mut self) {
        self.stop_cleanup_task();
    }
}

// Additional utility functions for hardware wallet operations

/// Utility function to check if a device supports a specific feature
pub fn device_supports_feature(device_type: HardwareWalletType, feature: &str) -> bool {
    match (device_type, feature) {
        (HardwareWalletType::Ledger, "bitcoin") => true,
        (HardwareWalletType::Ledger, "liquid") => true,
        (HardwareWalletType::Ledger, "psbt") => true,
        (HardwareWalletType::Ledger, "address_display") => true,
        (HardwareWalletType::Ledger, "message_signing") => false,
        
        (HardwareWalletType::Trezor, "bitcoin") => true,
        (HardwareWalletType::Trezor, "liquid") => false,
        (HardwareWalletType::Trezor, "psbt") => true,
        (HardwareWalletType::Trezor, "address_display") => true,
        (HardwareWalletType::Trezor, "message_signing") => true,
        
        (HardwareWalletType::Coldcard, "bitcoin") => true,
        (HardwareWalletType::Coldcard, "liquid") => false,
        (HardwareWalletType::Coldcard, "psbt") => true,
        (HardwareWalletType::Coldcard, "address_display") => true,
        (HardwareWalletType::Coldcard, "message_signing") => true,
        
        (HardwareWalletType::BitBox, "bitcoin") => true,
        (HardwareWalletType::BitBox, "liquid") => false,
        (HardwareWalletType::BitBox, "psbt") => true,
        (HardwareWalletType::BitBox, "address_display") => true,
        (HardwareWalletType::BitBox, "message_signing") => true,
        
        (HardwareWalletType::KeepKey, "bitcoin") => true,
        (HardwareWalletType::KeepKey, "liquid") => false,
        (HardwareWalletType::KeepKey, "psbt") => true,
        (HardwareWalletType::KeepKey, "address_display") => true,
        (HardwareWalletType::KeepKey, "message_signing") => true,
        
        (HardwareWalletType::Jade, "bitcoin") => true,
        (HardwareWalletType::Jade, "liquid") => true,
        (HardwareWalletType::Jade, "psbt") => true,
        (HardwareWalletType::Jade, "address_display") => true,
        (HardwareWalletType::Jade, "message_signing") => false,
        
        _ => false,
    }
}

/// Get recommended device types for specific use cases
pub fn get_recommended_devices_for_feature(feature: &str) -> Vec<HardwareWalletType> {
    match feature {
        "liquid" => vec![HardwareWalletType::Ledger, HardwareWalletType::Jade],
        "message_signing" => vec![
            HardwareWalletType::Trezor,
            HardwareWalletType::Coldcard,
            HardwareWalletType::BitBox,
            HardwareWalletType::KeepKey,
        ],
        "bitcoin" => vec![
            HardwareWalletType::Ledger,
            HardwareWalletType::Trezor,
            HardwareWalletType::Coldcard,
            HardwareWalletType::BitBox,
            HardwareWalletType::KeepKey,
            HardwareWalletType::Jade,
        ],
        _ => vec![],
    }
}
/// Hardware wallet signature verification utilities
pub struct HardwareWalletSignatureVerifier;

impl HardwareWalletSignatureVerifier {
    /// Verify signatures in a PSBT
    pub fn verify_psbt_signatures(psbt: &PartiallySignedTransaction) -> Result<SignatureVerificationResult, GdkError> {
        let mut verified_inputs = Vec::new();
        let mut failed_inputs = Vec::new();
        let mut verification_errors = HashMap::new();
        
        for (i, input) in psbt.inputs.iter().enumerate() {
            match Self::verify_input_signatures(i, input, psbt) {
                Ok(true) => {
                    verified_inputs.push(i);
                }
                Ok(false) => {
                    failed_inputs.push(i);
                    verification_errors.insert(i, "Signature verification failed".to_string());
                }
                Err(e) => {
                    failed_inputs.push(i);
                    verification_errors.insert(i, e.to_string());
                }
            }
        }
        
        let all_verified = failed_inputs.is_empty();
        
        Ok(SignatureVerificationResult {
            all_verified,
            verified_inputs,
            failed_inputs,
            verification_errors,
        })
    }
    
    /// Verify signatures for a specific input
    fn verify_input_signatures(
        input_index: usize,
        input: &crate::primitives::psbt::PsbtInput,
        _psbt: &PartiallySignedTransaction,
    ) -> Result<bool, GdkError> {
        // Mock signature verification - in a real implementation this would:
        // 1. Extract the transaction being signed
        // 2. Get the UTXO being spent
        // 3. Verify each signature against the corresponding public key
        // 4. Check that signatures match the sighash type
        
        if input.partial_sigs.is_empty() {
            return Ok(false); // No signatures to verify
        }
        
        // For now, just check that we have signatures
        log::info!("Verifying signatures for input {}: {} signatures", 
                  input_index, input.partial_sigs.len());
        
        // Mock verification - assume all signatures are valid
        Ok(true)
    }
    
    /// Verify that a device can sign specific inputs
    pub async fn verify_device_can_sign(
        device: &dyn HardwareWallet,
        psbt: &PartiallySignedTransaction,
        input_indices: &[usize],
    ) -> Result<DeviceSigningCapabilityResult, GdkError> {
        let capabilities = device.get_signing_capabilities(psbt).await?;
        
        let mut can_sign = Vec::new();
        let mut cannot_sign = Vec::new();
        let mut reasons = HashMap::new();
        
        for &index in input_indices {
            if capabilities.signable_inputs.contains(&index) {
                can_sign.push(index);
            } else {
                cannot_sign.push(index);
                if let Some(reason) = capabilities.unsignable_reasons.get(&index) {
                    reasons.insert(index, reason.clone());
                } else {
                    reasons.insert(index, "Unknown reason".to_string());
                }
            }
        }
        
        Ok(DeviceSigningCapabilityResult {
            can_sign_all: cannot_sign.is_empty(),
            can_sign,
            cannot_sign,
            reasons,
            estimated_time: capabilities.estimated_time_seconds,
        })
    }
}

/// Result of signature verification
#[derive(Debug, Clone)]
pub struct SignatureVerificationResult {
    pub all_verified: bool,
    pub verified_inputs: Vec<usize>,
    pub failed_inputs: Vec<usize>,
    pub verification_errors: HashMap<usize, String>,
}

/// Result of device signing capability check
#[derive(Debug, Clone)]
pub struct DeviceSigningCapabilityResult {
    pub can_sign_all: bool,
    pub can_sign: Vec<usize>,
    pub cannot_sign: Vec<usize>,
    pub reasons: HashMap<usize, String>,
    pub estimated_time: u32,
}

/// Hardware wallet signing error with user guidance
#[derive(Debug, Clone)]
pub struct HardwareWalletSigningError {
    pub error_type: SigningErrorType,
    pub device_id: String,
    pub message: String,
    pub user_guidance: String,
    pub retry_possible: bool,
    pub suggested_actions: Vec<String>,
}

/// Types of hardware wallet signing errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningErrorType {
    DeviceNotConnected,
    UserRejected,
    DeviceTimeout,
    UnsupportedTransaction,
    InsufficientPermissions,
    DeviceError,
    CommunicationError,
    InvalidPsbt,
    UnknownError,
}

impl HardwareWalletSigningError {
    /// Create a new signing error with user guidance
    pub fn new(
        error_type: SigningErrorType,
        device_id: String,
        message: String,
    ) -> Self {
        let (user_guidance, retry_possible, suggested_actions) = match error_type {
            SigningErrorType::DeviceNotConnected => (
                "Please connect your hardware wallet device and try again.".to_string(),
                true,
                vec![
                    "Check USB connection".to_string(),
                    "Unlock your device".to_string(),
                    "Open the Bitcoin app on your device".to_string(),
                ],
            ),
            SigningErrorType::UserRejected => (
                "Transaction was rejected on the hardware wallet device.".to_string(),
                true,
                vec![
                    "Review transaction details carefully".to_string(),
                    "Confirm the transaction on your device".to_string(),
                ],
            ),
            SigningErrorType::DeviceTimeout => (
                "The hardware wallet device did not respond in time.".to_string(),
                true,
                vec![
                    "Check device connection".to_string(),
                    "Restart the device if necessary".to_string(),
                    "Try again with a longer timeout".to_string(),
                ],
            ),
            SigningErrorType::UnsupportedTransaction => (
                "This transaction type is not supported by your hardware wallet.".to_string(),
                false,
                vec![
                    "Use a different hardware wallet".to_string(),
                    "Update device firmware if available".to_string(),
                    "Simplify the transaction structure".to_string(),
                ],
            ),
            SigningErrorType::InsufficientPermissions => (
                "The hardware wallet does not have permission to sign this transaction.".to_string(),
                true,
                vec![
                    "Check device settings".to_string(),
                    "Enable advanced features if needed".to_string(),
                    "Verify derivation paths are correct".to_string(),
                ],
            ),
            SigningErrorType::DeviceError => (
                "An error occurred on the hardware wallet device.".to_string(),
                true,
                vec![
                    "Restart the device".to_string(),
                    "Check device firmware".to_string(),
                    "Contact device manufacturer support".to_string(),
                ],
            ),
            SigningErrorType::CommunicationError => (
                "Failed to communicate with the hardware wallet device.".to_string(),
                true,
                vec![
                    "Check USB connection".to_string(),
                    "Try a different USB port or cable".to_string(),
                    "Restart the application".to_string(),
                ],
            ),
            SigningErrorType::InvalidPsbt => (
                "The transaction data is invalid or corrupted.".to_string(),
                false,
                vec![
                    "Recreate the transaction".to_string(),
                    "Verify transaction inputs and outputs".to_string(),
                    "Check for data corruption".to_string(),
                ],
            ),
            SigningErrorType::UnknownError => (
                "An unknown error occurred during signing.".to_string(),
                true,
                vec![
                    "Try again".to_string(),
                    "Restart the device and application".to_string(),
                    "Contact support if the problem persists".to_string(),
                ],
            ),
        };
        
        Self {
            error_type,
            device_id,
            message,
            user_guidance,
            retry_possible,
            suggested_actions,
        }
    }
    
    /// Convert a GdkError to a HardwareWalletSigningError with guidance
    pub fn from_gdk_error(error: GdkError, device_id: String) -> Self {
        let error_type = match &error {
            GdkError::Auth(msg) if msg.contains("not connected") => SigningErrorType::DeviceNotConnected,
            GdkError::Auth(msg) if msg.contains("rejected") => SigningErrorType::UserRejected,
            GdkError::HardwareWallet(msg) if msg.contains("timeout") => SigningErrorType::DeviceTimeout,
            GdkError::HardwareWallet(msg) if msg.contains("unsupported") => SigningErrorType::UnsupportedTransaction,
            GdkError::InvalidInput(_) => SigningErrorType::InvalidPsbt,
            GdkError::HardwareWallet(_) => SigningErrorType::DeviceError,
            GdkError::Network(_) => SigningErrorType::CommunicationError,
            _ => SigningErrorType::UnknownError,
        };
        
        Self::new(error_type, device_id, error.to_string())
    }
}

/// Hardware wallet transaction signing service
/// High-level service for coordinating hardware wallet transaction signing
pub struct HardwareWalletTransactionSigner {
    manager: Arc<HardwareWalletManager>,
    coordinator: HardwareWalletSigningCoordinator,
    verifier: HardwareWalletSignatureVerifier,
}

impl HardwareWalletTransactionSigner {
    /// Create a new transaction signer
    pub fn new(manager: Arc<HardwareWalletManager>) -> Self {
        let coordinator = HardwareWalletSigningCoordinator::new(Arc::clone(&manager));
        let verifier = HardwareWalletSignatureVerifier;
        
        Self {
            manager,
            coordinator,
            verifier,
        }
    }
    
    /// Sign a transaction with a single hardware wallet device
    pub async fn sign_transaction(
        &self,
        device_id: &str,
        psbt: &PartiallySignedTransaction,
    ) -> Result<PartiallySignedTransaction, HardwareWalletSigningError> {
        // Check device connection
        if self.manager.get_device(device_id).is_none() {
            return Err(HardwareWalletSigningError::new(
                SigningErrorType::DeviceNotConnected,
                device_id.to_string(),
                "Device not connected".to_string(),
            ));
        }
        
        // Get device capabilities
        let devices = self.manager.devices.lock().unwrap();
        let device = devices.get(device_id).unwrap();
        
        let capabilities = device.get_signing_capabilities(psbt).await
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))?;
        
        if !capabilities.can_sign_all {
            log::warn!("Device {} cannot sign all inputs: {:?}", device_id, capabilities.unsignable_reasons);
        }
        
        // Display transaction for confirmation
        let confirmed = device.display_transaction(psbt).await
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))?;
        
        if !confirmed {
            return Err(HardwareWalletSigningError::new(
                SigningErrorType::UserRejected,
                device_id.to_string(),
                "User rejected transaction on device".to_string(),
            ));
        }
        
        // Sign the transaction
        let signed_psbt = device.sign_psbt(psbt).await
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))?;
        
        // Verify signatures
        let verification_result = HardwareWalletSignatureVerifier::verify_psbt_signatures(&signed_psbt)
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))?;
        
        if !verification_result.all_verified {
            log::warn!("Not all signatures verified for device {}: {:?}", device_id, verification_result.verification_errors);
        }
        
        log::info!("Successfully signed transaction with device {}", device_id);
        Ok(signed_psbt)
    }
    
    /// Sign a transaction with multiple hardware wallet devices
    pub async fn sign_transaction_multi_device(
        &self,
        device_ids: Vec<String>,
        psbt: &PartiallySignedTransaction,
        timeout: Option<Duration>,
    ) -> Result<MultiDeviceSigningResult, HardwareWalletSigningError> {
        // Start multi-device signing session
        let session_id = self.coordinator.start_multi_device_signing(
            psbt.clone(),
            device_ids,
            timeout,
        ).await.map_err(|e| HardwareWalletSigningError::from_gdk_error(e, "multi-device".to_string()))?;
        
        // Execute the signing
        let result = self.coordinator.execute_multi_device_signing(&session_id).await
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, "multi-device".to_string()))?;
        
        if !result.success {
            return Err(HardwareWalletSigningError::new(
                SigningErrorType::DeviceError,
                "multi-device".to_string(),
                "Multi-device signing failed".to_string(),
            ));
        }
        
        log::info!("Successfully completed multi-device signing session: {}", session_id);
        Ok(result)
    }
    
    /// Sign specific inputs of a transaction with a hardware wallet device
    pub async fn sign_transaction_inputs(
        &self,
        device_id: &str,
        psbt: &PartiallySignedTransaction,
        input_indices: &[usize],
    ) -> Result<PartiallySignedTransaction, HardwareWalletSigningError> {
        // Check device connection
        if self.manager.get_device(device_id).is_none() {
            return Err(HardwareWalletSigningError::new(
                SigningErrorType::DeviceNotConnected,
                device_id.to_string(),
                "Device not connected".to_string(),
            ));
        }
        
        // Verify device can sign the specified inputs
        let devices = self.manager.devices.lock().unwrap();
        let device = devices.get(device_id).unwrap();
        
        let capability_result = HardwareWalletSignatureVerifier::verify_device_can_sign(
            device.as_ref(),
            psbt,
            input_indices,
        ).await.map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))?;
        
        if !capability_result.can_sign_all {
            return Err(HardwareWalletSigningError::new(
                SigningErrorType::InsufficientPermissions,
                device_id.to_string(),
                format!("Cannot sign inputs: {:?}", capability_result.reasons),
            ));
        }
        
        // Display transaction for confirmation
        let confirmed = device.display_transaction(psbt).await
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))?;
        
        if !confirmed {
            return Err(HardwareWalletSigningError::new(
                SigningErrorType::UserRejected,
                device_id.to_string(),
                "User rejected transaction on device".to_string(),
            ));
        }
        
        // Sign the specified inputs
        let signed_psbt = device.sign_psbt_inputs(psbt, input_indices).await
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))?;
        
        log::info!("Successfully signed inputs {:?} with device {}", input_indices, device_id);
        Ok(signed_psbt)
    }
    
    /// Get signing capabilities for a device and transaction
    pub async fn get_signing_capabilities(
        &self,
        device_id: &str,
        psbt: &PartiallySignedTransaction,
    ) -> Result<HardwareWalletSigningCapabilities, HardwareWalletSigningError> {
        let devices = self.manager.devices.lock().unwrap();
        let device = devices.get(device_id)
            .ok_or_else(|| HardwareWalletSigningError::new(
                SigningErrorType::DeviceNotConnected,
                device_id.to_string(),
                "Device not connected".to_string(),
            ))?;
        
        device.get_signing_capabilities(psbt).await
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, device_id.to_string()))
    }
    
    /// Verify signatures in a PSBT
    pub fn verify_signatures(
        &self,
        psbt: &PartiallySignedTransaction,
    ) -> Result<SignatureVerificationResult, HardwareWalletSigningError> {
        HardwareWalletSignatureVerifier::verify_psbt_signatures(psbt)
            .map_err(|e| HardwareWalletSigningError::from_gdk_error(e, "verifier".to_string()))
    }
}

#[cfg(test)]
mod signing_tests {
    use super::*;
    use crate::primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
    use crate::primitives::script::Script;

    fn create_test_psbt() -> PartiallySignedTransaction {
        let tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: [0u8; 32],
                    vout: 0,
                },
                script_sig: Script::new(),
                sequence: 0xffffffff,
                witness: Vec::new(),
            }],
            output: vec![TxOut {
                value: 100000,
                script_pubkey: Script::new(),
            }],
        };
        
        PartiallySignedTransaction::new(tx).unwrap()
    }

    #[tokio::test]
    async fn test_signing_coordinator_creation() {
        let manager = Arc::new(HardwareWalletManager::new());
        let coordinator = HardwareWalletSigningCoordinator::new(manager);
        
        assert_eq!(coordinator.list_active_sessions().len(), 0);
    }
    
    #[tokio::test]
    async fn test_multi_device_signing_session_creation() {
        let manager = Arc::new(HardwareWalletManager::new());
        let coordinator = HardwareWalletSigningCoordinator::new(manager);
        
        let psbt = create_test_psbt();
        let device_ids = vec!["device1".to_string(), "device2".to_string()];
        
        // This should fail because devices are not connected
        let result = coordinator.start_multi_device_signing(psbt, device_ids, None).await;
        assert!(result.is_err());
    }
    
    #[test]
    fn test_signature_verification_empty_psbt() {
        let psbt = create_test_psbt();
        let result = HardwareWalletSignatureVerifier::verify_psbt_signatures(&psbt).unwrap();
        
        // Should have no verified inputs since there are no signatures
        assert!(!result.all_verified);
        assert_eq!(result.verified_inputs.len(), 0);
        assert_eq!(result.failed_inputs.len(), 1); // One input with no signatures
    }
    
    #[test]
    fn test_signing_error_creation() {
        let error = HardwareWalletSigningError::new(
            SigningErrorType::DeviceNotConnected,
            "test_device".to_string(),
            "Test error".to_string(),
        );
        
        assert_eq!(error.error_type, SigningErrorType::DeviceNotConnected);
        assert_eq!(error.device_id, "test_device");
        assert!(error.retry_possible);
        assert!(!error.suggested_actions.is_empty());
    }
    
    #[test]
    fn test_signing_error_from_gdk_error() {
        let gdk_error = GdkError::Auth("Device not connected".to_string());
        let signing_error = HardwareWalletSigningError::from_gdk_error(gdk_error, "test_device".to_string());
        
        assert_eq!(signing_error.error_type, SigningErrorType::DeviceNotConnected);
        assert_eq!(signing_error.device_id, "test_device");
    }
    
    #[tokio::test]
    async fn test_transaction_signer_creation() {
        let manager = Arc::new(HardwareWalletManager::new());
        let signer = HardwareWalletTransactionSigner::new(manager);
        
        let psbt = create_test_psbt();
        
        // Should fail because device is not connected
        let result = signer.sign_transaction("nonexistent_device", &psbt).await;
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert_eq!(error.error_type, SigningErrorType::DeviceNotConnected);
    }
}