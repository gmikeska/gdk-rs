use crate::error::GdkError;
use crate::hw::{HardwareWalletManager, HardwareWalletCredentials, HardwareWalletInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of PIN attempts before lockout
const MAX_PIN_ATTEMPTS: u32 = 3;

/// PIN attempt lockout duration in seconds
const PIN_LOCKOUT_DURATION: u64 = 300; // 5 minutes

/// PBKDF2 iteration count for PIN derivation
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt length for PIN derivation
const SALT_LENGTH: usize = 32;

/// Encrypted credential storage for PIN-based authentication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PinData {
    /// Encrypted mnemonic or seed data
    pub encrypted_data: Vec<u8>,
    /// Salt used for PIN derivation
    pub salt: Vec<u8>,
    /// Number of failed PIN attempts
    pub failed_attempts: u32,
    /// Timestamp of last failed attempt (for lockout)
    pub last_failed_attempt: Option<u64>,
    /// PIN hash for validation (derived using PBKDF2)
    pub pin_hash: Vec<u8>,
}

impl PinData {
    /// Create new PinData by encrypting credentials with PIN
    pub fn new(pin: &str, credentials: &[u8]) -> Result<Self, GdkError> {
        // Generate random salt
        let salt = generate_random_bytes(SALT_LENGTH)?;
        
        // Derive key from PIN using PBKDF2
        let derived_key = derive_key_from_pin(pin, &salt)?;
        
        // Create PIN hash for validation
        let pin_hash = create_pin_hash(pin, &salt)?;
        
        // Encrypt credentials
        let encrypted_data = encrypt_data(credentials, &derived_key)?;
        
        Ok(PinData {
            encrypted_data,
            salt,
            failed_attempts: 0,
            last_failed_attempt: None,
            pin_hash,
        })
    }
    
    /// Validate PIN and decrypt credentials
    pub fn decrypt_with_pin(&mut self, pin: &str) -> Result<Vec<u8>, GdkError> {
        // Check if PIN is locked out
        if self.is_locked_out() {
            return Err(GdkError::Auth("PIN is locked out due to too many failed attempts".to_string()));
        }
        
        // Validate PIN
        if !self.validate_pin(pin)? {
            self.record_failed_attempt();
            return Err(GdkError::Auth("Invalid PIN".to_string()));
        }
        
        // Reset failed attempts on successful validation
        self.failed_attempts = 0;
        self.last_failed_attempt = None;
        
        // Derive key and decrypt
        let derived_key = derive_key_from_pin(pin, &self.salt)?;
        decrypt_data(&self.encrypted_data, &derived_key)
    }
    
    /// Change PIN by re-encrypting credentials
    pub fn change_pin(&mut self, old_pin: &str, new_pin: &str) -> Result<(), GdkError> {
        // First decrypt with old PIN to get credentials
        let credentials = self.decrypt_with_pin(old_pin)?;
        
        // Generate new salt for new PIN
        let new_salt = generate_random_bytes(SALT_LENGTH)?;
        
        // Derive new key from new PIN
        let new_derived_key = derive_key_from_pin(new_pin, &new_salt)?;
        
        // Create new PIN hash
        let new_pin_hash = create_pin_hash(new_pin, &new_salt)?;
        
        // Re-encrypt credentials with new key
        let new_encrypted_data = encrypt_data(&credentials, &new_derived_key)?;
        
        // Update PinData
        self.encrypted_data = new_encrypted_data;
        self.salt = new_salt;
        self.pin_hash = new_pin_hash;
        self.failed_attempts = 0;
        self.last_failed_attempt = None;
        
        Ok(())
    }
    
    /// Check if PIN is currently locked out
    pub fn is_locked_out(&self) -> bool {
        if self.failed_attempts < MAX_PIN_ATTEMPTS {
            return false;
        }
        
        if let Some(last_failed) = self.last_failed_attempt {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            now - last_failed < PIN_LOCKOUT_DURATION
        } else {
            true
        }
    }
    
    /// Get remaining lockout time in seconds
    pub fn lockout_remaining(&self) -> Option<u64> {
        if !self.is_locked_out() {
            return None;
        }
        
        if let Some(last_failed) = self.last_failed_attempt {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            
            let elapsed = now - last_failed;
            if elapsed < PIN_LOCKOUT_DURATION {
                Some(PIN_LOCKOUT_DURATION - elapsed)
            } else {
                None
            }
        } else {
            Some(PIN_LOCKOUT_DURATION)
        }
    }
    
    /// Validate PIN against stored hash
    fn validate_pin(&self, pin: &str) -> Result<bool, GdkError> {
        let pin_hash = create_pin_hash(pin, &self.salt)?;
        Ok(constant_time_compare(&pin_hash, &self.pin_hash))
    }
    
    /// Record a failed PIN attempt
    fn record_failed_attempt(&mut self) {
        self.failed_attempts += 1;
        self.last_failed_attempt = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
    }
}

/// Login credentials for various authentication methods
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginCredentials {
    /// BIP39 mnemonic phrase
    pub mnemonic: Option<String>,
    /// Password for mnemonic (BIP39 passphrase)
    pub password: Option<String>,
    /// BIP39 passphrase
    pub bip39_passphrase: Option<String>,
    /// PIN for PIN-based authentication
    pub pin: Option<String>,
    /// Encrypted PIN data
    pub pin_data: Option<PinData>,
    /// Username for watch-only wallets
    pub username: Option<String>,
    /// Core descriptors for descriptor-based watch-only wallets
    pub core_descriptors: Option<Vec<String>>,
    /// Extended public key for watch-only wallets
    pub xpub: Option<String>,
    /// Hardware wallet device ID
    pub hardware_device_id: Option<String>,
    /// Hardware wallet credentials
    pub hardware_credentials: Option<HardwareWalletCredentials>,
}

impl LoginCredentials {
    /// Create credentials for mnemonic-based authentication
    pub fn from_mnemonic(mnemonic: String, password: Option<String>) -> Self {
        Self {
            mnemonic: Some(mnemonic),
            password,
            bip39_passphrase: None,
            pin: None,
            pin_data: None,
            username: None,
            core_descriptors: None,
            xpub: None,
            hardware_device_id: None,
            hardware_credentials: None,
        }
    }
    
    /// Create credentials for PIN-based authentication
    pub fn from_pin(pin: String, pin_data: PinData) -> Self {
        Self {
            mnemonic: None,
            password: None,
            bip39_passphrase: None,
            pin: Some(pin),
            pin_data: Some(pin_data),
            username: None,
            core_descriptors: None,
            xpub: None,
            hardware_device_id: None,
            hardware_credentials: None,
        }
    }
    
    /// Create credentials for watch-only authentication with username/password
    pub fn from_watch_only_user(username: String, password: String) -> Self {
        Self {
            mnemonic: None,
            password: Some(password),
            bip39_passphrase: None,
            pin: None,
            pin_data: None,
            username: Some(username),
            core_descriptors: None,
            xpub: None,
            hardware_device_id: None,
            hardware_credentials: None,
        }
    }
    
    /// Create credentials for descriptor-based watch-only authentication
    pub fn from_descriptors(descriptors: Vec<String>) -> Self {
        Self {
            mnemonic: None,
            password: None,
            bip39_passphrase: None,
            pin: None,
            pin_data: None,
            username: None,
            core_descriptors: Some(descriptors),
            xpub: None,
            hardware_device_id: None,
            hardware_credentials: None,
        }
    }
    
    /// Create credentials for xpub-based watch-only authentication
    pub fn from_xpub(xpub: String) -> Self {
        Self {
            mnemonic: None,
            password: None,
            bip39_passphrase: None,
            pin: None,
            pin_data: None,
            username: None,
            core_descriptors: None,
            xpub: Some(xpub),
            hardware_device_id: None,
            hardware_credentials: None,
        }
    }
    
    /// Create credentials for hardware wallet authentication
    pub fn from_hardware_wallet(device_id: String, credentials: HardwareWalletCredentials) -> Self {
        Self {
            mnemonic: None,
            password: None,
            bip39_passphrase: None,
            pin: None,
            pin_data: None,
            username: None,
            core_descriptors: None,
            xpub: None,
            hardware_device_id: Some(device_id),
            hardware_credentials: Some(credentials),
        }
    }
}

/// Result of registration or login operations
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterLoginResult {
    /// Wallet identifier
    pub wallet_hash_id: String,
    /// Whether this is a watch-only wallet
    pub watch_only: bool,
    /// Available authentication methods
    pub available_auth_methods: Vec<String>,
    /// Warnings or additional information
    pub warnings: Vec<String>,
}

/// Authentication manager for handling different authentication methods
pub struct AuthManager {
    /// Storage for PIN data by wallet ID
    pin_storage: HashMap<String, PinData>,
    /// Hardware wallet manager
    hw_manager: HardwareWalletManager,
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            pin_storage: HashMap::new(),
            hw_manager: HardwareWalletManager::new(),
        }
    }
    
    /// Register a new user with given credentials
    pub async fn register_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        match self.validate_credentials(credentials)? {
            AuthMethod::Mnemonic => self.register_mnemonic_user(credentials),
            AuthMethod::Pin => self.register_pin_user(credentials),
            AuthMethod::WatchOnlyUser => self.register_watch_only_user(credentials),
            AuthMethod::WatchOnlyDescriptor => self.register_descriptor_user(credentials),
            AuthMethod::WatchOnlyXpub => self.register_xpub_user(credentials),
            AuthMethod::HardwareWallet => self.register_hardware_wallet_user(credentials).await,
        }
    }
    
    /// Login user with given credentials
    pub async fn login_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        match self.validate_credentials(credentials)? {
            AuthMethod::Mnemonic => self.login_mnemonic_user(credentials),
            AuthMethod::Pin => self.login_pin_user(credentials),
            AuthMethod::WatchOnlyUser => self.login_watch_only_user(credentials),
            AuthMethod::WatchOnlyDescriptor => self.login_descriptor_user(credentials),
            AuthMethod::WatchOnlyXpub => self.login_xpub_user(credentials),
            AuthMethod::HardwareWallet => self.login_hardware_wallet_user(credentials).await,
        }
    }
    
    /// Validate credentials and determine authentication method
    fn validate_credentials(&self, credentials: &LoginCredentials) -> Result<AuthMethod, GdkError> {
        if credentials.mnemonic.is_some() {
            Ok(AuthMethod::Mnemonic)
        } else if credentials.pin.is_some() && credentials.pin_data.is_some() {
            Ok(AuthMethod::Pin)
        } else if credentials.hardware_device_id.is_some() {
            Ok(AuthMethod::HardwareWallet)
        } else if credentials.username.is_some() && credentials.password.is_some() {
            Ok(AuthMethod::WatchOnlyUser)
        } else if credentials.core_descriptors.is_some() {
            Ok(AuthMethod::WatchOnlyDescriptor)
        } else if credentials.xpub.is_some() {
            Ok(AuthMethod::WatchOnlyXpub)
        } else {
            Err(GdkError::InvalidInput("Invalid or incomplete credentials".to_string()))
        }
    }
    
    /// Register user with mnemonic
    fn register_mnemonic_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let mnemonic = credentials.mnemonic.as_ref().unwrap();
        
        // Validate mnemonic
        if !crate::utils::validate_mnemonic(mnemonic)? {
            return Err(GdkError::Auth("Invalid mnemonic".to_string()));
        }
        
        // Generate wallet hash ID from mnemonic
        let wallet_hash_id = generate_wallet_hash_id(mnemonic)?;
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: false,
            available_auth_methods: vec!["mnemonic".to_string(), "pin".to_string()],
            warnings: vec![],
        })
    }
    
    /// Register user with PIN
    fn register_pin_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let pin = credentials.pin.as_ref().unwrap();
        let pin_data = credentials.pin_data.as_ref().unwrap();
        
        // Validate PIN format
        if !is_valid_pin(pin) {
            return Err(GdkError::Auth("Invalid PIN format".to_string()));
        }
        
        // Generate wallet hash ID from PIN data
        let wallet_hash_id = generate_wallet_hash_id_from_pin_data(pin_data)?;
        
        // Store PIN data
        self.pin_storage.insert(wallet_hash_id.clone(), pin_data.clone());
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: false,
            available_auth_methods: vec!["pin".to_string()],
            warnings: vec![],
        })
    }
    
    /// Register watch-only user with username/password
    fn register_watch_only_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let username = credentials.username.as_ref().unwrap();
        let password = credentials.password.as_ref().unwrap();
        
        // Validate username and password
        if username.is_empty() || password.is_empty() {
            return Err(GdkError::Auth("Username and password cannot be empty".to_string()));
        }
        
        // Generate wallet hash ID from username
        let wallet_hash_id = generate_wallet_hash_id(username)?;
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: true,
            available_auth_methods: vec!["watch_only_user".to_string()],
            warnings: vec!["This is a watch-only wallet with limited functionality".to_string()],
        })
    }
    
    /// Register descriptor-based watch-only user
    fn register_descriptor_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let descriptors = credentials.core_descriptors.as_ref().unwrap();
        
        // Validate descriptors
        if descriptors.is_empty() {
            return Err(GdkError::Auth("At least one descriptor is required".to_string()));
        }
        
        for descriptor in descriptors {
            if !is_valid_descriptor(descriptor) {
                return Err(GdkError::Auth(format!("Invalid descriptor: {}", descriptor)));
            }
        }
        
        // Generate wallet hash ID from descriptors
        let wallet_hash_id = generate_wallet_hash_id(&descriptors.join(","))?;
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: true,
            available_auth_methods: vec!["watch_only_descriptor".to_string()],
            warnings: vec!["This is a watch-only wallet with limited functionality".to_string()],
        })
    }
    
    /// Register xpub-based watch-only user
    fn register_xpub_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let xpub = credentials.xpub.as_ref().unwrap();
        
        // Validate extended public key
        if !is_valid_xpub(xpub) {
            return Err(GdkError::Auth("Invalid extended public key".to_string()));
        }
        
        // Generate wallet hash ID from xpub
        let wallet_hash_id = generate_wallet_hash_id(xpub)?;
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: true,
            available_auth_methods: vec!["watch_only_xpub".to_string()],
            warnings: vec!["This is a watch-only wallet with limited functionality".to_string()],
        })
    }
    
    /// Login with mnemonic
    fn login_mnemonic_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        // Same as register for mnemonic-based auth
        self.register_mnemonic_user(credentials)
    }
    
    /// Login with PIN
    fn login_pin_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let pin = credentials.pin.as_ref().unwrap();
        let mut pin_data = credentials.pin_data.as_ref().unwrap().clone();
        
        // Attempt to decrypt with PIN
        let _decrypted_data = pin_data.decrypt_with_pin(pin)?;
        
        // Generate wallet hash ID
        let wallet_hash_id = generate_wallet_hash_id_from_pin_data(&pin_data)?;
        
        // Update stored PIN data with any changes (failed attempts, etc.)
        self.pin_storage.insert(wallet_hash_id.clone(), pin_data);
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: false,
            available_auth_methods: vec!["pin".to_string()],
            warnings: vec![],
        })
    }
    
    /// Login watch-only user
    fn login_watch_only_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        // Same as register for watch-only auth
        self.register_watch_only_user(credentials)
    }
    
    /// Login descriptor user
    fn login_descriptor_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        // Same as register for descriptor auth
        self.register_descriptor_user(credentials)
    }
    
    /// Login xpub user
    fn login_xpub_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        // Same as register for xpub auth
        self.register_xpub_user(credentials)
    }
    
    /// Register hardware wallet user
    async fn register_hardware_wallet_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let device_id = credentials.hardware_device_id.as_ref().unwrap();
        
        // Discover and connect to the hardware wallet
        let device_info = self.discover_and_connect_hardware_wallet(device_id).await?;
        
        // Authenticate with the device
        let hw_credentials = self.hw_manager.authenticate_device(device_id).await?;
        
        // Verify device authenticity
        let is_authentic = self.hw_manager.verify_device_authenticity(device_id).await?;
        if !is_authentic {
            return Err(GdkError::Auth("Hardware wallet device authentication failed".to_string()));
        }
        
        // Generate wallet hash ID from device info
        let wallet_hash_id = generate_wallet_hash_id(&format!("{}:{}", device_info.device_type as u8, device_info.device_id))?;
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: false,
            available_auth_methods: vec!["hardware_wallet".to_string()],
            warnings: vec![
                format!("Hardware wallet: {} {}", device_info.device_type as u8, device_info.model),
                "Ensure your hardware wallet is connected and unlocked for transactions".to_string(),
            ],
        })
    }
    
    /// Login hardware wallet user
    async fn login_hardware_wallet_user(&mut self, credentials: &LoginCredentials) -> Result<RegisterLoginResult, GdkError> {
        let device_id = credentials.hardware_device_id.as_ref().unwrap();
        
        // Check if device is already connected
        if self.hw_manager.get_device(device_id).is_none() {
            // Try to reconnect
            self.discover_and_connect_hardware_wallet(device_id).await?;
        }
        
        // Authenticate with the device
        let hw_credentials = self.hw_manager.authenticate_device(device_id).await?;
        
        // Generate wallet hash ID from device info
        let device_info = &hw_credentials.device_info;
        let wallet_hash_id = generate_wallet_hash_id(&format!("{}:{}", device_info.device_type as u8, device_info.device_id))?;
        
        Ok(RegisterLoginResult {
            wallet_hash_id,
            watch_only: false,
            available_auth_methods: vec!["hardware_wallet".to_string()],
            warnings: vec![],
        })
    }
    
    /// Discover and connect to hardware wallet
    async fn discover_and_connect_hardware_wallet(&mut self, device_id: &str) -> Result<HardwareWalletInfo, GdkError> {
        // Discover available devices
        let devices = self.hw_manager.discover_devices().await?;
        
        // Find the requested device
        let device_info = devices.into_iter()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| GdkError::Auth(format!("Hardware wallet device not found: {}", device_id)))?;
        
        // Connect to the device
        let _device = self.hw_manager.connect_device(device_id).await?;
        
        Ok(device_info)
    }
    
    /// Get hardware wallet manager
    pub fn get_hardware_wallet_manager(&self) -> &HardwareWalletManager {
        &self.hw_manager
    }
    
    /// Get hardware wallet manager (mutable)
    pub fn get_hardware_wallet_manager_mut(&mut self) -> &mut HardwareWalletManager {
        &mut self.hw_manager
    }
    
    /// List available hardware wallet devices
    pub async fn list_hardware_wallet_devices(&self) -> Result<Vec<HardwareWalletInfo>, GdkError> {
        self.hw_manager.discover_devices().await
    }
    
    /// Connect to a specific hardware wallet device
    pub async fn connect_hardware_wallet(&mut self, device_id: &str) -> Result<(), GdkError> {
        self.hw_manager.connect_device(device_id).await?;
        Ok(())
    }
    
    /// Disconnect from a hardware wallet device
    pub async fn disconnect_hardware_wallet(&mut self, device_id: &str) -> Result<(), GdkError> {
        self.hw_manager.disconnect_device(device_id).await
    }
    
    /// Get PIN data for a wallet
    pub fn get_pin_data(&self, wallet_id: &str) -> Option<&PinData> {
        self.pin_storage.get(wallet_id)
    }
    
    /// Update PIN data for a wallet
    pub fn update_pin_data(&mut self, wallet_id: &str, pin_data: PinData) {
        self.pin_storage.insert(wallet_id.to_string(), pin_data);
    }
}

/// Authentication methods supported by the system
#[derive(Debug, Clone, PartialEq)]
enum AuthMethod {
    Mnemonic,
    Pin,
    WatchOnlyUser,
    WatchOnlyDescriptor,
    WatchOnlyXpub,
    HardwareWallet,
}

// Cryptographic utility functions

/// Generate cryptographically secure random bytes
fn generate_random_bytes(length: usize) -> Result<Vec<u8>, GdkError> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    Ok(bytes)
}

/// Derive key from PIN using PBKDF2
fn derive_key_from_pin(pin: &str, salt: &[u8]) -> Result<Vec<u8>, GdkError> {
    use pbkdf2::pbkdf2;
    use hmac::Hmac;
    use sha2::Sha256;
    
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(pin.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key.to_vec())
}

/// Create PIN hash for validation
fn create_pin_hash(pin: &str, salt: &[u8]) -> Result<Vec<u8>, GdkError> {
    use pbkdf2::pbkdf2;
    use hmac::Hmac;
    use sha2::Sha256;
    
    let mut hash = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(pin.as_bytes(), salt, PBKDF2_ITERATIONS, &mut hash);
    Ok(hash.to_vec())
}

/// Encrypt data using AES-256-GCM
fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, GdkError> {
    use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = generate_random_bytes(12)?; // 96-bit nonce for GCM
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|e| GdkError::Auth(format!("Encryption failed: {}", e)))?;
    
    // Prepend nonce to ciphertext
    let mut result = nonce_bytes;
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data using AES-256-GCM
fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, GdkError> {
    use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, KeyInit}};
    
    if encrypted_data.len() < 12 {
        return Err(GdkError::Auth("Invalid encrypted data length".to_string()));
    }
    
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&encrypted_data[..12]);
    let ciphertext = &encrypted_data[12..];
    
    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| GdkError::Auth(format!("Decryption failed: {}", e)))
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Generate wallet hash ID from input data
fn generate_wallet_hash_id(data: &str) -> Result<String, GdkError> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Generate wallet hash ID from PIN data
fn generate_wallet_hash_id_from_pin_data(pin_data: &PinData) -> Result<String, GdkError> {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(&pin_data.encrypted_data);
    hasher.update(&pin_data.salt);
    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

/// Validate PIN format (4-8 digits)
fn is_valid_pin(pin: &str) -> bool {
    pin.len() >= 4 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit())
}

/// Validate descriptor format (basic validation)
fn is_valid_descriptor(descriptor: &str) -> bool {
    // Basic validation - should contain valid descriptor syntax
    !descriptor.is_empty() && 
    (descriptor.contains("wpkh(") || descriptor.contains("wsh(") || 
     descriptor.contains("pkh(") || descriptor.contains("sh(") ||
     descriptor.contains("tr("))
}

/// Validate extended public key format
fn is_valid_xpub(xpub: &str) -> bool {
    // Basic validation - should start with xpub, ypub, zpub, etc.
    (xpub.starts_with("xpub") || xpub.starts_with("ypub") || 
     xpub.starts_with("zpub") || xpub.starts_with("tpub") ||
     xpub.starts_with("upub") || xpub.starts_with("vpub")) &&
    xpub.len() >= 100 // Minimum length for base58 encoded xpub
}

#[cfg(test)]
mod tests {
    use super::*;

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
    
    #[test]
    fn test_auth_manager_register_mnemonic() {
        let mut auth_manager = AuthManager::new();
        let credentials = LoginCredentials::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            None
        );
        
        let result = auth_manager.register_user(&credentials).unwrap();
        assert!(!result.watch_only);
        assert!(result.available_auth_methods.contains(&"mnemonic".to_string()));
    }
    
    #[test]
    fn test_auth_manager_register_watch_only() {
        let mut auth_manager = AuthManager::new();
        let credentials = LoginCredentials::from_watch_only_user(
            "testuser".to_string(),
            "testpass".to_string()
        );
        
        let result = auth_manager.register_user(&credentials).unwrap();
        assert!(result.watch_only);
        assert!(result.available_auth_methods.contains(&"watch_only_user".to_string()));
    }
    
    #[test]
    fn test_pin_format_validation() {
        assert!(is_valid_pin("1234"));
        assert!(is_valid_pin("12345678"));
        assert!(!is_valid_pin("123")); // too short
        assert!(!is_valid_pin("123456789")); // too long
        assert!(!is_valid_pin("12a4")); // contains letter
        assert!(!is_valid_pin("")); // empty
    }
    
    #[test]
    fn test_xpub_validation() {
        assert!(is_valid_xpub("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"));
        assert!(!is_valid_xpub("invalid"));
        assert!(!is_valid_xpub(""));
    }
}