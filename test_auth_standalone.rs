// Standalone test for auth module
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

// Copy the error type we need
#[derive(Debug)]
pub enum GdkError {
    Auth(String),
    InvalidInput(String),
}

impl std::fmt::Display for GdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GdkError::Auth(msg) => write!(f, "Authentication failed: {}", msg),
            GdkError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for GdkError {}

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
    use pbkdf2::{pbkdf2_hmac};
    use sha2::Sha256;
    
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    Ok(key.to_vec())
}

/// Create PIN hash for validation
fn create_pin_hash(pin: &str, salt: &[u8]) -> Result<Vec<u8>, GdkError> {
    use pbkdf2::{pbkdf2_hmac};
    use sha2::Sha256;
    
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin.as_bytes(), salt, PBKDF2_ITERATIONS, &mut hash);
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

/// Validate PIN format (4-8 digits)
fn is_valid_pin(pin: &str) -> bool {
    pin.len() >= 4 && pin.len() <= 8 && pin.chars().all(|c| c.is_ascii_digit())
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
    fn test_pin_format_validation() {
        assert!(is_valid_pin("1234"));
        assert!(is_valid_pin("12345678"));
        assert!(!is_valid_pin("123")); // too short
        assert!(!is_valid_pin("123456789")); // too long
        assert!(!is_valid_pin("12a4")); // contains letter
        assert!(!is_valid_pin("")); // empty
    }
}

fn main() {
    println!("Running PIN authentication tests...");
    
    // Test basic PIN functionality
    let pin = "1234";
    let credentials = b"test mnemonic phrase for wallet";
    
    let mut pin_data = PinData::new(pin, credentials).unwrap();
    println!("✓ Created PIN data successfully");
    
    let decrypted = pin_data.decrypt_with_pin(pin).unwrap();
    assert_eq!(decrypted, credentials);
    println!("✓ PIN decryption works correctly");
    
    // Test wrong PIN
    let result = pin_data.decrypt_with_pin("5678");
    assert!(result.is_err());
    println!("✓ Wrong PIN correctly rejected");
    
    // Test PIN change
    let new_pin = "9876";
    pin_data.change_pin(pin, new_pin).unwrap();
    println!("✓ PIN change successful");
    
    let decrypted_new = pin_data.decrypt_with_pin(new_pin).unwrap();
    assert_eq!(decrypted_new, credentials);
    println!("✓ New PIN works correctly");
    
    // Test old PIN no longer works
    let result = pin_data.decrypt_with_pin(pin);
    assert!(result.is_err());
    println!("✓ Old PIN correctly rejected after change");
    
    println!("\nAll PIN authentication tests passed! ✅");
}