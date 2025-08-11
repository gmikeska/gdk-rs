//! Cryptographic utility functions for GDK.
//!
//! This module provides secure cryptographic operations including:
//! - Secure random number generation
//! - Hash function implementations (SHA256, RIPEMD160, etc.)
//! - HMAC and PBKDF2 key derivation functions
//! - Message signing and verification utilities
//! - Cryptographic constant-time comparison functions

use crate::{GdkError, Result};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{RngCore, CryptoRng};
use secp256k1::{Message, PublicKey, SecretKey, Secp256k1, All};
use secp256k1::ecdsa::Signature;
use sha2::{Sha256, Sha512, Digest};
use ripemd::Ripemd160;
use subtle::ConstantTimeEq;
use std::fmt;

/// Number of iterations for PBKDF2 key derivation (recommended minimum)
pub const PBKDF2_ITERATIONS: u32 = 100_000;

/// Standard salt length for cryptographic operations
pub const SALT_LENGTH: usize = 32;

/// Standard key length for derived keys
pub const KEY_LENGTH: usize = 32;

/// Secure random number generator wrapper
pub struct SecureRng {
    rng: rand::rngs::ThreadRng,
}

impl SecureRng {
    /// Create a new secure random number generator
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    /// Generate random bytes with proper entropy
    pub fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a random salt for cryptographic operations
    pub fn random_salt(&mut self) -> [u8; SALT_LENGTH] {
        let mut salt = [0u8; SALT_LENGTH];
        self.rng.fill_bytes(&mut salt);
        salt
    }

    /// Generate a cryptographically secure random u64
    pub fn random_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.rng.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
}

impl Default for SecureRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RngCore for SecureRng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for SecureRng {}

/// Hash function implementations
pub struct Hash;

impl Hash {
    /// Compute SHA256 hash
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute double SHA256 hash (SHA256(SHA256(data)))
    pub fn double_sha256(data: &[u8]) -> [u8; 32] {
        let first_hash = Self::sha256(data);
        Self::sha256(&first_hash)
    }

    /// Compute SHA512 hash
    pub fn sha512(data: &[u8]) -> [u8; 64] {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute RIPEMD160 hash
    pub fn ripemd160(data: &[u8]) -> [u8; 20] {
        let mut hasher = Ripemd160::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Compute Hash160 (RIPEMD160(SHA256(data))) - commonly used in Bitcoin
    pub fn hash160(data: &[u8]) -> [u8; 20] {
        let sha256_hash = Self::sha256(data);
        Self::ripemd160(&sha256_hash)
    }

    /// Compute HMAC-SHA256
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| GdkError::crypto(crate::error::GdkErrorCode::CryptoHashFailed, &format!("HMAC key error: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().into())
    }

    /// Compute HMAC-SHA512
    pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64]> {
        let mut mac = Hmac::<Sha512>::new_from_slice(key)
            .map_err(|e| GdkError::crypto(crate::error::GdkErrorCode::CryptoHashFailed, &format!("HMAC key error: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().into())
    }
}

/// Key derivation functions
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive key using PBKDF2 with SHA256
    pub fn pbkdf2_sha256(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_len: usize,
    ) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output);
        output
    }

    /// Derive key using PBKDF2 with SHA512
    pub fn pbkdf2_sha512(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_len: usize,
    ) -> Vec<u8> {
        let mut output = vec![0u8; output_len];
        pbkdf2::<Hmac<Sha512>>(password, salt, iterations, &mut output);
        output
    }

    /// Derive a standard 32-byte key using PBKDF2-SHA256 with default iterations
    pub fn derive_key(password: &[u8], salt: &[u8]) -> [u8; KEY_LENGTH] {
        let mut output = [0u8; KEY_LENGTH];
        pbkdf2::<Hmac<Sha256>>(password, salt, PBKDF2_ITERATIONS, &mut output);
        output
    }

    /// Derive a key with custom parameters
    pub fn derive_key_custom(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_len: usize,
    ) -> Vec<u8> {
        Self::pbkdf2_sha256(password, salt, iterations, output_len)
    }
}

/// Message signing and verification utilities
pub struct MessageSigning {
    secp: Secp256k1<All>,
}

impl MessageSigning {
    /// Create a new message signing instance
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Sign a message with a private key
    pub fn sign_message(&self, message: &[u8], private_key: &SecretKey) -> Result<Signature> {
        let message_hash = Hash::sha256(message);
        let message = Message::from_digest_slice(&message_hash)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid message hash: {}", e)))?;
        
        Ok(self.secp.sign_ecdsa(&message, private_key))
    }

    /// Verify a message signature
    pub fn verify_message(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool> {
        let message_hash = Hash::sha256(message);
        let message = Message::from_digest_slice(&message_hash)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid message hash: {}", e)))?;
        
        match self.secp.verify_ecdsa(&message, signature, public_key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Sign a hash directly (for when you already have the hash)
    pub fn sign_hash(&self, hash: &[u8; 32], private_key: &SecretKey) -> Result<Signature> {
        let message = Message::from_digest_slice(hash)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid message hash: {}", e)))?;
        
        Ok(self.secp.sign_ecdsa(&message, private_key))
    }

    /// Verify a hash signature directly
    pub fn verify_hash(
        &self,
        hash: &[u8; 32],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool> {
        let message = Message::from_digest_slice(hash)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid message hash: {}", e)))?;
        
        match self.secp.verify_ecdsa(&message, signature, public_key) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Recover public key from signature and message
    pub fn recover_public_key(
        &self,
        message: &[u8],
        signature: &secp256k1::ecdsa::RecoverableSignature,
    ) -> Result<PublicKey> {
        let message_hash = Hash::sha256(message);
        let message = Message::from_digest_slice(&message_hash)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid message hash: {}", e)))?;
        
        self.secp.recover_ecdsa(&message, signature)
            .map_err(|e| GdkError::crypto(crate::error::GdkErrorCode::CryptoSignatureFailed, &format!("Key recovery failed: {}", e)))
    }
}

impl Default for MessageSigning {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time comparison utilities
pub struct ConstantTime;

impl ConstantTime {
    /// Compare two byte slices in constant time
    pub fn eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Compare two arrays in constant time
    pub fn eq_arrays<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
        a.ct_eq(b).into()
    }

    /// Conditionally select between two values in constant time
    pub fn select(condition: bool, if_true: u8, if_false: u8) -> u8 {
        let mask = if condition { 0xFF } else { 0x00 };
        (if_true & mask) | (if_false & !mask)
    }

    /// Conditionally select between two byte arrays in constant time
    pub fn select_bytes(condition: bool, if_true: &[u8], if_false: &[u8]) -> Vec<u8> {
        assert_eq!(if_true.len(), if_false.len());
        if_true.iter()
            .zip(if_false.iter())
            .map(|(&t, &f)| Self::select(condition, t, f))
            .collect()
    }
}

/// Utility functions for working with cryptographic data
pub struct CryptoUtils;

impl CryptoUtils {
    /// Securely zero out memory
    pub fn secure_zero(data: &mut [u8]) {
        // Use volatile write to prevent compiler optimization
        for byte in data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }

    /// Generate a cryptographically secure random private key
    pub fn generate_private_key() -> Result<SecretKey> {
        let mut rng = SecureRng::new();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        
        SecretKey::from_slice(&key_bytes)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid private key: {}", e)))
    }

    /// Derive public key from private key
    pub fn derive_public_key(private_key: &SecretKey) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, private_key)
    }

    /// Convert bytes to hex string
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// Convert hex string to bytes
    pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
        hex::decode(hex_str)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid hex string: {}", e)))
    }

    /// Validate that a byte slice is a valid private key
    pub fn validate_private_key(key_bytes: &[u8]) -> Result<()> {
        if key_bytes.len() != 32 {
            return Err(GdkError::crypto_simple("Private key must be 32 bytes".to_string()));
        }

        SecretKey::from_slice(key_bytes)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid private key: {}", e)))?;
        
        Ok(())
    }

    /// Validate that a byte slice is a valid public key
    pub fn validate_public_key(key_bytes: &[u8]) -> Result<()> {
        PublicKey::from_slice(key_bytes)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid public key: {}", e)))?;
        
        Ok(())
    }
}

/// Secure string type that zeros memory on drop
pub struct SecureString {
    data: Vec<u8>,
}

impl SecureString {
    /// Create a new secure string from bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { data: bytes }
    }

    /// Create a new secure string from a string
    pub fn from_string(s: String) -> Self {
        Self { data: s.into_bytes() }
    }

    /// Get the bytes (read-only)
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the string representation
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.data)
            .map_err(|e| GdkError::crypto_simple(format!("Invalid UTF-8: {}", e)))
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        CryptoUtils::secure_zero(&mut self.data);
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureString([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_rng() {
        let mut rng = SecureRng::new();
        let bytes1 = rng.random_bytes(32);
        let bytes2 = rng.random_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_hash_functions() {
        let data = b"hello world";
        
        let sha256 = Hash::sha256(data);
        assert_eq!(sha256.len(), 32);
        
        let double_sha256 = Hash::double_sha256(data);
        assert_eq!(double_sha256.len(), 32);
        
        let sha512 = Hash::sha512(data);
        assert_eq!(sha512.len(), 64);
        
        let ripemd160 = Hash::ripemd160(data);
        assert_eq!(ripemd160.len(), 20);
        
        let hash160 = Hash::hash160(data);
        assert_eq!(hash160.len(), 20);
    }

    #[test]
    fn test_hmac() {
        let key = b"secret key";
        let data = b"message";
        
        let hmac_sha256 = Hash::hmac_sha256(key, data).unwrap();
        assert_eq!(hmac_sha256.len(), 32);
        
        let hmac_sha512 = Hash::hmac_sha512(key, data).unwrap();
        assert_eq!(hmac_sha512.len(), 64);
    }

    #[test]
    fn test_pbkdf2() {
        let password = b"password";
        let salt = b"salt";
        
        let key = KeyDerivation::derive_key(password, salt);
        assert_eq!(key.len(), 32);
        
        let custom_key = KeyDerivation::derive_key_custom(password, salt, 1000, 16);
        assert_eq!(custom_key.len(), 16);
    }

    #[test]
    fn test_message_signing() {
        let signer = MessageSigning::new();
        let private_key = CryptoUtils::generate_private_key().unwrap();
        let public_key = CryptoUtils::derive_public_key(&private_key);
        let message = b"test message";
        
        let signature = signer.sign_message(message, &private_key).unwrap();
        let is_valid = signer.verify_message(message, &signature, &public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        
        assert!(ConstantTime::eq_arrays(&a, &b));
        assert!(!ConstantTime::eq_arrays(&a, &c));
    }

    #[test]
    fn test_secure_string() {
        let secure_str = SecureString::from_string("secret".to_string());
        assert_eq!(secure_str.len(), 6);
        assert_eq!(secure_str.as_str().unwrap(), "secret");
        assert!(!secure_str.is_empty());
    }

    #[test]
    fn test_crypto_utils() {
        let private_key = CryptoUtils::generate_private_key().unwrap();
        let public_key = CryptoUtils::derive_public_key(&private_key);
        
        // Test key validation
        let private_key_bytes = private_key.secret_bytes();
        CryptoUtils::validate_private_key(&private_key_bytes).unwrap();
        
        let public_key_bytes = public_key.serialize();
        CryptoUtils::validate_public_key(&public_key_bytes).unwrap();
        
        // Test hex conversion
        let hex_str = CryptoUtils::bytes_to_hex(&private_key_bytes);
        let decoded_bytes = CryptoUtils::hex_to_bytes(&hex_str).unwrap();
        assert_eq!(private_key_bytes.to_vec(), decoded_bytes);
    }
}