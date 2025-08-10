//! Comprehensive unit tests for cryptographic utilities

use gdk_rs::utils::crypto::*;
use gdk_rs::{GdkError, Result};
use secp256k1::{SecretKey, PublicKey, Signature};
use std::str::FromStr;

#[test]
fn test_secure_rng_basic_functionality() {
    let mut rng = SecureRng::new();
    
    // Test random bytes generation
    let bytes1 = rng.random_bytes(32);
    let bytes2 = rng.random_bytes(32);
    
    assert_eq!(bytes1.len(), 32);
    assert_eq!(bytes2.len(), 32);
    assert_ne!(bytes1, bytes2); // Should be different with high probability
    
    // Test different lengths
    let short_bytes = rng.random_bytes(8);
    let long_bytes = rng.random_bytes(64);
    assert_eq!(short_bytes.len(), 8);
    assert_eq!(long_bytes.len(), 64);
}

#[test]
fn test_secure_rng_salt_generation() {
    let mut rng = SecureRng::new();
    
    let salt1 = rng.random_salt();
    let salt2 = rng.random_salt();
    
    assert_eq!(salt1.len(), SALT_LENGTH);
    assert_eq!(salt2.len(), SALT_LENGTH);
    assert_ne!(salt1, salt2); // Should be different
}

#[test]
fn test_secure_rng_u64_generation() {
    let mut rng = SecureRng::new();
    
    let num1 = rng.random_u64();
    let num2 = rng.random_u64();
    
    // Should be different with high probability
    assert_ne!(num1, num2);
}

#[test]
fn test_secure_rng_zero_length() {
    let mut rng = SecureRng::new();
    let empty_bytes = rng.random_bytes(0);
    assert_eq!(empty_bytes.len(), 0);
}

#[test]
fn test_hash_sha256() {
    let data = b"hello world";
    let hash = Hash::sha256(data);
    
    assert_eq!(hash.len(), 32);
    
    // Test known vector
    let expected = hex::decode("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").unwrap();
    assert_eq!(hash.to_vec(), expected);
    
    // Test empty input
    let empty_hash = Hash::sha256(b"");
    let expected_empty = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    assert_eq!(empty_hash.to_vec(), expected_empty);
}

#[test]
fn test_hash_double_sha256() {
    let data = b"hello world";
    let hash = Hash::double_sha256(data);
    
    assert_eq!(hash.len(), 32);
    
    // Verify it's actually double SHA256
    let single_hash = Hash::sha256(data);
    let expected_double = Hash::sha256(&single_hash);
    assert_eq!(hash, expected_double);
}

#[test]
fn test_hash_sha512() {
    let data = b"hello world";
    let hash = Hash::sha512(data);
    
    assert_eq!(hash.len(), 64);
    
    // Test known vector
    let expected = hex::decode("309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f").unwrap();
    assert_eq!(hash.to_vec(), expected);
}

#[test]
fn test_hash_ripemd160() {
    let data = b"hello world";
    let hash = Hash::ripemd160(data);
    
    assert_eq!(hash.len(), 20);
    
    // Test known vector
    let expected = hex::decode("98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f").unwrap();
    assert_eq!(hash.to_vec(), expected);
}

#[test]
fn test_hash_hash160() {
    let data = b"hello world";
    let hash = Hash::hash160(data);
    
    assert_eq!(hash.len(), 20);
    
    // Verify it's SHA256 followed by RIPEMD160
    let sha256_hash = Hash::sha256(data);
    let expected = Hash::ripemd160(&sha256_hash);
    assert_eq!(hash, expected);
}

#[test]
fn test_hash_hmac_sha256() {
    let key = b"secret key";
    let data = b"message";
    
    let hmac = Hash::hmac_sha256(key, data).unwrap();
    assert_eq!(hmac.len(), 32);
    
    // Test with empty key (should still work)
    let hmac_empty_key = Hash::hmac_sha256(b"", data).unwrap();
    assert_eq!(hmac_empty_key.len(), 32);
    assert_ne!(hmac, hmac_empty_key);
    
    // Test with empty data
    let hmac_empty_data = Hash::hmac_sha256(key, b"").unwrap();
    assert_eq!(hmac_empty_data.len(), 32);
    assert_ne!(hmac, hmac_empty_data);
}

#[test]
fn test_hash_hmac_sha512() {
    let key = b"secret key";
    let data = b"message";
    
    let hmac = Hash::hmac_sha512(key, data).unwrap();
    assert_eq!(hmac.len(), 64);
    
    // Test consistency
    let hmac2 = Hash::hmac_sha512(key, data).unwrap();
    assert_eq!(hmac, hmac2);
}

#[test]
fn test_key_derivation_pbkdf2_sha256() {
    let password = b"password";
    let salt = b"salt";
    let iterations = 1000;
    let output_len = 32;
    
    let key = KeyDerivation::pbkdf2_sha256(password, salt, iterations, output_len);
    assert_eq!(key.len(), output_len);
    
    // Test consistency
    let key2 = KeyDerivation::pbkdf2_sha256(password, salt, iterations, output_len);
    assert_eq!(key, key2);
    
    // Test different parameters produce different keys
    let key_diff_salt = KeyDerivation::pbkdf2_sha256(password, b"different_salt", iterations, output_len);
    assert_ne!(key, key_diff_salt);
    
    let key_diff_iterations = KeyDerivation::pbkdf2_sha256(password, salt, iterations * 2, output_len);
    assert_ne!(key, key_diff_iterations);
}

#[test]
fn test_key_derivation_pbkdf2_sha512() {
    let password = b"password";
    let salt = b"salt";
    let iterations = 1000;
    let output_len = 64;
    
    let key = KeyDerivation::pbkdf2_sha512(password, salt, iterations, output_len);
    assert_eq!(key.len(), output_len);
    
    // Test different output lengths
    let short_key = KeyDerivation::pbkdf2_sha512(password, salt, iterations, 16);
    assert_eq!(short_key.len(), 16);
}

#[test]
fn test_key_derivation_derive_key() {
    let password = b"password";
    let salt = b"salt";
    
    let key = KeyDerivation::derive_key(password, salt);
    assert_eq!(key.len(), KEY_LENGTH);
    
    // Test consistency
    let key2 = KeyDerivation::derive_key(password, salt);
    assert_eq!(key, key2);
}

#[test]
fn test_key_derivation_derive_key_custom() {
    let password = b"password";
    let salt = b"salt";
    let iterations = 5000;
    let output_len = 48;
    
    let key = KeyDerivation::derive_key_custom(password, salt, iterations, output_len);
    assert_eq!(key.len(), output_len);
}

#[test]
fn test_message_signing_basic() {
    let signer = MessageSigning::new();
    let private_key = CryptoUtils::generate_private_key().unwrap();
    let public_key = CryptoUtils::derive_public_key(&private_key);
    let message = b"test message";
    
    // Test signing and verification
    let signature = signer.sign_message(message, &private_key).unwrap();
    let is_valid = signer.verify_message(message, &signature, &public_key).unwrap();
    assert!(is_valid);
    
    // Test with wrong message
    let wrong_message = b"wrong message";
    let is_valid_wrong = signer.verify_message(wrong_message, &signature, &public_key).unwrap();
    assert!(!is_valid_wrong);
    
    // Test with wrong public key
    let wrong_private_key = CryptoUtils::generate_private_key().unwrap();
    let wrong_public_key = CryptoUtils::derive_public_key(&wrong_private_key);
    let is_valid_wrong_key = signer.verify_message(message, &signature, &wrong_public_key).unwrap();
    assert!(!is_valid_wrong_key);
}

#[test]
fn test_message_signing_hash_direct() {
    let signer = MessageSigning::new();
    let private_key = CryptoUtils::generate_private_key().unwrap();
    let public_key = CryptoUtils::derive_public_key(&private_key);
    let hash = Hash::sha256(b"test message");
    
    // Test hash signing and verification
    let signature = signer.sign_hash(&hash, &private_key).unwrap();
    let is_valid = signer.verify_hash(&hash, &signature, &public_key).unwrap();
    assert!(is_valid);
    
    // Test with wrong hash
    let wrong_hash = Hash::sha256(b"wrong message");
    let is_valid_wrong = signer.verify_hash(&wrong_hash, &signature, &public_key).unwrap();
    assert!(!is_valid_wrong);
}

#[test]
fn test_message_signing_empty_message() {
    let signer = MessageSigning::new();
    let private_key = CryptoUtils::generate_private_key().unwrap();
    let public_key = CryptoUtils::derive_public_key(&private_key);
    let empty_message = b"";
    
    let signature = signer.sign_message(empty_message, &private_key).unwrap();
    let is_valid = signer.verify_message(empty_message, &signature, &public_key).unwrap();
    assert!(is_valid);
}

#[test]
fn test_constant_time_eq() {
    let a = [1, 2, 3, 4];
    let b = [1, 2, 3, 4];
    let c = [1, 2, 3, 5];
    let d = [1, 2, 3]; // Different length
    
    // Test equal arrays
    assert!(ConstantTime::eq_arrays(&a, &b));
    
    // Test different arrays
    assert!(!ConstantTime::eq_arrays(&a, &c));
    
    // Test slices
    assert!(ConstantTime::eq(&a, &b));
    assert!(!ConstantTime::eq(&a, &c));
    assert!(!ConstantTime::eq(&a, &d)); // Different lengths
}

#[test]
fn test_constant_time_select() {
    let if_true = 0xFF;
    let if_false = 0x00;
    
    assert_eq!(ConstantTime::select(true, if_true, if_false), if_true);
    assert_eq!(ConstantTime::select(false, if_true, if_false), if_false);
}

#[test]
fn test_constant_time_select_bytes() {
    let if_true = [1, 2, 3, 4];
    let if_false = [5, 6, 7, 8];
    
    let result_true = ConstantTime::select_bytes(true, &if_true, &if_false);
    assert_eq!(result_true, if_true);
    
    let result_false = ConstantTime::select_bytes(false, &if_true, &if_false);
    assert_eq!(result_false, if_false);
}

#[test]
#[should_panic]
fn test_constant_time_select_bytes_different_lengths() {
    let if_true = [1, 2, 3];
    let if_false = [5, 6, 7, 8];
    
    // Should panic due to different lengths
    ConstantTime::select_bytes(true, &if_true, &if_false);
}

#[test]
fn test_crypto_utils_generate_private_key() {
    let key1 = CryptoUtils::generate_private_key().unwrap();
    let key2 = CryptoUtils::generate_private_key().unwrap();
    
    // Keys should be different
    assert_ne!(key1.secret_bytes(), key2.secret_bytes());
    
    // Keys should be valid
    assert_eq!(key1.secret_bytes().len(), 32);
    assert_eq!(key2.secret_bytes().len(), 32);
}

#[test]
fn test_crypto_utils_derive_public_key() {
    let private_key = CryptoUtils::generate_private_key().unwrap();
    let public_key = CryptoUtils::derive_public_key(&private_key);
    
    // Public key should be valid
    assert!(public_key.serialize().len() == 33 || public_key.serialize().len() == 65);
    
    // Same private key should produce same public key
    let public_key2 = CryptoUtils::derive_public_key(&private_key);
    assert_eq!(public_key, public_key2);
}

#[test]
fn test_crypto_utils_hex_conversion() {
    let data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
    let hex_str = CryptoUtils::bytes_to_hex(&data);
    assert_eq!(hex_str, "0123456789abcdef");
    
    let decoded = CryptoUtils::hex_to_bytes(&hex_str).unwrap();
    assert_eq!(decoded, data);
    
    // Test uppercase hex
    let uppercase_hex = "0123456789ABCDEF";
    let decoded_upper = CryptoUtils::hex_to_bytes(uppercase_hex).unwrap();
    assert_eq!(decoded_upper, data);
}

#[test]
fn test_crypto_utils_hex_conversion_errors() {
    // Invalid hex characters
    assert!(CryptoUtils::hex_to_bytes("invalid").is_err());
    assert!(CryptoUtils::hex_to_bytes("0123456789abcdeg").is_err());
    
    // Odd length hex string
    assert!(CryptoUtils::hex_to_bytes("123").is_err());
}

#[test]
fn test_crypto_utils_validate_private_key() {
    // Valid private key
    let valid_key = [1u8; 32];
    assert!(CryptoUtils::validate_private_key(&valid_key).is_ok());
    
    // Invalid length
    let short_key = [1u8; 31];
    assert!(CryptoUtils::validate_private_key(&short_key).is_err());
    
    let long_key = [1u8; 33];
    assert!(CryptoUtils::validate_private_key(&long_key).is_err());
    
    // Zero key (invalid)
    let zero_key = [0u8; 32];
    assert!(CryptoUtils::validate_private_key(&zero_key).is_err());
    
    // Maximum valid key
    let mut max_key = [0xFFu8; 32];
    max_key[0] = 0xFF;
    max_key[1] = 0xFF;
    max_key[2] = 0xFF;
    max_key[3] = 0xFF;
    max_key[4] = 0xFF;
    max_key[5] = 0xFF;
    max_key[6] = 0xFF;
    max_key[7] = 0xFF;
    max_key[8] = 0xFF;
    max_key[9] = 0xFF;
    max_key[10] = 0xFF;
    max_key[11] = 0xFF;
    max_key[12] = 0xFF;
    max_key[13] = 0xFF;
    max_key[14] = 0xFF;
    max_key[15] = 0xFE;
    max_key[16] = 0xFF;
    max_key[17] = 0xFF;
    max_key[18] = 0xFF;
    max_key[19] = 0xFF;
    max_key[20] = 0xFF;
    max_key[21] = 0xFF;
    max_key[22] = 0xFF;
    max_key[23] = 0xFF;
    max_key[24] = 0xFF;
    max_key[25] = 0xFF;
    max_key[26] = 0xFF;
    max_key[27] = 0xFF;
    max_key[28] = 0xFF;
    max_key[29] = 0xFF;
    max_key[30] = 0xFF;
    max_key[31] = 0xFF;
    // This is larger than the secp256k1 curve order, so should be invalid
    assert!(CryptoUtils::validate_private_key(&max_key).is_err());
}

#[test]
fn test_crypto_utils_validate_public_key() {
    let private_key = CryptoUtils::generate_private_key().unwrap();
    let public_key = CryptoUtils::derive_public_key(&private_key);
    
    // Valid compressed public key
    let compressed_bytes = public_key.serialize();
    assert!(CryptoUtils::validate_public_key(&compressed_bytes).is_ok());
    
    // Valid uncompressed public key
    let uncompressed_bytes = public_key.serialize_uncompressed();
    assert!(CryptoUtils::validate_public_key(&uncompressed_bytes).is_ok());
    
    // Invalid length
    let short_key = [1u8; 32];
    assert!(CryptoUtils::validate_public_key(&short_key).is_err());
    
    // Invalid format
    let invalid_key = [0u8; 33];
    assert!(CryptoUtils::validate_public_key(&invalid_key).is_err());
}

#[test]
fn test_crypto_utils_secure_zero() {
    let mut data = vec![1, 2, 3, 4, 5];
    CryptoUtils::secure_zero(&mut data);
    assert_eq!(data, vec![0, 0, 0, 0, 0]);
    
    // Test empty slice
    let mut empty_data: Vec<u8> = vec![];
    CryptoUtils::secure_zero(&mut empty_data);
    assert_eq!(empty_data, vec![]);
}

#[test]
fn test_secure_string_basic() {
    let secure_str = SecureString::from_string("secret".to_string());
    
    assert_eq!(secure_str.len(), 6);
    assert!(!secure_str.is_empty());
    assert_eq!(secure_str.as_str().unwrap(), "secret");
    assert_eq!(secure_str.as_bytes(), b"secret");
}

#[test]
fn test_secure_string_from_bytes() {
    let bytes = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
    let secure_str = SecureString::from_bytes(bytes);
    
    assert_eq!(secure_str.len(), 5);
    assert_eq!(secure_str.as_str().unwrap(), "Hello");
}

#[test]
fn test_secure_string_empty() {
    let secure_str = SecureString::from_string("".to_string());
    
    assert_eq!(secure_str.len(), 0);
    assert!(secure_str.is_empty());
    assert_eq!(secure_str.as_str().unwrap(), "");
}

#[test]
fn test_secure_string_invalid_utf8() {
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let secure_str = SecureString::from_bytes(invalid_utf8);
    
    assert!(secure_str.as_str().is_err());
}

#[test]
fn test_secure_string_debug() {
    let secure_str = SecureString::from_string("secret".to_string());
    let debug_str = format!("{:?}", secure_str);
    
    // Should not contain the actual secret
    assert!(!debug_str.contains("secret"));
    assert!(debug_str.contains("REDACTED"));
}

// Edge case and error condition tests

#[test]
fn test_hash_functions_large_input() {
    let large_data = vec![0x42; 1_000_000]; // 1MB of data
    
    let sha256_hash = Hash::sha256(&large_data);
    assert_eq!(sha256_hash.len(), 32);
    
    let sha512_hash = Hash::sha512(&large_data);
    assert_eq!(sha512_hash.len(), 64);
    
    let ripemd160_hash = Hash::ripemd160(&large_data);
    assert_eq!(ripemd160_hash.len(), 20);
}

#[test]
fn test_pbkdf2_edge_cases() {
    let password = b"password";
    let salt = b"salt";
    
    // Test with 1 iteration (minimum)
    let key_min = KeyDerivation::pbkdf2_sha256(password, salt, 1, 32);
    assert_eq!(key_min.len(), 32);
    
    // Test with very high iterations
    let key_high = KeyDerivation::pbkdf2_sha256(password, salt, 1_000_000, 32);
    assert_eq!(key_high.len(), 32);
    assert_ne!(key_min, key_high);
    
    // Test with very long output
    let long_key = KeyDerivation::pbkdf2_sha256(password, salt, 1000, 1024);
    assert_eq!(long_key.len(), 1024);
}

#[test]
fn test_message_signing_deterministic() {
    let signer = MessageSigning::new();
    
    // Use a known private key for deterministic testing
    let private_key_bytes = [1u8; 32];
    let private_key = SecretKey::from_slice(&private_key_bytes).unwrap();
    let public_key = CryptoUtils::derive_public_key(&private_key);
    let message = b"deterministic test";
    
    // Sign the same message multiple times
    let sig1 = signer.sign_message(message, &private_key).unwrap();
    let sig2 = signer.sign_message(message, &private_key).unwrap();
    
    // Signatures should be the same (deterministic)
    assert_eq!(sig1, sig2);
    
    // Both should verify
    assert!(signer.verify_message(message, &sig1, &public_key).unwrap());
    assert!(signer.verify_message(message, &sig2, &public_key).unwrap());
}

#[test]
fn test_constant_time_operations_timing() {
    // This test ensures constant-time operations don't leak timing information
    // In practice, this would require more sophisticated timing analysis
    
    let a = [0x00; 32];
    let b = [0x00; 32];
    let c = [0xFF; 32];
    
    // These operations should take the same time regardless of input
    assert!(ConstantTime::eq_arrays(&a, &b));
    assert!(!ConstantTime::eq_arrays(&a, &c));
    
    // Test with different positions of differences
    let mut d = [0x00; 32];
    d[0] = 0xFF; // Difference at start
    assert!(!ConstantTime::eq_arrays(&a, &d));
    
    let mut e = [0x00; 32];
    e[31] = 0xFF; // Difference at end
    assert!(!ConstantTime::eq_arrays(&a, &e));
}

#[test]
fn test_rng_distribution() {
    let mut rng = SecureRng::new();
    let mut counts = [0u32; 256];
    
    // Generate many random bytes and check distribution
    for _ in 0..10000 {
        let byte = rng.random_bytes(1)[0];
        counts[byte as usize] += 1;
    }
    
    // Check that all values appear (with high probability)
    let zeros = counts.iter().filter(|&&count| count == 0).count();
    assert!(zeros < 50, "Too many unused byte values: {}", zeros);
    
    // Check that distribution is roughly uniform
    let avg = 10000.0 / 256.0;
    let max_deviation = counts.iter().map(|&count| (count as f64 - avg).abs()).fold(0.0, f64::max);
    assert!(max_deviation < avg * 0.5, "Distribution too skewed: max deviation {}", max_deviation);
}

#[test]
fn test_key_derivation_consistency_across_calls() {
    let password = b"test_password";
    let salt = b"test_salt";
    
    // Multiple calls should produce identical results
    for _ in 0..10 {
        let key1 = KeyDerivation::derive_key(password, salt);
        let key2 = KeyDerivation::derive_key(password, salt);
        assert_eq!(key1, key2);
    }
}

#[test]
fn test_hmac_key_sizes() {
    let data = b"test data";
    
    // Test with various key sizes
    let small_key = b"key";
    let normal_key = b"this is a normal sized key for testing";
    let large_key = vec![0x42; 1000]; // Very large key
    
    let hmac1 = Hash::hmac_sha256(small_key, data).unwrap();
    let hmac2 = Hash::hmac_sha256(normal_key, data).unwrap();
    let hmac3 = Hash::hmac_sha256(&large_key, data).unwrap();
    
    assert_eq!(hmac1.len(), 32);
    assert_eq!(hmac2.len(), 32);
    assert_eq!(hmac3.len(), 32);
    
    // All should be different
    assert_ne!(hmac1, hmac2);
    assert_ne!(hmac2, hmac3);
    assert_ne!(hmac1, hmac3);
}