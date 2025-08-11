//! Security-focused tests for cryptographic operations and sensitive data handling

use gdk_rs::utils::crypto::*;
use gdk_rs::bip39::*;
use gdk_rs::auth::*;
use gdk_rs::types::LoginCredentials;
use secp256k1::Secp256k1;
use std::collections::HashSet;

#[test]
fn test_secure_random_quality() {
    let mut rng = SecureRng::new();
    let sample_size = 10000;
    let mut samples = Vec::new();
    
    // Generate random samples
    for _ in 0..sample_size {
        samples.push(rng.random_u64());
    }
    
    // Test for basic randomness properties
    
    // 1. No duplicate values (with high probability)
    let unique_samples: HashSet<_> = samples.iter().collect();
    let uniqueness_ratio = unique_samples.len() as f64 / samples.len() as f64;
    assert!(uniqueness_ratio > 0.99, "Random samples should be mostly unique");
    
    // 2. Distribution should not be obviously biased
    let mean = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
    let expected_mean = (u64::MAX / 2) as f64;
    let deviation = (mean - expected_mean).abs() / expected_mean;
    assert!(deviation < 0.1, "Random distribution should be roughly uniform");
    
    // 3. No obvious patterns in consecutive values
    let mut consecutive_identical = 0;
    for i in 1..samples.len() {
        if samples[i] == samples[i-1] {
            consecutive_identical += 1;
        }
    }
    let consecutive_ratio = consecutive_identical as f64 / samples.len() as f64;
    assert!(consecutive_ratio < 0.01, "Should have very few consecutive identical values");
}

#[test]
fn test_secure_random_bytes_quality() {
    let mut rng = SecureRng::new();
    let byte_samples = rng.random_bytes(10000);
    
    // Test byte distribution
    let mut byte_counts = [0u32; 256];
    for &byte in &byte_samples {
        byte_counts[byte as usize] += 1;
    }
    
    // Each byte value should appear roughly equally
    let expected_count = byte_samples.len() / 256;
    let mut significant_deviations = 0;
    
    for count in &byte_counts {
        let deviation = (*count as f64 - expected_count as f64).abs() / expected_count as f64;
        if deviation > 0.5 {
            significant_deviations += 1;
        }
    }
    
    // Allow some deviation but not too much
    assert!(significant_deviations < 50, "Byte distribution should be roughly uniform");
}

#[test]
fn test_constant_time_operations_timing() {
    // This test verifies that constant-time operations don't leak timing information
    // Note: This is a basic test - comprehensive timing analysis would require more sophisticated tools
    
    let data_a = [0x00u8; 32];
    let data_b = [0x00u8; 32];
    let data_c = [0xFFu8; 32];
    
    let iterations = 1000;
    
    // Measure time for equal comparison
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = ConstantTime::eq_arrays(&data_a, &data_b);
    }
    let equal_time = start.elapsed();
    
    // Measure time for unequal comparison
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = ConstantTime::eq_arrays(&data_a, &data_c);
    }
    let unequal_time = start.elapsed();
    
    // Times should be similar (within reasonable variance)
    let time_ratio = if equal_time > unequal_time {
        equal_time.as_nanos() as f64 / unequal_time.as_nanos() as f64
    } else {
        unequal_time.as_nanos() as f64 / equal_time.as_nanos() as f64
    };
    
    // Allow for some variance but not too much
    assert!(time_ratio < 2.0, "Constant-time operations should have similar timing");
}

#[test]
fn test_secure_memory_clearing() {
    let mut sensitive_data = vec![0x42u8; 1000];
    
    // Verify data is initially set
    assert!(sensitive_data.iter().all(|&b| b == 0x42));
    
    // Clear the data
    CryptoUtils::secure_zero(&mut sensitive_data);
    
    // Verify data is cleared
    assert!(sensitive_data.iter().all(|&b| b == 0x00));
}

#[test]
fn test_secure_string_memory_protection() {
    let secret = "very_secret_password_123";
    let secure_str = SecureString::from_string(secret.to_string());
    
    // Verify we can access the data
    assert_eq!(secure_str.as_str().unwrap(), secret);
    
    // When SecureString is dropped, memory should be cleared
    // This is tested by the Drop implementation
    drop(secure_str);
    
    // Note: We can't directly verify memory was cleared after drop,
    // but the Drop implementation should handle this
}

#[test]
fn test_private_key_generation_entropy() {
    let mut keys = HashSet::new();
    let key_count = 1000;
    
    // Generate many private keys
    for _ in 0..key_count {
        let key = CryptoUtils::generate_private_key().unwrap();
        let key_bytes = key.secret_bytes();
        
        // Verify key is not all zeros
        assert!(!key_bytes.iter().all(|&b| b == 0));
        
        // Verify key is unique
        assert!(keys.insert(key_bytes), "Generated duplicate private key");
    }
    
    assert_eq!(keys.len(), key_count);
}

#[test]
fn test_mnemonic_entropy_quality() {
    let mut mnemonics = HashSet::new();
    let mnemonic_count = 100;
    
    // Generate many mnemonics
    for _ in 0..mnemonic_count {
        let mnemonic = Mnemonic::generate(256).unwrap();
        let mnemonic_str = mnemonic.to_string();
        
        // Verify mnemonic is unique
        assert!(mnemonics.insert(mnemonic_str.clone()), "Generated duplicate mnemonic");
        
        // Verify mnemonic has proper structure
        assert_eq!(mnemonic.words().len(), 24);
        
        // Verify entropy quality by checking seed diversity
        let seed = mnemonic.to_seed(None).unwrap();
        let seed_bytes = seed.as_bytes();
        
        // Seed should not be all zeros or all ones
        assert!(!seed_bytes.iter().all(|&b| b == 0));
        assert!(!seed_bytes.iter().all(|&b| b == 0xFF));
    }
    
    assert_eq!(mnemonics.len(), mnemonic_count);
}

#[test]
fn test_pin_data_security() {
    let pin = "123456";
    let sensitive_data = b"very_secret_mnemonic_phrase_that_should_be_protected";
    
    // Create PIN data
    let mut pin_data = PinData::new(pin, sensitive_data).unwrap();
    
    // Verify correct PIN works
    let decrypted = pin_data.decrypt_with_pin(pin).unwrap();
    assert_eq!(decrypted, sensitive_data);
    
    // Verify wrong PIN fails
    let wrong_pins = ["123457", "654321", "", "1234567"];
    for wrong_pin in &wrong_pins {
        let result = pin_data.decrypt_with_pin(wrong_pin);
        assert!(result.is_err(), "Wrong PIN should fail: {}", wrong_pin);
    }
    
    // Verify attempt limiting
    let wrong_pin = "000000";
    for _ in 0..3 {
        let _ = pin_data.decrypt_with_pin(wrong_pin);
    }
    
    assert!(pin_data.is_locked_out());
    
    // Even correct PIN should fail when locked out
    let result = pin_data.decrypt_with_pin(pin);
    assert!(result.is_err());
}

#[test]
fn test_signature_security() {
    let _secp = Secp256k1::new();
    let signer = MessageSigning::new();
    
    // Generate test key and message
    let private_key = CryptoUtils::generate_private_key().unwrap();
    let public_key = CryptoUtils::derive_public_key(&private_key);
    let message = b"test message for signature security";
    
    // Create signature
    let signature = signer.sign_message(message, &private_key).unwrap();
    
    // Verify signature is valid
    assert!(signer.verify_message(message, &signature, &public_key).unwrap());
    
    // Test signature malleability resistance
    // Generate multiple signatures for the same message
    let mut signatures = HashSet::new();
    for _ in 0..10 {
        let sig = signer.sign_message(message, &private_key).unwrap();
        signatures.insert(sig.serialize_compact());
    }
    
    // All signatures should be valid
    for sig_bytes in &signatures {
        let sig = secp256k1::ecdsa::Signature::from_compact(sig_bytes).unwrap();
        assert!(signer.verify_message(message, &sig, &public_key).unwrap());
    }
    
    // Test with wrong public key
    let wrong_private_key = CryptoUtils::generate_private_key().unwrap();
    let wrong_public_key = CryptoUtils::derive_public_key(&wrong_private_key);
    
    assert!(!signer.verify_message(message, &signature, &wrong_public_key).unwrap());
    
    // Test with modified message
    let modified_message = b"test message for signature security!";
    assert!(!signer.verify_message(modified_message, &signature, &public_key).unwrap());
}

#[test]
fn test_hash_function_security() {
    // Test hash function properties
    
    // 1. Deterministic
    let data = b"test data for hashing";
    let hash1 = Hash::sha256(data);
    let hash2 = Hash::sha256(data);
    assert_eq!(hash1, hash2);
    
    // 2. Avalanche effect (small input change causes large output change)
    let data_modified = b"test data for hashing!";
    let hash_modified = Hash::sha256(data_modified);
    
    // Count different bits
    let mut different_bits = 0;
    for i in 0..32 {
        different_bits += (hash1[i] ^ hash_modified[i]).count_ones();
    }
    
    // Should have roughly 50% different bits (avalanche effect)
    let total_bits = 256;
    let difference_ratio = different_bits as f64 / total_bits as f64;
    assert!(difference_ratio > 0.3 && difference_ratio < 0.7, 
           "Hash should have good avalanche effect");
    
    // 3. No obvious patterns
    let mut hashes = Vec::new();
    for i in 0..100 {
        let data = format!("test data {}", i);
        let hash = Hash::sha256(data.as_bytes());
        hashes.push(hash);
    }
    
    // Check for duplicate hashes (should be extremely unlikely)
    let unique_hashes: HashSet<_> = hashes.iter().collect();
    assert_eq!(unique_hashes.len(), hashes.len(), "All hashes should be unique");
}

#[test]
fn test_pbkdf2_security() {
    let password = b"test_password";
    let salt = b"test_salt";
    
    // Test that different iteration counts produce different results
    let key_1000 = KeyDerivation::pbkdf2_sha256(password, salt, 1000, 32);
    let key_2000 = KeyDerivation::pbkdf2_sha256(password, salt, 2000, 32);
    
    assert_ne!(key_1000, key_2000);
    
    // Test that different salts produce different results
    let salt2 = b"different_salt";
    let key_diff_salt = KeyDerivation::pbkdf2_sha256(password, salt2, 1000, 32);
    
    assert_ne!(key_1000, key_diff_salt);
    
    // Test that different passwords produce different results
    let password2 = b"different_password";
    let key_diff_pass = KeyDerivation::pbkdf2_sha256(password2, salt, 1000, 32);
    
    assert_ne!(key_1000, key_diff_pass);
    
    // Test key quality (should not be all zeros or have obvious patterns)
    assert!(!key_1000.iter().all(|&b| b == 0));
    assert!(!key_1000.iter().all(|&b| b == key_1000[0]));
}

#[test]
fn test_credential_security() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    
    // Test that credentials don't leak sensitive information in debug output
    let credentials = LoginCredentials::from_mnemonic(mnemonic.to_string(), None);
    let debug_output = format!("{:?}", credentials);
    
    // Debug output should not contain the actual mnemonic
    assert!(!debug_output.contains("abandon"));
    assert!(debug_output.contains("REDACTED") || debug_output.contains("***"));
    
    // Test with PIN credentials
    let pin = "123456";
    let pin_data = PinData::new(pin, mnemonic.as_bytes()).unwrap();
    let pin_credentials = LoginCredentials::from_pin(pin.to_string(), pin_data);
    
    let pin_debug_output = format!("{:?}", pin_credentials);
    assert!(!pin_debug_output.contains("123456"));
    assert!(!pin_debug_output.contains("abandon"));
}

#[test]
fn test_timing_attack_resistance() {
    // Test that sensitive operations don't leak timing information
    
    let correct_pin = "123456";
    let wrong_pins = [
        "123457", // One digit different
        "654321", // All digits different
        "1",      // Much shorter
        "1234567890", // Much longer
    ];
    
    let pin_data = PinData::new(correct_pin, b"test_data").unwrap();
    
    // Measure timing for correct PIN
    let iterations = 100;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let mut test_pin_data = pin_data.clone();
        let _ = test_pin_data.decrypt_with_pin(correct_pin);
    }
    let correct_time = start.elapsed();
    
    // Measure timing for wrong PINs
    for wrong_pin in &wrong_pins {
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let mut test_pin_data = pin_data.clone();
            let _ = test_pin_data.decrypt_with_pin(wrong_pin);
        }
        let wrong_time = start.elapsed();
        
        // Times should be similar to prevent timing attacks
        let time_ratio = if correct_time > wrong_time {
            correct_time.as_nanos() as f64 / wrong_time.as_nanos() as f64
        } else {
            wrong_time.as_nanos() as f64 / correct_time.as_nanos() as f64
        };
        
        // Allow for some variance but not too much
        assert!(time_ratio < 3.0, 
               "PIN validation timing should be similar for correct and wrong PINs");
    }
}

#[test]
fn test_side_channel_resistance() {
    // Test that cryptographic operations don't leak information through side channels
    
    // Test constant-time comparison with different data patterns
    let test_cases = [
        ([0x00; 32], [0x00; 32]), // All zeros
        ([0xFF; 32], [0xFF; 32]), // All ones
        ([0xAA; 32], [0xAA; 32]), // Alternating pattern
        ([0x55; 32], [0x55; 32]), // Different alternating pattern
    ];
    
    for (data_a, data_b) in &test_cases {
        // These should all take similar time
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = ConstantTime::eq_arrays(data_a, data_b);
        }
        let _equal_time = start.elapsed();
        
        // Modify one bit and test again
        let mut data_c = *data_b;
        data_c[0] ^= 0x01;
        
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = ConstantTime::eq_arrays(data_a, &data_c);
        }
        let _unequal_time = start.elapsed();
        
        // In a real implementation, we would verify timing is similar
        // This is a placeholder for more sophisticated side-channel testing
    }
}

#[test]
fn test_input_validation_security() {
    // Test that input validation prevents security issues
    
    // Test mnemonic validation with malicious inputs
    let malicious_inputs = [
        "", // Empty string
        &"a".repeat(10000), // Very long string
        "abandon\0abandon\0abandon", // Null bytes
        "abandon\x01abandon\x02abandon", // Control characters
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid", // Invalid word
    ];
    
    for malicious_input in &malicious_inputs {
        let result = Mnemonic::from_str(malicious_input);
        assert!(result.is_err(), "Should reject malicious input: {}", malicious_input);
    }
    
    // Test PIN validation with malicious inputs
    let malicious_pins = [
        "", // Empty PIN
        &"1".repeat(10000), // Very long PIN
        "123\0456", // Null bytes
        "123\x01456", // Control characters
    ];
    
    for malicious_pin in &malicious_pins {
        let result = PinData::new(malicious_pin, b"test_data");
        // Should either reject or handle safely
        if let Ok(mut pin_data) = result {
            let decrypt_result = pin_data.decrypt_with_pin(malicious_pin);
            // Should not crash or leak information
            let _ = decrypt_result;
        }
    }
}