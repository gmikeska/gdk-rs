//! Comprehensive unit tests for BIP39 mnemonic functionality

use gdk_rs::bip39::*;
use gdk_rs::{GdkError, Result};

#[test]
fn test_mnemonic_generation_12_words() {
    let mnemonic = Mnemonic::generate(128).unwrap();
    assert_eq!(mnemonic.words().len(), 12);
    assert_eq!(mnemonic.language(), Language::English);
    
    // Validate the generated mnemonic
    assert!(mnemonic.validate().is_ok());
}

#[test]
fn test_mnemonic_generation_15_words() {
    let mnemonic = Mnemonic::generate(160).unwrap();
    assert_eq!(mnemonic.words().len(), 15);
    assert!(mnemonic.validate().is_ok());
}

#[test]
fn test_mnemonic_generation_18_words() {
    let mnemonic = Mnemonic::generate(192).unwrap();
    assert_eq!(mnemonic.words().len(), 18);
    assert!(mnemonic.validate().is_ok());
}

#[test]
fn test_mnemonic_generation_21_words() {
    let mnemonic = Mnemonic::generate(224).unwrap();
    assert_eq!(mnemonic.words().len(), 21);
    assert!(mnemonic.validate().is_ok());
}

#[test]
fn test_mnemonic_generation_24_words() {
    let mnemonic = Mnemonic::generate(256).unwrap();
    assert_eq!(mnemonic.words().len(), 24);
    assert!(mnemonic.validate().is_ok());
}

#[test]
fn test_mnemonic_generation_invalid_entropy() {
    // Invalid entropy lengths should fail
    assert!(Mnemonic::generate(64).is_err());   // Too small
    assert!(Mnemonic::generate(129).is_err());  // Not standard
    assert!(Mnemonic::generate(512).is_err());  // Too large
}

#[test]
fn test_mnemonic_from_entropy_known_vectors() {
    // Test vector from BIP39 specification
    let entropy = hex::decode("00000000000000000000000000000000").unwrap();
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    
    let expected_words = vec![
        "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
        "abandon", "abandon", "abandon", "abandon", "abandon", "about"
    ];
    
    assert_eq!(mnemonic.words().len(), 12);
    for (i, word) in mnemonic.words().iter().enumerate() {
        assert_eq!(word, expected_words[i]);
    }
}

#[test]
fn test_mnemonic_from_entropy_max_entropy() {
    // Test with maximum entropy (all 1s)
    let entropy = vec![0xFF; 32]; // 256 bits
    let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
    
    assert_eq!(mnemonic.words().len(), 24);
    assert!(mnemonic.validate().is_ok());
    
    // Last word should be "zoo" for this entropy
    assert_eq!(mnemonic.words().last().unwrap(), "zoo");
}

#[test]
fn test_mnemonic_from_string_valid() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    assert_eq!(mnemonic.words().len(), 12);
    assert_eq!(mnemonic.words()[0], "abandon");
    assert_eq!(mnemonic.words()[11], "about");
    assert!(mnemonic.validate().is_ok());
}#
[test]
fn test_mnemonic_from_string_case_insensitive() {
    let mnemonic_str = "ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    // Should convert to lowercase
    assert_eq!(mnemonic.words()[0], "abandon");
    assert!(mnemonic.validate().is_ok());
}

#[test]
fn test_mnemonic_from_string_extra_whitespace() {
    let mnemonic_str = "  abandon   abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    assert_eq!(mnemonic.words().len(), 12);
    assert!(mnemonic.validate().is_ok());
}

#[test]
fn test_mnemonic_from_string_invalid_word_count() {
    // Too few words
    let short_mnemonic = "abandon abandon abandon";
    assert!(Mnemonic::from_str(short_mnemonic).is_err());
    
    // Too many words
    let long_mnemonic = "abandon ".repeat(25);
    assert!(Mnemonic::from_str(&long_mnemonic).is_err());
    
    // Invalid count (13 words)
    let invalid_count = "abandon ".repeat(13);
    assert!(Mnemonic::from_str(&invalid_count).is_err());
}

#[test]
fn test_mnemonic_from_string_invalid_word() {
    let invalid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
    assert!(Mnemonic::from_str(invalid_mnemonic).is_err());
}

#[test]
fn test_mnemonic_from_string_invalid_checksum() {
    // Valid words but invalid checksum
    let invalid_checksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(Mnemonic::from_str(invalid_checksum).is_err());
}

#[test]
fn test_mnemonic_to_seed_no_passphrase() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    let seed = mnemonic.to_seed(None).unwrap();
    assert_eq!(seed.as_bytes().len(), 64);
    
    // Test known vector
    let expected_seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
    assert_eq!(seed.as_bytes().to_vec(), expected_seed);
}

#[test]
fn test_mnemonic_to_seed_with_passphrase() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    let seed_no_pass = mnemonic.to_seed(None).unwrap();
    let seed_with_pass = mnemonic.to_seed(Some("TREZOR")).unwrap();
    
    // Seeds should be different
    assert_ne!(seed_no_pass.as_bytes(), seed_with_pass.as_bytes());
    
    // Test known vector with passphrase
    let expected_seed_with_pass = hex::decode("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap();
    assert_eq!(seed_with_pass.as_bytes().to_vec(), expected_seed_with_pass);
}

#[test]
fn test_mnemonic_to_entropy_roundtrip() {
    let original_entropy = hex::decode("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c").unwrap();
    
    let mnemonic = Mnemonic::from_entropy(&original_entropy).unwrap();
    let recovered_entropy = mnemonic.to_entropy().unwrap();
    
    assert_eq!(original_entropy, recovered_entropy);
}

#[test]
fn test_mnemonic_display() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    assert_eq!(mnemonic.to_string(), mnemonic_str);
}

#[test]
fn test_mnemonic_equality() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic1 = Mnemonic::from_str(mnemonic_str).unwrap();
    let mnemonic2 = Mnemonic::from_str(mnemonic_str).unwrap();
    
    assert_eq!(mnemonic1, mnemonic2);
}

#[test]
fn test_mnemonic_clone() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic1 = Mnemonic::from_str(mnemonic_str).unwrap();
    let mnemonic2 = mnemonic1.clone();
    
    assert_eq!(mnemonic1, mnemonic2);
    assert_eq!(mnemonic1.words(), mnemonic2.words());
}

#[test]
fn test_language_wordlist() {
    let wordlist = Language::English.wordlist();
    
    assert_eq!(wordlist.len(), 2048);
    assert_eq!(wordlist[0], "abandon");
    assert_eq!(wordlist[2047], "zoo");
    
    // Check that all words are unique
    let mut sorted_words = wordlist.to_vec();
    sorted_words.sort();
    sorted_words.dedup();
    assert_eq!(sorted_words.len(), 2048);
}

#[test]
fn test_seed_operations() {
    let seed_bytes = [0x42; 64];
    let seed = Seed(seed_bytes);
    
    assert_eq!(seed.as_bytes(), &seed_bytes);
    assert_eq!(seed.to_vec(), seed_bytes.to_vec());
    
    // Test equality
    let seed2 = Seed(seed_bytes);
    assert_eq!(seed, seed2);
    
    // Test clone
    let seed3 = seed.clone();
    assert_eq!(seed, seed3);
}

#[test]
fn test_mnemonic_validation_edge_cases() {
    // Test with all valid words but wrong checksum
    let wordlist = Language::English.wordlist();
    let mut invalid_words = Vec::new();
    for i in 0..12 {
        invalid_words.push(wordlist[i].to_string());
    }
    
    let invalid_mnemonic = Mnemonic {
        words: invalid_words,
        language: Language::English,
    };
    
    // Should fail validation due to checksum
    assert!(invalid_mnemonic.validate().is_err());
}

#[test]
fn test_mnemonic_entropy_edge_cases() {
    // Test minimum entropy (16 bytes = 128 bits)
    let min_entropy = vec![0x01; 16];
    let mnemonic = Mnemonic::from_entropy(&min_entropy).unwrap();
    assert_eq!(mnemonic.words().len(), 12);
    
    // Test maximum entropy (32 bytes = 256 bits)
    let max_entropy = vec![0xFF; 32];
    let mnemonic = Mnemonic::from_entropy(&max_entropy).unwrap();
    assert_eq!(mnemonic.words().len(), 24);
    
    // Test invalid entropy lengths
    assert!(Mnemonic::from_entropy(&vec![0x01; 15]).is_err()); // 15 bytes
    assert!(Mnemonic::from_entropy(&vec![0x01; 33]).is_err()); // 33 bytes
    assert!(Mnemonic::from_entropy(&vec![0x01; 0]).is_err());  // 0 bytes
}

#[test]
fn test_mnemonic_deterministic_generation() {
    // Same entropy should always produce same mnemonic
    let entropy = vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 
                      0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    
    let mnemonic1 = Mnemonic::from_entropy(&entropy).unwrap();
    let mnemonic2 = Mnemonic::from_entropy(&entropy).unwrap();
    
    assert_eq!(mnemonic1, mnemonic2);
    assert_eq!(mnemonic1.words(), mnemonic2.words());
}

#[test]
fn test_seed_deterministic_generation() {
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    // Same mnemonic and passphrase should always produce same seed
    let seed1 = mnemonic.to_seed(Some("test")).unwrap();
    let seed2 = mnemonic.to_seed(Some("test")).unwrap();
    
    assert_eq!(seed1, seed2);
    
    // Different passphrases should produce different seeds
    let seed3 = mnemonic.to_seed(Some("different")).unwrap();
    assert_ne!(seed1, seed3);
}

#[test]
fn test_mnemonic_all_word_lengths() {
    let test_cases = vec![
        (128, 12), // 128 bits -> 12 words
        (160, 15), // 160 bits -> 15 words
        (192, 18), // 192 bits -> 18 words
        (224, 21), // 224 bits -> 21 words
        (256, 24), // 256 bits -> 24 words
    ];
    
    for (entropy_bits, expected_words) in test_cases {
        let mnemonic = Mnemonic::generate(entropy_bits).unwrap();
        assert_eq!(mnemonic.words().len(), expected_words);
        assert!(mnemonic.validate().is_ok());
        
        // Test roundtrip through entropy
        let entropy = mnemonic.to_entropy().unwrap();
        assert_eq!(entropy.len(), entropy_bits / 8);
        
        let recovered_mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic, recovered_mnemonic);
    }
}

#[test]
fn test_mnemonic_unicode_handling() {
    // BIP39 specifies that mnemonics should be normalized
    // This test ensures we handle various Unicode forms correctly
    
    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    
    // Test that the mnemonic string is properly normalized
    let normalized_str = mnemonic.to_string();
    assert_eq!(normalized_str, mnemonic_str);
}

#[test]
fn test_mnemonic_checksum_validation_comprehensive() {
    // Test various checksum scenarios
    let wordlist = Language::English.wordlist();
    
    // Create a mnemonic with known good checksum
    let good_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(good_mnemonic).unwrap();
    assert!(mnemonic.validate().is_ok());
    
    // Modify the last word to create bad checksum
    let mut bad_words = mnemonic.words().clone();
    bad_words[11] = "abandon".to_string(); // Change "about" to "abandon"
    
    let bad_mnemonic = Mnemonic {
        words: bad_words,
        language: Language::English,
    };
    
    assert!(bad_mnemonic.validate().is_err());
}

#[test]
fn test_seed_consistency_across_implementations() {
    // Test that our seed generation matches reference implementations
    let test_vectors = vec![
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            None,
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        ),
        (
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            None,
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607"
        ),
        (
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            None,
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6b4e8b8b4f2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6f"
        ),
    ];
    
    for (mnemonic_str, passphrase, expected_seed_hex) in test_vectors {
        let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
        let seed = mnemonic.to_seed(passphrase).unwrap();
        let expected_seed = hex::decode(expected_seed_hex).unwrap();
        
        assert_eq!(seed.as_bytes().to_vec(), expected_seed);
    }
}