//! Simple tests for script functionality

use gdk_rs::primitives::script::*;

    #[test]
    fn test_basic_script_execution() {
        // Test simple push and verify
        let script = Script(vec![0x01, 0x01, 0x69]); // Push 1, OP_VERIFY
        let mut stack = vec![];
        let result = script.execute(&mut stack, None);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_script_patterns() {
        let hash160 = [0x12; 20];
        let hash256 = [0x34; 32];
        
        let p2pkh = Script::new_p2pkh(&hash160);
        assert!(p2pkh.is_p2pkh());
        assert!(!p2pkh.is_p2sh());
        
        let p2sh = Script::new_p2sh(&hash160);
        assert!(p2sh.is_p2sh());
        assert!(!p2sh.is_p2pkh());
        
        let p2wpkh = Script::new_p2wpkh(&hash160);
        assert!(p2wpkh.is_p2wpkh());
        
        let p2wsh = Script::new_p2wsh(&hash256);
        assert!(p2wsh.is_p2wsh());
    }

    #[test]
    fn test_script_validation() {
        let valid_script = Script::new_p2pkh(&[0x12; 20]);
        assert!(valid_script.validate().is_ok());
        
        // Test script too large
        let large_script = Script(vec![0; 10001]);
        assert!(large_script.validate().is_err());
    }

    #[test]
    fn test_signature_verification() {
        let script = Script::new();
        
        // Test with valid-looking inputs
        let mut signature = vec![0x30, 0x44]; // DER prefix
        signature.extend_from_slice(&[0x12; 66]); // Valid length signature
        let mut pubkey = vec![0x02]; // Compressed pubkey
        pubkey.extend_from_slice(&[0x34; 32]);
        let message_hash = [0x56; 32];
        
        let result = script.verify_signature(&signature, &pubkey, &message_hash);
        assert!(result.is_ok());
        assert!(result.unwrap());
        
        // Test with invalid inputs
        let result = script.verify_signature(&[], &pubkey, &message_hash);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
