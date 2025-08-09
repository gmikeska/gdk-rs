//! General utility functions for GDK.

use crate::Result;
// use crate::bip39::{Mnemonic}; // Will use this once implemented

/// Generates a new 24-word BIP39 mnemonic.
/// Corresponds to GA_generate_mnemonic.
pub fn generate_mnemonic() -> Result<String> {
    // Placeholder implementation
    Ok("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string())
}

/// Validates a BIP39 mnemonic.
/// Corresponds to GA_validate_mnemonic.
pub fn validate_mnemonic(mnemonic_str: &str) -> Result<bool> {
    // Placeholder implementation
    Ok(!mnemonic_str.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic().unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12); // Placeholder returns 12 words
    }
}
