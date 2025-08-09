//! Tests for the simplified wallet subaccount management system

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_simple::{Wallet, SubaccountType, Subaccount};
    use crate::primitives::address::Network;

    #[test]
    fn test_subaccount_type_properties() {
        // Test Legacy subaccount type
        let legacy = SubaccountType::Legacy;
        assert_eq!(legacy.purpose(), 44);
        assert_eq!(legacy.coin_type(Network::Mainnet), 0);
        assert_eq!(legacy.coin_type(Network::Testnet), 1);
        assert_eq!(legacy.name(), "Legacy");

        // Test SegWit wrapped subaccount type
        let segwit_wrapped = SubaccountType::SegwitWrapped;
        assert_eq!(segwit_wrapped.purpose(), 49);
        assert_eq!(segwit_wrapped.coin_type(Network::Mainnet), 0);
        assert_eq!(segwit_wrapped.coin_type(Network::Testnet), 1);
        assert_eq!(segwit_wrapped.name(), "SegWit (wrapped)");

        // Test Native SegWit subaccount type
        let native_segwit = SubaccountType::NativeSegwit;
        assert_eq!(native_segwit.purpose(), 84);
        assert_eq!(native_segwit.coin_type(Network::Mainnet), 0);
        assert_eq!(native_segwit.coin_type(Network::Testnet), 1);
        assert_eq!(native_segwit.name(), "Native SegWit");
    }

    #[test]
    fn test_subaccount_base_path() {
        let legacy = SubaccountType::Legacy;
        let path = legacy.base_path(Network::Mainnet, 0);
        
        // Should be m/44'/0'/0'
        let expected_path = vec![
            crate::primitives::bip32::DerivationPath::hardened(44),
            crate::primitives::bip32::DerivationPath::hardened(0),
            crate::primitives::bip32::DerivationPath::hardened(0),
        ];
        assert_eq!(path.path(), &expected_path);
    }

    #[test]
    fn test_wallet_creation_from_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet);
        assert!(wallet.is_ok());
        
        let wallet = wallet.unwrap();
        let identifier = wallet.get_wallet_identifier();
        assert!(!identifier.is_empty());
        assert_eq!(identifier.len(), 8); // 4 bytes = 8 hex chars
        
        let master_xpub = wallet.get_master_xpub();
        assert!(master_xpub.starts_with("tpub")); // Testnet extended public key
    }

    #[test]
    fn test_subaccount_creation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        // Create a legacy subaccount
        let subaccount_id = wallet.create_subaccount(
            "Main Account".to_string(),
            SubaccountType::Legacy,
        ).unwrap();
        
        assert_eq!(subaccount_id, 0); // First subaccount should have ID 0
        
        // Create a SegWit subaccount
        let subaccount_id2 = wallet.create_subaccount(
            "SegWit Account".to_string(),
            SubaccountType::NativeSegwit,
        ).unwrap();
        
        assert_eq!(subaccount_id2, 1); // Second subaccount should have ID 1
    }

    #[test]
    fn test_subaccount_retrieval() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        // Create subaccounts
        let id1 = wallet.create_subaccount("Account 1".to_string(), SubaccountType::Legacy).unwrap();
        let id2 = wallet.create_subaccount("Account 2".to_string(), SubaccountType::NativeSegwit).unwrap();
        
        // Test get_subaccount
        let subaccount1 = wallet.get_subaccount(id1).unwrap();
        assert_eq!(subaccount1.name, "Account 1");
        assert_eq!(subaccount1.subaccount_type, SubaccountType::Legacy);
        assert_eq!(subaccount1.network, Network::Testnet);
        assert!(!subaccount1.hidden);
        assert_eq!(subaccount1.gap_limit, 20);
        
        let subaccount2 = wallet.get_subaccount(id2).unwrap();
        assert_eq!(subaccount2.name, "Account 2");
        assert_eq!(subaccount2.subaccount_type, SubaccountType::NativeSegwit);
        
        // Test get_subaccounts
        let all_subaccounts = wallet.get_subaccounts();
        assert_eq!(all_subaccounts.len(), 2);
        
        // Test non-existent subaccount
        let non_existent = wallet.get_subaccount(999);
        assert!(non_existent.is_none());
    }

    #[test]
    fn test_subaccount_updates() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Original Name".to_string(), SubaccountType::Legacy).unwrap();
        
        // Update name
        wallet.update_subaccount(subaccount_id, Some("Updated Name".to_string()), None).unwrap();
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert_eq!(subaccount.name, "Updated Name");
        assert!(!subaccount.hidden); // Should remain unchanged
        
        // Update hidden status
        wallet.update_subaccount(subaccount_id, None, Some(true)).unwrap();
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert_eq!(subaccount.name, "Updated Name"); // Should remain unchanged
        assert!(subaccount.hidden);
        
        // Update both
        wallet.update_subaccount(subaccount_id, Some("Final Name".to_string()), Some(false)).unwrap();
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert_eq!(subaccount.name, "Final Name");
        assert!(!subaccount.hidden);
        
        // Test updating non-existent subaccount
        let result = wallet.update_subaccount(999, Some("Test".to_string()), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_subaccount_balance_updates() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Initial balance should be zero
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert_eq!(subaccount.balance.confirmed, 0);
        assert_eq!(subaccount.balance.unconfirmed, 0);
        assert_eq!(subaccount.balance.total, 0);
        assert_eq!(subaccount.balance.utxo_count, 0);
        assert!(subaccount.last_sync.is_none());
        
        // Update balance
        wallet.update_subaccount_balance(subaccount_id, 100000, 50000, 5).unwrap();
        
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert_eq!(subaccount.balance.confirmed, 100000);
        assert_eq!(subaccount.balance.unconfirmed, 50000);
        assert_eq!(subaccount.balance.total, 150000);
        assert_eq!(subaccount.balance.utxo_count, 5);
        assert!(subaccount.last_sync.is_some());
        
        // Test updating non-existent subaccount
        let result = wallet.update_subaccount_balance(999, 0, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_subaccount_synchronization() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Initial state should have no sync timestamp
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert!(subaccount.last_sync.is_none());
        
        // Sync subaccount
        wallet.sync_subaccount(subaccount_id).unwrap();
        
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert!(subaccount.last_sync.is_some());
        
        // Test syncing non-existent subaccount
        let result = wallet.sync_subaccount(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_subaccount_address_path() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        
        // Test receiving address path (m/44'/1'/0'/0/0)
        let receive_path = subaccount.address_path(false, 0);
        let expected_receive = vec![
            crate::primitives::bip32::DerivationPath::hardened(44), // purpose
            crate::primitives::bip32::DerivationPath::hardened(1),  // coin_type (testnet)
            crate::primitives::bip32::DerivationPath::hardened(0),  // account
            0, // change (external)
            0, // address_index
        ];
        assert_eq!(receive_path.path(), &expected_receive);
        
        // Test change address path (m/44'/1'/0'/1/5)
        let change_path = subaccount.address_path(true, 5);
        let expected_change = vec![
            crate::primitives::bip32::DerivationPath::hardened(44), // purpose
            crate::primitives::bip32::DerivationPath::hardened(1),  // coin_type (testnet)
            crate::primitives::bip32::DerivationPath::hardened(0),  // account
            1, // change (internal)
            5, // address_index
        ];
        assert_eq!(change_path.path(), &expected_change);
    }

    #[test]
    fn test_subaccount_serialization() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::NativeSegwit).unwrap();
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        
        // Test serialization to JSON
        let json = serde_json::to_string(&subaccount).unwrap();
        assert!(json.contains("Test Account"));
        assert!(json.contains("p2wpkh")); // SubaccountType::NativeSegwit serializes to "p2wpkh"
        
        // Test deserialization from JSON
        let deserialized: Subaccount = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, subaccount.id);
        assert_eq!(deserialized.name, subaccount.name);
        assert_eq!(deserialized.subaccount_type, subaccount.subaccount_type);
        assert_eq!(deserialized.network, subaccount.network);
        assert_eq!(deserialized.extended_pubkey, subaccount.extended_pubkey);
    }

    #[test]
    fn test_multiple_subaccount_types() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Mainnet).unwrap();
        
        // Create one of each subaccount type
        let legacy_id = wallet.create_subaccount("Legacy".to_string(), SubaccountType::Legacy).unwrap();
        let wrapped_id = wallet.create_subaccount("Wrapped".to_string(), SubaccountType::SegwitWrapped).unwrap();
        let native_id = wallet.create_subaccount("Native".to_string(), SubaccountType::NativeSegwit).unwrap();
        
        let subaccounts = wallet.get_subaccounts();
        assert_eq!(subaccounts.len(), 3);
        
        // Verify each subaccount has the correct type and derivation path
        let legacy = wallet.get_subaccount(legacy_id).unwrap();
        let legacy_path = legacy.address_path(false, 0);
        assert_eq!(legacy_path.path()[0], crate::primitives::bip32::DerivationPath::hardened(44));
        
        let wrapped = wallet.get_subaccount(wrapped_id).unwrap();
        let wrapped_path = wrapped.address_path(false, 0);
        assert_eq!(wrapped_path.path()[0], crate::primitives::bip32::DerivationPath::hardened(49));
        
        let native = wallet.get_subaccount(native_id).unwrap();
        let native_path = native.address_path(false, 0);
        assert_eq!(native_path.path()[0], crate::primitives::bip32::DerivationPath::hardened(84));
    }
}