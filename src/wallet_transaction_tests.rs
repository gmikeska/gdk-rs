//! Tests for transaction history and UTXO management functionality

#[cfg(test)]
mod tests {
    use crate::wallet_simple::{
        Wallet, SubaccountType, TransactionInfo, UtxoInfo, PaginationParams, 
        CoinSelectionStrategy, TransactionType, TransactionInput, TransactionOutput
    };
    use crate::primitives::address::Network;

    #[test]
    fn test_transaction_history_retrieval() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Test getting transactions with default pagination
        let transactions = wallet.get_transactions(subaccount_id, None).unwrap();
        assert_eq!(transactions.len(), 0); // Empty for new wallet
        
        // Test getting transactions with custom pagination
        let pagination = PaginationParams { limit: 10, offset: 0 };
        let transactions = wallet.get_transactions(subaccount_id, Some(pagination)).unwrap();
        assert_eq!(transactions.len(), 0);
        
        // Test with non-existent subaccount
        let result = wallet.get_transactions(999, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_transactions_retrieval() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        // Create multiple subaccounts
        let _id1 = wallet.create_subaccount("Account 1".to_string(), SubaccountType::Legacy).unwrap();
        let _id2 = wallet.create_subaccount("Account 2".to_string(), SubaccountType::NativeSegwit).unwrap();
        
        // Test getting all transactions
        let transactions = wallet.get_all_transactions(None).unwrap();
        assert_eq!(transactions.len(), 0); // Empty for new wallet
        
        // Test with pagination
        let pagination = PaginationParams { limit: 25, offset: 0 };
        let transactions = wallet.get_all_transactions(Some(pagination)).unwrap();
        assert_eq!(transactions.len(), 0);
    }

    #[test]
    fn test_transaction_details_retrieval() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        // Test getting details for non-existent transaction
        let details = wallet.get_transaction_details("nonexistent_txid").unwrap();
        assert!(details.is_none());
        
        // Test with empty txid
        let details = wallet.get_transaction_details("").unwrap();
        assert!(details.is_none());
    }

    #[test]
    fn test_utxo_retrieval() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Test getting UTXOs for subaccount
        let utxos = wallet.get_unspent_outputs(subaccount_id).unwrap();
        assert_eq!(utxos.len(), 0); // Empty for new wallet
        
        // Test getting all UTXOs
        let all_utxos = wallet.get_all_unspent_outputs().unwrap();
        assert_eq!(all_utxos.len(), 0);
        
        // Test with non-existent subaccount
        let result = wallet.get_unspent_outputs(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_utxo_status_management() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        // Test setting UTXO status with valid format
        let utxos = vec![
            "abcd1234:0".to_string(),
            "efgh5678:1".to_string(),
        ];
        let result = wallet.set_unspent_outputs_status(&utxos, true);
        assert!(result.is_ok());
        
        // Test unfreezing UTXOs
        let result = wallet.set_unspent_outputs_status(&utxos, false);
        assert!(result.is_ok());
        
        // Test with invalid UTXO format
        let invalid_utxos = vec!["invalid_format".to_string()];
        let result = wallet.set_unspent_outputs_status(&invalid_utxos, true);
        assert!(result.is_err());
        
        // Test with empty list
        let result = wallet.set_unspent_outputs_status(&[], true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_coin_selection_strategies() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Test all coin selection strategies with empty UTXO set
        let strategies = vec![
            CoinSelectionStrategy::BranchAndBound,
            CoinSelectionStrategy::Fifo,
            CoinSelectionStrategy::LargestFirst,
            CoinSelectionStrategy::SmallestFirst,
            CoinSelectionStrategy::Random,
        ];
        
        for strategy in strategies {
            let result = wallet.select_coins(subaccount_id, 100000, strategy);
            // Should fail with insufficient funds since no UTXOs exist
            assert!(result.is_err());
        }
        
        // Test with non-existent subaccount
        let result = wallet.select_coins(999, 100000, CoinSelectionStrategy::BranchAndBound);
        assert!(result.is_err());
    }

    #[test]
    fn test_balance_calculations() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Test total balance calculation (should be 0 for new wallet)
        let total_balance = wallet.calculate_total_balance().unwrap();
        assert_eq!(total_balance, 0);
        
        // Test subaccount balance calculation
        let subaccount_balance = wallet.calculate_subaccount_balance(subaccount_id).unwrap();
        assert_eq!(subaccount_balance, 0);
        
        // Test with non-existent subaccount
        let result = wallet.calculate_subaccount_balance(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_history_synchronization() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Test synchronizing transaction history
        let result = wallet.sync_transaction_history(subaccount_id);
        assert!(result.is_ok());
        
        // Verify subaccount was marked as synced
        let subaccount = wallet.get_subaccount(subaccount_id).unwrap();
        assert!(subaccount.last_sync.is_some());
        
        // Test with non-existent subaccount
        let result = wallet.sync_transaction_history(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_and_utxo_counts() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // Test transaction count (should be 0 for new wallet)
        let tx_count = wallet.get_transaction_count(subaccount_id).unwrap();
        assert_eq!(tx_count, 0);
        
        // Test UTXO count (should be 0 for new wallet)
        let utxo_count = wallet.get_utxo_count(subaccount_id).unwrap();
        assert_eq!(utxo_count, 0);
        
        // Test with non-existent subaccount
        let result = wallet.get_transaction_count(999);
        assert!(result.is_err());
        
        let result = wallet.get_utxo_count(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_pagination_params() {
        // Test default pagination parameters
        let default_pagination = PaginationParams::default();
        assert_eq!(default_pagination.limit, 50);
        assert_eq!(default_pagination.offset, 0);
        
        // Test custom pagination parameters
        let custom_pagination = PaginationParams { limit: 100, offset: 25 };
        assert_eq!(custom_pagination.limit, 100);
        assert_eq!(custom_pagination.offset, 25);
    }

    #[test]
    fn test_transaction_type_enum() {
        // Test transaction type serialization/deserialization
        let tx_types = vec![
            TransactionType::Receive,
            TransactionType::Send,
            TransactionType::Internal,
            TransactionType::Mixed,
        ];
        
        for tx_type in tx_types {
            let json = serde_json::to_string(&tx_type).unwrap();
            let deserialized: TransactionType = serde_json::from_str(&json).unwrap();
            assert_eq!(tx_type, deserialized);
        }
    }

    #[test]
    fn test_coin_selection_strategy_enum() {
        // Test coin selection strategy serialization/deserialization
        let strategies = vec![
            CoinSelectionStrategy::BranchAndBound,
            CoinSelectionStrategy::Fifo,
            CoinSelectionStrategy::LargestFirst,
            CoinSelectionStrategy::SmallestFirst,
            CoinSelectionStrategy::Random,
        ];
        
        for strategy in strategies {
            let json = serde_json::to_string(&strategy).unwrap();
            let deserialized: CoinSelectionStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, deserialized);
        }
    }

    #[test]
    fn test_transaction_info_structure() {
        // Test creating and serializing a TransactionInfo
        let tx_info = TransactionInfo {
            txid: "abcd1234".to_string(),
            block_height: Some(100000),
            block_hash: Some("block_hash".to_string()),
            timestamp: 1640995200, // 2022-01-01
            fee: 1000,
            net_amount: 50000,
            inputs: vec![TransactionInput {
                prev_txid: "prev_tx".to_string(),
                prev_vout: 0,
                value: 100000,
                address: Some("input_address".to_string()),
                is_mine: false,
                subaccount_id: None,
            }],
            outputs: vec![TransactionOutput {
                vout: 0,
                value: 50000,
                address: Some("output_address".to_string()),
                is_mine: true,
                subaccount_id: Some(0),
                spent: false,
                spent_txid: None,
            }],
            confirmations: 6,
            size: 250,
            vsize: 200,
            tx_type: TransactionType::Receive,
            memo: Some("Test transaction".to_string()),
        };
        
        // Test serialization
        let json = serde_json::to_string(&tx_info).unwrap();
        assert!(json.contains("abcd1234"));
        assert!(json.contains("Receive"));
        
        // Test deserialization
        let deserialized: TransactionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.txid, tx_info.txid);
        assert_eq!(deserialized.tx_type, tx_info.tx_type);
        assert_eq!(deserialized.inputs.len(), 1);
        assert_eq!(deserialized.outputs.len(), 1);
    }

    #[test]
    fn test_utxo_info_structure() {
        // Test creating and serializing a UtxoInfo
        let utxo_info = UtxoInfo {
            txid: "utxo_tx".to_string(),
            vout: 1,
            value: 25000,
            address: "utxo_address".to_string(),
            subaccount_id: 0,
            derivation_path: "m/44'/1'/0'/0/5".to_string(),
            is_change: false,
            block_height: Some(99999),
            confirmations: 10,
            frozen: false,
            script_type: "p2pkh".to_string(),
        };
        
        // Test serialization
        let json = serde_json::to_string(&utxo_info).unwrap();
        assert!(json.contains("utxo_tx"));
        assert!(json.contains("p2pkh"));
        
        // Test deserialization
        let deserialized: UtxoInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.txid, utxo_info.txid);
        assert_eq!(deserialized.value, utxo_info.value);
        assert_eq!(deserialized.script_type, utxo_info.script_type);
        assert!(!deserialized.frozen);
        assert!(!deserialized.is_change);
    }

    #[test]
    fn test_mock_coin_selection_with_utxos() {
        // This test would be more meaningful with actual UTXOs
        // For now, we test the error handling when no UTXOs are available
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        let subaccount_id = wallet.create_subaccount("Test Account".to_string(), SubaccountType::Legacy).unwrap();
        
        // All strategies should fail with insufficient funds
        let strategies = vec![
            CoinSelectionStrategy::BranchAndBound,
            CoinSelectionStrategy::Fifo,
            CoinSelectionStrategy::LargestFirst,
            CoinSelectionStrategy::SmallestFirst,
            CoinSelectionStrategy::Random,
        ];
        
        for strategy in strategies {
            let result = wallet.select_coins(subaccount_id, 1000, strategy);
            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("Insufficient funds"));
            }
        }
    }

    #[test]
    fn test_transaction_input_output_structures() {
        // Test TransactionInput
        let input = TransactionInput {
            prev_txid: "input_tx".to_string(),
            prev_vout: 2,
            value: 75000,
            address: Some("input_addr".to_string()),
            is_mine: true,
            subaccount_id: Some(1),
        };
        
        let json = serde_json::to_string(&input).unwrap();
        let deserialized: TransactionInput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.prev_txid, input.prev_txid);
        assert_eq!(deserialized.prev_vout, input.prev_vout);
        assert_eq!(deserialized.is_mine, input.is_mine);
        
        // Test TransactionOutput
        let output = TransactionOutput {
            vout: 1,
            value: 30000,
            address: Some("output_addr".to_string()),
            is_mine: false,
            subaccount_id: None,
            spent: true,
            spent_txid: Some("spending_tx".to_string()),
        };
        
        let json = serde_json::to_string(&output).unwrap();
        let deserialized: TransactionOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.vout, output.vout);
        assert_eq!(deserialized.value, output.value);
        assert_eq!(deserialized.spent, output.spent);
        assert_eq!(deserialized.spent_txid, output.spent_txid);
    }

    #[test]
    fn test_comprehensive_wallet_operations() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet).unwrap();
        
        // Create multiple subaccounts
        let legacy_id = wallet.create_subaccount("Legacy".to_string(), SubaccountType::Legacy).unwrap();
        let segwit_id = wallet.create_subaccount("SegWit".to_string(), SubaccountType::NativeSegwit).unwrap();
        
        // Test transaction operations on both subaccounts
        for &subaccount_id in &[legacy_id, segwit_id] {
            // Test transaction history
            let transactions = wallet.get_transactions(subaccount_id, None).unwrap();
            assert_eq!(transactions.len(), 0);
            
            // Test UTXO operations
            let utxos = wallet.get_unspent_outputs(subaccount_id).unwrap();
            assert_eq!(utxos.len(), 0);
            
            // Test balance calculations
            let balance = wallet.calculate_subaccount_balance(subaccount_id).unwrap();
            assert_eq!(balance, 0);
            
            // Test counts
            let tx_count = wallet.get_transaction_count(subaccount_id).unwrap();
            let utxo_count = wallet.get_utxo_count(subaccount_id).unwrap();
            assert_eq!(tx_count, 0);
            assert_eq!(utxo_count, 0);
            
            // Test synchronization
            let sync_result = wallet.sync_transaction_history(subaccount_id);
            assert!(sync_result.is_ok());
        }
        
        // Test wallet-wide operations
        let all_transactions = wallet.get_all_transactions(None).unwrap();
        assert_eq!(all_transactions.len(), 0);
        
        let all_utxos = wallet.get_all_unspent_outputs().unwrap();
        assert_eq!(all_utxos.len(), 0);
        
        let total_balance = wallet.calculate_total_balance().unwrap();
        assert_eq!(total_balance, 0);
    }
}