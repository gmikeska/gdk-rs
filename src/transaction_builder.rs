//! Transaction creation and building functionality with comprehensive fee estimation and coin selection.

use crate::primitives::transaction::{Transaction, TxIn, TxOut, OutPoint};
use crate::primitives::script::Script;
use crate::primitives::address::{Address, Network};
use crate::primitives::encode::Encodable;
use crate::protocol::{Addressee, UnspentOutput};
use crate::{Result, GdkError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Fee estimation strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeEstimationStrategy {
    /// Use a fixed fee rate (satoshis per vbyte)
    FixedRate(u64),
    /// Use conservative fee estimation (high priority)
    Conservative,
    /// Use economical fee estimation (low priority)
    Economical,
    /// Use fast confirmation fee estimation
    Fast,
    /// Use custom fee estimation with target blocks
    Custom(u32),
}

impl Default for FeeEstimationStrategy {
    fn default() -> Self {
        FeeEstimationStrategy::Conservative
    }
}

/// Coin selection strategies for UTXO selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoinSelectionStrategy {
    /// Branch and Bound (BnB) - optimal selection for exact change
    BranchAndBound,
    /// First In, First Out - select oldest UTXOs first
    Fifo,
    /// Largest first - select largest UTXOs first
    LargestFirst,
    /// Smallest first - select smallest UTXOs first (good for privacy)
    SmallestFirst,
    /// Random selection
    Random,
}

impl Default for CoinSelectionStrategy {
    fn default() -> Self {
        CoinSelectionStrategy::BranchAndBound
    }
}

/// UTXO information for transaction building
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    /// Transaction ID containing this UTXO
    pub txid: String,
    /// Output index in the transaction
    pub vout: u32,
    /// UTXO value in satoshis
    pub value: u64,
    /// Address that controls this UTXO
    pub address: String,
    /// Script pubkey for this UTXO
    pub script_pubkey: Script,
    /// Subaccount that owns this UTXO
    pub subaccount_id: u32,
    /// Whether this is a change output
    pub is_change: bool,
    /// Block height when this UTXO was created
    pub block_height: Option<u32>,
    /// Number of confirmations
    pub confirmations: u32,
    /// Whether this UTXO is frozen (not available for spending)
    pub frozen: bool,
    /// Script type (p2pkh, p2wpkh, p2sh, etc.)
    pub script_type: String,
}

impl UtxoInfo {
    /// Convert from protocol UnspentOutput
    pub fn from_unspent_output(unspent: &UnspentOutput, network: Network) -> Result<Self> {
        // Parse the address to get the script pubkey
        let address = Address::from_str(&unspent.address)?;
        
        // Validate the address is for the correct network
        if address.network != network {
            return Err(GdkError::InvalidInput(format!("Address network mismatch: expected {:?}, got {:?}", network, address.network)));
        }
        let script_pubkey = address.script_pubkey();

        Ok(UtxoInfo {
            txid: unspent.txhash.clone(),
            vout: unspent.pt_idx,
            value: unspent.satoshi,
            address: unspent.address.clone(),
            script_pubkey,
            subaccount_id: unspent.subaccount,
            is_change: false, // This would need to be determined from address derivation
            block_height: None, // Not provided in UnspentOutput
            confirmations: 0, // Would need to be calculated
            frozen: false, // Default to not frozen
            script_type: unspent.address_type.clone(),
        })
    }

    /// Get the outpoint for this UTXO
    pub fn outpoint(&self) -> Result<OutPoint> {
        let txid_bytes = hex::decode(&self.txid)
            .map_err(|_| GdkError::InvalidInput("Invalid transaction ID".to_string()))?;
        
        if txid_bytes.len() != 32 {
            return Err(GdkError::InvalidInput("Transaction ID must be 32 bytes".to_string()));
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);
        
        Ok(OutPoint::new(txid, self.vout))
    }

    /// Estimate the input size in virtual bytes for fee calculation
    pub fn input_vsize(&self) -> u64 {
        match self.script_type.as_str() {
            "p2pkh" => 148, // 32 (outpoint) + 1 (script_sig len) + 107 (script_sig) + 4 (sequence) + 4 (witness discount)
            "p2wpkh" => 68, // 32 (outpoint) + 1 (empty script_sig) + 4 (sequence) + witness data / 4
            "p2sh" => 91,   // Variable, but this is a reasonable estimate for P2SH-P2WPKH
            "p2wsh" => 68,  // Similar to P2WPKH but with larger witness
            _ => 148,       // Default to P2PKH size
        }
    }
}

/// Transaction building parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBuildParams {
    /// Recipients and amounts
    pub addressees: Vec<Addressee>,
    /// Fee estimation strategy
    pub fee_strategy: FeeEstimationStrategy,
    /// Coin selection strategy
    pub coin_strategy: CoinSelectionStrategy,
    /// Send all available funds (ignore addressee amounts)
    pub send_all: bool,
    /// Specific UTXOs to use (if None, will select automatically)
    pub utxos: Option<Vec<UtxoInfo>>,
    /// Subaccount to spend from
    pub subaccount: u32,
    /// Change address (if None, will generate one)
    pub change_address: Option<String>,
    /// Minimum number of confirmations required for UTXOs
    pub min_confirmations: u32,
    /// Replace-by-fee (RBF) enabled
    pub rbf_enabled: bool,
}

impl Default for TransactionBuildParams {
    fn default() -> Self {
        Self {
            addressees: Vec::new(),
            fee_strategy: FeeEstimationStrategy::default(),
            coin_strategy: CoinSelectionStrategy::default(),
            send_all: false,
            utxos: None,
            subaccount: 0,
            change_address: None,
            min_confirmations: 1,
            rbf_enabled: true,
        }
    }
}

/// Result of transaction building
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionBuildResult {
    /// The built transaction
    pub transaction: Transaction,
    /// Selected UTXOs used as inputs
    pub selected_utxos: Vec<UtxoInfo>,
    /// Total input value
    pub input_value: u64,
    /// Total output value (excluding fee)
    pub output_value: u64,
    /// Calculated fee
    pub fee: u64,
    /// Fee rate in satoshis per vbyte
    pub fee_rate: u64,
    /// Change output value (if any)
    pub change_value: Option<u64>,
    /// Transaction size in bytes
    pub tx_size: u64,
    /// Transaction virtual size in vbytes
    pub tx_vsize: u64,
}

/// Fee estimation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    /// Fee rates for different confirmation targets (blocks -> sat/vbyte)
    pub fee_rates: HashMap<u32, u64>,
    /// Minimum relay fee rate
    pub min_relay_fee: u64,
}

impl Default for FeeEstimate {
    fn default() -> Self {
        let mut fee_rates = HashMap::new();
        fee_rates.insert(1, 20);   // Fast (1 block)
        fee_rates.insert(3, 15);   // Medium (3 blocks)
        fee_rates.insert(6, 10);   // Slow (6 blocks)
        fee_rates.insert(144, 5);  // Very slow (1 day)

        Self {
            fee_rates,
            min_relay_fee: 1, // 1 sat/vbyte minimum
        }
    }
}

/// Comprehensive transaction builder
pub struct TransactionBuilder {
    /// Network this builder operates on
    network: Network,
    /// Current fee estimates
    fee_estimates: FeeEstimate,
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new(network: Network) -> Self {
        Self {
            network,
            fee_estimates: FeeEstimate::default(),
        }
    }

    /// Update fee estimates
    pub fn update_fee_estimates(&mut self, estimates: FeeEstimate) {
        self.fee_estimates = estimates;
    }

    /// Get current fee estimates
    pub fn get_fee_estimates(&self) -> &FeeEstimate {
        &self.fee_estimates
    }

    /// Build a transaction from the given parameters
    pub fn build_transaction(
        &self,
        params: &TransactionBuildParams,
        available_utxos: &[UtxoInfo],
    ) -> Result<TransactionBuildResult> {
        // Validate parameters
        self.validate_build_params(params)?;

        // Filter available UTXOs
        let filtered_utxos = self.filter_utxos(available_utxos, params)?;

        // Calculate target amount
        let target_amount = if params.send_all {
            // Will be calculated after coin selection
            0
        } else {
            params.addressees.iter().map(|a| a.satoshi).sum::<u64>()
        };

        // Select UTXOs
        let selected_utxos = if let Some(ref specific_utxos) = params.utxos {
            specific_utxos.clone()
        } else {
            self.select_coins(&filtered_utxos, target_amount, params.coin_strategy)?
        };

        // Calculate fee
        let (fee, fee_rate) = self.calculate_fee(&selected_utxos, &params.addressees, params)?;

        // Build the transaction
        self.build_transaction_from_selection(params, &selected_utxos, fee, fee_rate)
    }

    /// Validate build parameters
    fn validate_build_params(&self, params: &TransactionBuildParams) -> Result<()> {
        if !params.send_all && params.addressees.is_empty() {
            return Err(GdkError::InvalidInput("No recipients specified".to_string()));
        }

        for addressee in &params.addressees {
            if addressee.satoshi == 0 && !params.send_all {
                return Err(GdkError::InvalidInput("Output amount cannot be zero".to_string()));
            }

            // Validate address format
            let address = Address::from_str(&addressee.address)
                .map_err(|_| GdkError::InvalidInput(format!("Invalid address: {}", addressee.address)))?;
            
            // Validate the address is for the correct network
            if address.network != self.network {
                return Err(GdkError::InvalidInput(format!("Address network mismatch: expected {:?}, got {:?}", self.network, address.network)));
            }
        }

        Ok(())
    }

    /// Filter UTXOs based on parameters
    fn filter_utxos(&self, utxos: &[UtxoInfo], params: &TransactionBuildParams) -> Result<Vec<UtxoInfo>> {
        let filtered: Vec<UtxoInfo> = utxos
            .iter()
            .filter(|utxo| {
                // Filter by subaccount
                utxo.subaccount_id == params.subaccount
                    // Filter by confirmations
                    && utxo.confirmations >= params.min_confirmations
                    // Filter out frozen UTXOs
                    && !utxo.frozen
                    // Filter out dust UTXOs (less than 546 sats)
                    && utxo.value >= 546
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            return Err(GdkError::InvalidInput("No suitable UTXOs available".to_string()));
        }

        Ok(filtered)
    }

    /// Select coins using the specified strategy
    fn select_coins(
        &self,
        utxos: &[UtxoInfo],
        target_amount: u64,
        strategy: CoinSelectionStrategy,
    ) -> Result<Vec<UtxoInfo>> {
        match strategy {
            CoinSelectionStrategy::BranchAndBound => self.select_coins_bnb(utxos, target_amount),
            CoinSelectionStrategy::Fifo => self.select_coins_fifo(utxos, target_amount),
            CoinSelectionStrategy::LargestFirst => self.select_coins_largest_first(utxos, target_amount),
            CoinSelectionStrategy::SmallestFirst => self.select_coins_smallest_first(utxos, target_amount),
            CoinSelectionStrategy::Random => self.select_coins_random(utxos, target_amount),
        }
    }

    /// Branch and Bound coin selection (optimal for exact change)
    fn select_coins_bnb(&self, utxos: &[UtxoInfo], target_amount: u64) -> Result<Vec<UtxoInfo>> {
        // Simplified BnB implementation
        // In a full implementation, this would use the actual BnB algorithm
        
        let mut sorted_utxos = utxos.to_vec();
        sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value)); // Largest first for simplicity

        let mut selected = Vec::new();
        let mut total = 0;

        for utxo in sorted_utxos {
            if total >= target_amount {
                break;
            }
            total += utxo.value;
            selected.push(utxo);
        }

        if total < target_amount {
            return Err(GdkError::InvalidInput("Insufficient funds".to_string()));
        }

        Ok(selected)
    }

    /// FIFO coin selection
    fn select_coins_fifo(&self, utxos: &[UtxoInfo], target_amount: u64) -> Result<Vec<UtxoInfo>> {
        let mut sorted_utxos = utxos.to_vec();
        // Sort by block height (oldest first)
        sorted_utxos.sort_by(|a, b| {
            match (a.block_height, b.block_height) {
                (Some(a_height), Some(b_height)) => a_height.cmp(&b_height),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });

        let mut selected = Vec::new();
        let mut total = 0;

        for utxo in sorted_utxos {
            if total >= target_amount {
                break;
            }
            total += utxo.value;
            selected.push(utxo);
        }

        if total < target_amount {
            return Err(GdkError::InvalidInput("Insufficient funds".to_string()));
        }

        Ok(selected)
    }

    /// Largest first coin selection
    fn select_coins_largest_first(&self, utxos: &[UtxoInfo], target_amount: u64) -> Result<Vec<UtxoInfo>> {
        let mut sorted_utxos = utxos.to_vec();
        sorted_utxos.sort_by(|a, b| b.value.cmp(&a.value));

        let mut selected = Vec::new();
        let mut total = 0;

        for utxo in sorted_utxos {
            if total >= target_amount {
                break;
            }
            total += utxo.value;
            selected.push(utxo);
        }

        if total < target_amount {
            return Err(GdkError::InvalidInput("Insufficient funds".to_string()));
        }

        Ok(selected)
    }

    /// Smallest first coin selection (good for privacy)
    fn select_coins_smallest_first(&self, utxos: &[UtxoInfo], target_amount: u64) -> Result<Vec<UtxoInfo>> {
        let mut sorted_utxos = utxos.to_vec();
        sorted_utxos.sort_by(|a, b| a.value.cmp(&b.value));

        let mut selected = Vec::new();
        let mut total = 0;

        for utxo in sorted_utxos {
            if total >= target_amount {
                break;
            }
            total += utxo.value;
            selected.push(utxo);
        }

        if total < target_amount {
            return Err(GdkError::InvalidInput("Insufficient funds".to_string()));
        }

        Ok(selected)
    }

    /// Random coin selection
    fn select_coins_random(&self, utxos: &[UtxoInfo], target_amount: u64) -> Result<Vec<UtxoInfo>> {
        use rand::seq::SliceRandom;
        use rand::thread_rng;

        let mut shuffled_utxos = utxos.to_vec();
        shuffled_utxos.shuffle(&mut thread_rng());

        let mut selected = Vec::new();
        let mut total = 0;

        for utxo in shuffled_utxos {
            if total >= target_amount {
                break;
            }
            total += utxo.value;
            selected.push(utxo);
        }

        if total < target_amount {
            return Err(GdkError::InvalidInput("Insufficient funds".to_string()));
        }

        Ok(selected)
    }

    /// Calculate fee for the transaction
    fn calculate_fee(
        &self,
        selected_utxos: &[UtxoInfo],
        addressees: &[Addressee],
        params: &TransactionBuildParams,
    ) -> Result<(u64, u64)> {
        // Get fee rate based on strategy
        let fee_rate = self.get_fee_rate(params.fee_strategy)?;

        // Estimate transaction size
        let tx_vsize = self.estimate_transaction_vsize(selected_utxos, addressees, params)?;

        // Calculate fee
        let fee = fee_rate * tx_vsize;

        // Ensure fee meets minimum relay fee
        let min_fee = self.fee_estimates.min_relay_fee * tx_vsize;
        let final_fee = fee.max(min_fee);

        Ok((final_fee, fee_rate))
    }

    /// Get fee rate based on strategy
    fn get_fee_rate(&self, strategy: FeeEstimationStrategy) -> Result<u64> {
        match strategy {
            FeeEstimationStrategy::FixedRate(rate) => Ok(rate),
            FeeEstimationStrategy::Conservative => {
                Ok(self.fee_estimates.fee_rates.get(&1).copied().unwrap_or(20))
            }
            FeeEstimationStrategy::Economical => {
                Ok(self.fee_estimates.fee_rates.get(&144).copied().unwrap_or(5))
            }
            FeeEstimationStrategy::Fast => {
                Ok(self.fee_estimates.fee_rates.get(&1).copied().unwrap_or(25))
            }
            FeeEstimationStrategy::Custom(blocks) => {
                // Find the closest fee rate
                let mut closest_blocks = 144u32;
                let mut min_diff = u32::MAX;

                for &target_blocks in self.fee_estimates.fee_rates.keys() {
                    let diff = if target_blocks > blocks {
                        target_blocks - blocks
                    } else {
                        blocks - target_blocks
                    };
                    if diff < min_diff {
                        min_diff = diff;
                        closest_blocks = target_blocks;
                    }
                }

                Ok(self.fee_estimates.fee_rates.get(&closest_blocks).copied().unwrap_or(10))
            }
        }
    }

    /// Estimate transaction virtual size
    fn estimate_transaction_vsize(
        &self,
        selected_utxos: &[UtxoInfo],
        addressees: &[Addressee],
        params: &TransactionBuildParams,
    ) -> Result<u64> {
        // Base transaction size (version + locktime + input/output counts)
        let mut vsize = 10u64;

        // Add input sizes
        for utxo in selected_utxos {
            vsize += utxo.input_vsize();
        }

        // Add output sizes
        for _addressee in addressees {
            vsize += 34; // Standard output size (8 bytes value + 26 bytes script)
        }

        // Add change output if needed
        let input_total: u64 = selected_utxos.iter().map(|u| u.value).sum();
        let output_total: u64 = addressees.iter().map(|a| a.satoshi).sum();
        
        if input_total > output_total {
            vsize += 34; // Change output
        }

        Ok(vsize)
    }

    /// Build the final transaction from selected inputs
    fn build_transaction_from_selection(
        &self,
        params: &TransactionBuildParams,
        selected_utxos: &[UtxoInfo],
        fee: u64,
        fee_rate: u64,
    ) -> Result<TransactionBuildResult> {
        let mut transaction = Transaction::new();
        transaction.version = 2; // Use version 2 for RBF support

        // Calculate totals
        let input_value: u64 = selected_utxos.iter().map(|u| u.value).sum();
        let mut output_value = 0u64;

        // Add inputs
        for utxo in selected_utxos {
            let outpoint = utxo.outpoint()?;
            let sequence = if params.rbf_enabled { 0xfffffffd } else { 0xffffffff };
            
            let tx_in = TxIn::new(outpoint, Script::new(), sequence);
            transaction.input.push(tx_in);
        }

        // Add outputs
        if params.send_all {
            // Send all: single output with (input_value - fee)
            if params.addressees.len() != 1 {
                return Err(GdkError::InvalidInput("Send all requires exactly one recipient".to_string()));
            }
            
            let send_amount = input_value.saturating_sub(fee);
            if send_amount < 546 {
                return Err(GdkError::InvalidInput("Insufficient funds after fee".to_string()));
            }

            let address = Address::from_str(&params.addressees[0].address)?;
            let tx_out = TxOut::new(send_amount, address.script_pubkey());
            transaction.output.push(tx_out);
            output_value = send_amount;
        } else {
            // Regular transaction: add all specified outputs
            for addressee in &params.addressees {
                let address = Address::from_str(&addressee.address)?;
                let tx_out = TxOut::new(addressee.satoshi, address.script_pubkey());
                transaction.output.push(tx_out);
                output_value += addressee.satoshi;
            }

            // Add change output if needed
            let change_amount = input_value.saturating_sub(output_value + fee);
            if change_amount >= 546 {
                // Generate or use provided change address
                let change_address = if let Some(ref addr) = params.change_address {
                    Address::from_str(addr)?
                } else {
                    // In a real implementation, this would generate a new change address
                    return Err(GdkError::InvalidInput("Change address required".to_string()));
                };

                let change_out = TxOut::new(change_amount, change_address.script_pubkey());
                transaction.output.push(change_out);
            }
        }

        // Calculate final sizes
        let tx_size = transaction.consensus_encode_to_vec()?.len() as u64;
        let tx_vsize = self.estimate_transaction_vsize(selected_utxos, &params.addressees, params)?;

        Ok(TransactionBuildResult {
            transaction,
            selected_utxos: selected_utxos.to_vec(),
            input_value,
            output_value,
            fee,
            fee_rate,
            change_value: if input_value > output_value + fee {
                Some(input_value - output_value - fee)
            } else {
                None
            },
            tx_size,
            tx_vsize,
        })
    }

    /// Estimate fee for a transaction without building it
    pub fn estimate_fee(
        &self,
        params: &TransactionBuildParams,
        available_utxos: &[UtxoInfo],
    ) -> Result<(u64, u64)> {
        let filtered_utxos = self.filter_utxos(available_utxos, params)?;
        
        let target_amount = if params.send_all {
            0
        } else {
            params.addressees.iter().map(|a| a.satoshi).sum::<u64>()
        };

        let selected_utxos = if let Some(ref specific_utxos) = params.utxos {
            specific_utxos.clone()
        } else {
            self.select_coins(&filtered_utxos, target_amount, params.coin_strategy)?
        };

        self.calculate_fee(&selected_utxos, &params.addressees, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::address::Network;

    fn create_test_utxo(value: u64, script_type: &str) -> UtxoInfo {
        UtxoInfo {
            txid: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            vout: 0,
            value,
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            script_pubkey: Script::new(),
            subaccount_id: 0,
            is_change: false,
            block_height: Some(100),
            confirmations: 6,
            frozen: false,
            script_type: script_type.to_string(),
        }
    }

    #[test]
    fn test_transaction_builder_creation() {
        let builder = TransactionBuilder::new(Network::Testnet);
        assert_eq!(builder.network, Network::Testnet);
    }

    #[test]
    fn test_coin_selection_largest_first() {
        let builder = TransactionBuilder::new(Network::Testnet);
        let utxos = vec![
            create_test_utxo(1000, "p2pkh"),
            create_test_utxo(5000, "p2pkh"),
            create_test_utxo(2000, "p2pkh"),
        ];

        let selected = builder.select_coins_largest_first(&utxos, 3000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 5000);
    }

    #[test]
    fn test_coin_selection_smallest_first() {
        let builder = TransactionBuilder::new(Network::Testnet);
        let utxos = vec![
            create_test_utxo(1000, "p2pkh"),
            create_test_utxo(5000, "p2pkh"),
            create_test_utxo(2000, "p2pkh"),
        ];

        let selected = builder.select_coins_smallest_first(&utxos, 2500).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].value, 1000);
        assert_eq!(selected[1].value, 2000);
    }

    #[test]
    fn test_fee_calculation() {
        let builder = TransactionBuilder::new(Network::Testnet);
        let utxos = vec![create_test_utxo(100000, "p2pkh")];
        let addressees = vec![Addressee {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            satoshi: 50000,
            asset_id: None,
        }];

        let params = TransactionBuildParams {
            addressees,
            fee_strategy: FeeEstimationStrategy::FixedRate(10),
            ..Default::default()
        };

        let (fee, fee_rate) = builder.calculate_fee(&utxos, &params.addressees, &params).unwrap();
        assert!(fee > 0);
        assert_eq!(fee_rate, 10);
    }

    #[test]
    fn test_insufficient_funds() {
        let builder = TransactionBuilder::new(Network::Testnet);
        let utxos = vec![create_test_utxo(1000, "p2pkh")];

        let result = builder.select_coins_largest_first(&utxos, 2000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Insufficient funds"));
    }

    #[test]
    fn test_validate_build_params() {
        let builder = TransactionBuilder::new(Network::Testnet);
        
        // Test empty addressees without send_all
        let params = TransactionBuildParams::default();
        let result = builder.validate_build_params(&params);
        assert!(result.is_err());

        // Test zero amount without send_all
        let params = TransactionBuildParams {
            addressees: vec![Addressee {
                address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
                satoshi: 0,
                asset_id: None,
            }],
            ..Default::default()
        };
        let result = builder.validate_build_params(&params);
        assert!(result.is_err());
    }
}