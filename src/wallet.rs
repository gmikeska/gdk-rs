//! Wallet operations, subaccount management, and address generation.
//!
//! This module provides comprehensive wallet functionality including hierarchical deterministic
//! key management, subaccount organization, address generation, and balance tracking. It implements
//! BIP32/BIP44/BIP49/BIP84 standards for deterministic wallet operations.
//!
//! # Overview
//!
//! The wallet system is organized around the concept of subaccounts, where each subaccount
//! represents a different address type or purpose:
//!
//! - **Legacy (P2PKH)**: Traditional Bitcoin addresses starting with '1'
//! - **SegWit Wrapped (P2SH-P2WPKH)**: SegWit addresses wrapped in P2SH, starting with '3'
//! - **Native SegWit (P2WPKH)**: Native SegWit addresses starting with 'bc1'
//! - **Native SegWit Multisig (P2WSH)**: Native SegWit multisig addresses
//!
//! # Examples
//!
//! ## Creating a Wallet from Mnemonic
//!
//! ```rust
//! use gdk_rs::wallet::{Wallet, SubaccountType};
//! use gdk_rs::primitives::address::Network;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//!     let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet)?;
//!
//!     // Create a native SegWit subaccount
//!     let subaccount_id = wallet.create_subaccount(
//!         "Main Account".to_string(),
//!         SubaccountType::NativeSegwit,
//!     )?;
//!
//!     // Get a receiving address
//!     let address = wallet.get_receive_address(subaccount_id)?;
//!     println!("Receiving address: {}", address);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Managing Multiple Subaccounts
//!
//! ```rust
//! use gdk_rs::wallet::{Wallet, SubaccountType};
//! use gdk_rs::primitives::address::Network;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let wallet = Wallet::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Network::Mainnet)?;
//!
//!     // Create different types of subaccounts
//!     let legacy_id = wallet.create_subaccount("Legacy".to_string(), SubaccountType::Legacy)?;
//!     let segwit_id = wallet.create_subaccount("SegWit".to_string(), SubaccountType::NativeSegwit)?;
//!     let wrapped_id = wallet.create_subaccount("Wrapped SegWit".to_string(), SubaccountType::SegwitWrapped)?;
//!
//!     // List all subaccounts
//!     let subaccounts = wallet.get_subaccounts();
//!     for subaccount in subaccounts {
//!         println!("Subaccount {}: {} ({})", subaccount.id, subaccount.name, subaccount.subaccount_type.name());
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Address Generation and Tracking
//!
//! ```rust
//! use gdk_rs::wallet::{Wallet, SubaccountType};
//! use gdk_rs::primitives::address::Network;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let wallet = Wallet::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Network::Testnet)?;
//!     let subaccount_id = wallet.create_subaccount("Test".to_string(), SubaccountType::NativeSegwit)?;
//!
//!     // Generate multiple receiving addresses
//!     for i in 0..5 {
//!         let address = wallet.get_receive_address(subaccount_id)?;
//!         println!("Address {}: {}", i + 1, address);
//!     }
//!
//!     // Get all previous addresses with usage information
//!     let addresses = wallet.get_previous_addresses(subaccount_id)?;
//!     for addr_info in addresses {
//!         println!("Address: {}, Used: {}, Balance: {} sats", 
//!                  addr_info.address, addr_info.used, addr_info.balance);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Key Management
//!
//! The wallet uses BIP32 hierarchical deterministic key derivation with the following structure:
//!
//! ```text
//! m / purpose' / coin_type' / account' / change / address_index
//! ```
//!
//! Where:
//! - `purpose`: 44 (Legacy), 49 (SegWit Wrapped), 84 (Native SegWit)
//! - `coin_type`: 0 (Bitcoin Mainnet), 1 (Bitcoin Testnet)
//! - `account`: Subaccount index (0, 1, 2, ...)
//! - `change`: 0 (receiving), 1 (change addresses)
//! - `address_index`: Sequential address index within the chain
//!
//! # Thread Safety
//!
//! All wallet operations are thread-safe and can be called concurrently from multiple threads.
//! Internal state is protected by appropriate synchronization primitives.

use crate::primitives::bip32::{ExtendedPrivateKey, ExtendedPublicKey, DerivationPath, Network as BipNetwork};
use crate::primitives::address::{Address, Network};
use crate::bip39::Mnemonic;
use crate::{Result, GdkError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Subaccount types supported by the wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubaccountType {
    /// Legacy P2PKH addresses (BIP44)
    #[serde(rename = "p2pkh")]
    Legacy,
    /// P2SH-wrapped SegWit addresses (BIP49)
    #[serde(rename = "p2sh-segwit")]
    SegwitWrapped,
    /// Native SegWit addresses (BIP84)
    #[serde(rename = "p2wpkh")]
    NativeSegwit,
    /// P2WSH multisig addresses
    #[serde(rename = "p2wsh")]
    NativeSegwitMultisig,
}

impl SubaccountType {
    /// Get the BIP purpose for this subaccount type
    pub fn purpose(&self) -> u32 {
        match self {
            SubaccountType::Legacy => 44,
            SubaccountType::SegwitWrapped => 49,
            SubaccountType::NativeSegwit => 84,
            SubaccountType::NativeSegwitMultisig => 84, // Same as native segwit
        }
    }

    /// Get the coin type for Bitcoin (0 for mainnet, 1 for testnet)
    pub fn coin_type(&self, network: Network) -> u32 {
        match network {
            Network::Mainnet => 0,
            Network::Testnet | Network::Regtest | Network::Signet => 1,
        }
    }

    /// Create the base derivation path for this subaccount type
    pub fn base_path(&self, network: Network, account: u32) -> DerivationPath {
        let purpose = self.purpose();
        let coin_type = self.coin_type(network);
        DerivationPath::new(vec![
            DerivationPath::hardened(purpose),
            DerivationPath::hardened(coin_type),
            DerivationPath::hardened(account),
        ])
    }

    /// Get a human-readable name for this subaccount type
    pub fn name(&self) -> &'static str {
        match self {
            SubaccountType::Legacy => "Legacy",
            SubaccountType::SegwitWrapped => "SegWit (wrapped)",
            SubaccountType::NativeSegwit => "Native SegWit",
            SubaccountType::NativeSegwitMultisig => "Native SegWit Multisig",
        }
    }
}

/// Address information with usage tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// The address string
    pub address: String,
    /// Derivation path used to generate this address
    pub derivation_path: DerivationPath,
    /// Whether this address has been used (has transactions)
    pub used: bool,
    /// Number of transactions involving this address
    pub tx_count: u32,
    /// Current balance in satoshis
    pub balance: u64,
    /// Address index within the subaccount
    pub address_index: u32,
    /// Whether this is a change address (internal) or receiving address (external)
    pub is_change: bool,
}

/// Subaccount balance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubaccountBalance {
    /// Total confirmed balance in satoshis
    pub confirmed: u64,
    /// Total unconfirmed balance in satoshis
    pub unconfirmed: u64,
    /// Total balance (confirmed + unconfirmed)
    pub total: u64,
    /// Number of UTXOs
    pub utxo_count: u32,
}

impl Default for SubaccountBalance {
    fn default() -> Self {
        Self {
            confirmed: 0,
            unconfirmed: 0,
            total: 0,
            utxo_count: 0,
        }
    }
}

/// Subaccount metadata and state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subaccount {
    /// Unique identifier for this subaccount
    pub id: u32,
    /// Human-readable name for this subaccount
    pub name: String,
    /// Type of addresses this subaccount generates
    pub subaccount_type: SubaccountType,
    /// Network this subaccount operates on
    pub network: Network,
    /// Extended public key for this subaccount
    pub extended_pubkey: String,
    /// Current balance information
    pub balance: SubaccountBalance,
    /// Next unused receiving address index
    pub next_receive_index: u32,
    /// Next unused change address index
    pub next_change_index: u32,
    /// Gap limit for address generation
    pub gap_limit: u32,
    /// Whether this subaccount is hidden from the UI
    pub hidden: bool,
    /// Creation timestamp
    pub created_at: u64,
    /// Last synchronization timestamp
    pub last_sync: Option<u64>,
}

impl Subaccount {
    /// Create a new subaccount
    pub fn new(
        id: u32,
        name: String,
        subaccount_type: SubaccountType,
        network: Network,
        extended_pubkey: ExtendedPublicKey,
    ) -> Self {
        Self {
            id,
            name,
            subaccount_type,
            network,
            extended_pubkey: extended_pubkey.to_string(),
            balance: SubaccountBalance::default(),
            next_receive_index: 0,
            next_change_index: 0,
            gap_limit: 20, // Standard gap limit
            hidden: false,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_sync: None,
        }
    }

    /// Get the derivation path for a specific address
    pub fn address_path(&self, is_change: bool, index: u32) -> DerivationPath {
        let base_path = self.subaccount_type.base_path(self.network, self.id);
        let change_index = if is_change { 1 } else { 0 };
        base_path.child(change_index).child(index)
    }

    /// Update balance information
    pub fn update_balance(&mut self, confirmed: u64, unconfirmed: u64, utxo_count: u32) {
        self.balance.confirmed = confirmed;
        self.balance.unconfirmed = unconfirmed;
        self.balance.total = confirmed + unconfirmed;
        self.balance.utxo_count = utxo_count;
        self.last_sync = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
    }

    /// Check if this subaccount needs more addresses generated
    pub fn needs_more_addresses(&self, used_addresses: &[AddressInfo]) -> bool {
        let receive_used = used_addresses
            .iter()
            .filter(|addr| !addr.is_change && addr.used)
            .count() as u32;
        let change_used = used_addresses
            .iter()
            .filter(|addr| addr.is_change && addr.used)
            .count() as u32;

        (self.next_receive_index - receive_used) < self.gap_limit
            || (self.next_change_index - change_used) < self.gap_limit
    }
}

/// Address generation and management for subaccounts
pub struct AddressManager {
    /// Cache of generated addresses by subaccount ID
    addresses: Arc<Mutex<HashMap<u32, Vec<AddressInfo>>>>,
    /// Extended public keys for each subaccount
    subaccount_keys: Arc<Mutex<HashMap<u32, ExtendedPublicKey>>>,
}

impl AddressManager {
    pub fn new() -> Self {
        Self {
            addresses: Arc::new(Mutex::new(HashMap::new())),
            subaccount_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a subaccount's extended public key
    pub fn register_subaccount(&self, subaccount_id: u32, extended_pubkey: ExtendedPublicKey) {
        let mut keys = self.subaccount_keys.lock().unwrap();
        keys.insert(subaccount_id, extended_pubkey);
    }

    /// Generate a new address for a subaccount
    pub fn generate_address(
        &self,
        subaccount: &Subaccount,
        is_change: bool,
        index: u32,
    ) -> Result<AddressInfo> {
        let keys = self.subaccount_keys.lock().unwrap();
        let extended_pubkey = keys
            .get(&subaccount.id)
            .ok_or_else(|| GdkError::invalid_input_simple("Subaccount not registered".to_string()))?;

        // Derive the specific key for this address
        let derivation_path = subaccount.address_path(is_change, index);
        let change_index = if is_change { 1 } else { 0 };
        
        let change_key = extended_pubkey.derive_child(change_index)?;
        let address_key = change_key.derive_child(index)?;

        // Generate the address based on subaccount type
        let address = match subaccount.subaccount_type {
            SubaccountType::Legacy => {
                Address::p2pkh(&address_key.public_key, subaccount.network)
            }
            SubaccountType::SegwitWrapped => {
                // P2SH-wrapped P2WPKH
                let p2wpkh_script = Address::p2wpkh(&address_key.public_key, subaccount.network).script_pubkey();
                Address::p2sh(&p2wpkh_script, subaccount.network)
            }
            SubaccountType::NativeSegwit => {
                Address::p2wpkh(&address_key.public_key, subaccount.network)
            }
            SubaccountType::NativeSegwitMultisig => {
                // For now, treat as single-sig P2WSH
                let p2wpkh_script = Address::p2wpkh(&address_key.public_key, subaccount.network).script_pubkey();
                Address::p2wsh(&p2wpkh_script, subaccount.network)
            }
        };

        Ok(AddressInfo {
            address: address.to_string(),
            derivation_path,
            used: false,
            tx_count: 0,
            balance: 0,
            address_index: index,
            is_change,
        })
    }

    /// Get all addresses for a subaccount
    pub fn get_addresses(&self, subaccount_id: u32) -> Vec<AddressInfo> {
        let addresses = self.addresses.lock().unwrap();
        addresses.get(&subaccount_id).cloned().unwrap_or_default()
    }

    /// Update address usage information
    pub fn update_address_usage(
        &self,
        subaccount_id: u32,
        address: &str,
        used: bool,
        tx_count: u32,
        balance: u64,
    ) -> Result<()> {
        let mut addresses = self.addresses.lock().unwrap();
        let subaccount_addresses = addresses.entry(subaccount_id).or_insert_with(Vec::new);

        if let Some(addr_info) = subaccount_addresses.iter_mut().find(|a| a.address == address) {
            addr_info.used = used;
            addr_info.tx_count = tx_count;
            addr_info.balance = balance;
        }

        Ok(())
    }

    /// Generate addresses up to the gap limit
    pub fn ensure_addresses(&self, subaccount: &mut Subaccount) -> Result<Vec<AddressInfo>> {
        let mut new_addresses = Vec::new();
        let mut addresses = self.addresses.lock().unwrap();
        let subaccount_addresses = addresses.entry(subaccount.id).or_insert_with(Vec::new);

        // Generate receiving addresses
        while subaccount.next_receive_index < subaccount.gap_limit {
            let addr_info = self.generate_address(subaccount, false, subaccount.next_receive_index)?;
            subaccount_addresses.push(addr_info.clone());
            new_addresses.push(addr_info);
            subaccount.next_receive_index += 1;
        }

        // Generate change addresses
        while subaccount.next_change_index < subaccount.gap_limit {
            let addr_info = self.generate_address(subaccount, true, subaccount.next_change_index)?;
            subaccount_addresses.push(addr_info.clone());
            new_addresses.push(addr_info);
            subaccount.next_change_index += 1;
        }

        Ok(new_addresses)
    }
}

/// Main wallet structure with subaccount management.
///
/// The `Wallet` struct represents a hierarchical deterministic (HD) wallet that manages
/// multiple subaccounts, each with their own address generation and balance tracking.
/// It implements BIP32/BIP44/BIP49/BIP84 standards for deterministic key derivation.
///
/// # Features
///
/// - **HD Key Management**: BIP32 hierarchical deterministic key derivation
/// - **Multiple Address Types**: Support for Legacy, SegWit, and Native SegWit addresses
/// - **Subaccount Organization**: Separate subaccounts for different purposes
/// - **Address Generation**: Automatic address generation with gap limit management
/// - **Balance Tracking**: Real-time balance updates and UTXO management
/// - **Thread Safety**: All operations are thread-safe and can be called concurrently
///
/// # Key Derivation Structure
///
/// The wallet follows the BIP44 derivation structure:
/// ```text
/// m / purpose' / coin_type' / account' / change / address_index
/// ```
///
/// # Examples
///
/// See the module-level documentation for comprehensive examples.
pub struct Wallet {
    /// Master extended private key
    master_key: ExtendedPrivateKey,
    /// Network this wallet operates on
    network: Network,
    /// All subaccounts in this wallet
    subaccounts: Arc<Mutex<HashMap<u32, Subaccount>>>,
    /// Address manager for generating and tracking addresses
    address_manager: AddressManager,
    /// Next available subaccount ID
    next_subaccount_id: Arc<Mutex<u32>>,
}

impl Wallet {
    /// Create a new wallet from a BIP39 mnemonic seed phrase.
    ///
    /// This method creates a hierarchical deterministic (HD) wallet from a BIP39 mnemonic
    /// seed phrase. The wallet will derive all keys using BIP32 key derivation.
    ///
    /// # Arguments
    ///
    /// * `mnemonic_str` - A valid BIP39 mnemonic seed phrase (12 or 24 words)
    /// * `network` - The Bitcoin network this wallet will operate on
    ///
    /// # Returns
    ///
    /// Returns a new `Wallet` instance on success, or a [`GdkError`] if the mnemonic
    /// is invalid or key derivation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gdk_rs::wallet::Wallet;
    /// use gdk_rs::primitives::address::Network;
    ///
    /// // Create a wallet from a 12-word mnemonic
    /// let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let wallet = Wallet::from_mnemonic(mnemonic, Network::Testnet)?;
    ///
    /// println!("Wallet ID: {}", wallet.get_wallet_identifier());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Security Considerations
    ///
    /// - The mnemonic should be generated using cryptographically secure randomness
    /// - Store the mnemonic securely and never transmit it over insecure channels
    /// - Consider using a BIP39 passphrase for additional security
    /// - The master private key is kept in memory and should be protected
    pub fn from_mnemonic(mnemonic_str: &str, network: Network) -> Result<Self> {
        let mnemonic = Mnemonic::from_str(mnemonic_str)?;
        let seed = mnemonic.to_seed(Some(""))?;
        
        let bip_network = match network {
            Network::Mainnet => BipNetwork::Bitcoin,
            Network::Testnet | Network::Regtest | Network::Signet => BipNetwork::Testnet,
        };
        
        let master_key = ExtendedPrivateKey::new_master_from_seed(seed.as_bytes(), bip_network)?;
        
        Ok(Wallet {
            master_key,
            network,
            subaccounts: Arc::new(Mutex::new(HashMap::new())),
            address_manager: AddressManager::new(),
            next_subaccount_id: Arc::new(Mutex::new(0)),
        })
    }

    /// Create a new subaccount with the specified address type.
    ///
    /// This method creates a new subaccount within the wallet, each with its own
    /// address generation and balance tracking. Subaccounts allow organizing funds
    /// by purpose or address type.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the subaccount
    /// * `subaccount_type` - Type of addresses this subaccount will generate
    ///
    /// # Returns
    ///
    /// Returns the unique subaccount ID on success, or a [`GdkError`] if creation fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use gdk_rs::wallet::{Wallet, SubaccountType};
    /// use gdk_rs::primitives::address::Network;
    ///
    /// let wallet = Wallet::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Network::Testnet)?;
    ///
    /// // Create different types of subaccounts
    /// let legacy_id = wallet.create_subaccount("Legacy Account".to_string(), SubaccountType::Legacy)?;
    /// let segwit_id = wallet.create_subaccount("SegWit Account".to_string(), SubaccountType::NativeSegwit)?;
    /// let wrapped_id = wallet.create_subaccount("Wrapped SegWit".to_string(), SubaccountType::SegwitWrapped)?;
    ///
    /// println!("Created subaccounts: {}, {}, {}", legacy_id, segwit_id, wrapped_id);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Address Types
    ///
    /// - [`SubaccountType::Legacy`]: P2PKH addresses (1...)
    /// - [`SubaccountType::SegwitWrapped`]: P2SH-wrapped SegWit addresses (3...)
    /// - [`SubaccountType::NativeSegwit`]: Native SegWit addresses (bc1...)
    /// - [`SubaccountType::NativeSegwitMultisig`]: Native SegWit multisig addresses
    pub fn create_subaccount(
        &self,
        name: String,
        subaccount_type: SubaccountType,
    ) -> Result<u32> {
        let mut next_id = self.next_subaccount_id.lock().unwrap();
        let subaccount_id = *next_id;
        *next_id += 1;
        drop(next_id);

        // Derive the extended key for this subaccount
        let base_path = subaccount_type.base_path(self.network, subaccount_id);
        let subaccount_key = self.master_key.derive_path(&base_path)?;
        let extended_pubkey = subaccount_key.extended_public_key();

        // Create the subaccount
        let mut subaccount = Subaccount::new(
            subaccount_id,
            name,
            subaccount_type,
            self.network,
            extended_pubkey.clone(),
        );

        // Register with address manager
        self.address_manager.register_subaccount(subaccount_id, extended_pubkey);

        // Generate initial addresses
        self.address_manager.ensure_addresses(&mut subaccount)?;

        // Store the subaccount
        let mut subaccounts = self.subaccounts.lock().unwrap();
        subaccounts.insert(subaccount_id, subaccount);

        Ok(subaccount_id)
    }

    /// Get all subaccounts
    pub fn get_subaccounts(&self) -> Vec<Subaccount> {
        let subaccounts = self.subaccounts.lock().unwrap();
        subaccounts.values().cloned().collect()
    }

    /// Get a specific subaccount
    pub fn get_subaccount(&self, subaccount_id: u32) -> Option<Subaccount> {
        let subaccounts = self.subaccounts.lock().unwrap();
        subaccounts.get(&subaccount_id).cloned()
    }

    /// Update subaccount metadata
    pub fn update_subaccount(&self, subaccount_id: u32, name: Option<String>, hidden: Option<bool>) -> Result<()> {
        let mut subaccounts = self.subaccounts.lock().unwrap();
        let subaccount = subaccounts
            .get_mut(&subaccount_id)
            .ok_or_else(|| GdkError::invalid_input_simple("Subaccount not found".to_string()))?;

        if let Some(name) = name {
            subaccount.name = name;
        }
        if let Some(hidden) = hidden {
            subaccount.hidden = hidden;
        }

        Ok(())
    }

    /// Get the next receiving address for a subaccount
    pub fn get_receive_address(&self, subaccount_id: u32) -> Result<String> {
        let mut subaccounts = self.subaccounts.lock().unwrap();
        let subaccount = subaccounts
            .get_mut(&subaccount_id)
            .ok_or_else(|| GdkError::invalid_input_simple("Subaccount not found".to_string()))?;

        // Find the next unused receiving address
        let addresses = self.address_manager.get_addresses(subaccount_id);
        let next_unused = addresses
            .iter()
            .filter(|addr| !addr.is_change && !addr.used)
            .min_by_key(|addr| addr.address_index);

        if let Some(addr_info) = next_unused {
            Ok(addr_info.address.clone())
        } else {
            // Generate a new address if none available
            let addr_info = self.address_manager.generate_address(
                subaccount,
                false,
                subaccount.next_receive_index,
            )?;
            subaccount.next_receive_index += 1;
            Ok(addr_info.address)
        }
    }

    /// Get all previous addresses for a subaccount
    pub fn get_previous_addresses(&self, subaccount_id: u32) -> Result<Vec<AddressInfo>> {
        Ok(self.address_manager.get_addresses(subaccount_id))
    }

    /// Update subaccount balance from network data
    pub fn update_subaccount_balance(
        &self,
        subaccount_id: u32,
        confirmed: u64,
        unconfirmed: u64,
        utxo_count: u32,
    ) -> Result<()> {
        let mut subaccounts = self.subaccounts.lock().unwrap();
        let subaccount = subaccounts
            .get_mut(&subaccount_id)
            .ok_or_else(|| GdkError::invalid_input_simple("Subaccount not found".to_string()))?;

        subaccount.update_balance(confirmed, unconfirmed, utxo_count);
        Ok(())
    }

    /// Synchronize subaccount with network state
    pub fn sync_subaccount(&self, subaccount_id: u32) -> Result<()> {
        // This would typically involve:
        // 1. Fetching address usage from the network
        // 2. Updating address information
        // 3. Calculating new balances
        // 4. Generating new addresses if needed
        
        // For now, just mark as synced
        let mut subaccounts = self.subaccounts.lock().unwrap();
        let subaccount = subaccounts
            .get_mut(&subaccount_id)
            .ok_or_else(|| GdkError::invalid_input_simple("Subaccount not found".to_string()))?;

        subaccount.last_sync = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        Ok(())
    }

    /// Get wallet identifier (fingerprint of master key)
    pub fn get_wallet_identifier(&self) -> String {
        let fingerprint = self.master_key.fingerprint();
        hex::encode(fingerprint.as_bytes())
    }

    /// Get the master extended public key
    pub fn get_master_xpub(&self) -> String {
        self.master_key.extended_public_key().to_string()
    }
}
