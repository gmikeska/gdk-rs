# API Reference

This document provides comprehensive API documentation for all public interfaces in `gdk-rs`.

## Table of Contents

- [Core Functions](#core-functions)
- [Session Management](#session-management)
- [Wallet Operations](#wallet-operations)
- [Authentication](#authentication)
- [Transaction Management](#transaction-management)
- [Hardware Wallet Integration](#hardware-wallet-integration)
- [Network Communication](#network-communication)
- [Cryptographic Utilities](#cryptographic-utilities)
- [Error Handling](#error-handling)
- [Type Definitions](#type-definitions)

## Core Functions

### `init(config: &GdkConfig) -> Result<()>`

Initializes the GDK library. Must be called once per process before using any other functionality.

**Parameters:**
- `config`: Configuration parameters for the GDK library

**Returns:**
- `Ok(())` on success
- `GdkError` if initialization fails

**Example:**
```rust
use gdk_rs::{init, GdkConfig};

let config = GdkConfig::default();
init(&config)?;
```

## Session Management

### `Session`

The primary interface for interacting with Bitcoin and Liquid networks.

#### `Session::new(config: GdkConfig) -> Self`

Creates a new session with default configuration.

**Parameters:**
- `config`: Session configuration parameters

**Returns:**
- New `Session` instance

**Example:**
```rust
use gdk_rs::{Session, GdkConfig};

let session = Session::new(GdkConfig::default());
```

#### `Session::connect(&mut self, params: &ConnectParams, urls: &[String]) -> Result<()>`

Connects to Green backend servers with failover support.

**Parameters:**
- `params`: Connection parameters including network settings
- `urls`: Array of WebSocket URLs for failover

**Returns:**
- `Ok(())` on successful connection
- `GdkError::Network` if all connections fail

**Example:**
```rust
let connect_params = ConnectParams {
    chain_id: "mainnet".to_string(),
    user_agent: Some("MyWallet/1.0".to_string()),
    use_proxy: false,
    proxy: None,
    tor_enabled: false,
};

let endpoints = vec![
    "wss://green-backend.blockstream.com/ws".to_string(),
    "wss://green-backend-tor.blockstream.com/ws".to_string(),
];

session.connect(&connect_params, &endpoints).await?;
```

#### `Session::connect_single(&mut self, params: &ConnectParams, url: &str) -> Result<()>`

Connects to a single Green backend server.

**Parameters:**
- `params`: Connection parameters
- `url`: WebSocket URL to connect to

**Returns:**
- `Ok(())` on successful connection
- `GdkError::Network` if connection fails

#### `Session::login(&self, credentials: &LoginCredentials) -> Result<RegisterLoginResult>`

Authenticates with the session using provided credentials.

**Parameters:**
- `credentials`: Authentication credentials (mnemonic, PIN, hardware wallet, etc.)

**Returns:**
- `RegisterLoginResult` containing wallet information
- `GdkError::Auth` if authentication fails

**Example:**
```rust
let credentials = LoginCredentials {
    mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
    ..Default::default()
};

let result = session.login(&credentials).await?;
println!("Wallet ID: {}", result.wallet_hash_id);
```

#### `Session::subscribe(&self) -> broadcast::Receiver<Notification>`

Subscribes to all notifications from the session.

**Returns:**
- `broadcast::Receiver<Notification>` for receiving notifications

**Example:**
```rust
let mut notifications = session.subscribe();

while let Ok(notification) = notifications.recv().await {
    match notification {
        Notification::Block { height, .. } => {
            println!("New block: {}", height);
        }
        Notification::Transaction { txid, .. } => {
            println!("Transaction update: {}", txid);
        }
        _ => {}
    }
}
```

#### `Session::subscribe_filtered(&self, filter: NotificationFilter) -> Result<(Uuid, broadcast::Receiver<Notification>)>`

Subscribes to filtered notifications with advanced filtering options.

**Parameters:**
- `filter`: Notification filter configuration

**Returns:**
- Tuple of subscription ID and notification receiver
- `GdkError` if subscription fails

#### `Session::get_subaccounts(&self) -> Result<SubaccountsList>`

Retrieves all subaccounts for the authenticated wallet.

**Returns:**
- `SubaccountsList` containing all subaccounts
- `GdkError` if not authenticated or request fails

#### `Session::get_transactions(&self, params: &GetTransactionsParams) -> Result<Vec<TransactionListItem>>`

Retrieves transaction history with pagination.

**Parameters:**
- `params`: Transaction query parameters (subaccount, pagination, etc.)

**Returns:**
- Vector of transaction list items
- `GdkError` if request fails

#### `Session::create_transaction(&self, params: &mut CreateTransactionParams) -> Result<PartiallySignedTransaction>`

Creates an unsigned transaction.

**Parameters:**
- `params`: Transaction creation parameters (outputs, fee rate, etc.)

**Returns:**
- `PartiallySignedTransaction` ready for signing
- `GdkError` if transaction creation fails

#### `Session::sign_transaction(&self, psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction>`

Signs a transaction using the wallet's keys.

**Parameters:**
- `psbt`: Partially signed transaction to sign

**Returns:**
- Signed `PartiallySignedTransaction`
- `GdkError` if signing fails

#### `Session::broadcast_transaction(&self, transaction: &Transaction) -> Result<String>`

Broadcasts a transaction to the network.

**Parameters:**
- `transaction`: Complete transaction to broadcast

**Returns:**
- Transaction ID (txid) as string
- `GdkError` if broadcast fails

#### `Session::send_transaction(&self, params: &mut CreateTransactionParams) -> Result<String>`

Creates, signs, and broadcasts a transaction in one call.

**Parameters:**
- `params`: Transaction creation parameters

**Returns:**
- Transaction ID (txid) as string
- `GdkError` if any step fails

#### `Session::disconnect(&mut self) -> Result<()>`

Disconnects from the server and cleans up resources.

**Returns:**
- `Ok(())` on successful disconnection
- `GdkError` if cleanup fails

## Wallet Operations

### `Wallet`

Hierarchical deterministic wallet with subaccount management.

#### `Wallet::from_mnemonic(mnemonic: &str, network: Network) -> Result<Self>`

Creates a wallet from a BIP39 mnemonic seed phrase.

**Parameters:**
- `mnemonic`: Valid BIP39 mnemonic (12 or 24 words)
- `network`: Bitcoin network (Mainnet, Testnet, etc.)

**Returns:**
- New `Wallet` instance
- `GdkError` if mnemonic is invalid

#### `Wallet::create_subaccount(&self, name: String, subaccount_type: SubaccountType) -> Result<u32>`

Creates a new subaccount with the specified address type.

**Parameters:**
- `name`: Human-readable name for the subaccount
- `subaccount_type`: Type of addresses to generate

**Returns:**
- Subaccount ID (u32)
- `GdkError` if creation fails

#### `Wallet::get_receive_address(&self, subaccount_id: u32) -> Result<String>`

Gets the next unused receiving address for a subaccount.

**Parameters:**
- `subaccount_id`: ID of the subaccount

**Returns:**
- Bitcoin address as string
- `GdkError` if subaccount not found

#### `Wallet::get_previous_addresses(&self, subaccount_id: u32) -> Result<Vec<AddressInfo>>`

Gets all previously generated addresses with usage information.

**Parameters:**
- `subaccount_id`: ID of the subaccount

**Returns:**
- Vector of `AddressInfo` structures
- `GdkError` if subaccount not found

### `SubaccountType`

Enumeration of supported address types.

#### Variants

- `Legacy`: P2PKH addresses (1...)
- `SegwitWrapped`: P2SH-wrapped SegWit addresses (3...)
- `NativeSegwit`: Native SegWit addresses (bc1...)
- `NativeSegwitMultisig`: Native SegWit multisig addresses

#### Methods

- `purpose(&self) -> u32`: Returns BIP purpose number
- `name(&self) -> &'static str`: Returns human-readable name

## Authentication

### `LoginCredentials`

Structure containing authentication credentials.

#### Fields

- `mnemonic: Option<String>`: BIP39 mnemonic seed phrase
- `password: Option<String>`: Password for encrypted wallets
- `bip39_passphrase: Option<String>`: BIP39 passphrase
- `pin: Option<String>`: PIN for PIN-protected wallets
- `pin_data: Option<PinData>`: Encrypted PIN data
- `username: Option<String>`: Username for watch-only wallets
- `core_descriptors: Option<Vec<String>>`: Descriptors for watch-only wallets

### `PinData`

Structure for PIN-based authentication data.

#### Fields

- `encrypted_data: String`: Encrypted wallet data
- `pin_identifier: String`: PIN identifier
- `salt: String`: Cryptographic salt

## Transaction Management

### `CreateTransactionParams`

Parameters for creating transactions.

#### Fields

- `subaccount: u32`: Source subaccount ID
- `addressees: Vec<Addressee>`: Transaction outputs
- `fee_rate: Option<u64>`: Fee rate in satoshis per byte
- `send_all: bool`: Whether to send all available funds
- `utxos: Option<Vec<UnspentOutput>>`: Specific UTXOs to use

### `Addressee`

Transaction output specification.

#### Fields

- `address: String`: Destination address
- `satoshi: u64`: Amount in satoshis
- `asset_id: Option<String>`: Asset ID for Liquid transactions

### `PartiallySignedTransaction`

Represents a PSBT (Partially Signed Bitcoin Transaction).

#### Methods

- `is_complete(&self) -> bool`: Checks if all inputs are signed
- `extract_transaction(&self) -> Result<Transaction>`: Extracts final transaction

## Hardware Wallet Integration

### `HardwareWallet` Trait

Interface for hardware wallet devices.

#### Required Methods

- `get_master_xpub(&self) -> Result<ExtendedPublicKey>`: Gets master public key
- `sign_transaction(&self, psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction>`: Signs transaction
- `get_address(&self, path: &DerivationPath) -> Result<Address>`: Gets address for path
- `display_address(&self, path: &DerivationPath) -> Result<bool>`: Shows address on device

## Network Communication

### `Connection`

WebSocket connection to Green backend.

#### Methods

- `new(url: &str, notification_sender: broadcast::Sender<Notification>) -> Result<Self>`: Creates connection
- `call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>`: Makes JSON-RPC call
- `close(&mut self) -> Result<()>`: Closes connection

### `ConnectionPool`

Manages multiple connections with failover.

#### Methods

- `new(endpoints: Vec<ConnectionEndpoint>, config: ConnectionConfig, notification_sender: broadcast::Sender<Notification>) -> Self`: Creates pool
- `connect(&self) -> Result<()>`: Establishes connections
- `call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>`: Makes load-balanced call

## Cryptographic Utilities

### Hash Functions

- `sha256(data: &[u8]) -> [u8; 32]`: SHA-256 hash
- `ripemd160(data: &[u8]) -> [u8; 20]`: RIPEMD-160 hash
- `hash160(data: &[u8]) -> [u8; 20]`: Bitcoin hash160 (RIPEMD160(SHA256(data)))

### Key Derivation

- `pbkdf2(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8])`: PBKDF2 key derivation
- `hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32]`: HMAC-SHA256

### Random Generation

- `secure_random(size: usize) -> Vec<u8>`: Cryptographically secure random bytes

## Error Handling

### `GdkError`

Main error type for all GDK operations.

#### Variants

- `Network(String)`: Network-related errors
- `Auth(String)`: Authentication failures
- `Transaction(String)`: Transaction-related errors
- `HardwareWallet(String)`: Hardware wallet errors
- `Crypto(String)`: Cryptographic errors
- `InvalidInput(String)`: Invalid input parameters
- `Persistence(String)`: Data storage errors
- `Json(serde_json::Error)`: JSON serialization errors
- `Io(std::io::Error)`: I/O errors

#### Methods

- `code(&self) -> GdkErrorCode`: Gets error code for compatibility
- `recovery_strategy(&self) -> RecoveryStrategy`: Gets suggested recovery action

## Type Definitions

### `Result<T>`

Type alias for `std::result::Result<T, GdkError>`.

### `GdkConfig`

Main configuration structure.

#### Fields

- `data_dir: Option<PathBuf>`: Directory for persistent data

### `ConnectParams`

Connection parameters for Green backend.

#### Fields

- `chain_id: String`: Network identifier ("mainnet", "testnet", etc.)
- `user_agent: Option<String>`: HTTP user agent string
- `use_proxy: bool`: Whether to use proxy
- `proxy: Option<String>`: Proxy URL
- `tor_enabled: bool`: Whether to use Tor

### `Network`

Bitcoin network enumeration.

#### Variants

- `Mainnet`: Bitcoin mainnet
- `Testnet`: Bitcoin testnet
- `Regtest`: Bitcoin regtest
- `Signet`: Bitcoin signet

This completes the comprehensive API reference. Each function and type includes detailed parameter descriptions, return values, examples, and error conditions.