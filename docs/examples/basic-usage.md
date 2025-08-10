# Basic Usage Examples

This document provides practical examples for common `gdk-rs` operations.

## Table of Contents

- [Session Management](#session-management)
- [Wallet Creation and Login](#wallet-creation-and-login)
- [Address Generation](#address-generation)
- [Transaction History](#transaction-history)
- [Balance Checking](#balance-checking)
- [Simple Transaction Creation](#simple-transaction-creation)

## Session Management

### Creating and Connecting a Session

```rust
use gdk_rs::{init, Session, GdkConfig};
use gdk_rs::types::ConnectParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the library
    let config = GdkConfig::default();
    init(&config)?;
    
    // Create a session
    let mut session = Session::new(config);
    
    // Configure connection
    let connect_params = ConnectParams {
        chain_id: "testnet".to_string(),
        user_agent: Some("BasicExample/1.0".to_string()),
        use_proxy: false,
        proxy: None,
        tor_enabled: false,
    };
    
    // Connect to testnet
    session.connect_single(
        &connect_params, 
        "wss://green-backend-testnet.blockstream.com/ws"
    ).await?;
    
    println!("Connected successfully!");
    
    // Always disconnect when done
    session.disconnect().await?;
    Ok(())
}
```

### Connection with Failover

```rust
use gdk_rs::{Session, GdkConfig};
use gdk_rs::types::ConnectParams;

async fn connect_with_failover() -> Result<Session, Box<dyn std::error::Error>> {
    let mut session = Session::new(GdkConfig::default());
    
    let connect_params = ConnectParams {
        chain_id: "mainnet".to_string(),
        user_agent: Some("FailoverExample/1.0".to_string()),
        ..Default::default()
    };
    
    // Multiple endpoints for redundancy
    let endpoints = vec![
        "wss://green-backend.blockstream.com/ws".to_string(),
        "wss://green-backend-tor.blockstream.com/ws".to_string(),
        "wss://green-backend-backup.blockstream.com/ws".to_string(),
    ];
    
    session.connect(&connect_params, &endpoints).await?;
    println!("Connected with failover support");
    
    Ok(session)
}
```

## Wallet Creation and Login

### Login with Mnemonic

```rust
use gdk_rs::{Session, GdkConfig};
use gdk_rs::types::LoginCredentials;

async fn login_with_mnemonic(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = LoginCredentials {
        mnemonic: Some(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string()
        ),
        password: None,
        bip39_passphrase: None,
        pin: None,
        pin_data: None,
        username: None,
        core_descriptors: None,
    };
    
    let login_result = session.login(&credentials).await?;
    
    println!("Login successful!");
    println!("Wallet ID: {}", login_result.wallet_hash_id);
    println!("Receiving ID: {}", login_result.receiving_id);
    
    Ok(())
}
```

### Login with BIP39 Passphrase

```rust
use gdk_rs::types::LoginCredentials;

async fn login_with_passphrase(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let credentials = LoginCredentials {
        mnemonic: Some(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string()
        ),
        bip39_passphrase: Some("my_secure_passphrase".to_string()),
        ..Default::default()
    };
    
    let login_result = session.login(&credentials).await?;
    println!("Login with passphrase successful! Wallet ID: {}", login_result.wallet_hash_id);
    
    Ok(())
}
```

### Login with PIN

```rust
use gdk_rs::types::{LoginCredentials, PinData};

async fn login_with_pin(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // PIN data would typically be stored from a previous registration
    let pin_data = PinData {
        encrypted_data: "encrypted_wallet_data_here".to_string(),
        pin_identifier: "unique_pin_id".to_string(),
        salt: "cryptographic_salt".to_string(),
    };
    
    let credentials = LoginCredentials {
        pin: Some("1234".to_string()),
        pin_data: Some(pin_data),
        ..Default::default()
    };
    
    let login_result = session.login(&credentials).await?;
    println!("PIN login successful! Wallet ID: {}", login_result.wallet_hash_id);
    
    Ok(())
}
```

## Address Generation

### Get Receiving Address

```rust
use gdk_rs::protocol::GetReceiveAddressParams;

async fn get_receiving_address(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let address_params = GetReceiveAddressParams {
        subaccount: 0,
        address_type: Some("p2wpkh".to_string()), // Native SegWit
    };
    
    let address_result = session.get_receive_address(&address_params).await?;
    
    println!("Receiving address: {}", address_result.address);
    println!("Address pointer: {}", address_result.pointer);
    println!("Subaccount: {}", address_result.subaccount);
    
    Ok(())
}
```

### Get Multiple Addresses

```rust
async fn get_multiple_addresses(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // Get addresses for different address types
    let address_types = vec![
        ("p2pkh", "Legacy"),
        ("p2sh-segwit", "SegWit Wrapped"),
        ("p2wpkh", "Native SegWit"),
    ];
    
    for (addr_type, name) in address_types {
        let params = GetReceiveAddressParams {
            subaccount: 0,
            address_type: Some(addr_type.to_string()),
        };
        
        let result = session.get_receive_address(&params).await?;
        println!("{} address: {}", name, result.address);
    }
    
    Ok(())
}
```

### Get Previous Addresses

```rust
use gdk_rs::protocol::GetPreviousAddressesParams;

async fn get_previous_addresses(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let params = GetPreviousAddressesParams {
        subaccount: 0,
        last_pointer: None,
    };
    
    let addresses = session.get_previous_addresses(&params).await?;
    
    println!("Found {} previous addresses", addresses.list.len());
    
    for addr in addresses.list.iter().take(5) {
        println!("Address: {}, Used: {}, Pointer: {}", 
                 addr.address, 
                 addr.user_path.is_some(), 
                 addr.pointer);
    }
    
    Ok(())
}
```

## Transaction History

### Get Recent Transactions

```rust
use gdk_rs::protocol::GetTransactionsParams;

async fn get_recent_transactions(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let params = GetTransactionsParams {
        subaccount: 0,
        first: 0,
        count: 10,
    };
    
    let transactions = session.get_transactions(&params).await?;
    
    println!("Found {} transactions", transactions.len());
    
    for tx in transactions {
        let amount_btc = tx.satoshi as f64 / 100_000_000.0;
        let status = if tx.block_height > 0 { "Confirmed" } else { "Unconfirmed" };
        
        println!("TX: {} | {} BTC | {} | Block: {}", 
                 &tx.txhash[..8], 
                 amount_btc, 
                 status, 
                 tx.block_height);
    }
    
    Ok(())
}
```

### Get Transaction Details

```rust
use gdk_rs::protocol::GetTransactionDetailsParams;

async fn get_transaction_details(
    session: &Session, 
    txid: &str
) -> Result<(), Box<dyn std::error::Error>> {
    let params = GetTransactionDetailsParams {
        txhash: txid.to_string(),
    };
    
    let details = session.get_transaction_details(&params).await?;
    
    println!("Transaction Details:");
    println!("  TXID: {}", details.txhash);
    println!("  Amount: {} BTC", details.satoshi as f64 / 100_000_000.0);
    println!("  Fee: {} sats", details.fee);
    println!("  Block Height: {}", details.block_height);
    println!("  Confirmations: {}", details.confirmations);
    println!("  Transaction Type: {}", details.type_);
    
    Ok(())
}
```

## Balance Checking

### Get Subaccount Balance

```rust
async fn get_balance(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let subaccounts = session.get_subaccounts().await?;
    
    for subaccount in &subaccounts.subaccounts {
        let confirmed_btc = subaccount.satoshi.get("btc").unwrap_or(&0) as f64 / 100_000_000.0;
        
        println!("Subaccount '{}': {} BTC", 
                 subaccount.name, 
                 confirmed_btc);
    }
    
    Ok(())
}
```

### Get UTXO Information

```rust
use gdk_rs::protocol::GetUnspentOutputsParams;

async fn get_utxos(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let params = GetUnspentOutputsParams {
        subaccount: 0,
        num_confs: Some(1), // Only confirmed UTXOs
    };
    
    let utxos = session.get_unspent_outputs(&params).await?;
    
    println!("Found {} UTXOs", utxos.unspent_outputs.len());
    
    let mut total_value = 0u64;
    for utxo in &utxos.unspent_outputs {
        total_value += utxo.satoshi;
        println!("UTXO: {}:{} | {} sats | {} confirmations", 
                 &utxo.txhash[..8], 
                 utxo.pt_idx, 
                 utxo.satoshi,
                 utxo.confirmations);
    }
    
    println!("Total UTXO value: {} BTC", total_value as f64 / 100_000_000.0);
    
    Ok(())
}
```

## Simple Transaction Creation

### Create a Basic Transaction

```rust
use gdk_rs::protocol::{CreateTransactionParams, Addressee};

async fn create_simple_transaction(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // Define the recipient
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(), // Testnet address
        satoshi: 50000, // 0.0005 BTC
        asset_id: None, // Bitcoin (not Liquid asset)
    };
    
    let mut params = CreateTransactionParams {
        subaccount: 0,
        addressees: vec![addressee],
        fee_rate: Some(1000), // 1000 sat/vB
        send_all: false,
        utxos: None, // Let the system choose UTXOs
    };
    
    // Create the transaction
    let psbt = session.create_transaction(&mut params).await?;
    
    println!("Transaction created successfully!");
    println!("Transaction has {} inputs and {} outputs", 
             psbt.inputs.len(), 
             psbt.outputs.len());
    
    // Sign the transaction
    let signed_psbt = session.sign_transaction(&psbt).await?;
    
    println!("Transaction signed successfully!");
    
    // Note: In a real application, you would broadcast the transaction here
    // let txid = session.broadcast_transaction(&final_tx).await?;
    
    Ok(())
}
```

### Send All Funds

```rust
use gdk_rs::protocol::{CreateTransactionParams, Addressee};

async fn send_all_funds(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 0, // Will be calculated automatically
        asset_id: None,
    };
    
    let mut params = CreateTransactionParams {
        subaccount: 0,
        addressees: vec![addressee],
        fee_rate: Some(1000),
        send_all: true, // Send all available funds
        utxos: None,
    };
    
    let psbt = session.create_transaction(&mut params).await?;
    let signed_psbt = session.sign_transaction(&psbt).await?;
    
    println!("Send-all transaction created and signed!");
    println!("This transaction will send all available funds minus fees");
    
    Ok(())
}
```

## Complete Example: Basic Wallet Operations

```rust
use gdk_rs::{init, Session, GdkConfig};
use gdk_rs::types::{ConnectParams, LoginCredentials};
use gdk_rs::protocol::{GetReceiveAddressParams, GetTransactionsParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize
    let config = GdkConfig::default();
    init(&config)?;
    
    // Create and connect session
    let mut session = Session::new(config);
    let connect_params = ConnectParams {
        chain_id: "testnet".to_string(),
        user_agent: Some("BasicWalletExample/1.0".to_string()),
        ..Default::default()
    };
    
    session.connect_single(
        &connect_params, 
        "wss://green-backend-testnet.blockstream.com/ws"
    ).await?;
    
    // Login
    let credentials = LoginCredentials {
        mnemonic: Some(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string()
        ),
        ..Default::default()
    };
    
    let login_result = session.login(&credentials).await?;
    println!("✓ Logged in (Wallet ID: {})", login_result.wallet_hash_id);
    
    // Get subaccounts and show balances
    let subaccounts = session.get_subaccounts().await?;
    println!("✓ Found {} subaccounts", subaccounts.subaccounts.len());
    
    for subaccount in &subaccounts.subaccounts {
        let balance_btc = subaccount.satoshi.get("btc").unwrap_or(&0) as f64 / 100_000_000.0;
        println!("  {}: {} BTC", subaccount.name, balance_btc);
    }
    
    // Get a receiving address
    let address_params = GetReceiveAddressParams {
        subaccount: 0,
        address_type: Some("p2wpkh".to_string()),
    };
    let address_result = session.get_receive_address(&address_params).await?;
    println!("✓ Receiving address: {}", address_result.address);
    
    // Get recent transactions
    let tx_params = GetTransactionsParams {
        subaccount: 0,
        first: 0,
        count: 5,
    };
    let transactions = session.get_transactions(&tx_params).await?;
    println!("✓ Found {} recent transactions", transactions.len());
    
    for tx in transactions.iter().take(3) {
        let amount_btc = tx.satoshi as f64 / 100_000_000.0;
        println!("  {}: {} BTC", &tx.txhash[..8], amount_btc);
    }
    
    // Clean up
    session.disconnect().await?;
    println!("✓ Disconnected successfully");
    
    Ok(())
}
```

This completes the basic usage examples. These examples demonstrate the most common operations you'll perform with `gdk-rs`. For more advanced scenarios, see the [Advanced Usage Examples](advanced-usage.md).