# Getting Started with GDK-RS

This guide will help you get up and running with `gdk-rs` quickly. We'll cover installation, basic setup, and your first wallet operations.

## Installation

Add `gdk-rs` to your `Cargo.toml`:

```toml
[dependencies]
gdk-rs = "0.1"
tokio = { version = "1.0", features = ["full"] }
```

### Optional Features

Enable additional features as needed:

```toml
[dependencies]
gdk-rs = { version = "0.1", features = ["hardware-wallets", "tor-support", "liquid-network"] }
```

Available features:
- `hardware-wallets`: Support for Ledger, Trezor, and other hardware wallets
- `tor-support`: Tor proxy integration for enhanced privacy
- `liquid-network`: Liquid Network specific functionality

## Basic Setup

### 1. Initialize the Library

```rust
use gdk_rs::{init, GdkConfig};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the GDK library
    let config = GdkConfig {
        data_dir: Some(PathBuf::from("./wallet-data")),
    };
    
    // Initialize the library (call once per process)
    init(&config)?;
    
    println!("GDK initialized successfully!");
    Ok(())
}
```

### 2. Create and Connect a Session

```rust
use gdk_rs::{init, Session, GdkConfig};
use gdk_rs::types::ConnectParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize
    let config = GdkConfig::default();
    init(&config)?;
    
    // Create a session
    let mut session = Session::new(config);
    
    // Configure connection parameters
    let connect_params = ConnectParams {
        chain_id: "testnet".to_string(),
        user_agent: Some("MyWallet/1.0".to_string()),
        use_proxy: false,
        proxy: None,
        tor_enabled: false,
    };
    
    // Connect to the Green backend
    session.connect_single(&connect_params, "wss://green-backend-testnet.blockstream.com/ws").await?;
    
    println!("Connected to Green backend!");
    Ok(())
}
```

### 3. Authenticate with a Wallet

```rust
use gdk_rs::{init, Session, GdkConfig};
use gdk_rs::types::{ConnectParams, LoginCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize and connect (as above)
    let config = GdkConfig::default();
    init(&config)?;
    
    let mut session = Session::new(config);
    let connect_params = ConnectParams {
        chain_id: "testnet".to_string(),
        ..Default::default()
    };
    session.connect_single(&connect_params, "wss://green-backend-testnet.blockstream.com/ws").await?;
    
    // Login with a mnemonic
    let credentials = LoginCredentials {
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        password: None,
        bip39_passphrase: None,
        pin: None,
        pin_data: None,
        username: None,
        core_descriptors: None,
    };
    
    let login_result = session.login(&credentials).await?;
    println!("Logged in successfully! Wallet ID: {}", login_result.wallet_hash_id);
    
    Ok(())
}
```

## Your First Wallet Operations

### Get Subaccounts

```rust
// Get all subaccounts
let subaccounts = session.get_subaccounts().await?;
println!("Found {} subaccounts", subaccounts.subaccounts.len());

for subaccount in &subaccounts.subaccounts {
    println!("Subaccount {}: {} ({})", 
             subaccount.pointer, 
             subaccount.name, 
             subaccount.type_);
}
```

### Generate a Receiving Address

```rust
use gdk_rs::protocol::GetReceiveAddressParams;

// Get a receiving address for the first subaccount
let address_params = GetReceiveAddressParams {
    subaccount: 0,
    address_type: Some("p2wpkh".to_string()),
};

let address_result = session.get_receive_address(&address_params).await?;
println!("Receiving address: {}", address_result.address);
```

### Check Transaction History

```rust
use gdk_rs::protocol::GetTransactionsParams;

// Get recent transactions
let tx_params = GetTransactionsParams {
    subaccount: 0,
    first: 0,
    count: 10,
};

let transactions = session.get_transactions(&tx_params).await?;
println!("Found {} transactions", transactions.len());

for tx in transactions {
    println!("Transaction {}: {} BTC", tx.txhash, tx.satoshi as f64 / 100_000_000.0);
}
```

## Complete Example

Here's a complete example that demonstrates the basic workflow:

```rust
use gdk_rs::{init, Session, GdkConfig};
use gdk_rs::types::{ConnectParams, LoginCredentials};
use gdk_rs::protocol::{GetTransactionsParams, GetReceiveAddressParams};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize the library
    let config = GdkConfig::default();
    init(&config)?;
    
    // 2. Create and connect session
    let mut session = Session::new(config);
    let connect_params = ConnectParams {
        chain_id: "testnet".to_string(),
        user_agent: Some("GettingStarted/1.0".to_string()),
        ..Default::default()
    };
    
    session.connect_single(&connect_params, "wss://green-backend-testnet.blockstream.com/ws").await?;
    println!("✓ Connected to Green backend");
    
    // 3. Login with mnemonic
    let credentials = LoginCredentials {
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        ..Default::default()
    };
    
    let login_result = session.login(&credentials).await?;
    println!("✓ Logged in successfully (Wallet ID: {})", login_result.wallet_hash_id);
    
    // 4. Get subaccounts
    let subaccounts = session.get_subaccounts().await?;
    println!("✓ Found {} subaccounts", subaccounts.subaccounts.len());
    
    // 5. Get a receiving address
    let address_params = GetReceiveAddressParams {
        subaccount: 0,
        address_type: Some("p2wpkh".to_string()),
    };
    let address_result = session.get_receive_address(&address_params).await?;
    println!("✓ Receiving address: {}", address_result.address);
    
    // 6. Check transaction history
    let tx_params = GetTransactionsParams {
        subaccount: 0,
        first: 0,
        count: 5,
    };
    let transactions = session.get_transactions(&tx_params).await?;
    println!("✓ Found {} recent transactions", transactions.len());
    
    // 7. Clean up
    session.disconnect().await?;
    println!("✓ Disconnected successfully");
    
    Ok(())
}
```

## Next Steps

Now that you have the basics working, you can explore more advanced features:

- **[Transaction Creation](examples/transactions.md)**: Learn how to create and send transactions
- **[Hardware Wallets](examples/hardware-wallets.md)**: Integrate with hardware signing devices
- **[Notifications](examples/notifications.md)**: Handle real-time blockchain events
- **[Liquid Network](examples/liquid.md)**: Work with Liquid assets and confidential transactions
- **[Advanced Authentication](examples/authentication.md)**: PIN-based and watch-only wallets

## Common Issues

If you encounter problems, check the [Troubleshooting Guide](troubleshooting.md) for solutions to common issues.

## Environment Setup

### Development Environment

For development, you might want to use testnet or regtest:

```rust
// Testnet configuration
let connect_params = ConnectParams {
    chain_id: "testnet".to_string(),
    ..Default::default()
};

// Regtest configuration (for local testing)
let connect_params = ConnectParams {
    chain_id: "regtest".to_string(),
    ..Default::default()
};
```

### Logging

Enable logging to see what's happening:

```rust
// Add to Cargo.toml
// env_logger = "0.10"

// In your main function
env_logger::init();
```

Set the log level with the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug cargo run
RUST_LOG=gdk_rs=info cargo run
```

This completes the getting started guide. You should now have a working setup and understand the basic workflow for using `gdk-rs`.