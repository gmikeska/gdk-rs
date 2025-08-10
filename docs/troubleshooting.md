# Troubleshooting Guide

This guide helps you diagnose and resolve common issues when using `gdk-rs`.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Connection Problems](#connection-problems)
- [Authentication Failures](#authentication-failures)
- [Transaction Issues](#transaction-issues)
- [Performance Problems](#performance-problems)
- [Hardware Wallet Issues](#hardware-wallet-issues)
- [Logging and Debugging](#logging-and-debugging)
- [Common Error Messages](#common-error-messages)

## Installation Issues

### Compilation Errors

**Problem:** Compilation fails with dependency errors.

```
error: failed to resolve dependencies
```

**Solution:**
1. Ensure you're using a compatible Rust version:
   ```bash
   rustc --version  # Should be 1.70.0 or later
   ```

2. Update your `Cargo.toml`:
   ```toml
   [dependencies]
   gdk-rs = "0.1"
   tokio = { version = "1.0", features = ["full"] }
   serde = { version = "1.0", features = ["derive"] }
   ```

3. Clean and rebuild:
   ```bash
   cargo clean
   cargo build
   ```

### Missing System Dependencies

**Problem:** Linking errors during compilation.

**Solution:**
Install required system libraries:

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev
```

**macOS:**
```bash
brew install openssl pkg-config
```

**Windows:**
Ensure you have Visual Studio Build Tools installed.

### Feature Flag Issues

**Problem:** Compilation errors related to optional features.

**Solution:**
Enable required features explicitly:
```toml
[dependencies]
gdk-rs = { version = "0.1", features = ["hardware-wallets", "tor-support"] }
```

## Connection Problems

### WebSocket Connection Failures

**Problem:** Cannot connect to Green backend servers.

```rust
Error: Network("WebSocket connection failed")
```

**Diagnosis:**
```rust
use gdk_rs::{Session, GdkConfig};
use gdk_rs::types::ConnectParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init(); // Enable logging
    
    let mut session = Session::new(GdkConfig::default());
    
    let connect_params = ConnectParams {
        chain_id: "testnet".to_string(),
        user_agent: Some("Debug/1.0".to_string()),
        ..Default::default()
    };
    
    // Try different endpoints
    let endpoints = vec![
        "wss://green-backend-testnet.blockstream.com/ws",
        "wss://green-backend.blockstream.com/ws",
    ];
    
    for endpoint in endpoints {
        println!("Trying endpoint: {}", endpoint);
        match session.connect_single(&connect_params, endpoint).await {
            Ok(_) => {
                println!("Connected successfully to {}", endpoint);
                return Ok(());
            }
            Err(e) => {
                eprintln!("Failed to connect to {}: {}", endpoint, e);
            }
        }
    }
    
    eprintln!("All connection attempts failed");
    Ok(())
}
```

**Solutions:**

1. **Check network connectivity:**
   ```bash
   curl -I https://green-backend.blockstream.com
   ```

2. **Verify firewall settings:**
   Ensure WebSocket connections (port 443) are allowed.

3. **Try different endpoints:**
   ```rust
   let endpoints = vec![
       "wss://green-backend.blockstream.com/ws".to_string(),
       "wss://green-backend-tor.blockstream.com/ws".to_string(),
   ];
   session.connect(&connect_params, &endpoints).await?;
   ```

4. **Use proxy if needed:**
   ```rust
   let connect_params = ConnectParams {
       chain_id: "mainnet".to_string(),
       use_proxy: true,
       proxy: Some("socks5://127.0.0.1:9050".to_string()),
       tor_enabled: true,
       ..Default::default()
   };
   ```

### Connection Timeouts

**Problem:** Connections timeout frequently.

**Solution:**
Adjust connection configuration:
```rust
use gdk_rs::network::ConnectionConfig;
use std::time::Duration;

let connection_config = ConnectionConfig {
    connection_timeout: Duration::from_secs(30), // Increase timeout
    reconnect_delay: Duration::from_secs(10),
    max_reconnect_attempts: 10,
    ping_interval: Duration::from_secs(60),
    request_timeout: Duration::from_secs(60),
    ..Default::default()
};

let session = Session::new_with_config(GdkConfig::default(), connection_config);
```

### Proxy Connection Issues

**Problem:** Cannot connect through proxy.

**Solution:**
1. **Verify proxy settings:**
   ```bash
   curl --proxy socks5://127.0.0.1:9050 https://green-backend.blockstream.com
   ```

2. **Configure proxy correctly:**
   ```rust
   let connect_params = ConnectParams {
       chain_id: "mainnet".to_string(),
       use_proxy: true,
       proxy: Some("socks5://127.0.0.1:9050".to_string()),
       tor_enabled: true,
       ..Default::default()
   };
   ```

3. **Test without proxy first:**
   ```rust
   let connect_params = ConnectParams {
       chain_id: "mainnet".to_string(),
       use_proxy: false,
       proxy: None,
       tor_enabled: false,
       ..Default::default()
   };
   ```

## Authentication Failures

### Invalid Mnemonic

**Problem:** Login fails with mnemonic error.

```rust
Error: Auth("Invalid mnemonic phrase")
```

**Solution:**
1. **Verify mnemonic format:**
   ```rust
   use gdk_rs::bip39::Mnemonic;
   
   let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
   
   // Validate mnemonic before using
   match Mnemonic::from_str(mnemonic_str) {
       Ok(_) => println!("Mnemonic is valid"),
       Err(e) => eprintln!("Invalid mnemonic: {}", e),
   }
   ```

2. **Check word count:**
   ```rust
   let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
   if words.len() != 12 && words.len() != 24 {
       eprintln!("Mnemonic must be 12 or 24 words, got {}", words.len());
   }
   ```

3. **Verify checksum:**
   The last word contains a checksum. Ensure all words are from the BIP39 wordlist.

### PIN Authentication Issues

**Problem:** PIN login fails.

**Solution:**
1. **Verify PIN data structure:**
   ```rust
   use gdk_rs::types::{LoginCredentials, PinData};
   
   let pin_data = PinData {
       encrypted_data: "your_encrypted_data".to_string(),
       pin_identifier: "your_pin_id".to_string(),
       salt: "your_salt".to_string(),
   };
   
   // Ensure all fields are properly populated
   if pin_data.encrypted_data.is_empty() {
       eprintln!("Encrypted data is empty");
   }
   ```

2. **Check PIN format:**
   ```rust
   let pin = "1234";
   if pin.len() < 4 || pin.len() > 8 {
       eprintln!("PIN must be 4-8 digits");
   }
   ```

### Hardware Wallet Authentication

**Problem:** Hardware wallet not detected or authentication fails.

**Solution:**
1. **Check device connection:**
   ```rust
   // Enable hardware wallet feature
   #[cfg(feature = "hardware-wallets")]
   {
       use gdk_rs::hw::detect_devices;
       
       let devices = detect_devices().await?;
       if devices.is_empty() {
           eprintln!("No hardware wallets detected");
       } else {
           println!("Found {} devices", devices.len());
       }
   }
   ```

2. **Verify device permissions:**
   On Linux, ensure udev rules are set up for hardware wallets.

## Transaction Issues

### Insufficient Funds

**Problem:** Transaction creation fails due to insufficient balance.

```rust
Error: Transaction("Insufficient funds")
```

**Solution:**
1. **Check available balance:**
   ```rust
   let subaccounts = session.get_subaccounts().await?;
   for subaccount in &subaccounts.subaccounts {
       let balance_btc = subaccount.satoshi.get("btc").unwrap_or(&0) as f64 / 100_000_000.0;
       println!("Subaccount {}: {} BTC", subaccount.pointer, balance_btc);
   }
   ```

2. **Check UTXOs:**
   ```rust
   use gdk_rs::protocol::GetUnspentOutputsParams;
   
   let utxo_params = GetUnspentOutputsParams {
       subaccount: 0,
       num_confs: Some(1),
   };
   
   let utxos = session.get_unspent_outputs(&utxo_params).await?;
   let total_value: u64 = utxos.unspent_outputs.iter().map(|u| u.satoshi).sum();
   println!("Total UTXO value: {} sats", total_value);
   ```

3. **Account for fees:**
   ```rust
   let fee_estimate = 1000; // sats per vbyte
   let tx_size_estimate = 250; // vbytes
   let estimated_fee = fee_estimate * tx_size_estimate;
   
   if total_value < (amount + estimated_fee) {
       eprintln!("Insufficient funds including fees");
   }
   ```

### High Fee Rates

**Problem:** Transaction fees are unexpectedly high.

**Solution:**
1. **Check current fee rates:**
   ```rust
   let fee_estimates = session.get_fee_estimates().await?;
   println!("Current fee rates: {:?}", fee_estimates);
   ```

2. **Use appropriate fee rate:**
   ```rust
   let mut params = CreateTransactionParams {
       subaccount: 0,
       addressees: vec![addressee],
       fee_rate: Some(1000), // 1 sat/vbyte for low priority
       send_all: false,
       utxos: None,
   };
   ```

3. **Optimize transaction size:**
   - Use native SegWit addresses (lower fees)
   - Consolidate UTXOs when fees are low
   - Use appropriate address types

### Transaction Broadcasting Failures

**Problem:** Transaction broadcast fails.

**Solution:**
1. **Verify transaction validity:**
   ```rust
   // Check if transaction is properly signed
   if !psbt.is_complete() {
       eprintln!("Transaction is not fully signed");
   }
   ```

2. **Check network connectivity:**
   ```rust
   let connection_state = session.get_connection_state().await;
   println!("Connection state: {:?}", connection_state);
   ```

3. **Retry with different endpoint:**
   ```rust
   match session.broadcast_transaction(&transaction).await {
       Ok(txid) => println!("Broadcasted: {}", txid),
       Err(e) => {
           eprintln!("Broadcast failed: {}", e);
           // Try reconnecting and retrying
           session.reconnect().await?;
           let txid = session.broadcast_transaction(&transaction).await?;
           println!("Retry successful: {}", txid);
       }
   }
   ```

## Performance Problems

### Slow Connection Establishment

**Problem:** Connections take too long to establish.

**Solution:**
1. **Use connection pooling:**
   ```rust
   let endpoints = vec![
       "wss://green-backend-1.blockstream.com/ws".to_string(),
       "wss://green-backend-2.blockstream.com/ws".to_string(),
       "wss://green-backend-3.blockstream.com/ws".to_string(),
   ];
   
   // Connect to multiple endpoints simultaneously
   session.connect(&connect_params, &endpoints).await?;
   ```

2. **Optimize connection configuration:**
   ```rust
   let connection_config = ConnectionConfig {
       max_connections: 3,
       connection_timeout: Duration::from_secs(5),
       reconnect_delay: Duration::from_secs(1),
       ..Default::default()
   };
   ```

### High Memory Usage

**Problem:** Application uses excessive memory.

**Solution:**
1. **Limit notification history:**
   ```rust
   use gdk_rs::notifications::NotificationConfig;
   
   let notification_config = NotificationConfig {
       max_history_size: 100, // Limit history
       enable_persistence: false, // Disable if not needed
       ..Default::default()
   };
   
   let session = Session::new_with_notification_config(config, notification_config);
   ```

2. **Clean up resources:**
   ```rust
   // Unsubscribe from notifications when done
   session.unsubscribe(subscription_id).await?;
   
   // Disconnect session when finished
   session.disconnect().await?;
   ```

### Slow Transaction Processing

**Problem:** Transaction operations are slow.

**Solution:**
1. **Use batch operations:**
   ```rust
   // Generate multiple addresses concurrently
   let address_futures: Vec<_> = (0..10).map(|_| {
       session.get_receive_address(&address_params)
   }).collect();
   
   let addresses = futures::future::join_all(address_futures).await;
   ```

2. **Cache frequently used data:**
   ```rust
   // Cache subaccounts to avoid repeated API calls
   static SUBACCOUNTS_CACHE: std::sync::Mutex<Option<SubaccountsList>> = std::sync::Mutex::new(None);
   ```

## Hardware Wallet Issues

### Device Not Detected

**Problem:** Hardware wallet is not recognized.

**Solution:**
1. **Check USB connection:**
   - Ensure device is properly connected
   - Try different USB ports/cables
   - Verify device is unlocked

2. **Install device drivers:**
   - Windows: Install device-specific drivers
   - Linux: Set up udev rules
   - macOS: Usually works out of the box

3. **Check device permissions:**
   ```bash
   # Linux - Add user to plugdev group
   sudo usermod -a -G plugdev $USER
   ```

### Signing Failures

**Problem:** Hardware wallet fails to sign transactions.

**Solution:**
1. **Verify transaction on device:**
   - Check all transaction details on device screen
   - Ensure addresses and amounts are correct
   - Confirm the transaction on the device

2. **Check derivation paths:**
   ```rust
   // Ensure correct derivation paths are used
   let derivation_path = DerivationPath::from_str("m/84'/0'/0'/0/0")?;
   ```

3. **Update device firmware:**
   - Ensure hardware wallet has latest firmware
   - Check manufacturer's update instructions

## Logging and Debugging

### Enable Detailed Logging

```rust
// Add to Cargo.toml
// env_logger = "0.10"

// In your main function
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    
    // Your code here
}
```

Set log level with environment variable:
```bash
RUST_LOG=debug cargo run
RUST_LOG=gdk_rs=trace cargo run
RUST_LOG=gdk_rs::session=debug cargo run
```

### Debug Connection Issues

```rust
use log::{debug, info, warn, error};

async fn debug_connection(session: &Session) {
    loop {
        let state = session.get_state().await;
        let connection_state = session.get_connection_state().await;
        
        debug!("Session state: {:?}", state);
        debug!("Connection state: {:?}", connection_state);
        
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
```

### Capture Network Traffic

For debugging network issues, you can capture WebSocket traffic:

```bash
# Using tcpdump
sudo tcpdump -i any -s 0 -w gdk_traffic.pcap host green-backend.blockstream.com

# Using Wireshark
# Filter: websocket or tcp.port == 443
```

## Common Error Messages

### "Connection refused"

**Cause:** Cannot reach the server.
**Solution:** Check network connectivity and firewall settings.

### "Authentication failed"

**Cause:** Invalid credentials or expired session.
**Solution:** Verify credentials and re-authenticate.

### "Invalid transaction"

**Cause:** Transaction validation failed.
**Solution:** Check transaction parameters and UTXO availability.

### "Insufficient funds"

**Cause:** Not enough balance for transaction + fees.
**Solution:** Check balance and reduce amount or fees.

### "Network timeout"

**Cause:** Request took too long to complete.
**Solution:** Increase timeout values or check connection stability.

### "Hardware wallet error"

**Cause:** Communication with hardware device failed.
**Solution:** Check device connection and permissions.

## Getting Help

If you continue to experience issues:

1. **Check the logs:** Enable debug logging to get detailed information
2. **Review documentation:** Ensure you're following the correct API usage
3. **Test with minimal example:** Isolate the problem with a simple test case
4. **Check network connectivity:** Verify you can reach Green backend servers
5. **Update dependencies:** Ensure you're using the latest version of `gdk-rs`

For additional support, provide:
- Complete error messages and stack traces
- Minimal reproducible example
- System information (OS, Rust version, etc.)
- Network configuration details
- Log output with debug level enabled