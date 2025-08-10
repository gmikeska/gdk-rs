# Advanced Usage Examples

This document provides examples for advanced `gdk-rs` features and complex scenarios.

## Table of Contents

- [Advanced Session Management](#advanced-session-management)
- [Notification Handling](#notification-handling)
- [Transaction Broadcasting and Tracking](#transaction-broadcasting-and-tracking)
- [Hardware Wallet Integration](#hardware-wallet-integration)
- [Liquid Network Operations](#liquid-network-operations)
- [Multi-Signature Wallets](#multi-signature-wallets)
- [Error Handling and Recovery](#error-handling-and-recovery)
- [Performance Optimization](#performance-optimization)

## Advanced Session Management

### Custom Connection Configuration

```rust
use gdk_rs::{Session, GdkConfig};
use gdk_rs::network::{ConnectionConfig, ConnectionEndpoint};
use gdk_rs::types::ConnectParams;
use std::time::Duration;

async fn create_session_with_custom_config() -> Result<Session, Box<dyn std::error::Error>> {
    let config = GdkConfig::default();
    
    // Custom connection configuration
    let connection_config = ConnectionConfig {
        max_connections: 3,
        connection_timeout: Duration::from_secs(10),
        reconnect_delay: Duration::from_secs(5),
        max_reconnect_attempts: 5,
        ping_interval: Duration::from_secs(30),
        request_timeout: Duration::from_secs(30),
    };
    
    let session = Session::new_with_config(config, connection_config);
    
    let connect_params = ConnectParams {
        chain_id: "mainnet".to_string(),
        user_agent: Some("AdvancedWallet/1.0".to_string()),
        use_proxy: true,
        proxy: Some("socks5://127.0.0.1:9050".to_string()), // Tor proxy
        tor_enabled: true,
    };
    
    // Connect with multiple endpoints and priorities
    let endpoints = vec![
        "wss://green-backend.blockstream.com/ws".to_string(),
        "wss://green-backend-tor.blockstream.com/ws".to_string(),
        "wss://green-backend-backup.blockstream.com/ws".to_string(),
    ];
    
    session.connect(&connect_params, &endpoints).await?;
    
    println!("Connected with custom configuration and Tor support");
    Ok(session)
}
```

### Session State Monitoring

```rust
use gdk_rs::{Session, GdkConfig};
use gdk_rs::session::SessionState;
use tokio::time::{interval, Duration};

async fn monitor_session_state(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let mut interval = interval(Duration::from_secs(5));
    
    loop {
        interval.tick().await;
        
        let state = session.get_state().await;
        let connection_state = session.get_connection_state().await;
        
        match state {
            SessionState::Connected => {
                println!("Session connected, connection state: {:?}", connection_state);
            }
            SessionState::Disconnected => {
                println!("Session disconnected, attempting reconnection...");
                if let Err(e) = session.reconnect().await {
                    eprintln!("Reconnection failed: {}", e);
                }
            }
            SessionState::Failed => {
                println!("Session failed, manual intervention required");
                break;
            }
            _ => {
                println!("Session state: {:?}", state);
            }
        }
    }
    
    Ok(())
}
```

## Notification Handling

### Advanced Notification Filtering

```rust
use gdk_rs::{Session, GdkConfig};
use gdk_rs::protocol::{Notification, NotificationFilter};
use gdk_rs::notifications::NotificationBatch;
use tokio::time::{timeout, Duration};

async fn handle_filtered_notifications(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // Create a filter for specific notification types
    let filter = NotificationFilter::new()
        .with_blocks(true)
        .with_transactions(true)
        .with_subaccount(Some(0)) // Only notifications for subaccount 0
        .with_network_status(true);
    
    let (subscription_id, mut notifications) = session.subscribe_filtered(filter).await?;
    
    println!("Subscribed to filtered notifications (ID: {})", subscription_id);
    
    // Handle notifications with timeout
    loop {
        match timeout(Duration::from_secs(60), notifications.recv()).await {
            Ok(Ok(notification)) => {
                match notification {
                    Notification::Block { height, hash, .. } => {
                        println!("New block #{}: {}", height, hash);
                        
                        // Trigger wallet sync on new blocks
                        if let Err(e) = sync_wallet_on_new_block(session, height).await {
                            eprintln!("Failed to sync wallet: {}", e);
                        }
                    }
                    Notification::Transaction { txid, subaccount, satoshi, .. } => {
                        println!("Transaction update: {} ({} sats) for subaccount {}", 
                                 txid, satoshi, subaccount);
                        
                        // Update UI or trigger specific actions
                        handle_transaction_notification(&txid, subaccount, satoshi).await?;
                    }
                    Notification::NetworkStatus { connected, .. } => {
                        println!("Network status changed: connected = {}", connected);
                        
                        if !connected {
                            println!("Network disconnected, switching to offline mode");
                        }
                    }
                    _ => {
                        println!("Other notification: {:?}", notification);
                    }
                }
            }
            Ok(Err(e)) => {
                eprintln!("Notification error: {}", e);
                break;
            }
            Err(_) => {
                println!("No notifications received in 60 seconds, checking connection...");
                let state = session.get_state().await;
                if !matches!(state, SessionState::Connected | SessionState::Authenticated) {
                    println!("Session not connected, breaking notification loop");
                    break;
                }
            }
        }
    }
    
    // Clean up subscription
    session.unsubscribe(subscription_id).await?;
    println!("Unsubscribed from notifications");
    
    Ok(())
}

async fn sync_wallet_on_new_block(session: &Session, height: u32) -> Result<(), Box<dyn std::error::Error>> {
    println!("Syncing wallet for block height {}", height);
    
    // Refresh subaccounts to get updated balances
    let subaccounts = session.get_subaccounts().await?;
    
    for subaccount in &subaccounts.subaccounts {
        let balance_btc = subaccount.satoshi.get("btc").unwrap_or(&0) as f64 / 100_000_000.0;
        println!("Subaccount {} balance: {} BTC", subaccount.pointer, balance_btc);
    }
    
    Ok(())
}

async fn handle_transaction_notification(
    txid: &str, 
    subaccount: u32, 
    satoshi: i64
) -> Result<(), Box<dyn std::error::Error>> {
    if satoshi > 0 {
        println!("Received {} sats in transaction {}", satoshi, txid);
        // Could trigger UI notification, sound, etc.
    } else {
        println!("Sent {} sats in transaction {}", -satoshi, txid);
    }
    
    Ok(())
}
```

### Batched Notification Processing

```rust
use gdk_rs::protocol::NotificationFilter;
use gdk_rs::notifications::NotificationBatch;

async fn handle_batched_notifications(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    let filter = NotificationFilter::new()
        .with_transactions(true)
        .with_batch_size(10) // Process notifications in batches of 10
        .with_batch_timeout(Duration::from_secs(5)); // Or every 5 seconds
    
    let (subscription_id, mut batches) = session.subscribe_batched(filter).await?;
    
    while let Ok(batch) = batches.recv().await {
        println!("Processing batch of {} notifications", batch.notifications.len());
        
        // Process all notifications in the batch
        for notification in batch.notifications {
            match notification {
                Notification::Transaction { txid, .. } => {
                    // Batch process transaction notifications
                    println!("Batch processing transaction: {}", txid);
                }
                _ => {}
            }
        }
        
        // Acknowledge batch processing
        println!("Batch processed at {}", batch.timestamp);
    }
    
    session.unsubscribe(subscription_id).await?;
    Ok(())
}
```

## Transaction Broadcasting and Tracking

### Advanced Transaction Broadcasting with Confirmation Tracking

```rust
use gdk_rs::api::transactions::{TransactionStatus, RbfParams};
use gdk_rs::primitives::transaction::Transaction;
use tokio::time::{sleep, Duration};

async fn broadcast_and_track_transaction(
    session: &Session,
    transaction: &Transaction
) -> Result<(), Box<dyn std::error::Error>> {
    // Broadcast the transaction
    let txid = session.broadcast_transaction(transaction).await?;
    println!("Transaction broadcasted: {}", txid);
    
    // Track confirmation status
    let mut confirmation_count = 0;
    let target_confirmations = 6;
    
    loop {
        sleep(Duration::from_secs(30)).await; // Check every 30 seconds
        
        if let Some(status) = session.get_transaction_status(&txid).await? {
            match status {
                TransactionStatus::Pending => {
                    println!("Transaction {} is still pending", txid);
                }
                TransactionStatus::Confirmed { confirmations, block_height } => {
                    confirmation_count = confirmations;
                    println!("Transaction {} confirmed with {} confirmations at block {}", 
                             txid, confirmations, block_height);
                    
                    if confirmations >= target_confirmations {
                        println!("Transaction fully confirmed with {} confirmations!", confirmations);
                        break;
                    }
                }
                TransactionStatus::Failed { reason } => {
                    eprintln!("Transaction {} failed: {}", txid, reason);
                    break;
                }
            }
        } else {
            println!("Transaction {} not found in tracking", txid);
            break;
        }
    }
    
    // Stop tracking the transaction
    session.stop_tracking_transaction(&txid).await?;
    println!("Stopped tracking transaction {}", txid);
    
    Ok(())
}
```

### Replace-By-Fee (RBF) Transaction

```rust
use gdk_rs::protocol::{CreateTransactionParams, Addressee};
use gdk_rs::api::transactions::RbfParams;

async fn create_rbf_transaction(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // Create initial transaction with low fee
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 100000, // 0.001 BTC
        asset_id: None,
    };
    
    let mut params = CreateTransactionParams {
        subaccount: 0,
        addressees: vec![addressee.clone()],
        fee_rate: Some(500), // Low fee rate
        send_all: false,
        utxos: None,
    };
    
    // Create and broadcast initial transaction
    let psbt = session.create_transaction(&mut params).await?;
    let signed_psbt = session.sign_transaction(&psbt).await?;
    let initial_tx = session.finalize_psbt(&signed_psbt).await?;
    let initial_txid = session.broadcast_transaction(&initial_tx).await?;
    
    println!("Initial transaction broadcasted: {}", initial_txid);
    
    // Wait a bit, then replace with higher fee
    sleep(Duration::from_secs(60)).await;
    
    // Create replacement transaction with higher fee
    params.fee_rate = Some(2000); // Higher fee rate
    let new_psbt = session.create_transaction(&mut params).await?;
    let new_signed_psbt = session.sign_transaction(&new_psbt).await?;
    let new_tx = session.finalize_psbt(&new_signed_psbt).await?;
    
    // Replace the transaction
    let rbf_params = RbfParams {
        original_txid: initial_txid.clone(),
        fee_rate: 2000,
    };
    
    let replacement_txid = session.replace_transaction(&rbf_params, &new_tx).await?;
    println!("Transaction replaced: {} -> {}", initial_txid, replacement_txid);
    
    Ok(())
}
```

## Hardware Wallet Integration

### Hardware Wallet Transaction Signing

```rust
use gdk_rs::hw::HardwareWallet;
use gdk_rs::primitives::psbt::PartiallySignedTransaction;
use gdk_rs::primitives::bip32::DerivationPath;

// Mock hardware wallet implementation for example
struct MockHardwareWallet {
    device_id: String,
}

#[async_trait::async_trait]
impl HardwareWallet for MockHardwareWallet {
    async fn get_master_xpub(&self) -> Result<ExtendedPublicKey, Box<dyn std::error::Error>> {
        // In real implementation, this would communicate with the device
        println!("Getting master xpub from hardware wallet {}", self.device_id);
        // Return mock xpub
        todo!("Implement actual hardware wallet communication")
    }
    
    async fn sign_transaction(&self, psbt: &PartiallySignedTransaction) -> Result<PartiallySignedTransaction, Box<dyn std::error::Error>> {
        println!("Signing transaction on hardware wallet {}", self.device_id);
        println!("Transaction has {} inputs", psbt.inputs.len());
        
        // Display transaction details on device
        for (i, input) in psbt.inputs.iter().enumerate() {
            println!("Input {}: {} sats", i, input.witness_utxo.as_ref().map(|u| u.value).unwrap_or(0));
        }
        
        // User confirms on device
        println!("Please confirm transaction on hardware wallet...");
        
        // Return signed PSBT (mock implementation)
        Ok(psbt.clone())
    }
    
    async fn get_address(&self, path: &DerivationPath) -> Result<Address, Box<dyn std::error::Error>> {
        println!("Getting address for path {} from hardware wallet", path);
        todo!("Implement actual address derivation")
    }
    
    async fn display_address(&self, path: &DerivationPath) -> Result<bool, Box<dyn std::error::Error>> {
        println!("Displaying address for path {} on hardware wallet", path);
        // User confirms address on device screen
        Ok(true)
    }
}

async fn sign_with_hardware_wallet(
    session: &Session,
    hw_wallet: &MockHardwareWallet
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a transaction
    let addressee = Addressee {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
        satoshi: 50000,
        asset_id: None,
    };
    
    let mut params = CreateTransactionParams {
        subaccount: 0,
        addressees: vec![addressee],
        fee_rate: Some(1000),
        send_all: false,
        utxos: None,
    };
    
    // Create unsigned transaction
    let psbt = session.create_transaction(&mut params).await?;
    println!("Created unsigned transaction with {} inputs", psbt.inputs.len());
    
    // Sign with hardware wallet
    let signed_psbt = hw_wallet.sign_transaction(&psbt).await?;
    println!("Transaction signed by hardware wallet");
    
    // Finalize and broadcast
    let final_tx = session.finalize_psbt(&signed_psbt).await?;
    let txid = session.broadcast_transaction(&final_tx).await?;
    println!("Hardware wallet signed transaction broadcasted: {}", txid);
    
    Ok(())
}
```

### Multi-Device Signing Coordination

```rust
async fn coordinate_multi_device_signing(
    session: &Session,
    devices: Vec<&dyn HardwareWallet>
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a multisig transaction requiring multiple signatures
    let mut params = CreateTransactionParams {
        subaccount: 0, // Assume this is a multisig subaccount
        addressees: vec![Addressee {
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            satoshi: 100000,
            asset_id: None,
        }],
        fee_rate: Some(1000),
        send_all: false,
        utxos: None,
    };
    
    let mut psbt = session.create_transaction(&mut params).await?;
    println!("Created multisig transaction requiring {} signatures", devices.len());
    
    // Sign with each device
    for (i, device) in devices.iter().enumerate() {
        println!("Signing with device {}", i + 1);
        psbt = device.sign_transaction(&psbt).await?;
        
        // Check if we have enough signatures
        if psbt.is_complete() {
            println!("Transaction fully signed after {} devices", i + 1);
            break;
        }
    }
    
    if !psbt.is_complete() {
        return Err("Transaction not fully signed".into());
    }
    
    // Finalize and broadcast
    let final_tx = session.finalize_psbt(&psbt).await?;
    let txid = session.broadcast_transaction(&final_tx).await?;
    println!("Multisig transaction broadcasted: {}", txid);
    
    Ok(())
}
```

## Liquid Network Operations

### Asset Management

```rust
use gdk_rs::protocol::{GetAssetsParams, Asset};

async fn manage_liquid_assets(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // Refresh asset registry
    session.refresh_assets().await?;
    println!("Asset registry refreshed");
    
    // Get all known assets
    let assets_params = GetAssetsParams {
        assets_id: None, // Get all assets
        icons: true,
        refresh: false,
    };
    
    let assets = session.get_assets(&assets_params).await?;
    println!("Found {} assets", assets.assets.len());
    
    // Display asset information
    for (asset_id, asset) in &assets.assets {
        println!("Asset: {} ({})", asset.name, asset.ticker);
        println!("  ID: {}", asset_id);
        println!("  Precision: {}", asset.precision);
        println!("  Domain: {:?}", asset.domain);
        
        if let Some(domain) = &asset.domain {
            // Validate asset domain
            let is_valid = session.validate_asset_domain_name(asset_id, domain).await?;
            println!("  Domain valid: {}", is_valid);
        }
    }
    
    Ok(())
}
```

### Confidential Transactions

```rust
use gdk_rs::protocol::{CreateTransactionParams, Addressee};

async fn create_confidential_transaction(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // Create a Liquid transaction with confidential amounts
    let addressee = Addressee {
        address: "lq1qqw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(), // Liquid address
        satoshi: 100000, // This will be blinded
        asset_id: Some("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d".to_string()), // L-BTC
    };
    
    let mut params = CreateTransactionParams {
        subaccount: 0,
        addressees: vec![addressee],
        fee_rate: Some(100), // Lower fee rate for Liquid
        send_all: false,
        utxos: None,
    };
    
    // Create the transaction (automatically blinded for Liquid)
    let psbt = session.create_transaction(&mut params).await?;
    println!("Created confidential Liquid transaction");
    
    // The transaction outputs will have blinded amounts and assets
    for (i, output) in psbt.outputs.iter().enumerate() {
        println!("Output {}: Confidential amount and asset", i);
    }
    
    // Sign and broadcast
    let signed_psbt = session.sign_transaction(&psbt).await?;
    let final_tx = session.finalize_psbt(&signed_psbt).await?;
    let txid = session.broadcast_transaction(&final_tx).await?;
    
    println!("Confidential transaction broadcasted: {}", txid);
    
    Ok(())
}
```

## Error Handling and Recovery

### Comprehensive Error Handling

```rust
use gdk_rs::{GdkError, GdkErrorCode};
use gdk_rs::error::{RecoveryStrategy, ErrorReporter};

async fn handle_errors_comprehensively(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    match session.get_subaccounts().await {
        Ok(subaccounts) => {
            println!("Successfully retrieved {} subaccounts", subaccounts.subaccounts.len());
        }
        Err(e) => {
            // Detailed error handling
            match &e {
                GdkError::Network(msg) => {
                    eprintln!("Network error: {}", msg);
                    
                    // Check recovery strategy
                    match e.recovery_strategy() {
                        RecoveryStrategy::Retry => {
                            println!("Retrying operation...");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            // Retry the operation
                            return handle_errors_comprehensively(session).await;
                        }
                        RecoveryStrategy::Reconnect => {
                            println!("Attempting to reconnect...");
                            if let Err(reconnect_err) = session.reconnect().await {
                                eprintln!("Reconnection failed: {}", reconnect_err);
                            }
                        }
                        RecoveryStrategy::UserAction => {
                            println!("User action required: {}", msg);
                        }
                        RecoveryStrategy::Fatal => {
                            eprintln!("Fatal error, cannot recover: {}", msg);
                            return Err(e.into());
                        }
                    }
                }
                GdkError::Auth(msg) => {
                    eprintln!("Authentication error: {}", msg);
                    println!("Please check your credentials and try logging in again");
                }
                GdkError::Transaction(msg) => {
                    eprintln!("Transaction error: {}", msg);
                    println!("Please check transaction parameters and try again");
                }
                _ => {
                    eprintln!("Other error: {}", e);
                }
            }
            
            // Report error for telemetry
            let error_reporter = ErrorReporter::new();
            error_reporter.report_error(&e).await?;
        }
    }
    
    Ok(())
}
```

### Automatic Recovery Mechanisms

```rust
use tokio::time::{sleep, Duration};

async fn auto_recovery_session(mut session: Session) -> Result<(), Box<dyn std::error::Error>> {
    let max_retries = 3;
    let mut retry_count = 0;
    
    loop {
        match session.get_state().await {
            SessionState::Connected | SessionState::Authenticated => {
                // Session is healthy, perform operations
                if let Err(e) = perform_wallet_operations(&session).await {
                    eprintln!("Operation failed: {}", e);
                    
                    match e.recovery_strategy() {
                        RecoveryStrategy::Retry if retry_count < max_retries => {
                            retry_count += 1;
                            println!("Retrying operation ({}/{})", retry_count, max_retries);
                            sleep(Duration::from_secs(2_u64.pow(retry_count))).await; // Exponential backoff
                            continue;
                        }
                        _ => {
                            eprintln!("Max retries exceeded or unrecoverable error");
                            break;
                        }
                    }
                }
                
                // Reset retry count on success
                retry_count = 0;
            }
            SessionState::Disconnected => {
                println!("Session disconnected, attempting reconnection...");
                if let Err(e) = session.reconnect().await {
                    eprintln!("Reconnection failed: {}", e);
                    sleep(Duration::from_secs(10)).await;
                }
            }
            SessionState::Failed => {
                eprintln!("Session failed, manual intervention required");
                break;
            }
            _ => {
                println!("Session in transitional state, waiting...");
                sleep(Duration::from_secs(1)).await;
            }
        }
        
        sleep(Duration::from_secs(5)).await;
    }
    
    Ok(())
}

async fn perform_wallet_operations(session: &Session) -> Result<(), GdkError> {
    // Perform various wallet operations
    let _subaccounts = session.get_subaccounts().await?;
    // ... other operations
    Ok(())
}
```

## Performance Optimization

### Connection Pooling and Load Balancing

```rust
use gdk_rs::network::{ConnectionPool, ConnectionEndpoint};

async fn optimize_connection_performance() -> Result<(), Box<dyn std::error::Error>> {
    // Create multiple endpoints with different priorities
    let endpoints = vec![
        ConnectionEndpoint::new("wss://green-backend-1.blockstream.com/ws".to_string(), 100), // Highest priority
        ConnectionEndpoint::new("wss://green-backend-2.blockstream.com/ws".to_string(), 90),
        ConnectionEndpoint::new("wss://green-backend-3.blockstream.com/ws".to_string(), 80),
    ];
    
    let config = ConnectionConfig {
        max_connections: 3,
        connection_timeout: Duration::from_secs(5),
        reconnect_delay: Duration::from_secs(2),
        max_reconnect_attempts: 10,
        ping_interval: Duration::from_secs(30),
        request_timeout: Duration::from_secs(15),
    };
    
    let (tx, _rx) = tokio::sync::broadcast::channel(256);
    let pool = ConnectionPool::new(endpoints, config, tx);
    
    // Connect to all endpoints
    pool.connect().await?;
    
    // Make concurrent requests for better performance
    let futures = vec![
        pool.call("get_subaccounts", serde_json::json!({})),
        pool.call("get_transactions", serde_json::json!({"subaccount": 0, "first": 0, "count": 10})),
        pool.call("get_unspent_outputs", serde_json::json!({"subaccount": 0})),
    ];
    
    let results = futures::future::join_all(futures).await;
    
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(response) => println!("Request {} completed successfully", i),
            Err(e) => eprintln!("Request {} failed: {}", i, e),
        }
    }
    
    Ok(())
}
```

### Batch Operations

```rust
async fn batch_address_generation(session: &Session) -> Result<(), Box<dyn std::error::Error>> {
    // Generate multiple addresses in batch for better performance
    let mut addresses = Vec::new();
    
    // Create multiple address requests
    let address_futures: Vec<_> = (0..10).map(|i| {
        let params = GetReceiveAddressParams {
            subaccount: 0,
            address_type: Some("p2wpkh".to_string()),
        };
        session.get_receive_address(&params)
    }).collect();
    
    // Execute all requests concurrently
    let results = futures::future::join_all(address_futures).await;
    
    for (i, result) in results.into_iter().enumerate() {
        match result {
            Ok(addr_result) => {
                addresses.push(addr_result.address);
                println!("Generated address {}: {}", i + 1, addresses[i]);
            }
            Err(e) => {
                eprintln!("Failed to generate address {}: {}", i + 1, e);
            }
        }
    }
    
    println!("Generated {} addresses in batch", addresses.len());
    Ok(())
}
```

This completes the advanced usage examples, covering complex scenarios and best practices for using `gdk-rs` in production applications.