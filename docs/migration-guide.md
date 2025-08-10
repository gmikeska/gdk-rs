# Migration Guide: From Original GDK to gdk-rs

This guide helps developers migrate from the original C/C++ GDK to the pure Rust `gdk-rs` implementation.

## Table of Contents

- [Overview](#overview)
- [Key Differences](#key-differences)
- [API Mapping](#api-mapping)
- [Code Examples](#code-examples)
- [Error Handling Changes](#error-handling-changes)
- [Threading and Async](#threading-and-async)
- [Configuration Changes](#configuration-changes)
- [Migration Checklist](#migration-checklist)

## Overview

The `gdk-rs` library provides the same functionality as the original GDK but with several improvements:

- **Pure Rust**: No C/C++ dependencies or FFI overhead
- **Async/Await**: Modern async programming model
- **Type Safety**: Strong typing with Rust's type system
- **Memory Safety**: No memory leaks or buffer overflows
- **Thread Safety**: Built-in thread safety guarantees

## Key Differences

### Language and Runtime

| Original GDK | gdk-rs |
|--------------|--------|
| C/C++ with language bindings | Pure Rust |
| Callback-based async | async/await |
| Manual memory management | Automatic memory management |
| Error codes | Result types |
| JSON strings | Strongly typed structs |

### API Style

| Original GDK | gdk-rs |
|--------------|--------|
| `GA_init()` | `gdk_rs::init()` |
| `GA_create_session()` | `Session::new()` |
| `GA_connect()` | `session.connect().await` |
| `GA_login_user()` | `session.login().await` |
| Callback functions | async functions |

## API Mapping

### Initialization

**Original GDK:**
```c
// C API
GA_json *config = GA_json_create();
GA_json_add_string(config, "datadir", "/path/to/data");
int result = GA_init(config);
GA_json_destroy(config);
```

**gdk-rs:**
```rust
// Rust API
use gdk_rs::{init, GdkConfig};
use std::path::PathBuf;

let config = GdkConfig {
    data_dir: Some(PathBuf::from("/path/to/data")),
};
init(&config)?;
```

### Session Creation and Connection

**Original GDK:**
```c
// C API
struct GA_session *session;
int result = GA_create_session(&session);

GA_json *connect_params = GA_json_create();
GA_json_add_string(connect_params, "name", "mainnet");
result = GA_connect(session, connect_params);
GA_json_destroy(connect_params);
```

**gdk-rs:**
```rust
// Rust API
use gdk_rs::{Session, GdkConfig};
use gdk_rs::types::ConnectParams;

let mut session = Session::new(GdkConfig::default());

let connect_params = ConnectParams {
    chain_id: "mainnet".to_string(),
    user_agent: Some("MyWallet/1.0".to_string()),
    use_proxy: false,
    proxy: None,
    tor_enabled: false,
};

session.connect_single(&connect_params, "wss://green-backend.blockstream.com/ws").await?;
```

### User Authentication

**Original GDK:**
```c
// C API
GA_json *credentials = GA_json_create();
GA_json_add_string(credentials, "mnemonic", "abandon abandon abandon...");

GA_json *result_json;
int result = GA_login_user(session, credentials, &result_json);

// Parse result_json manually
GA_json_destroy(credentials);
GA_json_destroy(result_json);
```

**gdk-rs:**
```rust
// Rust API
use gdk_rs::types::LoginCredentials;

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
println!("Wallet ID: {}", login_result.wallet_hash_id);
```

### Getting Subaccounts

**Original GDK:**
```c
// C API
GA_json *params = GA_json_create();
GA_json_add_boolean(params, "refresh", false);

GA_json *subaccounts_json;
int result = GA_get_subaccounts(session, params, &subaccounts_json);

// Manually parse JSON
GA_json_destroy(params);
GA_json_destroy(subaccounts_json);
```

**gdk-rs:**
```rust
// Rust API
let subaccounts = session.get_subaccounts().await?;

for subaccount in &subaccounts.subaccounts {
    println!("Subaccount {}: {} ({})", 
             subaccount.pointer, 
             subaccount.name, 
             subaccount.type_);
}
```

### Transaction Creation

**Original GDK:**
```c
// C API
GA_json *tx_params = GA_json_create();
GA_json_add_integer(tx_params, "subaccount", 0);

GA_json *addressees = GA_json_create_array();
GA_json *addressee = GA_json_create();
GA_json_add_string(addressee, "address", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
GA_json_add_integer(addressee, "satoshi", 100000);
GA_json_array_append(addressees, addressee);
GA_json_add(tx_params, "addressees", addressees);

GA_json *transaction_json;
int result = GA_create_transaction(session, tx_params, &transaction_json);

// Cleanup
GA_json_destroy(tx_params);
GA_json_destroy(transaction_json);
```

**gdk-rs:**
```rust
// Rust API
use gdk_rs::protocol::{CreateTransactionParams, Addressee};

let addressee = Addressee {
    address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
    satoshi: 100000,
    asset_id: None,
};

let mut params = CreateTransactionParams {
    subaccount: 0,
    addressees: vec![addressee],
    fee_rate: Some(1000),
    send_all: false,
    utxos: None,
};

let psbt = session.create_transaction(&mut params).await?;
```

### Notification Handling

**Original GDK:**
```c
// C API
void notification_handler(void* context, GA_json* notification) {
    // Parse JSON manually
    const char* event = GA_json_get_string(notification, "event");
    if (strcmp(event, "block") == 0) {
        int height = GA_json_get_integer(notification, "block_height");
        printf("New block: %d\n", height);
    }
}

GA_set_notification_handler(session, notification_handler, NULL);
```

**gdk-rs:**
```rust
// Rust API
use gdk_rs::protocol::Notification;

let mut notifications = session.subscribe();

tokio::spawn(async move {
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
});
```

## Code Examples

### Complete Migration Example

**Original GDK (C):**
```c
#include <gdk.h>
#include <stdio.h>

int main() {
    // Initialize
    GA_json *config = GA_json_create();
    GA_json_add_string(config, "datadir", "./data");
    int result = GA_init(config);
    GA_json_destroy(config);
    
    if (result != GA_OK) {
        printf("Init failed: %d\n", result);
        return 1;
    }
    
    // Create session
    struct GA_session *session;
    result = GA_create_session(&session);
    if (result != GA_OK) {
        printf("Session creation failed: %d\n", result);
        return 1;
    }
    
    // Connect
    GA_json *connect_params = GA_json_create();
    GA_json_add_string(connect_params, "name", "testnet");
    result = GA_connect(session, connect_params);
    GA_json_destroy(connect_params);
    
    if (result != GA_OK) {
        printf("Connection failed: %d\n", result);
        GA_destroy_session(session);
        return 1;
    }
    
    // Login
    GA_json *credentials = GA_json_create();
    GA_json_add_string(credentials, "mnemonic", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    
    GA_json *login_result;
    result = GA_login_user(session, credentials, &login_result);
    GA_json_destroy(credentials);
    
    if (result != GA_OK) {
        printf("Login failed: %d\n", result);
        GA_destroy_session(session);
        return 1;
    }
    
    printf("Login successful\n");
    GA_json_destroy(login_result);
    
    // Cleanup
    GA_disconnect(session);
    GA_destroy_session(session);
    return 0;
}
```

**gdk-rs (Rust):**
```rust
use gdk_rs::{init, Session, GdkConfig};
use gdk_rs::types::{ConnectParams, LoginCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize
    let config = GdkConfig {
        data_dir: Some("./data".into()),
    };
    init(&config)?;
    
    // Create session
    let mut session = Session::new(config);
    
    // Connect
    let connect_params = ConnectParams {
        chain_id: "testnet".to_string(),
        ..Default::default()
    };
    
    session.connect_single(&connect_params, "wss://green-backend-testnet.blockstream.com/ws").await?;
    
    // Login
    let credentials = LoginCredentials {
        mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
        ..Default::default()
    };
    
    let login_result = session.login(&credentials).await?;
    println!("Login successful: {}", login_result.wallet_hash_id);
    
    // Cleanup
    session.disconnect().await?;
    Ok(())
}
```

## Error Handling Changes

### Original GDK Error Handling

```c
// C API - Error codes
int result = GA_login_user(session, credentials, &result_json);
switch (result) {
    case GA_OK:
        printf("Success\n");
        break;
    case GA_ERROR:
        printf("Generic error\n");
        break;
    case GA_NOT_AUTHORIZED:
        printf("Authentication failed\n");
        break;
    default:
        printf("Unknown error: %d\n", result);
}
```

### gdk-rs Error Handling

```rust
// Rust API - Result types
match session.login(&credentials).await {
    Ok(login_result) => {
        println!("Success: {}", login_result.wallet_hash_id);
    }
    Err(GdkError::Auth(msg)) => {
        eprintln!("Authentication failed: {}", msg);
    }
    Err(GdkError::Network(msg)) => {
        eprintln!("Network error: {}", msg);
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

## Threading and Async

### Original GDK Threading

```c
// C API - Manual thread management
#include <pthread.h>

void* notification_thread(void* arg) {
    struct GA_session* session = (struct GA_session*)arg;
    // Handle notifications in separate thread
    return NULL;
}

pthread_t thread;
pthread_create(&thread, NULL, notification_thread, session);
```

### gdk-rs Async

```rust
// Rust API - Built-in async support
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let session = Session::new(GdkConfig::default());
    
    // Spawn async task for notifications
    let mut notifications = session.subscribe();
    tokio::spawn(async move {
        while let Ok(notification) = notifications.recv().await {
            // Handle notification
        }
    });
    
    // Other async operations
    let subaccounts = session.get_subaccounts().await?;
    
    Ok(())
}
```

## Configuration Changes

### Original GDK Configuration

```c
// C API - JSON configuration
GA_json *config = GA_json_create();
GA_json_add_string(config, "datadir", "/path/to/data");
GA_json_add_boolean(config, "log_level", 3);
GA_json_add_string(config, "proxy", "socks5://127.0.0.1:9050");
```

### gdk-rs Configuration

```rust
// Rust API - Typed configuration
use gdk_rs::{GdkConfig, Session};
use gdk_rs::network::ConnectionConfig;
use gdk_rs::types::ConnectParams;
use std::path::PathBuf;
use std::time::Duration;

let gdk_config = GdkConfig {
    data_dir: Some(PathBuf::from("/path/to/data")),
};

let connection_config = ConnectionConfig {
    max_connections: 3,
    connection_timeout: Duration::from_secs(10),
    reconnect_delay: Duration::from_secs(5),
    max_reconnect_attempts: 5,
    ping_interval: Duration::from_secs(30),
    request_timeout: Duration::from_secs(30),
};

let connect_params = ConnectParams {
    chain_id: "mainnet".to_string(),
    use_proxy: true,
    proxy: Some("socks5://127.0.0.1:9050".to_string()),
    tor_enabled: true,
    ..Default::default()
};

let session = Session::new_with_config(gdk_config, connection_config);
```

## Migration Checklist

### Pre-Migration

- [ ] Review current GDK usage patterns
- [ ] Identify all GDK API calls in your codebase
- [ ] Document current error handling strategies
- [ ] Note any custom notification handling logic
- [ ] Review threading and concurrency patterns

### During Migration

- [ ] Replace GDK initialization with `gdk_rs::init()`
- [ ] Convert session creation to `Session::new()`
- [ ] Update connection logic to use async/await
- [ ] Replace JSON parameter construction with typed structs
- [ ] Convert callback-based notifications to async streams
- [ ] Update error handling from error codes to Result types
- [ ] Replace manual threading with async tasks
- [ ] Update configuration from JSON to typed structs

### Post-Migration

- [ ] Test all wallet operations (login, transactions, etc.)
- [ ] Verify notification handling works correctly
- [ ] Test error scenarios and recovery
- [ ] Performance testing and optimization
- [ ] Update documentation and examples
- [ ] Train team on new async patterns

### Common Migration Patterns

#### JSON to Structs

```rust
// Before (Original GDK)
GA_json *params = GA_json_create();
GA_json_add_integer(params, "subaccount", 0);
GA_json_add_integer(params, "first", 0);
GA_json_add_integer(params, "count", 10);

// After (gdk-rs)
let params = GetTransactionsParams {
    subaccount: 0,
    first: 0,
    count: 10,
};
```

#### Callbacks to Async

```rust
// Before (Original GDK)
void callback(void* context, GA_json* result) {
    // Handle result
}
GA_some_async_call(session, params, callback, context);

// After (gdk-rs)
let result = session.some_async_call(&params).await?;
// Handle result directly
```

#### Error Codes to Results

```rust
// Before (Original GDK)
int result = GA_operation(session, params, &output);
if (result != GA_OK) {
    // Handle error based on error code
}

// After (gdk-rs)
match session.operation(&params).await {
    Ok(output) => {
        // Handle success
    }
    Err(error) => {
        // Handle error with full context
    }
}
```

This migration guide should help you transition from the original GDK to `gdk-rs` while taking advantage of Rust's safety and performance benefits.