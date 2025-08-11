# Cargo Features Documentation

This document describes the optional features available in the gdk-rs crate and how to use them.

## Available Features

### `hardware-wallets`

Enables support for hardware wallet devices such as Ledger, Trezor, Coldcard, BitBox, KeepKey, and Jade.

**What it includes:**
- Hardware wallet device abstraction (`HardwareWallet` trait)
- Device discovery and connection management
- PSBT signing via hardware devices
- Address verification on device screens
- Device-specific authentication flows

**Usage:**
```toml
[dependencies]
gdk-rs = { version = "0.1", features = ["hardware-wallets"] }
```

### `tor-support`

Enables Tor proxy integration for enhanced privacy when connecting to Bitcoin/Liquid network nodes.

**What it includes:**
- SOCKS5 proxy support
- Onion service connections
- Tor circuit management and rotation
- Tor-specific error handling and fallbacks

**Usage:**
```toml
[dependencies]
gdk-rs = { version = "0.1", features = ["tor-support"] }
```

### `liquid-network`

Enables Liquid Network specific functionality including confidential transactions and asset management.

**What it includes:**
- Confidential transaction support
- Asset registry and metadata management
- Asset issuance and reissuance
- Transaction blinding/unblinding
- Range proof generation and verification

**Usage:**
```toml
[dependencies]
gdk-rs = { version = "0.1", features = ["liquid-network"] }
```

### `compression`

Enables optional compression support for network communications.

**What it includes:**
- DEFLATE compression for WebSocket messages
- Reduced bandwidth usage

**Usage:**
```toml
[dependencies]
gdk-rs = { version = "0.1", features = ["compression"] }
```

## Feature Combinations

Features can be combined as needed:

```toml
[dependencies]
# Enable all features
gdk-rs = { version = "0.1", features = ["hardware-wallets", "tor-support", "liquid-network", "compression"] }

# Bitcoin-only with hardware wallet support
gdk-rs = { version = "0.1", features = ["hardware-wallets"] }

# Liquid with Tor privacy
gdk-rs = { version = "0.1", features = ["liquid-network", "tor-support"] }
```

## Default Configuration

By default, no optional features are enabled. This provides a minimal Bitcoin-only wallet implementation without hardware wallet support, Tor integration, or Liquid Network functionality.

## Conditional Compilation

When using feature-gated functionality in your code, you may need to use conditional compilation:

```rust
#[cfg(feature = "hardware-wallets")]
use gdk_rs::hw::{HardwareWallet, HardwareWalletManager};

#[cfg(feature = "liquid-network")]
use gdk_rs::assets::{AssetRegistry, AssetManager};

#[cfg(feature = "tor-support")]
use gdk_rs::tor::{TorManager, TorConfig};
```

## Feature Dependencies

Some features may have additional system requirements:

- **hardware-wallets**: May require USB permissions on Linux systems
- **tor-support**: Requires a running Tor daemon or the ability to start one
- **liquid-network**: No additional system requirements

## Testing with Features

To run tests with specific features enabled:

```bash
# Test with hardware wallet support
cargo test --features hardware-wallets

# Test with all features
cargo test --all-features

# Test specific feature combinations
cargo test --features "liquid-network,tor-support"
```

## Building Documentation

To build documentation with all features enabled:

```bash
cargo doc --all-features --open
```

This ensures that documentation for all feature-gated modules is generated.
