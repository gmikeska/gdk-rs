# Testing with Features

## Overview

Some tests in gdk-rs require specific features to be enabled. To simplify running all tests, we've created a `test-full` feature that combines all the features needed for testing.

## Running Tests

### Basic Tests (without feature-gated modules)
```bash
cargo test
```

### Full Test Suite (with all features)
```bash
cargo test --features test-full
```

Or use the convenient alias:
```bash
cargo test-full
```

### Testing Specific Features
```bash
# Test only hardware wallet functionality
cargo test --features hardware-wallets

# Test only Liquid Network functionality  
cargo test --features liquid-network

# Test with multiple features
cargo test --features "hardware-wallets liquid-network"
```

## Feature Gates in Test Files

Test files that depend on optional features are gated with conditional compilation:

```rust
#![cfg(feature = "hardware-wallets")]
// This entire test file only compiles when hardware-wallets feature is enabled
```

This ensures that:
- Tests compile successfully regardless of enabled features
- Feature-specific tests only run when their dependencies are available
- No import errors occur for feature-gated modules

## Feature Combinations

The `test-full` feature in `Cargo.toml` enables:
- `hardware-wallets` - Hardware wallet integration tests
- `liquid-network` - Liquid Network functionality tests

This allows running the complete test suite with a single command.
