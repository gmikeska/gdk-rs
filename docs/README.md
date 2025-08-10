# GDK-RS Documentation

Welcome to the comprehensive documentation for `gdk-rs`, a pure Rust implementation of the Blockstream Green Development Kit (GDK).

## Table of Contents

- [Getting Started](getting-started.md)
- [API Reference](api-reference.md)
- [Examples](examples/)
- [Migration Guide](migration-guide.md)
- [Troubleshooting](troubleshooting.md)
- [FAQ](faq.md)

## Quick Links

- **[Getting Started Guide](getting-started.md)**: Step-by-step instructions for setting up and using gdk-rs
- **[API Reference](api-reference.md)**: Complete API documentation with examples
- **[Basic Examples](examples/basic-usage.md)**: Simple examples to get you started
- **[Advanced Examples](examples/advanced-usage.md)**: Complex scenarios and best practices
- **[Migration Guide](migration-guide.md)**: How to migrate from the original C/C++ GDK
- **[Troubleshooting](troubleshooting.md)**: Common issues and solutions

## Overview

`gdk-rs` is a complete, thread-safe, and idiomatic Rust implementation of the Blockstream Green Development Kit. It provides all the functionality needed to build Bitcoin and Liquid Network wallets without any C/C++ dependencies.

### Key Features

- **Pure Rust**: No C/C++ dependencies, fully memory-safe
- **Thread-Safe**: All APIs designed for concurrent access
- **Bitcoin & Liquid**: Full support for both networks
- **Hardware Wallets**: Integration with popular devices
- **Tor Support**: Built-in privacy features
- **Comprehensive**: All original GDK functionality

### Architecture

The library is organized into several key modules:

- **Session Management**: Connection handling and state management
- **Wallet Operations**: Subaccounts, addresses, and balance tracking
- **Authentication**: Multiple authentication methods
- **Transaction Engine**: Creation, signing, and broadcasting
- **Hardware Wallet Integration**: External device support
- **Network Communication**: WebSocket and JSON-RPC protocols
- **Cryptographic Primitives**: Bitcoin and Liquid protocol implementation

## Getting Help

- Check the [FAQ](faq.md) for common questions
- Review the [Troubleshooting Guide](troubleshooting.md) for common issues
- Look at the [Examples](examples/) for practical usage patterns
- Consult the [API Reference](api-reference.md) for detailed function documentation

## Contributing

This documentation is part of the `gdk-rs` project. If you find errors or have suggestions for improvements, please contribute to the project repository.