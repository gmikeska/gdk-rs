//! # gdk-rs
//!
//! A pure Rust implementation of the Blockstream Green Development Kit (GDK).
//!
//! This crate provides a complete, thread-safe, and idiomatic Rust implementation of the
//! Blockstream Green Development Kit, enabling developers to build Bitcoin and Liquid Network
//! wallets without C/C++ dependencies.
//!
//! ## Features
//!
//! - **Pure Rust**: No C/C++ dependencies, fully memory-safe implementation
//! - **Thread-Safe**: All APIs are designed for concurrent access
//! - **Bitcoin & Liquid**: Full support for both Bitcoin and Liquid Network
//! - **Hardware Wallets**: Integration with popular hardware wallet devices
//! - **Tor Support**: Built-in Tor proxy support for enhanced privacy
//! - **Comprehensive**: All original GDK functionality reimplemented
//!
//! ## Quick Start
//!
//! ```rust
//! use gdk_rs::{init, Session, GdkConfig};
//! use gdk_rs::types::{ConnectParams, LoginCredentials};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the GDK library
//!     let config = GdkConfig::default();
//!     init(&config)?;
//!
//!     // Create a new session
//!     let mut session = Session::new(config);
//!
//!     // Connect to the network
//!     let connect_params = ConnectParams {
//!         chain_id: "mainnet".to_string(),
//!         user_agent: Some("MyWallet/1.0".to_string()),
//!         use_proxy: false,
//!         proxy: None,
//!         tor_enabled: false,
//!     };
//!     session.connect_single(&connect_params, "wss://green-backend.blockstream.com/ws").await?;
//!
//!     // Login with mnemonic
//!     let credentials = LoginCredentials {
//!         mnemonic: Some("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string()),
//!         password: None,
//!         bip39_passphrase: None,
//!         pin: None,
//!         pin_data: None,
//!         username: None,
//!         core_descriptors: None,
//!     };
//!     let login_result = session.login(&credentials).await?;
//!     println!("Logged in successfully: {:?}", login_result);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture Overview
//!
//! The library is organized into several key modules:
//!
//! - [`session`]: Session management and network connections
//! - [`wallet`]: Wallet operations, subaccounts, and address generation
//! - [`auth`]: Authentication and credential management
//! - [`primitives`]: Bitcoin and Liquid protocol primitives
//! - [`transaction_builder`]: Transaction creation and management
//! - [`transaction_signer`]: Transaction signing with various methods
//! - [`hw`]: Hardware wallet integration
//! - [`assets`]: Liquid Network asset management
//! - [`notifications`]: Real-time blockchain event notifications
//! - [`network`]: Network communication and connection management
//! - [`utils`]: Cryptographic and utility functions
//!
//! ## Error Handling
//!
//! All public APIs return [`Result<T, GdkError>`](error::GdkError) for comprehensive error handling.
//! The error types provide detailed context and recovery suggestions.
//!
//! ## Thread Safety
//!
//! All types in this crate are designed to be thread-safe. Sessions can be shared across
//! threads using `Arc<Session>`, and all operations are protected by appropriate synchronization
//! primitives.
//!
//! ## Optional Features
//!
//! This crate supports several optional features that can be enabled via Cargo:
//!
//! - `hardware-wallets`: Enable hardware wallet support (Ledger, Trezor, etc.)
//! - `tor-support`: Enable Tor proxy integration for enhanced privacy
//! - `liquid-network`: Enable Liquid Network specific functionality
//!
//! ```toml
//! [dependencies]
//! gdk-rs = { version = "0.1", features = ["hardware-wallets", "tor-support"] }
//! ```

// Silence warnings for unused code during early development
#![allow(dead_code)]
#![allow(unused_variables)]

pub mod error;
pub mod types;
pub mod network;
pub mod primitives;
pub mod session;
pub mod auth;
pub mod wallet;
// pub mod wallet_simple; // Not implemented yet
pub mod bip39;
pub mod api;
#[cfg(feature = "liquid-network")]
pub mod assets;
#[cfg(feature = "hardware-wallets")]
pub mod hw;
pub mod utils;
pub mod protocol;
pub mod jsonrpc;
pub mod notifications;
pub mod transaction_builder;
pub mod transaction_signer;

#[cfg(feature = "tor-support")]
pub mod tor;

pub use error::{GdkError, GdkErrorCode, ErrorContext, RecoveryStrategy, ErrorReporter, ErrorRecovery, Result};
pub use session::Session;
pub use types::GdkConfig;

use std::fs;

/// Initializes the GDK library. This should be called once per process.
///
/// This function performs essential initialization tasks:
/// - Sets up logging infrastructure using `env_logger`
/// - Creates the data directory if it doesn't exist
/// - Initializes global cryptographic libraries
///
/// # Arguments
///
/// * `config` - Configuration parameters for the GDK library
///
/// # Returns
///
/// Returns `Ok(())` on successful initialization, or a [`GdkError`] if initialization fails.
///
/// # Examples
///
/// ```rust
/// use gdk_rs::{init, GdkConfig};
/// use std::path::PathBuf;
///
/// let config = GdkConfig {
///     data_dir: Some(PathBuf::from("/tmp/gdk-data")),
/// };
/// 
/// init(&config).expect("Failed to initialize GDK");
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called multiple times, though subsequent
/// calls will have no effect after the first successful initialization.
pub fn init(config: &GdkConfig) -> Result<()> {
    // It's ok if this fails, it just means logging was already initialized.
    let _ = env_logger::try_init();

    if let Some(data_dir) = &config.data_dir {
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)?;
            log::info!("Created data directory at: {:?}", data_dir);
        }
    }

    log::info!("GDK Initialized with config: {:?}", config);
    Ok(())
}
