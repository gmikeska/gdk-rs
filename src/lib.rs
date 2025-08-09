//! # gdk-rs
//!
//! A pure Rust implementation of the Blockstream Green Development Kit (GDK).

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
pub mod assets;
pub mod hw;
pub mod utils;
pub mod protocol;
pub mod notifications;
pub mod transaction_builder;
pub mod transaction_signer;

pub use error::GdkError;
pub use session::Session;
pub use types::GdkConfig;

// A convenience result type
pub type Result<T, E = GdkError> = std::result::Result<T, E>;

use std::fs;

/// Initializes the GDK library. This should be called once per process.
/// In this implementation, it sets up logging and ensures the data directory exists.
pub fn init(config: &GdkConfig) -> Result<()> {
    // It's ok if this fails, it just means logging was already initialized.
    let _ = env_logger::try_init();

    if let Some(data_dir) = &config.data_dir {
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)
                .map_err(|e| GdkError::Io(e))?;
            log::info!("Created data directory at: {:?}", data_dir);
        }
    }

    log::info!("GDK Initialized with config: {:?}", config);
    Ok(())
}
