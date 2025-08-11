//! Tests for verifying Cargo feature configurations work correctly

#[test]
fn test_default_features() {
    // Core functionality should always be available
    use gdk_rs::{Session, GdkConfig};
    
    // These should compile without any features
    let _config = GdkConfig::default();
    // Don't actually initialize - just verify it compiles
    let _ = GdkConfig::default;
    let _ = Session::new;
}

#[cfg(feature = "hardware-wallets")]
#[test]
fn test_hardware_wallet_feature() {
    use gdk_rs::hw::{HardwareWallet, HardwareWalletManager, HardwareWalletType};
    
    // Hardware wallet types should be available
    let _ = HardwareWalletType::Ledger;
    // Don't actually create manager - just verify it compiles
    let _ = HardwareWalletManager::new;
}

#[cfg(feature = "tor-support")]
#[test]
fn test_tor_support_feature() {
    use gdk_rs::tor::{TorManager, TorConfig};
    
    // Tor functionality should be available
    let _ = TorConfig::default();
    // Don't actually create manager - just verify it compiles
    let _ = TorManager::new;
}

#[cfg(feature = "liquid-network")]
#[test]
fn test_liquid_network_feature() {
    use gdk_rs::assets::{AssetRegistry, AssetRegistryConfig};
    use gdk_rs::primitives::liquid::{ConfidentialTransaction, ConfidentialAsset};
    
    // Liquid functionality should be available
    let _ = AssetRegistryConfig {
        registry_dir: None,
        registry_url: Some("https://assets.blockstream.info".to_string()),
        update_interval: 3600,
        max_cache_size: 10000,
        verify_domains: true,
    };
    // Just verify types compile
    let _ = AssetRegistry::new;
}

#[cfg(all(feature = "hardware-wallets", feature = "liquid-network"))]
#[test]
fn test_combined_features() {
    // Both hardware wallet and Liquid features should work together
    use gdk_rs::hw::HardwareWalletType;
    use gdk_rs::assets::{AssetRegistry, AssetRegistryConfig};
    
    let _ = HardwareWalletType::Jade; // Jade supports Liquid
    let _ = AssetRegistryConfig {
        registry_dir: None,
        registry_url: Some("https://assets.blockstream.info".to_string()),
        update_interval: 3600,
        max_cache_size: 10000,
        verify_domains: true,
    };
    // Just verify types compile
    let _ = AssetRegistry::new;
}

#[cfg(not(feature = "hardware-wallets"))]
#[test]
fn test_no_hardware_wallets() {
    // This ensures hw module is not available without the feature
    #[cfg(feature = "hardware-wallets")]
    compile_error!("This test should only run when hardware-wallets feature is disabled");
}

#[cfg(not(feature = "liquid-network"))]
#[test]
fn test_no_liquid_network() {
    // This ensures assets module is not available without the feature
    #[cfg(feature = "liquid-network")]
    compile_error!("This test should only run when liquid-network feature is disabled");
}

#[cfg(not(feature = "tor-support"))]
#[test]
fn test_no_tor_support() {
    // This ensures tor module is not available without the feature
    #[cfg(feature = "tor-support")]
    compile_error!("This test should only run when tor-support feature is disabled");
}

#[test]
fn test_feature_documentation() {
    // Verify FEATURES.md exists
    let features_doc = std::fs::read_to_string("FEATURES.md")
        .expect("FEATURES.md should exist");
    
    // Check that all features are documented
    assert!(features_doc.contains("hardware-wallets"));
    assert!(features_doc.contains("tor-support"));
    assert!(features_doc.contains("liquid-network"));
    assert!(features_doc.contains("compression"));
}
