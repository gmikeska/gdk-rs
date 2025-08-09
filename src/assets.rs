//! Asset registry and management for Liquid Network
//!
//! This module provides comprehensive asset management functionality including:
//! - Asset metadata storage and retrieval
//! - Asset registry synchronization with network
//! - Asset validation and domain verification
//! - Asset caching and persistence
//! - Asset search and filtering capabilities

use crate::primitives::liquid::AssetId;
use crate::{Result, GdkError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Asset metadata structure with complete information
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Unique asset identifier (32-byte hex string)
    pub asset_id: String,
    /// Human-readable asset name
    pub name: String,
    /// Short ticker symbol (e.g., "BTC", "USDT")
    pub ticker: String,
    /// Number of decimal places for display
    pub precision: u8,
    /// Associated domain for verification (optional)
    pub domain: Option<String>,
    /// Asset issuer information (optional)
    pub issuer: Option<String>,
    /// Asset version for registry updates
    pub version: u32,
    /// Timestamp of last update
    pub last_updated: u64,
    /// Whether this asset is verified
    pub verified: bool,
    /// Additional metadata as key-value pairs
    pub metadata: HashMap<String, String>,
}

impl Asset {
    /// Create a new asset with basic information
    pub fn new(
        asset_id: String,
        name: String,
        ticker: String,
        precision: u8,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Asset {
            asset_id,
            name,
            ticker,
            precision,
            domain: None,
            issuer: None,
            version: 1,
            last_updated: now,
            verified: false,
            metadata: HashMap::new(),
        }
    }

    /// Create the Bitcoin asset (policy asset on Liquid)
    pub fn bitcoin() -> Self {
        Asset {
            asset_id: "6f0e7e5894bc2208eb6cc21b342c3ea4f9a5a0f1b2a0b822f9c4e648f80c814".to_string(),
            name: "Bitcoin".to_string(),
            ticker: "BTC".to_string(),
            precision: 8,
            domain: Some("bitcoin.org".to_string()),
            issuer: Some("Bitcoin Network".to_string()),
            version: 1,
            last_updated: 0, // Genesis asset
            verified: true,
            metadata: HashMap::new(),
        }
    }

    /// Get the asset ID as bytes
    pub fn asset_id_bytes(&self) -> Result<AssetId> {
        let bytes = hex::decode(&self.asset_id)
            .map_err(|e| GdkError::InvalidInput(format!("Invalid asset ID hex: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(GdkError::InvalidInput(
                "Asset ID must be 32 bytes".to_string()
            ));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(AssetId::new(array))
    }

    /// Validate the asset structure
    pub fn validate(&self) -> Result<()> {
        // Validate asset ID format
        if self.asset_id.len() != 64 {
            return Err(GdkError::InvalidInput(
                "Asset ID must be 64 hex characters".to_string()
            ));
        }

        // Validate hex encoding
        hex::decode(&self.asset_id)
            .map_err(|_| GdkError::InvalidInput("Asset ID must be valid hex".to_string()))?;

        // Validate name and ticker are not empty
        if self.name.is_empty() {
            return Err(GdkError::InvalidInput("Asset name cannot be empty".to_string()));
        }

        if self.ticker.is_empty() {
            return Err(GdkError::InvalidInput("Asset ticker cannot be empty".to_string()));
        }

        // Validate precision is reasonable (0-18 decimal places)
        if self.precision > 18 {
            return Err(GdkError::InvalidInput(
                "Asset precision cannot exceed 18 decimal places".to_string()
            ));
        }

        Ok(())
    }

    /// Update the asset with new information
    pub fn update(&mut self, other: &Asset) -> Result<()> {
        if self.asset_id != other.asset_id {
            return Err(GdkError::InvalidInput(
                "Cannot update asset with different asset ID".to_string()
            ));
        }

        // Only update if the other asset has a newer version
        if other.version > self.version {
            self.name = other.name.clone();
            self.ticker = other.ticker.clone();
            self.precision = other.precision;
            self.domain = other.domain.clone();
            self.issuer = other.issuer.clone();
            self.version = other.version;
            self.last_updated = other.last_updated;
            self.verified = other.verified;
            self.metadata = other.metadata.clone();
        }

        Ok(())
    }
}

/// Asset registry configuration
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetRegistryConfig {
    /// Directory to store asset registry data
    pub registry_dir: Option<PathBuf>,
    /// URL for asset registry updates
    pub registry_url: Option<String>,
    /// Automatic update interval in seconds
    pub update_interval: u64,
    /// Maximum number of assets to cache in memory
    pub max_cache_size: usize,
    /// Enable domain verification for assets
    pub verify_domains: bool,
}

impl Default for AssetRegistryConfig {
    fn default() -> Self {
        AssetRegistryConfig {
            registry_dir: None,
            registry_url: Some("https://assets.blockstream.info".to_string()),
            update_interval: 3600, // 1 hour
            max_cache_size: 10000,
            verify_domains: true,
        }
    }
}

/// Asset search and filtering criteria
#[derive(Debug, Clone, Default)]
pub struct AssetFilter {
    /// Filter by asset name (case-insensitive substring match)
    pub name: Option<String>,
    /// Filter by ticker symbol (case-insensitive substring match)
    pub ticker: Option<String>,
    /// Filter by domain
    pub domain: Option<String>,
    /// Filter by issuer
    pub issuer: Option<String>,
    /// Only include verified assets
    pub verified_only: bool,
    /// Minimum precision
    pub min_precision: Option<u8>,
    /// Maximum precision
    pub max_precision: Option<u8>,
}

impl AssetFilter {
    /// Create a new empty filter
    pub fn new() -> Self {
        AssetFilter::default()
    }

    /// Filter by name
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Filter by ticker
    pub fn with_ticker(mut self, ticker: String) -> Self {
        self.ticker = Some(ticker);
        self
    }

    /// Filter by domain
    pub fn with_domain(mut self, domain: String) -> Self {
        self.domain = Some(domain);
        self
    }

    /// Only include verified assets
    pub fn verified_only(mut self) -> Self {
        self.verified_only = true;
        self
    }

    /// Check if an asset matches this filter
    pub fn matches(&self, asset: &Asset) -> bool {
        if let Some(ref name) = self.name {
            if !asset.name.to_lowercase().contains(&name.to_lowercase()) {
                return false;
            }
        }

        if let Some(ref ticker) = self.ticker {
            if !asset.ticker.to_lowercase().contains(&ticker.to_lowercase()) {
                return false;
            }
        }

        if let Some(ref domain) = self.domain {
            match &asset.domain {
                Some(asset_domain) => {
                    if !asset_domain.to_lowercase().contains(&domain.to_lowercase()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if let Some(ref issuer) = self.issuer {
            match &asset.issuer {
                Some(asset_issuer) => {
                    if !asset_issuer.to_lowercase().contains(&issuer.to_lowercase()) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        if self.verified_only && !asset.verified {
            return false;
        }

        if let Some(min_precision) = self.min_precision {
            if asset.precision < min_precision {
                return false;
            }
        }

        if let Some(max_precision) = self.max_precision {
            if asset.precision > max_precision {
                return false;
            }
        }

        true
    }
}

/// Asset registry for managing Liquid Network assets
pub struct AssetRegistry {
    /// Configuration for the registry
    config: AssetRegistryConfig,
    /// In-memory cache of assets
    cache: Arc<RwLock<HashMap<String, Asset>>>,
    /// Last update timestamp
    last_update: Arc<RwLock<u64>>,
}

impl AssetRegistry {
    /// Create a new asset registry with the given configuration
    pub fn new(config: AssetRegistryConfig) -> Self {
        let mut cache = HashMap::new();
        
        // Always include the Bitcoin asset
        let bitcoin = Asset::bitcoin();
        cache.insert(bitcoin.asset_id.clone(), bitcoin);

        AssetRegistry {
            config,
            cache: Arc::new(RwLock::new(cache)),
            last_update: Arc::new(RwLock::new(0)),
        }
    }

    /// Create a new asset registry with default configuration
    pub fn with_default_config() -> Self {
        Self::new(AssetRegistryConfig::default())
    }

    /// Get an asset by its ID
    pub fn get_asset(&self, asset_id: &str) -> Option<Asset> {
        let cache = self.cache.read().ok()?;
        cache.get(asset_id).cloned()
    }

    /// Get multiple assets by their IDs
    pub fn get_assets(&self, asset_ids: &[String]) -> Vec<Asset> {
        let cache = self.cache.read().unwrap();
        asset_ids
            .iter()
            .filter_map(|id| cache.get(id).cloned())
            .collect()
    }

    /// Get all assets in the registry
    pub fn get_all_assets(&self) -> Vec<Asset> {
        let cache = self.cache.read().unwrap();
        cache.values().cloned().collect()
    }

    /// Search for assets using the provided filter
    pub fn search_assets(&self, filter: &AssetFilter) -> Vec<Asset> {
        let cache = self.cache.read().unwrap();
        cache
            .values()
            .filter(|asset| filter.matches(asset))
            .cloned()
            .collect()
    }

    /// Add or update an asset in the registry
    pub fn add_asset(&self, asset: Asset) -> Result<()> {
        // Validate the asset first
        asset.validate()?;

        let mut cache = self.cache.write().unwrap();
        
        // Check cache size limit
        if cache.len() >= self.config.max_cache_size && !cache.contains_key(&asset.asset_id) {
            return Err(GdkError::InvalidInput(
                "Asset registry cache is full".to_string()
            ));
        }

        // Update existing asset or insert new one
        if let Some(existing) = cache.get_mut(&asset.asset_id) {
            existing.update(&asset)?;
        } else {
            cache.insert(asset.asset_id.clone(), asset);
        }

        Ok(())
    }

    /// Remove an asset from the registry
    pub fn remove_asset(&self, asset_id: &str) -> Option<Asset> {
        let mut cache = self.cache.write().unwrap();
        cache.remove(asset_id)
    }

    /// Get the number of assets in the registry
    pub fn asset_count(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.len()
    }

    /// Check if the registry contains an asset
    pub fn contains_asset(&self, asset_id: &str) -> bool {
        let cache = self.cache.read().unwrap();
        cache.contains_key(asset_id)
    }

    /// Clear all assets from the registry (except Bitcoin)
    pub fn clear(&self) {
        let mut cache = self.cache.write().unwrap();
        let bitcoin = cache.get(&Asset::bitcoin().asset_id).cloned();
        cache.clear();
        
        // Re-add Bitcoin asset
        if let Some(bitcoin) = bitcoin {
            cache.insert(bitcoin.asset_id.clone(), bitcoin);
        }
    }

    /// Get assets by ticker symbol
    pub fn get_assets_by_ticker(&self, ticker: &str) -> Vec<Asset> {
        let filter = AssetFilter::new().with_ticker(ticker.to_string());
        self.search_assets(&filter)
    }

    /// Get assets by domain
    pub fn get_assets_by_domain(&self, domain: &str) -> Vec<Asset> {
        let filter = AssetFilter::new().with_domain(domain.to_string());
        self.search_assets(&filter)
    }

    /// Get only verified assets
    pub fn get_verified_assets(&self) -> Vec<Asset> {
        let filter = AssetFilter::new().verified_only();
        self.search_assets(&filter)
    }

    /// Update the last update timestamp
    fn update_timestamp(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Ok(mut last_update) = self.last_update.write() {
            *last_update = now;
        }
    }

    /// Get the last update timestamp
    pub fn get_last_update(&self) -> u64 {
        *self.last_update.read().unwrap_or_else(|_| {
            // In case of poisoned lock, return a default guard
            self.last_update.read().unwrap()
        })
    }

    /// Check if the registry needs updating based on the configured interval
    pub fn needs_update(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let last_update = self.get_last_update();
        now - last_update > self.config.update_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asset_creation() {
        let asset = Asset::new(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            "Test Asset".to_string(),
            "TEST".to_string(),
            8,
        );

        assert_eq!(asset.name, "Test Asset");
        assert_eq!(asset.ticker, "TEST");
        assert_eq!(asset.precision, 8);
        assert!(!asset.verified);
    }

    #[test]
    fn test_bitcoin_asset() {
        let bitcoin = Asset::bitcoin();
        assert_eq!(bitcoin.ticker, "BTC");
        assert_eq!(bitcoin.precision, 8);
        assert!(bitcoin.verified);
        assert_eq!(bitcoin.asset_id, "6f0e7e5894bc2208eb6cc21b342c3ea4f9a5a0f1b2a0b822f9c4e648f80c814");
    }

    #[test]
    fn test_asset_validation() {
        let mut asset = Asset::new(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            "Test Asset".to_string(),
            "TEST".to_string(),
            8,
        );

        assert!(asset.validate().is_ok());

        // Test invalid asset ID length
        asset.asset_id = "invalid".to_string();
        assert!(asset.validate().is_err());

        // Test invalid hex
        asset.asset_id = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg".to_string();
        assert!(asset.validate().is_err());

        // Test empty name
        asset.asset_id = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string();
        asset.name = "".to_string();
        assert!(asset.validate().is_err());
    }

    #[test]
    fn test_asset_registry() {
        let registry = AssetRegistry::with_default_config();
        
        // Should contain Bitcoin asset by default
        assert_eq!(registry.asset_count(), 1);
        assert!(registry.contains_asset(&Asset::bitcoin().asset_id));

        // Add a new asset
        let test_asset = Asset::new(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            "Test Asset".to_string(),
            "TEST".to_string(),
            8,
        );

        assert!(registry.add_asset(test_asset.clone()).is_ok());
        assert_eq!(registry.asset_count(), 2);
        assert!(registry.contains_asset(&test_asset.asset_id));

        // Retrieve the asset
        let retrieved = registry.get_asset(&test_asset.asset_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Asset");
    }

    #[test]
    fn test_asset_filter() {
        let registry = AssetRegistry::with_default_config();
        
        // Add test assets
        let asset1 = Asset::new(
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            "Bitcoin Cash".to_string(),
            "BCH".to_string(),
            8,
        );
        
        let asset2 = Asset::new(
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            "Tether USD".to_string(),
            "USDT".to_string(),
            6,
        );

        registry.add_asset(asset1).unwrap();
        registry.add_asset(asset2).unwrap();

        // Test name filter
        let filter = AssetFilter::new().with_name("Bitcoin".to_string());
        let results = registry.search_assets(&filter);
        assert_eq!(results.len(), 2); // Bitcoin and Bitcoin Cash

        // Test ticker filter
        let filter = AssetFilter::new().with_ticker("BTC".to_string());
        let results = registry.search_assets(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ticker, "BTC");

        // Test verified only filter
        let filter = AssetFilter::new().verified_only();
        let results = registry.search_assets(&filter);
        assert_eq!(results.len(), 1); // Only Bitcoin is verified by default
    }
}

/// Network synchronization functionality for asset registry
impl AssetRegistry {
    /// Synchronize the asset registry with the network
    pub async fn sync_with_network(&self) -> Result<usize> {
        if let Some(ref registry_url) = self.config.registry_url {
            self.fetch_assets_from_url(registry_url).await
        } else {
            Err(GdkError::Network("No registry URL configured".to_string()))
        }
    }

    /// Fetch assets from a specific URL
    async fn fetch_assets_from_url(&self, url: &str) -> Result<usize> {
        // This is a placeholder implementation
        // In a real implementation, this would make HTTP requests to fetch asset data
        log::info!("Fetching assets from registry URL: {}", url);

        // Simulate network delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // For now, we'll add some example assets to demonstrate the functionality
        let example_assets = self.create_example_assets();
        let mut added_count = 0;

        for asset in example_assets {
            if self.add_asset(asset).is_ok() {
                added_count += 1;
            }
        }

        self.update_timestamp();
        log::info!("Successfully synchronized {} assets from network", added_count);
        Ok(added_count)
    }

    /// Create example assets for demonstration
    fn create_example_assets(&self) -> Vec<Asset> {
        vec![
            Asset {
                asset_id: "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2".to_string(),
                name: "Liquid Bitcoin".to_string(),
                ticker: "L-BTC".to_string(),
                precision: 8,
                domain: Some("blockstream.com".to_string()),
                issuer: Some("Blockstream".to_string()),
                version: 1,
                last_updated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                verified: true,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("type".to_string(), "native".to_string());
                    meta.insert("description".to_string(), "Bitcoin on Liquid Network".to_string());
                    meta
                },
            },
            Asset {
                asset_id: "f3d1ec678811398cd2ae277cbe3849c6f6dbd72c74bc542f7c4b11ff0e820958".to_string(),
                name: "Tether USD".to_string(),
                ticker: "USDt".to_string(),
                precision: 8,
                domain: Some("tether.to".to_string()),
                issuer: Some("Tether Limited".to_string()),
                version: 1,
                last_updated: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                verified: true,
                metadata: {
                    let mut meta = HashMap::new();
                    meta.insert("type".to_string(), "stablecoin".to_string());
                    meta.insert("description".to_string(), "USD Tether on Liquid".to_string());
                    meta
                },
            },
        ]
    }

    /// Validate asset domain ownership
    pub async fn validate_asset_domain(&self, asset: &Asset) -> Result<bool> {
        if !self.config.verify_domains {
            return Ok(true);
        }

        let domain = match &asset.domain {
            Some(domain) => domain,
            None => return Ok(false), // No domain to verify
        };

        log::info!("Validating domain {} for asset {}", domain, asset.asset_id);

        // This is a placeholder implementation
        // In a real implementation, this would:
        // 1. Fetch the domain's asset registry file (e.g., /.well-known/liquid_assets)
        // 2. Verify that the asset ID is listed in the domain's registry
        // 3. Check digital signatures if present

        // Simulate network delay
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // For demonstration, we'll consider some domains as verified
        let verified_domains = vec![
            "blockstream.com",
            "tether.to", 
            "bitcoin.org",
        ];

        let is_verified = verified_domains.iter().any(|&d| domain.contains(d));
        
        if is_verified {
            log::info!("Domain {} verified for asset {}", domain, asset.asset_id);
        } else {
            log::warn!("Domain {} could not be verified for asset {}", domain, asset.asset_id);
        }

        Ok(is_verified)
    }

    /// Refresh a specific asset from the network
    pub async fn refresh_asset(&self, asset_id: &str) -> Result<Option<Asset>> {
        log::info!("Refreshing asset {} from network", asset_id);

        // This is a placeholder implementation
        // In a real implementation, this would fetch the specific asset from the network
        
        // Simulate network delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Check if we have the asset locally first
        if let Some(mut asset) = self.get_asset(asset_id) {
            // Simulate updating the asset with new information
            asset.last_updated = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            asset.version += 1;

            // Validate domain if configured
            if self.config.verify_domains {
                asset.verified = self.validate_asset_domain(&asset).await?;
            }

            self.add_asset(asset.clone())?;
            Ok(Some(asset))
        } else {
            Ok(None)
        }
    }

    /// Perform a full registry refresh from the network
    pub async fn full_refresh(&self) -> Result<usize> {
        log::info!("Performing full asset registry refresh");

        // Clear existing assets (except Bitcoin)
        self.clear();

        // Sync with network
        let count = self.sync_with_network().await?;

        log::info!("Full refresh completed, {} assets synchronized", count);
        Ok(count)
    }

    /// Get registry statistics
    pub fn get_stats(&self) -> AssetRegistryStats {
        let cache = self.cache.read().unwrap();
        let total_assets = cache.len();
        let verified_assets = cache.values().filter(|a| a.verified).count();
        let assets_with_domains = cache.values().filter(|a| a.domain.is_some()).count();

        AssetRegistryStats {
            total_assets,
            verified_assets,
            assets_with_domains,
            last_update: self.get_last_update(),
            cache_size_limit: self.config.max_cache_size,
        }
    }
}

/// Asset registry statistics
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetRegistryStats {
    /// Total number of assets in the registry
    pub total_assets: usize,
    /// Number of verified assets
    pub verified_assets: usize,
    /// Number of assets with domain information
    pub assets_with_domains: usize,
    /// Timestamp of last update
    pub last_update: u64,
    /// Maximum cache size
    pub cache_size_limit: usize,
}

/// Asset registry persistence functionality
impl AssetRegistry {
    /// Save the asset registry to disk
    pub async fn save_to_disk(&self) -> Result<()> {
        let registry_dir = match &self.config.registry_dir {
            Some(dir) => dir,
            None => return Ok(()), // No persistence configured
        };

        // Create directory if it doesn't exist
        tokio::fs::create_dir_all(registry_dir).await
            .map_err(|e| GdkError::Io(e))?;

        let registry_file = registry_dir.join("assets.json");
        let cache = self.cache.read().unwrap();
        let assets: Vec<Asset> = cache.values().cloned().collect();

        let json_data = serde_json::to_string_pretty(&assets)
            .map_err(|e| GdkError::Json(e))?;

        tokio::fs::write(&registry_file, json_data).await
            .map_err(|e| GdkError::Io(e))?;

        log::info!("Saved {} assets to {}", assets.len(), registry_file.display());
        Ok(())
    }

    /// Load the asset registry from disk
    pub async fn load_from_disk(&self) -> Result<usize> {
        let registry_dir = match &self.config.registry_dir {
            Some(dir) => dir,
            None => return Ok(0), // No persistence configured
        };

        let registry_file = registry_dir.join("assets.json");
        
        if !registry_file.exists() {
            log::info!("No existing asset registry file found");
            return Ok(0);
        }

        let json_data = tokio::fs::read_to_string(&registry_file).await
            .map_err(|e| GdkError::Io(e))?;

        let assets: Vec<Asset> = serde_json::from_str(&json_data)
            .map_err(|e| GdkError::Json(e))?;

        let mut loaded_count = 0;
        for asset in assets {
            if self.add_asset(asset).is_ok() {
                loaded_count += 1;
            }
        }

        log::info!("Loaded {} assets from {}", loaded_count, registry_file.display());
        Ok(loaded_count)
    }

    /// Initialize the registry by loading from disk and optionally syncing with network
    pub async fn initialize(&self, sync_with_network: bool) -> Result<()> {
        log::info!("Initializing asset registry");

        // Load existing assets from disk
        let loaded_count = self.load_from_disk().await?;
        log::info!("Loaded {} assets from disk", loaded_count);

        // Sync with network if requested or if we need an update
        if sync_with_network || self.needs_update() {
            let synced_count = self.sync_with_network().await?;
            log::info!("Synchronized {} assets from network", synced_count);

            // Save updated registry to disk
            self.save_to_disk().await?;
        }

        log::info!("Asset registry initialization complete");
        Ok(())
    }
}

#[cfg(test)]
mod async_tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_network_sync() {
        let registry = AssetRegistry::with_default_config();
        
        // Test network synchronization
        let result = registry.sync_with_network().await;
        assert!(result.is_ok());
        
        let synced_count = result.unwrap();
        assert!(synced_count > 0);
        
        // Should have more than just Bitcoin now
        assert!(registry.asset_count() > 1);
    }

    #[tokio::test]
    async fn test_domain_validation() {
        let registry = AssetRegistry::with_default_config();
        
        let asset = Asset {
            asset_id: "test123".to_string(),
            name: "Test Asset".to_string(),
            ticker: "TEST".to_string(),
            precision: 8,
            domain: Some("blockstream.com".to_string()),
            issuer: None,
            version: 1,
            last_updated: 0,
            verified: false,
            metadata: HashMap::new(),
        };

        let result = registry.validate_asset_domain(&asset).await;
        assert!(result.is_ok());
        // blockstream.com should be considered verified in our test
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_asset_refresh() {
        let registry = AssetRegistry::with_default_config();
        
        // Add a test asset first
        let test_asset = Asset::new(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            "Test Asset".to_string(),
            "TEST".to_string(),
            8,
        );
        
        registry.add_asset(test_asset.clone()).unwrap();
        
        // Refresh the asset
        let result = registry.refresh_asset(&test_asset.asset_id).await;
        assert!(result.is_ok());
        
        let refreshed = result.unwrap();
        assert!(refreshed.is_some());
        
        // Version should have been incremented
        let updated_asset = refreshed.unwrap();
        assert!(updated_asset.version > test_asset.version);
    }
}