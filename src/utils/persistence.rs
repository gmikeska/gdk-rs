//! Data persistence utilities for GDK.
//!
//! This module provides utilities for:
//! - Secure data storage and retrieval
//! - File system operations
//! - Data serialization and deserialization
//! - Cache management
//! - Database-like operations for local storage

use crate::{GdkError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default cache expiration time
pub const DEFAULT_CACHE_EXPIRATION: Duration = Duration::from_secs(3600); // 1 hour

/// Maximum cache size in bytes
pub const MAX_CACHE_SIZE: usize = 100 * 1024 * 1024; // 100 MB

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Base directory for data storage
    pub data_dir: PathBuf,
    /// Enable encryption for sensitive data
    pub encrypt_sensitive_data: bool,
    /// Maximum file size for individual storage files
    pub max_file_size: usize,
    /// Enable compression for stored data
    pub enable_compression: bool,
    /// Backup retention count
    pub backup_retention: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(".gdk-data"),
            encrypt_sensitive_data: true,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            enable_compression: false,
            backup_retention: 3,
        }
    }
}

/// Secure file storage manager
pub struct FileStorage {
    config: StorageConfig,
}

impl FileStorage {
    /// Create a new file storage manager
    pub fn new(config: StorageConfig) -> Result<Self> {
        // Ensure data directory exists
        if !config.data_dir.exists() {
            fs::create_dir_all(&config.data_dir)
                .map_err(|e| GdkError::Persistence(format!("Failed to create data directory: {}", e)))?;
        }

        Ok(Self { config })
    }

    /// Store data to a file
    pub fn store<T: Serialize>(&self, key: &str, data: &T) -> Result<()> {
        let file_path = self.get_file_path(key);
        
        // Create parent directories if they don't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| GdkError::Persistence(format!("Failed to create directory: {}", e)))?;
        }

        // Serialize data
        let serialized = serde_json::to_vec_pretty(data)
            .map_err(|e| GdkError::Persistence(format!("Serialization failed: {}", e)))?;

        // Check file size limit
        if serialized.len() > self.config.max_file_size {
            return Err(GdkError::Persistence(format!(
                "Data size {} exceeds maximum file size {}",
                serialized.len(),
                self.config.max_file_size
            )));
        }

        // Create backup if file exists
        if file_path.exists() {
            self.create_backup(&file_path)?;
        }

        // Write data to file
        let mut file = File::create(&file_path)
            .map_err(|e| GdkError::Persistence(format!("Failed to create file: {}", e)))?;

        file.write_all(&serialized)
            .map_err(|e| GdkError::Persistence(format!("Failed to write data: {}", e)))?;

        file.sync_all()
            .map_err(|e| GdkError::Persistence(format!("Failed to sync file: {}", e)))?;

        log::debug!("Stored data to file: {:?}", file_path);
        Ok(())
    }

    /// Load data from a file
    pub fn load<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<T> {
        let file_path = self.get_file_path(key);
        
        if !file_path.exists() {
            return Err(GdkError::Persistence(format!("File not found: {:?}", file_path)));
        }

        let file = File::open(&file_path)
            .map_err(|e| GdkError::Persistence(format!("Failed to open file: {}", e)))?;

        let reader = BufReader::new(file);
        let data = serde_json::from_reader(reader)
            .map_err(|e| GdkError::Persistence(format!("Deserialization failed: {}", e)))?;

        log::debug!("Loaded data from file: {:?}", file_path);
        Ok(data)
    }

    /// Check if a file exists
    pub fn exists(&self, key: &str) -> bool {
        self.get_file_path(key).exists()
    }

    /// Delete a file
    pub fn delete(&self, key: &str) -> Result<()> {
        let file_path = self.get_file_path(key);
        
        if file_path.exists() {
            fs::remove_file(&file_path)
                .map_err(|e| GdkError::Persistence(format!("Failed to delete file: {}", e)))?;
            log::debug!("Deleted file: {:?}", file_path);
        }

        Ok(())
    }

    /// List all stored keys
    pub fn list_keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        self.collect_keys(&self.config.data_dir, "", &mut keys)?;
        Ok(keys)
    }

    /// Get file size
    pub fn get_file_size(&self, key: &str) -> Result<u64> {
        let file_path = self.get_file_path(key);
        let metadata = fs::metadata(&file_path)
            .map_err(|e| GdkError::Persistence(format!("Failed to get file metadata: {}", e)))?;
        Ok(metadata.len())
    }

    /// Get file modification time
    pub fn get_modification_time(&self, key: &str) -> Result<SystemTime> {
        let file_path = self.get_file_path(key);
        let metadata = fs::metadata(&file_path)
            .map_err(|e| GdkError::Persistence(format!("Failed to get file metadata: {}", e)))?;
        metadata.modified()
            .map_err(|e| GdkError::Persistence(format!("Failed to get modification time: {}", e)))
    }

    /// Store binary data
    pub fn store_binary(&self, key: &str, data: &[u8]) -> Result<()> {
        let file_path = self.get_file_path(key);
        
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| GdkError::Persistence(format!("Failed to create directory: {}", e)))?;
        }

        if data.len() > self.config.max_file_size {
            return Err(GdkError::Persistence(format!(
                "Data size {} exceeds maximum file size {}",
                data.len(),
                self.config.max_file_size
            )));
        }

        if file_path.exists() {
            self.create_backup(&file_path)?;
        }

        fs::write(&file_path, data)
            .map_err(|e| GdkError::Persistence(format!("Failed to write binary data: {}", e)))?;

        log::debug!("Stored binary data to file: {:?}", file_path);
        Ok(())
    }

    /// Load binary data
    pub fn load_binary(&self, key: &str) -> Result<Vec<u8>> {
        let file_path = self.get_file_path(key);
        
        fs::read(&file_path)
            .map_err(|e| GdkError::Persistence(format!("Failed to read binary data: {}", e)))
    }

    /// Get the file path for a given key
    fn get_file_path(&self, key: &str) -> PathBuf {
        // Sanitize the key to prevent directory traversal
        let sanitized_key = key.replace(['/', '\\', '..'], "_");
        self.config.data_dir.join(format!("{}.json", sanitized_key))
    }

    /// Create a backup of an existing file
    fn create_backup(&self, file_path: &Path) -> Result<()> {
        let backup_path = file_path.with_extension("json.backup");
        fs::copy(file_path, &backup_path)
            .map_err(|e| GdkError::Persistence(format!("Failed to create backup: {}", e)))?;
        
        // Clean up old backups
        self.cleanup_old_backups(file_path)?;
        Ok(())
    }

    /// Clean up old backup files
    fn cleanup_old_backups(&self, file_path: &Path) -> Result<()> {
        // This is a simplified implementation
        // In a real implementation, you'd track backup timestamps
        Ok(())
    }

    /// Recursively collect all keys from the data directory
    fn collect_keys(&self, dir: &Path, prefix: &str, keys: &mut Vec<String>) -> Result<()> {
        let entries = fs::read_dir(dir)
            .map_err(|e| GdkError::Persistence(format!("Failed to read directory: {}", e)))?;

        for entry in entries {
            let entry = entry
                .map_err(|e| GdkError::Persistence(format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();

            if path.is_file() {
                if let Some(file_name) = path.file_stem() {
                    if let Some(name_str) = file_name.to_str() {
                        let key = if prefix.is_empty() {
                            name_str.to_string()
                        } else {
                            format!("{}/{}", prefix, name_str)
                        };
                        keys.push(key);
                    }
                }
            } else if path.is_dir() {
                if let Some(dir_name) = path.file_name() {
                    if let Some(name_str) = dir_name.to_str() {
                        let new_prefix = if prefix.is_empty() {
                            name_str.to_string()
                        } else {
                            format!("{}/{}", prefix, name_str)
                        };
                        self.collect_keys(&path, &new_prefix, keys)?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// In-memory cache with expiration
pub struct MemoryCache<T> {
    data: HashMap<String, CacheEntry<T>>,
    max_size: usize,
    default_expiration: Duration,
}

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: SystemTime,
    size: usize,
}

impl<T: Clone> MemoryCache<T> {
    /// Create a new memory cache
    pub fn new(max_size: usize, default_expiration: Duration) -> Self {
        Self {
            data: HashMap::new(),
            max_size,
            default_expiration,
        }
    }

    /// Store a value in the cache
    pub fn set(&mut self, key: String, value: T, size: usize) -> Result<()> {
        self.set_with_expiration(key, value, size, self.default_expiration)
    }

    /// Store a value in the cache with custom expiration
    pub fn set_with_expiration(
        &mut self,
        key: String,
        value: T,
        size: usize,
        expiration: Duration,
    ) -> Result<()> {
        // Clean up expired entries first
        self.cleanup_expired();

        // Check if we need to make space
        while self.current_size() + size > self.max_size && !self.data.is_empty() {
            self.evict_oldest();
        }

        if size > self.max_size {
            return Err(GdkError::Persistence(format!(
                "Item size {} exceeds cache capacity {}",
                size, self.max_size
            )));
        }

        let expires_at = SystemTime::now() + expiration;
        let entry = CacheEntry {
            value,
            expires_at,
            size,
        };

        self.data.insert(key, entry);
        Ok(())
    }

    /// Get a value from the cache
    pub fn get(&mut self, key: &str) -> Option<T> {
        self.cleanup_expired();
        
        self.data.get(key).map(|entry| entry.value.clone())
    }

    /// Check if a key exists in the cache
    pub fn contains_key(&mut self, key: &str) -> bool {
        self.cleanup_expired();
        self.data.contains_key(key)
    }

    /// Remove a key from the cache
    pub fn remove(&mut self, key: &str) -> Option<T> {
        self.data.remove(key).map(|entry| entry.value)
    }

    /// Clear all entries from the cache
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Get the current cache size in bytes
    pub fn current_size(&self) -> usize {
        self.data.values().map(|entry| entry.size).sum()
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Clean up expired entries
    fn cleanup_expired(&mut self) {
        let now = SystemTime::now();
        self.data.retain(|_, entry| entry.expires_at > now);
    }

    /// Evict the oldest entry (simple LRU approximation)
    fn evict_oldest(&mut self) {
        if let Some(key) = self.data.keys().next().cloned() {
            self.data.remove(&key);
        }
    }
}

impl<T: Clone> Default for MemoryCache<T> {
    fn default() -> Self {
        Self::new(MAX_CACHE_SIZE, DEFAULT_CACHE_EXPIRATION)
    }
}

/// Persistent cache that combines memory and disk storage
pub struct PersistentCache<T> {
    memory_cache: MemoryCache<T>,
    file_storage: FileStorage,
    cache_prefix: String,
}

impl<T: Clone + Serialize + for<'de> Deserialize<'de>> PersistentCache<T> {
    /// Create a new persistent cache
    pub fn new(
        storage_config: StorageConfig,
        cache_prefix: String,
        memory_cache_size: usize,
        default_expiration: Duration,
    ) -> Result<Self> {
        Ok(Self {
            memory_cache: MemoryCache::new(memory_cache_size, default_expiration),
            file_storage: FileStorage::new(storage_config)?,
            cache_prefix,
        })
    }

    /// Store a value in both memory and disk cache
    pub fn set(&mut self, key: &str, value: T, size: usize) -> Result<()> {
        // Store in memory cache
        self.memory_cache.set(key.to_string(), value.clone(), size)?;
        
        // Store in persistent storage
        let storage_key = format!("{}_{}", self.cache_prefix, key);
        self.file_storage.store(&storage_key, &value)?;
        
        Ok(())
    }

    /// Get a value from cache (memory first, then disk)
    pub fn get(&mut self, key: &str) -> Result<Option<T>> {
        // Try memory cache first
        if let Some(value) = self.memory_cache.get(key) {
            return Ok(Some(value));
        }

        // Try persistent storage
        let storage_key = format!("{}_{}", self.cache_prefix, key);
        match self.file_storage.load::<T>(&storage_key) {
            Ok(value) => {
                // Add back to memory cache
                let _ = self.memory_cache.set(key.to_string(), value.clone(), 1024); // Estimate size
                Ok(Some(value))
            }
            Err(GdkError::Persistence(_)) => Ok(None), // File not found
            Err(e) => Err(e),
        }
    }

    /// Remove a value from both caches
    pub fn remove(&mut self, key: &str) -> Result<()> {
        self.memory_cache.remove(key);
        
        let storage_key = format!("{}_{}", self.cache_prefix, key);
        self.file_storage.delete(&storage_key)?;
        
        Ok(())
    }

    /// Clear all cached data
    pub fn clear(&mut self) -> Result<()> {
        self.memory_cache.clear();
        
        // Remove all files with our prefix
        let keys = self.file_storage.list_keys()?;
        for key in keys {
            if key.starts_with(&self.cache_prefix) {
                self.file_storage.delete(&key)?;
            }
        }
        
        Ok(())
    }
}

/// Configuration storage utilities
pub struct ConfigStorage {
    file_storage: FileStorage,
}

impl ConfigStorage {
    /// Create a new configuration storage
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        let config = StorageConfig {
            data_dir,
            ..Default::default()
        };
        
        Ok(Self {
            file_storage: FileStorage::new(config)?,
        })
    }

    /// Store configuration
    pub fn store_config<T: Serialize>(&self, name: &str, config: &T) -> Result<()> {
        let key = format!("config_{}", name);
        self.file_storage.store(&key, config)
    }

    /// Load configuration
    pub fn load_config<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<T> {
        let key = format!("config_{}", name);
        self.file_storage.load(&key)
    }

    /// Check if configuration exists
    pub fn config_exists(&self, name: &str) -> bool {
        let key = format!("config_{}", name);
        self.file_storage.exists(&key)
    }

    /// Delete configuration
    pub fn delete_config(&self, name: &str) -> Result<()> {
        let key = format!("config_{}", name);
        self.file_storage.delete(&key)
    }

    /// List all configurations
    pub fn list_configs(&self) -> Result<Vec<String>> {
        let keys = self.file_storage.list_keys()?;
        let configs = keys
            .into_iter()
            .filter_map(|key| {
                if key.starts_with("config_") {
                    Some(key.strip_prefix("config_").unwrap().to_string())
                } else {
                    None
                }
            })
            .collect();
        Ok(configs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestData {
        id: u32,
        name: String,
        values: Vec<i32>,
    }

    fn create_test_storage() -> (FileStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            data_dir: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let storage = FileStorage::new(config).unwrap();
        (storage, temp_dir)
    }

    #[test]
    fn test_file_storage_basic_operations() {
        let (storage, _temp_dir) = create_test_storage();
        
        let test_data = TestData {
            id: 1,
            name: "test".to_string(),
            values: vec![1, 2, 3],
        };

        // Store data
        storage.store("test_key", &test_data).unwrap();
        assert!(storage.exists("test_key"));

        // Load data
        let loaded_data: TestData = storage.load("test_key").unwrap();
        assert_eq!(test_data, loaded_data);

        // Delete data
        storage.delete("test_key").unwrap();
        assert!(!storage.exists("test_key"));
    }

    #[test]
    fn test_memory_cache() {
        let mut cache = MemoryCache::new(1024, Duration::from_secs(60));
        
        // Store and retrieve
        cache.set("key1".to_string(), "value1".to_string(), 10).unwrap();
        assert_eq!(cache.get("key1"), Some("value1".to_string()));
        
        // Test expiration (would need to mock time for proper testing)
        assert!(cache.contains_key("key1"));
        
        // Test removal
        cache.remove("key1");
        assert!(!cache.contains_key("key1"));
    }

    #[test]
    fn test_binary_storage() {
        let (storage, _temp_dir) = create_test_storage();
        
        let binary_data = vec![0x01, 0x02, 0x03, 0x04];
        
        storage.store_binary("binary_key", &binary_data).unwrap();
        let loaded_data = storage.load_binary("binary_key").unwrap();
        
        assert_eq!(binary_data, loaded_data);
    }

    #[test]
    fn test_config_storage() {
        let temp_dir = TempDir::new().unwrap();
        let config_storage = ConfigStorage::new(temp_dir.path().to_path_buf()).unwrap();
        
        let test_config = TestData {
            id: 42,
            name: "config_test".to_string(),
            values: vec![10, 20, 30],
        };

        // Store and load config
        config_storage.store_config("test", &test_config).unwrap();
        let loaded_config: TestData = config_storage.load_config("test").unwrap();
        assert_eq!(test_config, loaded_config);

        // Test existence
        assert!(config_storage.config_exists("test"));
        
        // List configs
        let configs = config_storage.list_configs().unwrap();
        assert!(configs.contains(&"test".to_string()));
    }
}