//! Configuration management utilities for GDK.
//!
//! This module provides:
//! - Configuration loading from multiple sources (files, environment, defaults)
//! - Configuration validation and schema checking
//! - Environment-specific configuration management
//! - Configuration merging and overrides
//! - Secure configuration storage

use crate::{GdkError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration source priority (higher number = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigSource {
    Default = 0,
    File = 1,
    Environment = 2,
    Override = 3,
}

/// Configuration value with source tracking
#[derive(Debug, Clone)]
pub struct ConfigValue<T> {
    pub value: T,
    pub source: ConfigSource,
}

impl<T> ConfigValue<T> {
    pub fn new(value: T, source: ConfigSource) -> Self {
        Self { value, source }
    }
}

/// Configuration manager for handling multiple configuration sources
pub struct ConfigManager {
    config_dir: PathBuf,
    environment_prefix: String,
    loaded_configs: HashMap<String, serde_json::Value>,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new(config_dir: PathBuf, environment_prefix: &str) -> Self {
        Self {
            config_dir,
            environment_prefix: environment_prefix.to_string(),
            loaded_configs: HashMap::new(),
        }
    }

    /// Load configuration from multiple sources
    pub fn load_config<T>(&mut self, config_name: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de> + Default + Clone,
    {
        // Start with default configuration
        let config = T::default();
        let mut config_value = serde_json::to_value(&config)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to serialize default config: {}", e)))?;

        // Load from file if it exists
        let config_file_path = self.config_dir.join(format!("{}.json", config_name));
        if config_file_path.exists() {
            let file_config = self.load_from_file(&config_file_path)?;
            self.merge_config_values(&mut config_value, file_config, ConfigSource::File)?;
        }

        // Load from environment variables
        let env_config = self.load_from_environment(config_name)?;
        if !env_config.is_null() {
            self.merge_config_values(&mut config_value, env_config, ConfigSource::Environment)?;
        }

        // Convert back to typed configuration
        let final_config: T = serde_json::from_value(config_value)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to deserialize config: {}", e)))?;

        // Cache the loaded configuration
        let config_json = serde_json::to_value(&final_config)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to cache config: {}", e)))?;
        self.loaded_configs.insert(config_name.to_string(), config_json);

        Ok(final_config)
    }

    /// Save configuration to file
    pub fn save_config<T>(&self, config_name: &str, config: &T) -> Result<()>
    where
        T: Serialize,
    {
        // Ensure config directory exists
        if !self.config_dir.exists() {
            fs::create_dir_all(&self.config_dir)
                .map_err(|e| GdkError::Io(format!("Failed to create config directory: {}", e)))?;
        }

        let config_file_path = self.config_dir.join(format!("{}.json", config_name));
        let config_json = serde_json::to_string_pretty(config)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to serialize config: {}", e)))?;

        fs::write(&config_file_path, config_json)
            .map_err(|e| GdkError::Io(format!("Failed to write config file: {}", e)))?;

        log::info!("Configuration '{}' saved to {:?}", config_name, config_file_path);
        Ok(())
    }

    /// Check if a configuration file exists
    pub fn config_exists(&self, config_name: &str) -> bool {
        let config_file_path = self.config_dir.join(format!("{}.json", config_name));
        config_file_path.exists()
    }

    /// Delete a configuration file
    pub fn delete_config(&self, config_name: &str) -> Result<()> {
        let config_file_path = self.config_dir.join(format!("{}.json", config_name));
        
        if config_file_path.exists() {
            fs::remove_file(&config_file_path)
                .map_err(|e| GdkError::Io(format!("Failed to delete config file: {}", e)))?;
            log::info!("Configuration '{}' deleted", config_name);
        }

        Ok(())
    }

    /// List all available configuration files
    pub fn list_configs(&self) -> Result<Vec<String>> {
        if !self.config_dir.exists() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.config_dir)
            .map_err(|e| GdkError::Io(format!("Failed to read config directory: {}", e)))?;

        let mut configs = Vec::new();
        for entry in entries {
            let entry = entry
                .map_err(|e| GdkError::Io(format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();
            
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) {
                    configs.push(file_stem.to_string());
                }
            }
        }

        configs.sort();
        Ok(configs)
    }

    /// Load configuration from a file
    fn load_from_file(&self, file_path: &Path) -> Result<serde_json::Value> {
        let content = fs::read_to_string(file_path)
            .map_err(|e| GdkError::Io(format!("Failed to read config file: {}", e)))?;

        serde_json::from_str(&content)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to parse config file: {}", e)))
    }

    /// Load configuration from environment variables
    fn load_from_environment(&self, config_name: &str) -> Result<serde_json::Value> {
        let mut env_config = serde_json::Map::new();
        let prefix = format!("{}_{}", self.environment_prefix, config_name.to_uppercase());

        for (key, value) in env::vars() {
            if key.starts_with(&prefix) {
                // Convert environment variable name to config key
                let config_key = key
                    .strip_prefix(&format!("{}_", prefix))
                    .unwrap_or(&key)
                    .to_lowercase();

                // Try to parse as JSON first, then fall back to string
                let parsed_value = serde_json::from_str(&value)
                    .unwrap_or_else(|_| serde_json::Value::String(value));

                env_config.insert(config_key, parsed_value);
            }
        }

        Ok(serde_json::Value::Object(env_config))
    }

    /// Merge configuration values with source priority
    fn merge_config_values(
        &self,
        base: &mut serde_json::Value,
        overlay: serde_json::Value,
        _source: ConfigSource,
    ) -> Result<()> {
        match (base, overlay) {
            (serde_json::Value::Object(base_map), serde_json::Value::Object(overlay_map)) => {
                for (key, value) in overlay_map {
                    base_map.insert(key, value);
                }
            }
            _ => {
                *base = overlay;
            }
        }
        Ok(())
    }
}

/// Environment-specific configuration management
pub struct EnvironmentConfig {
    current_environment: String,
    config_manager: ConfigManager,
}

impl EnvironmentConfig {
    /// Create a new environment configuration manager
    pub fn new(config_dir: PathBuf, environment: &str) -> Self {
        let config_manager = ConfigManager::new(config_dir, "GDK");
        
        Self {
            current_environment: environment.to_string(),
            config_manager,
        }
    }

    /// Load environment-specific configuration
    pub fn load_config<T>(&mut self, config_name: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de> + Default + Clone,
    {
        // Try to load environment-specific config first
        let env_specific_name = format!("{}_{}", config_name, self.current_environment);
        
        if self.config_manager.config_exists(&env_specific_name) {
            log::info!("Loading environment-specific config: {}", env_specific_name);
            self.config_manager.load_config(&env_specific_name)
        } else {
            log::info!("Loading default config: {}", config_name);
            self.config_manager.load_config(config_name)
        }
    }

    /// Save environment-specific configuration
    pub fn save_config<T>(&self, config_name: &str, config: &T) -> Result<()>
    where
        T: Serialize,
    {
        let env_specific_name = format!("{}_{}", config_name, self.current_environment);
        self.config_manager.save_config(&env_specific_name, config)
    }

    /// Get current environment
    pub fn current_environment(&self) -> &str {
        &self.current_environment
    }

    /// Set current environment
    pub fn set_environment(&mut self, environment: &str) {
        self.current_environment = environment.to_string();
        log::info!("Environment changed to: {}", environment);
    }
}

/// Configuration builder for fluent configuration creation
pub struct ConfigBuilder<T> {
    config: T,
    overrides: HashMap<String, serde_json::Value>,
}

impl<T: Default> ConfigBuilder<T> {
    /// Create a new configuration builder
    pub fn new() -> Self {
        Self {
            config: T::default(),
            overrides: HashMap::new(),
        }
    }

    /// Create a configuration builder from an existing config
    pub fn from_config(config: T) -> Self {
        Self {
            config,
            overrides: HashMap::new(),
        }
    }

    /// Add an override value
    pub fn with_override<V: Serialize>(mut self, key: &str, value: V) -> Result<Self> {
        let json_value = serde_json::to_value(value)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to serialize override value: {}", e)))?;
        self.overrides.insert(key.to_string(), json_value);
        Ok(self)
    }

    /// Build the final configuration
    pub fn build(self) -> Result<T>
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        let mut config_value = serde_json::to_value(&self.config)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to serialize config: {}", e)))?;

        // Apply overrides
        if let serde_json::Value::Object(ref mut config_map) = config_value {
            for (key, value) in self.overrides {
                config_map.insert(key, value);
            }
        }

        serde_json::from_value(config_value)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to deserialize final config: {}", e)))
    }
}

impl<T: Default> Default for ConfigBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration validation utilities
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate that required fields are present
    pub fn validate_required_fields<T: Serialize>(
        config: &T,
        required_fields: &[&str],
    ) -> Result<Vec<String>> {
        let config_value = serde_json::to_value(config)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to serialize config: {}", e)))?;

        let mut missing_fields = Vec::new();

        if let serde_json::Value::Object(config_map) = config_value {
            for field in required_fields {
                if !config_map.contains_key(*field) {
                    missing_fields.push(field.to_string());
                }
            }
        }

        Ok(missing_fields)
    }

    /// Validate field types
    pub fn validate_field_types<T: Serialize>(
        config: &T,
        field_types: &[(&str, &str)],
    ) -> Result<Vec<String>> {
        let config_value = serde_json::to_value(config)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to serialize config: {}", e)))?;

        let mut type_errors = Vec::new();

        if let serde_json::Value::Object(config_map) = config_value {
            for (field_name, expected_type) in field_types {
                if let Some(field_value) = config_map.get(*field_name) {
                    let actual_type = match field_value {
                        serde_json::Value::Null => "null",
                        serde_json::Value::Bool(_) => "boolean",
                        serde_json::Value::Number(_) => "number",
                        serde_json::Value::String(_) => "string",
                        serde_json::Value::Array(_) => "array",
                        serde_json::Value::Object(_) => "object",
                    };

                    if actual_type != *expected_type {
                        type_errors.push(format!(
                            "Field '{}' expected type '{}' but got '{}'",
                            field_name, expected_type, actual_type
                        ));
                    }
                }
            }
        }

        Ok(type_errors)
    }

    /// Validate numeric ranges
    pub fn validate_numeric_ranges<T: Serialize>(
        config: &T,
        ranges: &[(&str, f64, f64)],
    ) -> Result<Vec<String>> {
        let config_value = serde_json::to_value(config)
            .map_err(|e| GdkError::InvalidInput(format!("Failed to serialize config: {}", e)))?;

        let mut range_errors = Vec::new();

        if let serde_json::Value::Object(config_map) = config_value {
            for (field_name, min_val, max_val) in ranges {
                if let Some(field_value) = config_map.get(*field_name) {
                    if let Some(num_value) = field_value.as_f64() {
                        if num_value < *min_val || num_value > *max_val {
                            range_errors.push(format!(
                                "Field '{}' value {} is outside valid range [{}, {}]",
                                field_name, num_value, min_val, max_val
                            ));
                        }
                    }
                }
            }
        }

        Ok(range_errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestConfig {
        pub name: String,
        pub port: u16,
        pub enabled: bool,
        pub timeout: f64,
    }

    impl Default for TestConfig {
        fn default() -> Self {
            Self {
                name: "default".to_string(),
                port: 8080,
                enabled: true,
                timeout: 30.0,
            }
        }
    }

    fn create_test_config_manager() -> (ConfigManager, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config_manager = ConfigManager::new(temp_dir.path().to_path_buf(), "TEST");
        (config_manager, temp_dir)
    }

    #[test]
    fn test_config_manager_basic_operations() {
        let (mut config_manager, _temp_dir) = create_test_config_manager();
        
        let test_config = TestConfig {
            name: "test_service".to_string(),
            port: 9090,
            enabled: false,
            timeout: 60.0,
        };

        // Save configuration
        config_manager.save_config("test", &test_config).unwrap();
        assert!(config_manager.config_exists("test"));

        // Load configuration
        let loaded_config: TestConfig = config_manager.load_config("test").unwrap();
        assert_eq!(test_config, loaded_config);

        // List configurations
        let configs = config_manager.list_configs().unwrap();
        assert!(configs.contains(&"test".to_string()));

        // Delete configuration
        config_manager.delete_config("test").unwrap();
        assert!(!config_manager.config_exists("test"));
    }

    #[test]
    fn test_environment_config() {
        let temp_dir = TempDir::new().unwrap();
        let mut env_config = EnvironmentConfig::new(temp_dir.path().to_path_buf(), "development");
        
        assert_eq!(env_config.current_environment(), "development");
        
        env_config.set_environment("production");
        assert_eq!(env_config.current_environment(), "production");
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::<TestConfig>::new()
            .with_override("name", "builder_test").unwrap()
            .with_override("port", 3000).unwrap()
            .build()
            .unwrap();

        assert_eq!(config.name, "builder_test");
        assert_eq!(config.port, 3000);
        assert_eq!(config.enabled, true); // Default value
    }

    #[test]
    fn test_config_validation() {
        let test_config = TestConfig::default();
        
        // Test required fields validation
        let required_fields = ["name", "port"];
        let missing_fields = ConfigValidator::validate_required_fields(&test_config, &required_fields).unwrap();
        assert!(missing_fields.is_empty());
        
        // Test field types validation
        let field_types = [("name", "string"), ("port", "number"), ("enabled", "boolean")];
        let type_errors = ConfigValidator::validate_field_types(&test_config, &field_types).unwrap();
        assert!(type_errors.is_empty());
        
        // Test numeric ranges validation
        let ranges = [("port", 1.0, 65535.0), ("timeout", 0.0, 300.0)];
        let range_errors = ConfigValidator::validate_numeric_ranges(&test_config, &ranges).unwrap();
        assert!(range_errors.is_empty());
    }

    #[test]
    fn test_config_source_priority() {
        assert!(ConfigSource::Override > ConfigSource::Environment);
        assert!(ConfigSource::Environment > ConfigSource::File);
        assert!(ConfigSource::File > ConfigSource::Default);
    }

    #[test]
    fn test_config_value() {
        let config_value = ConfigValue::new("test_value".to_string(), ConfigSource::File);
        assert_eq!(config_value.value, "test_value");
        assert_eq!(config_value.source, ConfigSource::File);
    }
}