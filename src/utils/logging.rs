//! Logging and debugging utilities for GDK.
//!
//! This module provides:
//! - Structured logging with configurable levels
//! - Performance metrics collection and reporting
//! - Debug tracing for complex operations
//! - Log filtering and level management
//! - Diagnostic information collection for troubleshooting

use crate::{GdkError, Result};
use log::{Level, LevelFilter, Record};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Log level configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

impl From<LogLevel> for Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => Level::Error,
            LogLevel::Warn => Level::Warn,
            LogLevel::Info => Level::Info,
            LogLevel::Debug => Level::Debug,
            LogLevel::Trace => Level::Trace,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Trace => write!(f, "TRACE"),
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Enable console logging
    pub console_enabled: bool,
    /// Enable file logging
    pub file_enabled: bool,
    /// Log file path
    pub log_file_path: Option<PathBuf>,
    /// Maximum log file size in bytes
    pub max_file_size: u64,
    /// Number of log files to retain
    pub max_files: u32,
    /// Enable structured JSON logging
    pub json_format: bool,
    /// Include timestamps in logs
    pub include_timestamp: bool,
    /// Include thread information
    pub include_thread_info: bool,
    /// Include module path in logs
    pub include_module_path: bool,
    /// Custom log format string
    pub custom_format: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            console_enabled: true,
            file_enabled: false,
            log_file_path: None,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            max_files: 5,
            json_format: false,
            include_timestamp: true,
            include_thread_info: false,
            include_module_path: true,
            custom_format: None,
        }
    }
}

/// Custom logger implementation
pub struct GdkLogger {
    config: LoggingConfig,
    file_writer: Option<Arc<Mutex<BufWriter<File>>>>,
}

impl GdkLogger {
    /// Create a new GDK logger
    pub fn new(config: LoggingConfig) -> Result<Self> {
        let file_writer = if config.file_enabled {
            if let Some(log_file_path) = &config.log_file_path {
                // Ensure parent directory exists
                if let Some(parent) = log_file_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log_file_path)?;

                Some(Arc::new(Mutex::new(BufWriter::new(file))))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            file_writer,
        })
    }

    /// Initialize the logger as the global logger
    pub fn init(config: LoggingConfig) -> Result<()> {
        let logger = Self::new(config.clone())?;
        
        log::set_boxed_logger(Box::new(logger))
            .map_err(|e| GdkError::io(crate::error::GdkErrorCode::IoFileNotFound, &format!("Failed to set logger: {}", e)))?;
        
        log::set_max_level(config.level.into());
        
        log::info!("GDK logger initialized with level: {}", config.level);
        Ok(())
    }

    /// Format a log record
    fn format_record(&self, record: &Record) -> String {
        if self.config.json_format {
            self.format_json_record(record)
        } else {
            self.format_text_record(record)
        }
    }

    /// Format a log record as JSON
    fn format_json_record(&self, record: &Record) -> String {
        let mut json_record = serde_json::Map::new();
        
        json_record.insert("level".to_string(), serde_json::Value::String(record.level().to_string()));
        json_record.insert("message".to_string(), serde_json::Value::String(record.args().to_string()));
        
        if self.config.include_timestamp {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            json_record.insert("timestamp".to_string(), serde_json::Value::Number(timestamp.into()));
        }
        
        if self.config.include_module_path {
            if let Some(module_path) = record.module_path() {
                json_record.insert("module".to_string(), serde_json::Value::String(module_path.to_string()));
            }
        }
        
        if self.config.include_thread_info {
            json_record.insert("thread".to_string(), serde_json::Value::String(format!("{:?}", std::thread::current().id())));
        }
        
        serde_json::to_string(&json_record).unwrap_or_else(|_| "Failed to serialize log record".to_string())
    }

    /// Format a log record as text
    fn format_text_record(&self, record: &Record) -> String {
        if let Some(custom_format) = &self.config.custom_format {
            // Simple custom format support (could be expanded)
            custom_format
                .replace("{level}", &record.level().to_string())
                .replace("{message}", &record.args().to_string())
                .replace("{module}", record.module_path().unwrap_or("unknown"))
        } else {
            let mut formatted = String::new();
            
            if self.config.include_timestamp {
                let now = SystemTime::now();
                if let Ok(duration) = now.duration_since(UNIX_EPOCH) {
                    formatted.push_str(&format!("[{}] ", duration.as_secs()));
                }
            }
            
            formatted.push_str(&format!("[{}] ", record.level()));
            
            if self.config.include_module_path {
                if let Some(module_path) = record.module_path() {
                    formatted.push_str(&format!("[{}] ", module_path));
                }
            }
            
            if self.config.include_thread_info {
                formatted.push_str(&format!("[{:?}] ", std::thread::current().id()));
            }
            
            formatted.push_str(&record.args().to_string());
            
            formatted
        }
    }

    /// Write log message to file
    fn write_to_file(&self, message: &str) {
        if let Some(file_writer) = &self.file_writer {
            if let Ok(mut writer) = file_writer.lock() {
                if let Err(e) = writeln!(writer, "{}", message) {
                    eprintln!("Failed to write to log file: {}", e);
                }
                if let Err(e) = writer.flush() {
                    eprintln!("Failed to flush log file: {}", e);
                }
            }
        }
    }
}

impl log::Log for GdkLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= Level::from(self.config.level)
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let formatted_message = self.format_record(record);
            
            if self.config.console_enabled {
                println!("{}", formatted_message);
            }
            
            if self.config.file_enabled {
                self.write_to_file(&formatted_message);
            }
        }
    }

    fn flush(&self) {
        if let Some(file_writer) = &self.file_writer {
            if let Ok(mut writer) = file_writer.lock() {
                let _ = writer.flush();
            }
        }
    }
}

/// Performance metrics collector
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    operation_times: HashMap<String, Vec<Duration>>,
    counters: HashMap<String, u64>,
    gauges: HashMap<String, f64>,
}

impl PerformanceMetrics {
    /// Create a new performance metrics collector
    pub fn new() -> Self {
        Self {
            operation_times: HashMap::new(),
            counters: HashMap::new(),
            gauges: HashMap::new(),
        }
    }

    /// Record the duration of an operation
    pub fn record_operation_time(&mut self, operation: &str, duration: Duration) {
        self.operation_times
            .entry(operation.to_string())
            .or_insert_with(Vec::new)
            .push(duration);
    }

    /// Increment a counter
    pub fn increment_counter(&mut self, name: &str) {
        *self.counters.entry(name.to_string()).or_insert(0) += 1;
    }

    /// Add to a counter
    pub fn add_to_counter(&mut self, name: &str, value: u64) {
        *self.counters.entry(name.to_string()).or_insert(0) += value;
    }

    /// Set a gauge value
    pub fn set_gauge(&mut self, name: &str, value: f64) {
        self.gauges.insert(name.to_string(), value);
    }

    /// Get average operation time
    pub fn get_average_operation_time(&self, operation: &str) -> Option<Duration> {
        self.operation_times.get(operation).and_then(|times| {
            if times.is_empty() {
                None
            } else {
                let total: Duration = times.iter().sum();
                Some(total / times.len() as u32)
            }
        })
    }

    /// Get counter value
    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters.get(name).copied().unwrap_or(0)
    }

    /// Get gauge value
    pub fn get_gauge(&self, name: &str) -> Option<f64> {
        self.gauges.get(name).copied()
    }

    /// Get all metrics as a report
    pub fn generate_report(&self) -> MetricsReport {
        let mut operation_stats = HashMap::new();
        
        for (operation, times) in &self.operation_times {
            if !times.is_empty() {
                let total: Duration = times.iter().sum();
                let average = total / times.len() as u32;
                let min = *times.iter().min().unwrap();
                let max = *times.iter().max().unwrap();
                
                operation_stats.insert(operation.clone(), OperationStats {
                    count: times.len(),
                    total,
                    average,
                    min,
                    max,
                });
            }
        }

        MetricsReport {
            operation_stats,
            counters: self.counters.clone(),
            gauges: self.gauges.clone(),
        }
    }

    /// Clear all metrics
    pub fn clear(&mut self) {
        self.operation_times.clear();
        self.counters.clear();
        self.gauges.clear();
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStats {
    pub count: usize,
    pub total: Duration,
    pub average: Duration,
    pub min: Duration,
    pub max: Duration,
}

/// Metrics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsReport {
    pub operation_stats: HashMap<String, OperationStats>,
    pub counters: HashMap<String, u64>,
    pub gauges: HashMap<String, f64>,
}

/// Performance timer for measuring operation duration
pub struct PerformanceTimer {
    start_time: Instant,
    operation_name: String,
    metrics: Option<Arc<Mutex<PerformanceMetrics>>>,
}

impl PerformanceTimer {
    /// Start a new performance timer
    pub fn start(operation_name: &str) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name: operation_name.to_string(),
            metrics: None,
        }
    }

    /// Start a performance timer with metrics collection
    pub fn start_with_metrics(
        operation_name: &str,
        metrics: Arc<Mutex<PerformanceMetrics>>,
    ) -> Self {
        Self {
            start_time: Instant::now(),
            operation_name: operation_name.to_string(),
            metrics: Some(metrics),
        }
    }

    /// Get the elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Stop the timer and return the duration
    pub fn stop(self) -> Duration {
        let duration = self.elapsed();
        
        if let Some(metrics) = &self.metrics {
            if let Ok(mut metrics) = metrics.lock() {
                metrics.record_operation_time(&self.operation_name, duration);
            }
        }
        
        log::debug!("Operation '{}' completed in {:?}", self.operation_name, duration);
        duration
    }
}

/// Debug tracer for complex operations
pub struct DebugTracer {
    operation_name: String,
    start_time: Instant,
    steps: Vec<TraceStep>,
}

#[derive(Debug, Clone)]
struct TraceStep {
    name: String,
    timestamp: Instant,
    duration_from_start: Duration,
    message: Option<String>,
}

impl DebugTracer {
    /// Start a new debug trace
    pub fn start(operation_name: &str) -> Self {
        log::trace!("Starting trace for operation: {}", operation_name);
        
        Self {
            operation_name: operation_name.to_string(),
            start_time: Instant::now(),
            steps: Vec::new(),
        }
    }

    /// Add a trace step
    pub fn step(&mut self, step_name: &str) {
        self.step_with_message(step_name, None);
    }

    /// Add a trace step with a message
    pub fn step_with_message(&mut self, step_name: &str, message: Option<String>) {
        let now = Instant::now();
        let duration_from_start = now.duration_since(self.start_time);
        
        log::trace!(
            "Trace step '{}' at +{:?}: {}",
            step_name,
            duration_from_start,
            message.as_deref().unwrap_or("")
        );
        
        let step = TraceStep {
            name: step_name.to_string(),
            timestamp: now,
            duration_from_start,
            message,
        };
        
        self.steps.push(step);
    }

    /// Finish the trace and log the summary
    pub fn finish(self) {
        let total_duration = self.start_time.elapsed();
        
        log::debug!(
            "Trace completed for '{}' in {:?} with {} steps",
            self.operation_name,
            total_duration,
            self.steps.len()
        );
        
        if log::log_enabled!(log::Level::Trace) {
            for (i, step) in self.steps.iter().enumerate() {
                log::trace!(
                    "  Step {}: {} at +{:?}{}",
                    i + 1,
                    step.name,
                    step.duration_from_start,
                    step.message.as_ref().map(|m| format!(" - {}", m)).unwrap_or_default()
                );
            }
        }
    }
}

/// Diagnostic information collector
pub struct DiagnosticCollector {
    system_info: HashMap<String, String>,
    runtime_info: HashMap<String, String>,
    error_history: Vec<DiagnosticError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticError {
    pub timestamp: SystemTime,
    pub error_type: String,
    pub message: String,
    pub context: HashMap<String, String>,
}

impl DiagnosticCollector {
    /// Create a new diagnostic collector
    pub fn new() -> Self {
        let mut collector = Self {
            system_info: HashMap::new(),
            runtime_info: HashMap::new(),
            error_history: Vec::new(),
        };
        
        collector.collect_system_info();
        collector
    }

    /// Collect system information
    fn collect_system_info(&mut self) {
        self.system_info.insert("os".to_string(), std::env::consts::OS.to_string());
        self.system_info.insert("arch".to_string(), std::env::consts::ARCH.to_string());
        self.system_info.insert("family".to_string(), std::env::consts::FAMILY.to_string());
        
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            self.system_info.insert("hostname".to_string(), hostname);
        }
        
        // Add more system info as needed
    }

    /// Update runtime information
    pub fn update_runtime_info(&mut self, key: &str, value: &str) {
        self.runtime_info.insert(key.to_string(), value.to_string());
    }

    /// Record an error for diagnostics
    pub fn record_error(&mut self, error_type: &str, message: &str, context: HashMap<String, String>) {
        let diagnostic_error = DiagnosticError {
            timestamp: SystemTime::now(),
            error_type: error_type.to_string(),
            message: message.to_string(),
            context,
        };
        
        self.error_history.push(diagnostic_error);
        
        // Keep only the last 100 errors
        if self.error_history.len() > 100 {
            self.error_history.remove(0);
        }
    }

    /// Generate a diagnostic report
    pub fn generate_report(&self) -> DiagnosticReport {
        DiagnosticReport {
            system_info: self.system_info.clone(),
            runtime_info: self.runtime_info.clone(),
            error_history: self.error_history.clone(),
            generated_at: SystemTime::now(),
        }
    }
}

impl Default for DiagnosticCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Diagnostic report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub system_info: HashMap<String, String>,
    pub runtime_info: HashMap<String, String>,
    pub error_history: Vec<DiagnosticError>,
    pub generated_at: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_log_level_conversion() {
        assert_eq!(LevelFilter::from(LogLevel::Error), LevelFilter::Error);
        assert_eq!(Level::from(LogLevel::Info), Level::Info);
    }

    #[test]
    fn test_performance_metrics() {
        let mut metrics = PerformanceMetrics::new();
        
        // Test operation timing
        metrics.record_operation_time("test_op", Duration::from_millis(100));
        metrics.record_operation_time("test_op", Duration::from_millis(200));
        
        let avg = metrics.get_average_operation_time("test_op").unwrap();
        assert_eq!(avg, Duration::from_millis(150));
        
        // Test counters
        metrics.increment_counter("test_counter");
        metrics.add_to_counter("test_counter", 5);
        assert_eq!(metrics.get_counter("test_counter"), 6);
        
        // Test gauges
        metrics.set_gauge("test_gauge", 42.5);
        assert_eq!(metrics.get_gauge("test_gauge"), Some(42.5));
    }

    #[test]
    fn test_performance_timer() {
        let timer = PerformanceTimer::start("test_operation");
        thread::sleep(Duration::from_millis(10));
        let duration = timer.stop();
        
        assert!(duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_debug_tracer() {
        let mut tracer = DebugTracer::start("test_trace");
        
        tracer.step("step1");
        thread::sleep(Duration::from_millis(1));
        tracer.step_with_message("step2", Some("test message".to_string()));
        
        assert_eq!(tracer.steps.len(), 2);
        assert_eq!(tracer.steps[0].name, "step1");
        assert_eq!(tracer.steps[1].name, "step2");
        assert_eq!(tracer.steps[1].message, Some("test message".to_string()));
        
        tracer.finish();
    }

    #[test]
    fn test_diagnostic_collector() {
        let mut collector = DiagnosticCollector::new();
        
        // Test system info collection
        assert!(!collector.system_info.is_empty());
        assert!(collector.system_info.contains_key("os"));
        
        // Test runtime info
        collector.update_runtime_info("test_key", "test_value");
        assert_eq!(collector.runtime_info.get("test_key"), Some(&"test_value".to_string()));
        
        // Test error recording
        let mut context = HashMap::new();
        context.insert("context_key".to_string(), "context_value".to_string());
        collector.record_error("TestError", "Test error message", context);
        
        assert_eq!(collector.error_history.len(), 1);
        assert_eq!(collector.error_history[0].error_type, "TestError");
        assert_eq!(collector.error_history[0].message, "Test error message");
    }
}