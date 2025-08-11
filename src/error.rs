use thiserror::Error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Error codes for compatibility with original GDK
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GdkErrorCode {
    // Network errors (1000-1999)
    NetworkConnectionFailed = 1001,
    NetworkTimeout = 1002,
    NetworkInvalidResponse = 1003,
    NetworkServerError = 1004,
    NetworkProxyError = 1005,
    NetworkTorError = 1006,
    NetworkCertificateError = 1007,
    
    // Authentication errors (2000-2999)
    AuthInvalidCredentials = 2001,
    AuthPinRequired = 2002,
    AuthPinIncorrect = 2003,
    AuthMnemonicInvalid = 2004,
    AuthHardwareWalletNotFound = 2005,
    AuthHardwareWalletError = 2006,
    AuthSessionExpired = 2007,
    AuthTwoFactorRequired = 2008,
    
    // Transaction errors (3000-3999)
    TransactionInvalidInput = 3001,
    TransactionInsufficientFunds = 3002,
    TransactionFeeTooLow = 3003,
    TransactionFeeTooHigh = 3004,
    TransactionInvalidAddress = 3005,
    TransactionSigningFailed = 3006,
    TransactionBroadcastFailed = 3007,
    TransactionAlreadyExists = 3008,
    TransactionReplaceByFeeFailed = 3009,
    
    // Hardware wallet errors (4000-4999)
    HardwareWalletNotConnected = 4001,
    HardwareWalletUserCancelled = 4002,
    HardwareWalletDeviceError = 4003,
    HardwareWalletFirmwareError = 4004,
    HardwareWalletUnsupportedOperation = 4005,
    
    // Cryptographic errors (5000-5999)
    CryptoInvalidKey = 5001,
    CryptoSignatureFailed = 5002,
    CryptoHashFailed = 5003,
    CryptoEncryptionFailed = 5004,
    CryptoDecryptionFailed = 5005,
    CryptoRandomGenerationFailed = 5006,
    
    // Input validation errors (6000-6999)
    InvalidInputFormat = 6001,
    InvalidInputLength = 6002,
    InvalidInputRange = 6003,
    InvalidInputEncoding = 6004,
    InvalidInputChecksum = 6005,
    
    // Persistence errors (7000-7999)
    PersistenceFileNotFound = 7001,
    PersistenceFileCorrupted = 7002,
    PersistencePermissionDenied = 7003,
    PersistenceDiskFull = 7004,
    PersistenceBackupFailed = 7005,
    
    // Serialization errors (8000-8999)
    JsonSerializationFailed = 8001,
    JsonDeserializationFailed = 8002,
    HexDecodingFailed = 8003,
    Base64DecodingFailed = 8004,
    
    // I/O errors (9000-9999)
    IoFileNotFound = 9001,
    IoPermissionDenied = 9002,
    IoConnectionRefused = 9003,
    IoTimeout = 9004,
    IoInterrupted = 9005,
    
    // Generic errors
    Unknown = 10000,
    InternalError = 10001,
    NotImplemented = 10002,
    ConfigurationError = 10003,
}

impl GdkErrorCode {
    /// Get the error category
    pub fn category(&self) -> &'static str {
        match *self as u32 {
            1000..=1999 => "Network",
            2000..=2999 => "Authentication",
            3000..=3999 => "Transaction",
            4000..=4999 => "Hardware Wallet",
            5000..=5999 => "Cryptographic",
            6000..=6999 => "Input Validation",
            7000..=7999 => "Persistence",
            8000..=8999 => "Serialization",
            9000..=9999 => "I/O",
            _ => "Generic",
        }
    }

    /// Check if the error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(self,
            GdkErrorCode::NetworkTimeout |
            GdkErrorCode::NetworkConnectionFailed |
            GdkErrorCode::NetworkServerError |
            GdkErrorCode::TransactionBroadcastFailed |
            GdkErrorCode::HardwareWalletNotConnected |
            GdkErrorCode::IoTimeout |
            GdkErrorCode::IoConnectionRefused |
            GdkErrorCode::IoInterrupted
        )
    }

    /// Get suggested retry delay in milliseconds
    pub fn retry_delay_ms(&self) -> Option<u64> {
        match self {
            GdkErrorCode::NetworkTimeout => Some(1000),
            GdkErrorCode::NetworkConnectionFailed => Some(5000),
            GdkErrorCode::NetworkServerError => Some(10000),
            GdkErrorCode::TransactionBroadcastFailed => Some(30000),
            GdkErrorCode::HardwareWalletNotConnected => Some(2000),
            GdkErrorCode::IoTimeout => Some(1000),
            GdkErrorCode::IoConnectionRefused => Some(5000),
            _ => None,
        }
    }
}

impl fmt::Display for GdkErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as u32)
    }
}

/// Error context providing additional information about the error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Additional context information
    pub context: HashMap<String, String>,
    /// Stack trace or call chain information
    pub call_chain: Vec<String>,
    /// Timestamp when the error occurred
    pub timestamp: std::time::SystemTime,
    /// Thread ID where the error occurred
    pub thread_id: String,
    /// Operation that was being performed
    pub operation: Option<String>,
    /// User-friendly error message
    pub user_message: Option<String>,
    /// Suggested actions for the user
    pub suggested_actions: Vec<String>,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new() -> Self {
        Self {
            context: HashMap::new(),
            call_chain: Vec::new(),
            timestamp: std::time::SystemTime::now(),
            thread_id: format!("{:?}", std::thread::current().id()),
            operation: None,
            user_message: None,
            suggested_actions: Vec::new(),
        }
    }

    /// Add context information
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }

    /// Add multiple context entries
    pub fn with_context_map(mut self, context: HashMap<String, String>) -> Self {
        self.context.extend(context);
        self
    }

    /// Add to call chain
    pub fn with_call(mut self, call: &str) -> Self {
        self.call_chain.push(call.to_string());
        self
    }

    /// Set the operation being performed
    pub fn with_operation(mut self, operation: &str) -> Self {
        self.operation = Some(operation.to_string());
        self
    }

    /// Set user-friendly message
    pub fn with_user_message(mut self, message: &str) -> Self {
        self.user_message = Some(message.to_string());
        self
    }

    /// Add suggested action
    pub fn with_suggested_action(mut self, action: &str) -> Self {
        self.suggested_actions.push(action.to_string());
        self
    }

    /// Add multiple suggested actions
    pub fn with_suggested_actions(mut self, actions: Vec<String>) -> Self {
        self.suggested_actions.extend(actions);
        self
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Recovery strategy for handling errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// No recovery possible
    None,
    /// Retry the operation
    Retry {
        max_attempts: u32,
        delay_ms: u64,
        backoff_multiplier: f64,
    },
    /// Fallback to alternative method
    Fallback {
        alternative: String,
    },
    /// Reconnect and retry
    Reconnect {
        max_attempts: u32,
        delay_ms: u64,
    },
    /// Reset state and retry
    Reset {
        component: String,
    },
    /// User intervention required
    UserIntervention {
        required_action: String,
    },
}

impl RecoveryStrategy {
    /// Create a retry strategy
    pub fn retry(max_attempts: u32, delay_ms: u64) -> Self {
        Self::Retry {
            max_attempts,
            delay_ms,
            backoff_multiplier: 2.0,
        }
    }

    /// Create a retry strategy with custom backoff
    pub fn retry_with_backoff(max_attempts: u32, delay_ms: u64, backoff_multiplier: f64) -> Self {
        Self::Retry {
            max_attempts,
            delay_ms,
            backoff_multiplier,
        }
    }

    /// Create a fallback strategy
    pub fn fallback(alternative: &str) -> Self {
        Self::Fallback {
            alternative: alternative.to_string(),
        }
    }

    /// Create a reconnect strategy
    pub fn reconnect(max_attempts: u32, delay_ms: u64) -> Self {
        Self::Reconnect {
            max_attempts,
            delay_ms,
        }
    }

    /// Create a reset strategy
    pub fn reset(component: &str) -> Self {
        Self::Reset {
            component: component.to_string(),
        }
    }

    /// Create a user intervention strategy
    pub fn user_intervention(required_action: &str) -> Self {
        Self::UserIntervention {
            required_action: required_action.to_string(),
        }
    }
}

/// Comprehensive GDK error type with detailed context and recovery information
#[derive(Error, Debug)]
pub enum GdkError {
    #[error("Network error: {message}")]
    Network {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Authentication error: {message}")]
    Auth {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Hardware wallet error: {message}")]
    HardwareWallet {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Persistence error: {message}")]
    Persistence {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Transaction error: {message}")]
    Transaction {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Invalid input: {message}")]
    InvalidInput {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Cryptographic error: {message}")]
    Crypto {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("JSON error: {message}")]
    Json {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("I/O error: {message}")]
    Io {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Hex decoding error: {message}")]
    Hex {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("Unknown error: {message}")]
    Unknown {
        code: GdkErrorCode,
        message: String,
        context: ErrorContext,
        recovery: RecoveryStrategy,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl GdkError {
    // Simplified constructors for backward compatibility
    /// Create a simple network error with default code
    pub fn network_simple(message: String) -> Self {
        Self::network(GdkErrorCode::NetworkConnectionFailed, &message)
    }
    
    /// Create a simple auth error with default code
    pub fn auth_simple(message: String) -> Self {
        Self::auth(GdkErrorCode::AuthInvalidCredentials, &message)
    }
    
    /// Create a simple hardware wallet error with default code
    pub fn hardware_wallet_simple(message: String) -> Self {
        Self::hardware_wallet(GdkErrorCode::HardwareWalletDeviceError, &message)
    }
    
    /// Create a simple persistence error with default code  
    pub fn persistence_simple(message: String) -> Self {
        Self::persistence(GdkErrorCode::PersistenceFileNotFound, &message)
    }
    
    /// Create a simple transaction error with default code
    pub fn transaction_simple(message: String) -> Self {
        Self::transaction(GdkErrorCode::TransactionInvalidInput, &message)
    }
    
    /// Create a simple invalid input error with default code
    pub fn invalid_input_simple(message: String) -> Self {
        Self::invalid_input(GdkErrorCode::InvalidInputFormat, &message)
    }
    
    /// Create a simple crypto error with default code
    pub fn crypto_simple(message: String) -> Self {
        Self::crypto(GdkErrorCode::CryptoInvalidKey, &message)
    }
    
    /// Create a simple JSON error with default code
    pub fn json_simple(message: String) -> Self {
        Self::json(GdkErrorCode::JsonSerializationFailed, &message)
    }
    
    /// Create a simple I/O error with default code
    pub fn io_simple(message: String) -> Self {
        Self::io(GdkErrorCode::IoFileNotFound, &message)
    }
    
    /// Create a simple hex error with default code
    pub fn hex_simple(message: String) -> Self {
        Self::hex(GdkErrorCode::HexDecodingFailed, &message)
    }
    
    /// Create a simple unknown error with default code
    pub fn unknown_simple(message: String) -> Self {
        Self::unknown(GdkErrorCode::Unknown, &message)
    }
    /// Get the error code
    pub fn code(&self) -> GdkErrorCode {
        match self {
            GdkError::Network { code, .. } => *code,
            GdkError::Auth { code, .. } => *code,
            GdkError::HardwareWallet { code, .. } => *code,
            GdkError::Persistence { code, .. } => *code,
            GdkError::Transaction { code, .. } => *code,
            GdkError::InvalidInput { code, .. } => *code,
            GdkError::Crypto { code, .. } => *code,
            GdkError::Json { code, .. } => *code,
            GdkError::Io { code, .. } => *code,
            GdkError::Hex { code, .. } => *code,
            GdkError::Unknown { code, .. } => *code,
        }
    }

    /// Get the error context
    pub fn context(&self) -> &ErrorContext {
        match self {
            GdkError::Network { context, .. } => context,
            GdkError::Auth { context, .. } => context,
            GdkError::HardwareWallet { context, .. } => context,
            GdkError::Persistence { context, .. } => context,
            GdkError::Transaction { context, .. } => context,
            GdkError::InvalidInput { context, .. } => context,
            GdkError::Crypto { context, .. } => context,
            GdkError::Json { context, .. } => context,
            GdkError::Io { context, .. } => context,
            GdkError::Hex { context, .. } => context,
            GdkError::Unknown { context, .. } => context,
        }
    }

    /// Get the recovery strategy
    pub fn recovery_strategy(&self) -> &RecoveryStrategy {
        match self {
            GdkError::Network { recovery, .. } => recovery,
            GdkError::Auth { recovery, .. } => recovery,
            GdkError::HardwareWallet { recovery, .. } => recovery,
            GdkError::Persistence { recovery, .. } => recovery,
            GdkError::Transaction { recovery, .. } => recovery,
            GdkError::InvalidInput { recovery, .. } => recovery,
            GdkError::Crypto { recovery, .. } => recovery,
            GdkError::Json { recovery, .. } => recovery,
            GdkError::Io { recovery, .. } => recovery,
            GdkError::Hex { recovery, .. } => recovery,
            GdkError::Unknown { recovery, .. } => recovery,
        }
    }

    /// Get user-friendly error message
    pub fn user_message(&self) -> Option<&str> {
        self.context().user_message.as_deref()
    }

    /// Get suggested actions
    pub fn suggested_actions(&self) -> &[String] {
        &self.context().suggested_actions
    }

    /// Check if the error is recoverable
    pub fn is_recoverable(&self) -> bool {
        self.code().is_recoverable()
    }

    /// Get suggested retry delay
    pub fn retry_delay_ms(&self) -> Option<u64> {
        self.code().retry_delay_ms()
    }

    /// Create a network error
    pub fn network(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("network_operation")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Network {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create an authentication error
    pub fn auth(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("authentication")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Auth {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create a transaction error
    pub fn transaction(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("transaction")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Transaction {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create a hardware wallet error
    pub fn hardware_wallet(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("hardware_wallet")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::HardwareWallet {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create a cryptographic error
    pub fn crypto(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("cryptographic_operation")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Crypto {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create an invalid input error
    pub fn invalid_input(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("input_validation")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::InvalidInput {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create a persistence error
    pub fn persistence(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("persistence")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Persistence {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create an I/O error
    pub fn io(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("io_operation")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Io {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create a JSON error
    pub fn json(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("json_operation")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Json {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create a hex error
    pub fn hex(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("hex_operation")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Hex {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Create an unknown error
    pub fn unknown(code: GdkErrorCode, message: &str) -> Self {
        let context = ErrorContext::new()
            .with_operation("unknown_operation")
            .with_user_message(&Self::generate_user_message(code, message))
            .with_suggested_actions(Self::generate_suggested_actions(code));

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Unknown {
            code,
            message: message.to_string(),
            context,
            recovery,
            source: None,
        }
    }

    /// Generate user-friendly error message
    fn generate_user_message(code: GdkErrorCode, technical_message: &str) -> String {
        match code {
            GdkErrorCode::NetworkConnectionFailed => "Unable to connect to the network. Please check your internet connection.".to_string(),
            GdkErrorCode::NetworkTimeout => "The network request timed out. Please try again.".to_string(),
            GdkErrorCode::AuthInvalidCredentials => "The provided credentials are invalid. Please check your login information.".to_string(),
            GdkErrorCode::AuthPinIncorrect => "The PIN you entered is incorrect. Please try again.".to_string(),
            GdkErrorCode::AuthMnemonicInvalid => "The recovery phrase is invalid. Please check the words and try again.".to_string(),
            GdkErrorCode::TransactionInsufficientFunds => "You don't have enough funds to complete this transaction.".to_string(),
            GdkErrorCode::TransactionFeeTooLow => "The transaction fee is too low. Please increase the fee and try again.".to_string(),
            GdkErrorCode::TransactionInvalidAddress => "The destination address is invalid. Please check the address and try again.".to_string(),
            GdkErrorCode::HardwareWalletNotConnected => "Hardware wallet is not connected. Please connect your device and try again.".to_string(),
            GdkErrorCode::HardwareWalletUserCancelled => "The operation was cancelled on the hardware wallet.".to_string(),
            _ => format!("An error occurred: {}", technical_message),
        }
    }

    /// Generate suggested actions for error recovery
    fn generate_suggested_actions(code: GdkErrorCode) -> Vec<String> {
        match code {
            GdkErrorCode::NetworkConnectionFailed => vec![
                "Check your internet connection".to_string(),
                "Try connecting to a different network".to_string(),
                "Disable VPN if enabled".to_string(),
                "Contact support if the problem persists".to_string(),
            ],
            GdkErrorCode::NetworkTimeout => vec![
                "Try again in a few moments".to_string(),
                "Check your internet connection speed".to_string(),
                "Switch to a more stable network".to_string(),
            ],
            GdkErrorCode::AuthInvalidCredentials => vec![
                "Double-check your login credentials".to_string(),
                "Reset your password if forgotten".to_string(),
                "Contact support if you're sure the credentials are correct".to_string(),
            ],
            GdkErrorCode::AuthPinIncorrect => vec![
                "Try entering your PIN again carefully".to_string(),
                "Make sure Caps Lock is not enabled".to_string(),
                "Reset your PIN if you've forgotten it".to_string(),
            ],
            GdkErrorCode::AuthMnemonicInvalid => vec![
                "Check each word in your recovery phrase".to_string(),
                "Ensure words are spelled correctly".to_string(),
                "Verify the word order is correct".to_string(),
                "Contact support if you need help recovering your wallet".to_string(),
            ],
            GdkErrorCode::TransactionInsufficientFunds => vec![
                "Add more funds to your wallet".to_string(),
                "Reduce the transaction amount".to_string(),
                "Lower the transaction fee".to_string(),
            ],
            GdkErrorCode::TransactionFeeTooLow => vec![
                "Increase the transaction fee".to_string(),
                "Use the recommended fee rate".to_string(),
                "Try again when network congestion is lower".to_string(),
            ],
            GdkErrorCode::HardwareWalletNotConnected => vec![
                "Connect your hardware wallet to the computer".to_string(),
                "Make sure the device is unlocked".to_string(),
                "Try a different USB cable or port".to_string(),
                "Update your hardware wallet firmware".to_string(),
            ],
            _ => vec!["Try the operation again".to_string(), "Contact support if the problem persists".to_string()],
        }
    }

    /// Generate recovery strategy based on error code
    fn generate_recovery_strategy(code: GdkErrorCode) -> RecoveryStrategy {
        match code {
            GdkErrorCode::NetworkTimeout | GdkErrorCode::NetworkConnectionFailed => {
                RecoveryStrategy::retry(3, code.retry_delay_ms().unwrap_or(5000))
            },
            GdkErrorCode::NetworkServerError => {
                RecoveryStrategy::retry_with_backoff(5, 10000, 2.0)
            },
            GdkErrorCode::TransactionBroadcastFailed => {
                RecoveryStrategy::retry(2, 30000)
            },
            GdkErrorCode::HardwareWalletNotConnected => {
                RecoveryStrategy::user_intervention("Please connect your hardware wallet")
            },
            GdkErrorCode::HardwareWalletUserCancelled => {
                RecoveryStrategy::user_intervention("Please confirm the operation on your hardware wallet")
            },
            GdkErrorCode::AuthInvalidCredentials | GdkErrorCode::AuthPinIncorrect => {
                RecoveryStrategy::user_intervention("Please provide correct credentials")
            },
            GdkErrorCode::TransactionInsufficientFunds => {
                RecoveryStrategy::user_intervention("Please add more funds or reduce the transaction amount")
            },
            _ => RecoveryStrategy::None,
        }
    }

    /// Add context to an existing error
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        match &mut self {
            GdkError::Network { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Auth { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::HardwareWallet { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Persistence { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Transaction { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::InvalidInput { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Crypto { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Json { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Io { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Hex { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
            GdkError::Unknown { context, .. } => { context.context.insert(key.to_string(), value.to_string()); },
        }
        self
    }

    /// Add call to the call chain
    pub fn with_call(mut self, call: &str) -> Self {
        match &mut self {
            GdkError::Network { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Auth { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::HardwareWallet { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Persistence { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Transaction { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::InvalidInput { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Crypto { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Json { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Io { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Hex { context, .. } => { context.call_chain.push(call.to_string()); },
            GdkError::Unknown { context, .. } => { context.call_chain.push(call.to_string()); },
        }
        self
    }
}

impl From<serde_json::Error> for GdkError {
    fn from(err: serde_json::Error) -> Self {
        let context = ErrorContext::new()
            .with_operation("json_serialization")
            .with_user_message("Failed to process JSON data")
            .with_suggested_action("Check the data format and try again");

        GdkError::Json {
            code: if err.is_syntax() {
                GdkErrorCode::JsonDeserializationFailed
            } else {
                GdkErrorCode::JsonSerializationFailed
            },
            message: err.to_string(),
            context,
            recovery: RecoveryStrategy::None,
            source: Some(Box::new(err)),
        }
    }
}

impl From<std::io::Error> for GdkError {
    fn from(err: std::io::Error) -> Self {
        let (code, user_message, suggested_actions) = match err.kind() {
            std::io::ErrorKind::NotFound => (
                GdkErrorCode::IoFileNotFound,
                "The requested file was not found",
                vec!["Check if the file path is correct".to_string(), "Ensure the file exists".to_string()],
            ),
            std::io::ErrorKind::PermissionDenied => (
                GdkErrorCode::IoPermissionDenied,
                "Permission denied accessing the file or directory",
                vec!["Check file permissions".to_string(), "Run with appropriate privileges".to_string()],
            ),
            std::io::ErrorKind::ConnectionRefused => (
                GdkErrorCode::IoConnectionRefused,
                "Connection was refused by the remote server",
                vec!["Check if the server is running".to_string(), "Verify the connection details".to_string()],
            ),
            std::io::ErrorKind::TimedOut => (
                GdkErrorCode::IoTimeout,
                "The operation timed out",
                vec!["Try again".to_string(), "Check your network connection".to_string()],
            ),
            std::io::ErrorKind::Interrupted => (
                GdkErrorCode::IoInterrupted,
                "The operation was interrupted",
                vec!["Try the operation again".to_string()],
            ),
            _ => (
                GdkErrorCode::InternalError,
                "An I/O error occurred",
                vec!["Try again".to_string(), "Contact support if the problem persists".to_string()],
            ),
        };

        let context = ErrorContext::new()
            .with_operation("io_operation")
            .with_user_message(user_message)
            .with_suggested_actions(suggested_actions);

        let recovery = Self::generate_recovery_strategy(code);

        GdkError::Io {
            code,
            message: err.to_string(),
            context,
            recovery,
            source: Some(Box::new(err)),
        }
    }
}

impl From<hex::FromHexError> for GdkError {
    fn from(err: hex::FromHexError) -> Self {
        let context = ErrorContext::new()
            .with_operation("hex_decoding")
            .with_user_message("Invalid hexadecimal data")
            .with_suggested_action("Check that the input contains only valid hexadecimal characters (0-9, a-f, A-F)");

        GdkError::Hex {
            code: GdkErrorCode::HexDecodingFailed,
            message: err.to_string(),
            context,
            recovery: RecoveryStrategy::None,
            source: Some(Box::new(err)),
        }
    }
}
/// Error reporting and telemetry collection
pub struct ErrorReporter {
    diagnostic_collector: crate::utils::logging::DiagnosticCollector,
    telemetry_enabled: bool,
    error_history: std::sync::Arc<std::sync::Mutex<Vec<ErrorReport>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorReport {
    pub error_code: GdkErrorCode,
    pub error_message: String,
    pub context: ErrorContext,
    pub recovery_strategy: RecoveryStrategy,
    pub stack_trace: Option<String>,
    pub system_info: HashMap<String, String>,
    pub reported_at: std::time::SystemTime,
}

impl ErrorReporter {
    /// Create a new error reporter
    pub fn new(telemetry_enabled: bool) -> Self {
        Self {
            diagnostic_collector: crate::utils::logging::DiagnosticCollector::new(),
            telemetry_enabled,
            error_history: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Report an error for telemetry and diagnostics
    pub fn report_error(&mut self, error: &GdkError) {
        let error_report = ErrorReport {
            error_code: error.code(),
            error_message: error.to_string(),
            context: error.context().clone(),
            recovery_strategy: error.recovery_strategy().clone(),
            stack_trace: self.capture_stack_trace(),
            system_info: self.collect_system_info(),
            reported_at: std::time::SystemTime::now(),
        };

        // Add to error history
        if let Ok(mut history) = self.error_history.lock() {
            history.push(error_report.clone());
            
            // Keep only the last 1000 errors
            if history.len() > 1000 {
                history.remove(0);
            }
        }

        // Record in diagnostic collector
        let mut context = HashMap::new();
        context.insert("error_code".to_string(), error.code().to_string());
        context.insert("category".to_string(), error.code().category().to_string());
        context.insert("recoverable".to_string(), error.is_recoverable().to_string());
        
        self.diagnostic_collector.record_error(
            &error.code().category(),
            &error.to_string(),
            context,
        );

        // Log the error
        log::error!(
            "Error reported: {} (code: {}, category: {}, recoverable: {})",
            error,
            error.code(),
            error.code().category(),
            error.is_recoverable()
        );

        // Send telemetry if enabled (placeholder for actual telemetry implementation)
        if self.telemetry_enabled {
            self.send_telemetry(&error_report);
        }
    }

    /// Get error statistics
    pub fn get_error_statistics(&self) -> ErrorStatistics {
        let history = self.error_history.lock().unwrap();
        let mut stats = ErrorStatistics::new();
        
        for error in history.iter() {
            stats.increment_category(error.error_code.category());
            stats.increment_code(error.error_code);
            
            if error.error_code.is_recoverable() {
                stats.recoverable_errors += 1;
            } else {
                stats.non_recoverable_errors += 1;
            }
        }
        
        stats.total_errors = history.len();
        stats
    }

    /// Get recent errors
    pub fn get_recent_errors(&self, limit: usize) -> Vec<ErrorReport> {
        let history = self.error_history.lock().unwrap();
        history.iter().rev().take(limit).cloned().collect()
    }

    /// Clear error history
    pub fn clear_error_history(&mut self) {
        if let Ok(mut history) = self.error_history.lock() {
            history.clear();
        }
    }

    /// Capture stack trace (simplified implementation)
    fn capture_stack_trace(&self) -> Option<String> {
        // In a real implementation, you might use backtrace crate
        // For now, we'll just return the current thread info
        Some(format!("Thread: {:?}", std::thread::current().id()))
    }

    /// Collect system information
    fn collect_system_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("os".to_string(), std::env::consts::OS.to_string());
        info.insert("arch".to_string(), std::env::consts::ARCH.to_string());
        info.insert("family".to_string(), std::env::consts::FAMILY.to_string());
        
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            info.insert("hostname".to_string(), hostname);
        }
        
        info
    }

    /// Send telemetry (placeholder implementation)
    fn send_telemetry(&self, _error_report: &ErrorReport) {
        // In a real implementation, this would send the error report to a telemetry service
        log::debug!("Telemetry would be sent here (not implemented)");
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorStatistics {
    pub total_errors: usize,
    pub recoverable_errors: usize,
    pub non_recoverable_errors: usize,
    pub errors_by_category: HashMap<String, usize>,
    pub errors_by_code: HashMap<GdkErrorCode, usize>,
}

impl ErrorStatistics {
    fn new() -> Self {
        Self {
            total_errors: 0,
            recoverable_errors: 0,
            non_recoverable_errors: 0,
            errors_by_category: HashMap::new(),
            errors_by_code: HashMap::new(),
        }
    }

    fn increment_category(&mut self, category: &str) {
        *self.errors_by_category.entry(category.to_string()).or_insert(0) += 1;
    }

    fn increment_code(&mut self, code: GdkErrorCode) {
        *self.errors_by_code.entry(code).or_insert(0) += 1;
    }
}

/// Error recovery utilities
pub struct ErrorRecovery;

impl ErrorRecovery {
    /// Execute an operation with automatic retry based on error recovery strategy
    pub async fn execute_with_retry<F, T, Fut>(
        operation: F,
        max_global_attempts: u32,
    ) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut global_attempts = 0;
        
        loop {
            global_attempts += 1;
            
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if global_attempts >= max_global_attempts {
                        return Err(error.with_context("max_global_attempts", &global_attempts.to_string()));
                    }
                    
                    let recovery_strategy = error.recovery_strategy().clone();
                    match recovery_strategy {
                        RecoveryStrategy::Retry { max_attempts, delay_ms, backoff_multiplier } => {
                            if global_attempts < max_attempts {
                                let delay = (delay_ms as f64 * backoff_multiplier.powi((global_attempts - 1) as i32)) as u64;
                                log::debug!("Retrying operation after {}ms (attempt {}/{})", delay, global_attempts, max_attempts);
                                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                                continue;
                            } else {
                                return Err(error.with_context("retry_exhausted", "true"));
                            }
                        },
                        RecoveryStrategy::Reconnect { max_attempts, delay_ms } => {
                            if global_attempts < max_attempts {
                                log::debug!("Attempting reconnect after {}ms (attempt {}/{})", delay_ms, global_attempts, max_attempts);
                                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                                // In a real implementation, this would trigger a reconnection
                                continue;
                            } else {
                                return Err(error.with_context("reconnect_exhausted", "true"));
                            }
                        },
                        RecoveryStrategy::Fallback { alternative } => {
                            log::debug!("Attempting fallback to: {}", alternative);
                            // In a real implementation, this would switch to the alternative method
                            return Err(error.with_context("fallback_attempted", &alternative));
                        },
                        RecoveryStrategy::Reset { component } => {
                            log::debug!("Attempting reset of component: {}", component);
                            // In a real implementation, this would reset the specified component
                            return Err(error.with_context("reset_attempted", &component));
                        },
                        RecoveryStrategy::UserIntervention { required_action } => {
                            log::debug!("User intervention required: {}", required_action);
                            return Err(error.with_context("user_intervention_required", &required_action));
                        },
                        RecoveryStrategy::None => {
                            return Err(error.with_context("no_recovery", "true"));
                        },
                    }
                }
            }
        }
    }

    /// Check if an error should be retried based on its characteristics
    pub fn should_retry(error: &GdkError, attempt: u32) -> bool {
        if !error.is_recoverable() {
            return false;
        }

        match error.recovery_strategy() {
            RecoveryStrategy::Retry { max_attempts, .. } => attempt < *max_attempts,
            RecoveryStrategy::Reconnect { max_attempts, .. } => attempt < *max_attempts,
            _ => false,
        }
    }

    /// Calculate the next retry delay
    pub fn calculate_retry_delay(error: &GdkError, attempt: u32) -> Option<std::time::Duration> {
        match error.recovery_strategy() {
            RecoveryStrategy::Retry { delay_ms, backoff_multiplier, .. } => {
                let delay = (*delay_ms as f64 * backoff_multiplier.powi(attempt as i32)) as u64;
                Some(std::time::Duration::from_millis(delay))
            },
            RecoveryStrategy::Reconnect { delay_ms, .. } => {
                Some(std::time::Duration::from_millis(*delay_ms))
            },
            _ => None,
        }
    }
}

/// Result type alias for GDK operations
pub type Result<T> = std::result::Result<T, GdkError>;

/// Macro for creating errors with context
#[macro_export]
macro_rules! gdk_error {
    ($error_type:ident, $code:expr, $msg:expr) => {
        GdkError::$error_type($code, $msg)
    };
    ($error_type:ident, $code:expr, $msg:expr, $($key:expr => $value:expr),+) => {
        {
            let mut error = GdkError::$error_type($code, $msg);
            $(
                error = error.with_context($key, $value);
            )+
            error
        }
    };
}

/// Macro for adding call chain context to errors
#[macro_export]
macro_rules! with_call_context {
    ($result:expr, $call:expr) => {
        $result.map_err(|e| e.with_call($call))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_properties() {
        let code = GdkErrorCode::NetworkTimeout;
        assert_eq!(code.category(), "Network");
        assert!(code.is_recoverable());
        assert_eq!(code.retry_delay_ms(), Some(1000));
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new()
            .with_context("key1", "value1")
            .with_call("test_function")
            .with_operation("test_operation")
            .with_user_message("Test message")
            .with_suggested_action("Try again");

        assert_eq!(context.context.get("key1"), Some(&"value1".to_string()));
        assert_eq!(context.call_chain.len(), 1);
        assert_eq!(context.operation, Some("test_operation".to_string()));
        assert_eq!(context.user_message, Some("Test message".to_string()));
        assert_eq!(context.suggested_actions.len(), 1);
    }

    #[test]
    fn test_recovery_strategy() {
        let retry_strategy = RecoveryStrategy::retry(3, 1000);
        match retry_strategy {
            RecoveryStrategy::Retry { max_attempts, delay_ms, backoff_multiplier } => {
                assert_eq!(max_attempts, 3);
                assert_eq!(delay_ms, 1000);
                assert_eq!(backoff_multiplier, 2.0);
            },
            _ => panic!("Expected retry strategy"),
        }
    }

    #[test]
    fn test_gdk_error_creation() {
        let error = GdkError::network(GdkErrorCode::NetworkTimeout, "Connection timed out");
        
        assert_eq!(error.code(), GdkErrorCode::NetworkTimeout);
        assert!(error.is_recoverable());
        assert!(error.user_message().is_some());
        assert!(!error.suggested_actions().is_empty());
    }

    #[test]
    fn test_error_with_context() {
        let error = GdkError::network(GdkErrorCode::NetworkTimeout, "Connection timed out")
            .with_context("url", "https://example.com")
            .with_call("connect_to_server");

        assert_eq!(error.context().context.get("url"), Some(&"https://example.com".to_string()));
        assert!(error.context().call_chain.contains(&"connect_to_server".to_string()));
    }

    #[test]
    fn test_error_reporter() {
        let mut reporter = ErrorReporter::new(false);
        let error = GdkError::network(GdkErrorCode::NetworkTimeout, "Test error");
        
        reporter.report_error(&error);
        
        let stats = reporter.get_error_statistics();
        assert_eq!(stats.total_errors, 1);
        assert_eq!(stats.recoverable_errors, 1);
        assert_eq!(stats.errors_by_category.get("Network"), Some(&1));
    }

    #[tokio::test]
    async fn test_error_recovery() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        
        let attempt_count = Arc::new(AtomicU32::new(0));
        let count_clone = attempt_count.clone();
        
        let operation = move || {
            let count = count_clone.clone();
            async move {
                let attempts = count.fetch_add(1, Ordering::SeqCst) + 1;
                if attempts < 3 {
                    Err(GdkError::network(GdkErrorCode::NetworkTimeout, "Temporary failure"))
                } else {
                    Ok("Success")
                }
            }
        };

        let result = ErrorRecovery::execute_with_retry(operation, 5).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Success");
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_should_retry() {
        let recoverable_error = GdkError::network(GdkErrorCode::NetworkTimeout, "Timeout");
        let non_recoverable_error = GdkError::crypto(GdkErrorCode::CryptoInvalidKey, "Invalid key");

        assert!(ErrorRecovery::should_retry(&recoverable_error, 1));
        assert!(!ErrorRecovery::should_retry(&non_recoverable_error, 1));
    }

    #[test]
    fn test_calculate_retry_delay() {
        let error = GdkError::network(GdkErrorCode::NetworkTimeout, "Timeout");
        let delay = ErrorRecovery::calculate_retry_delay(&error, 1);
        
        assert!(delay.is_some());
        assert!(delay.unwrap().as_millis() > 0);
    }
}