use thiserror::Error;

#[derive(Error, Debug)]
pub enum GdkError {
    #[error("Network connection failed: {0}")]
    Network(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Persistence error: {0}")]
    Persistence(String),

    #[error("Invalid transaction: {0}")]
    Transaction(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hex decoding error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("An unknown error occurred")]
    Unknown,
}
