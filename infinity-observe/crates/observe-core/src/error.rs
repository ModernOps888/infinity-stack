use thiserror::Error;

/// Errors produced by security-critical core operations and algorithms.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
