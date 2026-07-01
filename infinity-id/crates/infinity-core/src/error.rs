use thiserror::Error;

/// Errors produced by security-critical core operations.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("token error: {0}")]
    Token(String),

    #[error("mfa error: {0}")]
    Mfa(String),

    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CoreError>;
