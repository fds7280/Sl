//! Unified error type — replaces the ad-hoc `Result<_, String>` used before.

/// Top-level application error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("vault is corrupt or unreadable: {0}")]
    Corrupt(String),

    #[error("{0}")]
    Invalid(String),
}

impl Error {
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    pub fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }

    pub fn invalid(msg: impl Into<String>) -> Self {
        Error::Invalid(msg.into())
    }
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;
