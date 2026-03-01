//! Crate error type. Everything in `sqlmap-core` returns [`Result<T>`].
//!
//! We use a single `thiserror`-derived enum (mirrors upstream's pickled
//! exception family) so callers can pattern-match on specific failure modes
//! without parsing strings.

use thiserror::Error;

/// Result alias used across the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// All failure modes that `sqlmap-core` can produce.
#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("invalid HTTP request file: {0}")]
    RequestFile(String),

    #[error("invalid target: {0}")]
    InvalidTarget(String),

    #[error("session storage error: {0}")]
    Storage(String),

    #[error("redb error: {0}")]
    Redb(#[from] redb::Error),

    #[error("redb table error: {0}")]
    RedbTable(#[from] redb::TableError),

    #[error("redb transaction error: {0}")]
    RedbTxn(#[from] redb::TransactionError),

    #[error("redb commit error: {0}")]
    RedbCommit(#[from] redb::CommitError),

    #[error("redb database error: {0}")]
    RedbDb(#[from] redb::DatabaseError),

    #[error("redb storage error: {0}")]
    RedbStorage(#[from] redb::StorageError),

    #[error("serde JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[error("serde YAML error: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("oracle inconclusive: {0}")]
    OracleInconclusive(String),

    #[error("no working payload found")]
    NoWorkingPayload,

    #[error("no working technique found")]
    NoWorkingTechnique,

    #[error("DBMS fingerprint failed: {0}")]
    FingerprintFailed(String),

    #[error("unsupported DBMS: {0}")]
    UnsupportedDbms(String),

    #[error("extraction failed at position {pos}: {reason}")]
    ExtractionFailed { pos: usize, reason: String },

    #[error("auth challenge failed: {0}")]
    AuthFailed(String),

    #[error("CSRF token fetch failed: {0}")]
    CsrfFailed(String),

    #[error("Tor verification failed: {0}")]
    TorFailed(String),

    #[error("MFA prompt cancelled")]
    MfaCancelled,

    #[error("rate limited (HTTP {0})")]
    RateLimited(u16),

    #[error("operation cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }
}
