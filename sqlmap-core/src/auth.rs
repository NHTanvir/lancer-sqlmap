//! HTTP authentication. Covers the five upstream `AUTH_TYPE` variants plus
//! OAuth Bearer (newer 2024-2026 addition).
//!
//! The actual challenge handling is wired in `http::HttpEngine`; this module
//! just owns the serializable spec.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    Basic,
    Digest,
    Ntlm,
    Pki,
    Bearer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSpec {
    pub kind: AuthType,
    /// `user:pass` for Basic/Digest/NTLM.
    pub cred: Option<String>,
    /// PEM file for `--auth-file`.
    pub pem: Option<PathBuf>,
    /// OAuth bearer token (initial value).
    pub bearer: Option<String>,
    /// OAuth refresh-token endpoint (transparent rotation during long runs).
    pub refresh_url: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl AuthSpec {
    pub fn basic(cred: impl Into<String>) -> Self {
        Self::with_kind(AuthType::Basic).cred(cred)
    }
    pub fn digest(cred: impl Into<String>) -> Self {
        Self::with_kind(AuthType::Digest).cred(cred)
    }
    pub fn ntlm(cred: impl Into<String>) -> Self {
        Self::with_kind(AuthType::Ntlm).cred(cred)
    }
    pub fn pki(pem: PathBuf) -> Self {
        Self {
            kind: AuthType::Pki,
            cred: None,
            pem: Some(pem),
            bearer: None,
            refresh_url: None,
            refresh_token: None,
            client_id: None,
            client_secret: None,
        }
    }
    pub fn bearer(tok: impl Into<String>) -> Self {
        Self {
            kind: AuthType::Bearer,
            cred: None,
            pem: None,
            bearer: Some(tok.into()),
            refresh_url: None,
            refresh_token: None,
            client_id: None,
            client_secret: None,
        }
    }
    fn with_kind(kind: AuthType) -> Self {
        Self {
            kind,
            cred: None,
            pem: None,
            bearer: None,
            refresh_url: None,
            refresh_token: None,
            client_id: None,
            client_secret: None,
        }
    }
    pub fn cred(mut self, c: impl Into<String>) -> Self {
        self.cred = Some(c.into());
        self
    }
}
