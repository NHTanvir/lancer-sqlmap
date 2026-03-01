//! sqlmap-tamper
//!
//! Port of upstream `tamper/*.py` — 74 built-in tamper scripts plus an
//! optional Lua loader for ad-hoc user tampers (`--tamper=lua:my.lua`).
//!
//! Each tamper implements the [`Tamper`] trait: `name`, `priority`, `apply`,
//! `is_terminal` (encoders chain last), `family` (for chain validation).
//!
//! The CLI builds a `TamperChain` via [`TamperChain::from_names`], which
//! topologically sorts by priority and rejects unsafe orderings (e.g. an
//! encoder before a keyword swapper).

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod scripts;
pub mod chain;
#[cfg(feature = "lua")]
pub mod lua;

pub use chain::TamperChain;

/// Family tag used for chain-compat validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TamperFamily {
    Encoder,
    SpaceReplacer,
    CaseMutator,
    KeywordSwapper,
    VersionComment,
    Vendor,
    Numeric,
    Header,
    Misc,
}

pub trait Tamper: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u8;
    fn family(&self) -> TamperFamily;
    fn is_terminal(&self) -> bool { false }
    fn apply(&self, payload: &str) -> String;
}

#[derive(Debug, Error)]
pub enum TamperError {
    #[error("unknown tamper: {0}")]
    Unknown(String),
    #[error("invalid chain: terminal tamper '{0}' is not the last in the chain")]
    TerminalNotLast(String),
    #[error("invalid chain: case mutator '{0}' must run after keyword swapper '{1}'")]
    CaseBeforeKeyword(String, String),
    #[error("lua error: {0}")]
    Lua(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, TamperError>;

pub fn lookup(name: &str) -> Result<Box<dyn Tamper>> {
    scripts::factory(name)
}
