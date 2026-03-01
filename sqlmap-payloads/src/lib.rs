//! sqlmap-payloads
//!
//! Lazy-loaded boundary registry + six per-technique payload registries.
//! Each YAML file lives under `data/` and is embedded via `include_str!`
//! so the final binary is a single file.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod boundaries;
pub mod payloads;

pub use boundaries::{Boundary, BoundaryRegistry};
pub use payloads::{Payload, PayloadKind, PayloadRegistry, TechniqueId};

#[derive(Debug, Error)]
pub enum Error {
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("missing payload set: {0}")]
    Missing(String),
}

pub type Result<T> = std::result::Result<T, Error>;
