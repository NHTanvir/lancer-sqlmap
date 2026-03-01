//! sqlmap-techniques
//!
//! Six injection technique drivers implementing a shared [`Technique`] trait.
//! Detection and extraction share one code path — detection asks "does the
//! oracle flip when I inject this?", extraction asks "what is the value of
//! SUBSTR(secret, i, 1)?"

use async_trait::async_trait;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::errors::Result;
use sqlmap_core::extractor::ExtractResult;
use sqlmap_core::http::HttpEngine;
use sqlmap_core::oracle::Oracle;
use sqlmap_core::target::Target;

pub mod boolean;
pub mod error;
pub mod inline;
pub mod stacked;
pub mod time;
pub mod union;

pub use boolean::BooleanTechnique;
pub use error::ErrorTechnique;
pub use inline::InlineTechnique;
pub use stacked::StackedTechnique;
pub use time::TimeTechnique;
pub use union::UnionTechnique;

#[derive(Debug, Clone)]
pub struct DetectCtx<'a> {
    pub engine: &'a HttpEngine,
    pub target: &'a Target,
    pub param: &'a str,
    pub oracle: std::sync::Arc<parking_lot::Mutex<Oracle>>,
    pub level: u8,
    pub risk: u8,
    pub dbms_hint: Option<Dbms>,
    pub time_sec: u32,
}

#[derive(Debug, Clone)]
pub struct ExtractCtx<'a> {
    pub engine: &'a HttpEngine,
    pub target: &'a Target,
    pub param: &'a str,
    pub oracle: std::sync::Arc<parking_lot::Mutex<Oracle>>,
    pub working_prefix: String,
    pub working_suffix: String,
    pub working_vector: String,
    pub dbms: Dbms,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkingPayload {
    pub technique: char,
    pub title: String,
    pub vector: String,
    pub prefix: String,
    pub suffix: String,
    pub dbms: Option<Dbms>,
    pub evidence: String,
}

/// Concurrency cap for one technique. Used by the orchestrator so each
/// technique can opt-out of `--threads N`.
#[derive(Debug, Clone, Copy)]
pub enum ConcurrencyCap {
    /// Use as many threads as `--threads` allows.
    Full,
    /// Serialize — typical for time-blind / stacked.
    One,
}

#[async_trait]
pub trait Technique: Send + Sync {
    fn id(&self) -> char;
    fn name(&self) -> &'static str;
    fn dbms_scope(&self) -> &'static [Dbms];
    fn concurrency_cap(&self) -> ConcurrencyCap {
        ConcurrencyCap::Full
    }

    async fn detect(&self, ctx: &mut DetectCtx<'_>) -> Result<Option<WorkingPayload>>;
    async fn extract(&self, ctx: &mut ExtractCtx<'_>, query: &str) -> Result<ExtractResult>;
}

/// Registry of all six techniques in the canonical preference order used by
/// the enumerator (`U > E > Q > B > T`, with `S` last because it mutates).
pub fn all_techniques() -> Vec<Box<dyn Technique>> {
    vec![
        Box::new(UnionTechnique::default()),
        Box::new(ErrorTechnique::default()),
        Box::new(InlineTechnique::default()),
        Box::new(BooleanTechnique::default()),
        Box::new(TimeTechnique::default()),
        Box::new(StackedTechnique::default()),
    ]
}
