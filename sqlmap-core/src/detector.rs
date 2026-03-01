//! Detector — walks `boundaries × payloads × techniques` to find the first
//! working combination per (param, technique) tuple.

use crate::boundary::Boundary;
use crate::dbms_kind::Dbms;
use crate::errors::Result;
use crate::http::HttpEngine;
use crate::oracle::Oracle;
use crate::target::Target;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DetectGate {
    pub level: u8,
    pub risk: u8,
    pub time_sec: u32,
}

impl Default for DetectGate {
    fn default() -> Self {
        Self { level: 1, risk: 1, time_sec: 5 }
    }
}

#[derive(Debug, Clone)]
pub struct DetectCtx {
    pub engine: HttpEngine,
    pub target: Target,
    pub param: String,
    pub boundary: Boundary,
    pub oracle: Arc<parking_lot::Mutex<Oracle>>,
    pub gate: DetectGate,
    pub dbms_hint: Option<Dbms>,
    pub technique_letters: Vec<char>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingPayload {
    pub technique: char,
    pub title: String,
    pub vector: String,
    pub prefix: String,
    pub suffix: String,
    pub dbms: Option<Dbms>,
}

/// The detector itself is a thin shell that delegates per-technique work to
/// `sqlmap-techniques`. We keep the orchestration here so the `Session` /
/// `Enumerator` layers don't pull a dep on every technique.
#[derive(Debug, Clone, Default)]
pub struct Detector;

impl Detector {
    /// Iterate boundaries from a registry; the caller is responsible for
    /// instantiating per-technique drivers from `sqlmap-techniques`.
    pub fn applicable_boundaries<'a>(
        registry: &'a crate::boundary::BoundaryRegistry,
        gate: DetectGate,
    ) -> impl Iterator<Item = &'a Boundary> {
        registry.iter_for(gate.level)
    }

    /// Compose the final payload string from `(boundary.prefix, vector, boundary.suffix)`.
    pub fn render_payload(boundary: &Boundary, vector: &str) -> String {
        format!("{}{}{}", boundary.prefix, vector, boundary.suffix)
    }

    /// Skip-rule: a boundary doesn't apply if its ptype list excludes the
    /// observed param's ptype, or its clause list is non-`Any` and the param
    /// is known to live outside those clauses.
    pub fn boundary_applies(b: &Boundary, ptype: u8) -> bool {
        if b.ptype.is_empty() {
            return true;
        }
        b.ptype.contains(&ptype)
    }
}
