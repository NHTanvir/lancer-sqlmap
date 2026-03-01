//! Boundary registry. Port of upstream `xml/boundaries.xml`.
//!
//! A "boundary" is the syntactic context immediately surrounding the
//! injection point: the prefix to close the original expression, the suffix
//! to keep the rest of the query valid, and metadata about which clauses
//! (WHERE / HAVING / GROUP BY / ORDER BY / LIMIT / ...) and parameter types
//! it applies to. The detector walks the cartesian product of `boundaries ×
//! payloads × techniques` filtered by `--level` / `--risk`.

use crate::errors::Result;
use serde::{Deserialize, Serialize};

/// Clause bitfield. Matches upstream's integer set so we can copy `clause`
/// arrays verbatim from `boundaries.xml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BoundaryClause {
    /// `*` — any
    Any = 0,
    Where = 1,
    GroupBy = 2,
    OrderBy = 3,
    Limit = 4,
    Offset = 5,
    Top = 6,
    Table = 7,
    Having = 8,
    /// Generic — wraps unknown clause kinds.
    Generic = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BoundaryWhere {
    /// Replace original value with payload.
    OriginalReplace = 1,
    /// Append payload to original value.
    OriginalAppend = 2,
    /// Negate original value, e.g. `id=-1` for UNION.
    NegativeReplace = 3,
}

/// A single boundary entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Boundary {
    pub level: u8,
    pub clause: Vec<u8>,
    #[serde(rename = "where")]
    pub r#where: Vec<u8>,
    pub ptype: Vec<u8>,
    pub prefix: String,
    pub suffix: String,
    /// Optional comment.
    #[serde(default)]
    pub comment: String,
}

impl Boundary {
    pub fn applies(&self, level: u8) -> bool {
        self.level <= level
    }
}

/// Lazy-loaded registry. Reading the YAML at runtime keeps the catalog
/// editable without recompiling. v1 ships an authoritative bundled copy via
/// `include_str!` inside `sqlmap-payloads`; this module is the data model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoundaryRegistry {
    pub boundaries: Vec<Boundary>,
}

impl BoundaryRegistry {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    pub fn iter_for(&self, level: u8) -> impl Iterator<Item = &Boundary> {
        self.boundaries.iter().filter(move |b| b.applies(level))
    }

    pub fn len(&self) -> usize {
        self.boundaries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.boundaries.is_empty()
    }
}
