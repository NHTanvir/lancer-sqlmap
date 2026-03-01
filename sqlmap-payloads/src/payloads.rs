//! Per-technique payload registry. Six YAML files under `data/payloads/`:
//! `boolean.yaml` / `error.yaml` / `union.yaml` / `stacked.yaml` /
//! `time.yaml` / `inline.yaml`.

use crate::Result;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TechniqueId {
    Boolean,
    Error,
    Union,
    Stacked,
    Time,
    Inline,
}

impl TechniqueId {
    pub fn letter(self) -> char {
        match self {
            Self::Boolean => 'B',
            Self::Error => 'E',
            Self::Union => 'U',
            Self::Stacked => 'S',
            Self::Time => 'T',
            Self::Inline => 'Q',
        }
    }
    pub fn from_letter(c: char) -> Option<Self> {
        match c.to_ascii_uppercase() {
            'B' => Some(Self::Boolean),
            'E' => Some(Self::Error),
            'U' => Some(Self::Union),
            'S' => Some(Self::Stacked),
            'T' => Some(Self::Time),
            'Q' => Some(Self::Inline),
            _ => None,
        }
    }
}

/// Pluggable payload kind = technique class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadKind {
    BooleanBlind,
    ErrorBased,
    Union,
    Stacked,
    TimeBlind,
    InlineQuery,
}

impl From<TechniqueId> for PayloadKind {
    fn from(t: TechniqueId) -> Self {
        match t {
            TechniqueId::Boolean => Self::BooleanBlind,
            TechniqueId::Error => Self::ErrorBased,
            TechniqueId::Union => Self::Union,
            TechniqueId::Stacked => Self::Stacked,
            TechniqueId::Time => Self::TimeBlind,
            TechniqueId::Inline => Self::InlineQuery,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadRequest {
    pub payload: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub char: Option<String>,
    #[serde(default)]
    pub columns: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PayloadResponse {
    #[serde(default)]
    pub comparison: Option<PayloadRequest>,
    #[serde(default)]
    pub grep: Option<String>,
    #[serde(default)]
    pub time: Option<u32>,
    #[serde(default)]
    pub union: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    pub title: String,
    pub stype: u8,
    pub level: u8,
    pub risk: u8,
    pub clause: Vec<u8>,
    #[serde(rename = "where")]
    pub r#where: u8,
    #[serde(default)]
    pub vector: String,
    pub request: PayloadRequest,
    #[serde(default)]
    pub response: PayloadResponse,
    #[serde(default)]
    pub details: serde_yaml::Value,
    #[serde(default)]
    pub dbms: Vec<String>,
    #[serde(default)]
    pub comment: String,
}

pub const BOOLEAN_YAML: &str = include_str!("../data/payloads/boolean.yaml");
pub const ERROR_YAML: &str = include_str!("../data/payloads/error.yaml");
pub const UNION_YAML: &str = include_str!("../data/payloads/union.yaml");
pub const STACKED_YAML: &str = include_str!("../data/payloads/stacked.yaml");
pub const TIME_YAML: &str = include_str!("../data/payloads/time.yaml");
pub const INLINE_YAML: &str = include_str!("../data/payloads/inline.yaml");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PayloadSet {
    pub payloads: Vec<Payload>,
}

#[derive(Debug, Clone, Default)]
pub struct PayloadRegistry {
    pub boolean: PayloadSet,
    pub error: PayloadSet,
    pub union: PayloadSet,
    pub stacked: PayloadSet,
    pub time: PayloadSet,
    pub inline: PayloadSet,
}

impl PayloadRegistry {
    pub fn bundled() -> Result<Self> {
        Ok(Self {
            boolean: serde_yaml::from_str(BOOLEAN_YAML)?,
            error: serde_yaml::from_str(ERROR_YAML)?,
            union: serde_yaml::from_str(UNION_YAML)?,
            stacked: serde_yaml::from_str(STACKED_YAML)?,
            time: serde_yaml::from_str(TIME_YAML)?,
            inline: serde_yaml::from_str(INLINE_YAML)?,
        })
    }

    pub fn iter_for(
        &self,
        t: TechniqueId,
        level: u8,
        risk: u8,
        dbms_short: Option<&str>,
    ) -> impl Iterator<Item = &Payload> {
        let set = match t {
            TechniqueId::Boolean => &self.boolean,
            TechniqueId::Error => &self.error,
            TechniqueId::Union => &self.union,
            TechniqueId::Stacked => &self.stacked,
            TechniqueId::Time => &self.time,
            TechniqueId::Inline => &self.inline,
        };
        let owned = dbms_short.map(|s| s.to_string());
        set.payloads.iter().filter(move |p| {
            p.level <= level
                && p.risk <= risk
                && (p.dbms.is_empty() || owned.as_ref().map(|s| p.dbms.iter().any(|d| d == s)).unwrap_or(true))
        })
    }
}

static BUNDLED: Lazy<PayloadRegistry> = Lazy::new(|| PayloadRegistry::bundled().expect("bundled payloads parse"));

pub fn bundled() -> &'static PayloadRegistry {
    &BUNDLED
}
