//! Boundary registry. YAML payload schema lives next to this file in
//! `data/boundaries.yaml`. Each entry is a `(prefix, suffix, clause, where,
//! ptype)` tuple describing a syntactic context.

use crate::Result;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

pub const BOUNDARIES_YAML: &str = include_str!("../data/boundaries.yaml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Boundary {
    pub level: u8,
    pub clause: Vec<u8>,
    #[serde(rename = "where")]
    pub r#where: Vec<u8>,
    pub ptype: Vec<u8>,
    pub prefix: String,
    pub suffix: String,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoundaryRegistry {
    pub boundaries: Vec<Boundary>,
}

impl BoundaryRegistry {
    pub fn bundled() -> Result<Self> {
        Ok(serde_yaml::from_str(BOUNDARIES_YAML)?)
    }

    pub fn iter_for(&self, level: u8) -> impl Iterator<Item = &Boundary> {
        self.boundaries.iter().filter(move |b| b.level <= level)
    }
}

static BUNDLED: Lazy<BoundaryRegistry> = Lazy::new(|| BoundaryRegistry::bundled().expect("bundled boundaries parse"));

pub fn bundled() -> &'static BoundaryRegistry {
    &BUNDLED
}
