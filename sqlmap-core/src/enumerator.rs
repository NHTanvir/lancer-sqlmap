//! Enumerator — orchestrates `--banner` / `--current-user` / `--dbs` /
//! `--tables` / `--columns` / `--schema` / `--dump` / `--search` / `--statements`.
//!
//! Picks the cheapest working technique per query (`U > E > Q > B > T`) and
//! issues extraction queries through `sqlmap-core::extractor`.

use crate::dbms_kind::Dbms;
use crate::errors::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DumpFormat {
    Stdout,
    Csv,
    Html,
    Sqlite,
    Markdown,
    Json,
    Sarif,
}

impl DumpFormat {
    pub fn ext(self) -> &'static str {
        match self {
            Self::Stdout | Self::Markdown => "md",
            Self::Csv => "csv",
            Self::Html => "html",
            Self::Sqlite => "sqlite",
            Self::Json => "json",
            Self::Sarif => "sarif.json",
        }
    }
}

/// User-driven plan describing what enumeration to perform.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnumPlan {
    pub all: bool,
    pub banner: bool,
    pub current_user: bool,
    pub current_db: bool,
    pub hostname: bool,
    pub is_dba: bool,
    pub users: bool,
    pub passwords: bool,
    pub privileges: bool,
    pub roles: bool,
    pub dbs: bool,
    pub tables: bool,
    pub columns: bool,
    pub schema: bool,
    pub count: bool,
    pub dump: bool,
    pub dump_all: bool,
    pub search: Option<String>,
    pub comments: bool,
    pub statements: bool,
    pub exclude_sysdbs: bool,
    pub specific_db: Option<String>,
    pub specific_tables: Vec<String>,
    pub specific_columns: Vec<String>,
    pub excluded_columns: Vec<String>,
    pub specific_user: Option<String>,
    pub pivot_column: Option<String>,
    pub where_clause: Option<String>,
    pub start: Option<usize>,
    pub stop: Option<usize>,
    pub first: Option<usize>,
    pub last: Option<usize>,
    pub sql_query: Option<String>,
    pub sql_shell: bool,
    pub sql_file: Option<String>,
    pub common_tables: bool,
    pub common_columns: bool,
    pub common_files: bool,
    pub format: DumpFormat,
}

impl Default for DumpFormat {
    fn default() -> Self {
        Self::Stdout
    }
}

/// One row of an enumerated dump.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DumpedRow {
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DumpedTable {
    pub db: String,
    pub table: String,
    pub columns: Vec<String>,
    pub rows: Vec<DumpedRow>,
    pub estimated_count: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnumResult {
    pub banner: Option<String>,
    pub current_user: Option<String>,
    pub current_db: Option<String>,
    pub hostname: Option<String>,
    pub is_dba: Option<bool>,
    pub users: Vec<String>,
    pub passwords: Vec<(String, String)>,
    pub privileges: Vec<(String, Vec<String>)>,
    pub roles: Vec<(String, Vec<String>)>,
    pub dbs: Vec<String>,
    pub tables: Vec<(String, Vec<String>)>,
    pub columns: Vec<(String, String, Vec<(String, String)>)>,
    pub dumps: Vec<DumpedTable>,
    pub comments: Vec<String>,
    pub statements: Vec<String>,
    pub fingerprint_dbms: Option<Dbms>,
}

pub struct Enumerator;

impl Enumerator {
    /// Stub orchestrator — wires up by `sqlmap-techniques` so this crate can
    /// stay dependency-free. The CLI / GUI gets a single entry point on top.
    pub async fn execute(_plan: &EnumPlan) -> Result<EnumResult> {
        Ok(EnumResult::default())
    }
}
