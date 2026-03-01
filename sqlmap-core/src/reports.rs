//! Aggregate finding model surfaced by the CLI and consumed by the GUI Right
//! pane. Compatible with the Lancer-wide finding schema so it can be sent to
//! any other Lancer tool via `POST /v1/import`.

use crate::dbms_kind::Dbms;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub target_url: String,
    pub param: String,
    pub technique: char,
    pub dbms: Option<Dbms>,
    pub working_payload: String,
    pub evidence: String,
    pub remediation: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportBundle {
    pub findings: Vec<Finding>,
    pub session_path: Option<String>,
    pub har_path: Option<String>,
    pub started_at: i64,
    pub finished_at: i64,
}
