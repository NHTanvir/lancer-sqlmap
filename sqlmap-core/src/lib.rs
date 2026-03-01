//! sqlmap-core
//!
//! Foundation library for `lancer-sqlmap`. GUI-agnostic; the CLI binary and the
//! GUI binary both layer on top of this crate via the `Session`, `Detector`, and
//! `Enumerator` orchestrators.
//!
//! Modules:
//! - [`target`]      — Target/Param/AuthSpec/Place model (11 PLACE variants)
//! - [`session`]     — redb-backed resumable state (kb/inj/dump/oscmd_status/msf_status)
//! - [`http`]        — HTTP engine (reqwest+rustls + rate limit + retries + proxy + Tor + HTTP/2 + MFA + CSRF + HAR + cookie jar)
//! - [`fingerprint`] — DBMS fingerprint pipeline (two-confirmation rule)
//! - [`boundary`]    — Boundary registry (port of upstream `boundaries.xml`)
//! - [`extractor`]   — Character-by-character extractor (binary search + bitwise fallback)
//! - [`oracle`]      — Response oracle (Ratcliff-Obershelp + string/regex/code/text-only/titles)
//! - [`detector`]    — Walks boundaries × payloads × techniques per `--level` / `--risk`
//! - [`enumerator`]  — `--banner` / `--current-user` / `--dbs` / `--tables` / `--columns` / `--dump` / `--search` / `--schema`
//! - [`auth`]        — Basic/Digest/NTLM/PKI/Bearer/OAuth helpers
//! - [`crawl`]       — `--crawl=N` + `--forms` HTML harvester
//! - [`graphql`]     — GraphQL endpoint detection
//! - [`request_file`] — Burp-style `-r request.txt` parser
//! - [`har`]         — HAR-format request log writer
//! - [`output`]      — Pluggable report writers (text/JSON/CSV/HTML/SQLite/SARIF/Markdown)
//! - [`reports`]     — Aggregate finding model used by GUI and CLI
//! - [`util`]        — Random tokens, char encoding helpers
//! - [`errors`]      — Crate error type
//! - [`prelude`]     — Convenience re-exports
//!
//! See the workspace `plan.md` for the full architecture.

pub mod auth;
pub mod boundary;
pub mod crawl;
pub mod detector;
pub mod dbms_kind;
pub mod enumerator;
pub mod errors;
pub mod extractor;
pub mod fingerprint;
pub mod graphql;
pub mod har;
pub mod http;
pub mod oracle;
pub mod output;
pub mod reports;
pub mod request_file;
pub mod session;
pub mod target;
pub mod util;

pub mod prelude {
    pub use crate::auth::{AuthSpec, AuthType};
    pub use crate::boundary::{Boundary, BoundaryClause, BoundaryRegistry, BoundaryWhere};
    pub use crate::dbms_kind::Dbms;
    pub use crate::detector::{DetectCtx, DetectGate, Detector};
    pub use crate::enumerator::{DumpFormat, EnumPlan, Enumerator};
    pub use crate::errors::{Error, Result};
    pub use crate::extractor::{ExtractCtx, ExtractMode, ExtractResult, Extractor};
    pub use crate::fingerprint::{FingerprintResult, Fingerprinter};
    pub use crate::har::HarWriter;
    pub use crate::http::{HttpEngine, HttpEngineBuilder, HttpRequest, HttpResponse, ProxyKind};
    pub use crate::oracle::{Oracle, OracleConfig, OracleVerdict};
    pub use crate::output::{OutputFormat, OutputWriter};
    pub use crate::reports::{Finding, FindingSeverity, ReportBundle};
    pub use crate::request_file::parse_request_file;
    pub use crate::session::{Session, SessionRecord};
    pub use crate::target::{Param, ParamPlace, ParamType, Target, TargetBuilder};
}
