//! sqlmap-dbms
//!
//! Per-DBMS dialect modules. Each implements [`Dialect`] which provides:
//! - fingerprint hints (banner regex + function probes)
//! - syntax shims (concat / substring / ascii / sleep / version)
//! - privilege query
//! - file read/write SQL templates
//! - OS command vector (where supported)
//! - hash table location for `--passwords`

use sqlmap_core::dbms_kind::Dbms;

pub mod dbms;
pub mod registry;
pub mod hashing;
pub mod udf;

pub use registry::Registry;

/// One-stop shim that translates dialect-neutral queries into DBMS-specific
/// SQL. Implementors live under `src/dbms/`.
pub trait Dialect: Send + Sync {
    fn dbms(&self) -> Dbms;

    /// Banner / version function.
    fn banner_query(&self) -> &'static str;
    /// Current user.
    fn current_user_query(&self) -> &'static str;
    /// Current database / schema.
    fn current_db_query(&self) -> &'static str;
    /// Host name as seen by the server.
    fn hostname_query(&self) -> &'static str;
    /// Boolean — is the current user a DBA / superuser?
    fn is_dba_query(&self) -> &'static str;

    /// Enumerate databases.
    fn list_dbs(&self) -> &'static str;
    /// Enumerate tables for a given DB.
    fn list_tables(&self, db: &str) -> String;
    /// Enumerate columns for `db.table`.
    fn list_columns(&self, db: &str, table: &str) -> String;
    /// Count rows in a table.
    fn count_rows(&self, db: &str, table: &str) -> String;
    /// Dump rows (with LIMIT/OFFSET).
    fn dump_rows(&self, db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String;

    /// File read SQL (or `""` if unsupported).
    fn file_read(&self, path: &str) -> String;
    /// File write SQL (or `""` if unsupported).
    fn file_write(&self, bytes_hex: &str, dest: &str) -> String;
    /// OS command vector (or `""` if unsupported).
    fn os_cmd(&self, cmd: &str) -> String;

    /// Inline-substring function (DBMS-specific).
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String;
    /// ASCII / ORD of one character.
    fn ord(&self, ch: &str) -> String;
    /// Concat operator / function.
    fn concat(&self, parts: &[&str]) -> String;
    /// Sleep / delay statement.
    fn sleep(&self, seconds: u32) -> String;
    /// Password / user table location.
    fn password_table(&self) -> &'static str;
    /// Inline-comment style for `-- ` vs `#` etc.
    fn comment(&self) -> &'static str { "-- -" }
}
