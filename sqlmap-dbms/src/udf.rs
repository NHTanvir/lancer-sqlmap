//! UDF (user-defined-function) injection helpers.
//!
//! For MySQL and PostgreSQL we ship pre-compiled UDF libraries that expose
//! `sys_exec(...)` and `sys_bineval(...)`. The library bytes are bundled at
//! build-time via `include_bytes!` (see `udf/` subdir). At runtime, the OS
//! shell driver picks the right blob, writes it to the DBMS host with
//! `--file-write`, and `CREATE FUNCTION`s it.
//!
//! NOTE: these payloads are present only as 1-byte placeholders in the
//! workspace so the binary stays small; real UDFs are pulled from an external
//! repo on first use. Callers should treat `&[u8]` as opaque.

#[derive(Debug, Clone, Copy)]
pub enum UdfTarget {
    MysqlLinuxX64,
    MysqlLinuxArm64,
    MysqlWinX64,
    PostgresLinuxX64,
    PostgresWinX64,
}

pub fn library_bytes(t: UdfTarget) -> &'static [u8] {
    match t {
        UdfTarget::MysqlLinuxX64 => include_bytes!("../udf/mysql-linux-x64.placeholder"),
        UdfTarget::MysqlLinuxArm64 => include_bytes!("../udf/mysql-linux-arm64.placeholder"),
        UdfTarget::MysqlWinX64 => include_bytes!("../udf/mysql-win-x64.placeholder"),
        UdfTarget::PostgresLinuxX64 => include_bytes!("../udf/postgres-linux-x64.placeholder"),
        UdfTarget::PostgresWinX64 => include_bytes!("../udf/postgres-win-x64.placeholder"),
    }
}

pub fn create_function_sql(t: UdfTarget, name: &str, path: &str) -> String {
    match t {
        UdfTarget::MysqlLinuxX64 | UdfTarget::MysqlLinuxArm64 | UdfTarget::MysqlWinX64 => {
            format!("CREATE FUNCTION {name} RETURNS STRING SONAME '{path}'")
        }
        UdfTarget::PostgresLinuxX64 | UdfTarget::PostgresWinX64 => {
            format!("CREATE OR REPLACE FUNCTION {name}(text) RETURNS text AS '{path}','{name}' LANGUAGE 'c' STRICT")
        }
    }
}
