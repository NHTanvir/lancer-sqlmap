use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct DorisDialect;
impl Dialect for DorisDialect {
    fn dbms(&self) -> Dbms { Dbms::Doris }
    fn banner_query(&self) -> &'static str { "VERSION()" }
    fn current_user_query(&self) -> &'static str { "USER()" }
    fn current_db_query(&self) -> &'static str { "DATABASE()" }
    fn hostname_query(&self) -> &'static str { "@@HOSTNAME" }
    fn is_dba_query(&self) -> &'static str { "USER()='root@%'" }
    fn list_dbs(&self) -> &'static str { "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA" }
    fn list_tables(&self, db: &str) -> String { format!("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{db}'") }
    fn list_columns(&self, db: &str, t: &str) -> String { format!("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{db}' AND TABLE_NAME='{t}'") }
    fn count_rows(&self, db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {db}.{t}") }
    fn dump_rows(&self, db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {db}.{t} LIMIT {start},{count}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTRING(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { format!("CONCAT({})", p.join(",")) }
    fn sleep(&self, s: u32) -> String { format!("SLEEP({s})") }
    fn password_table(&self) -> &'static str { "" }
}
