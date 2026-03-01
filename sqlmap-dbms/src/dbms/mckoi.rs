use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct McKoiDialect;
impl Dialect for McKoiDialect {
    fn dbms(&self) -> Dbms { Dbms::Mckoi }
    fn banner_query(&self) -> &'static str { "(SELECT VERSION FROM SYS_INFO.PRODUCT_INFO)" }
    fn current_user_query(&self) -> &'static str { "USER()" }
    fn current_db_query(&self) -> &'static str { "CURRENT_SCHEMA" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "USER()='ADMIN'" }
    fn list_dbs(&self) -> &'static str { "SELECT NAME FROM SYS_INFO.DB_INFO" }
    fn list_tables(&self, _db: &str) -> String { "SELECT TABLE_NAME FROM SYS_INFO.TABLES".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT COLUMN_NAME FROM SYS_INFO.COLUMNS WHERE TABLE_NAME='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} LIMIT {count} OFFSET {start}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTRING(({e}) FROM {p} FOR {l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "" }
}
