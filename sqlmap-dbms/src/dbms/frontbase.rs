use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct FrontBaseDialect;
impl Dialect for FrontBaseDialect {
    fn dbms(&self) -> Dbms { Dbms::FrontBase }
    fn banner_query(&self) -> &'static str { "'FrontBase'" }
    fn current_user_query(&self) -> &'static str { "USER" }
    fn current_db_query(&self) -> &'static str { "CURRENT_CATALOG" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM INFORMATION_SCHEMA.USERS WHERE USER_NAME=USER AND IS_DBA=TRUE)" }
    fn list_dbs(&self) -> &'static str { "SELECT CATALOG_NAME FROM INFORMATION_SCHEMA.CATALOGS" }
    fn list_tables(&self, _db: &str) -> String { "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{t}'") }
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
    fn password_table(&self) -> &'static str { "INFORMATION_SCHEMA.USERS" }
}
