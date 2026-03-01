use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct ExtremeDbDialect;
impl Dialect for ExtremeDbDialect {
    fn dbms(&self) -> Dbms { Dbms::ExtremeDb }
    fn banner_query(&self) -> &'static str { "'eXtremeDB'" }
    fn current_user_query(&self) -> &'static str { "''" }
    fn current_db_query(&self) -> &'static str { "''" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "1=1" }
    fn list_dbs(&self) -> &'static str { "(SELECT 'extremedb')" }
    fn list_tables(&self, _db: &str) -> String { "SELECT name FROM mco_sys_class".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT name FROM mco_sys_attribute WHERE class='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], _start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} LIMIT {count}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTR(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "" }
}
