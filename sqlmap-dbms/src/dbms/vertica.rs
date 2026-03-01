use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct VerticaDialect;
impl Dialect for VerticaDialect {
    fn dbms(&self) -> Dbms { Dbms::Vertica }
    fn banner_query(&self) -> &'static str { "VERSION()" }
    fn current_user_query(&self) -> &'static str { "CURRENT_USER" }
    fn current_db_query(&self) -> &'static str { "CURRENT_DATABASE" }
    fn hostname_query(&self) -> &'static str { "(SELECT host_name FROM v_monitor.nodes LIMIT 1)" }
    fn is_dba_query(&self) -> &'static str { "(SELECT is_super_user FROM users WHERE user_name=CURRENT_USER)" }
    fn list_dbs(&self) -> &'static str { "SELECT database_name FROM v_catalog.databases" }
    fn list_tables(&self, _db: &str) -> String { "SELECT table_name FROM v_catalog.tables".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT column_name FROM v_catalog.columns WHERE table_name='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} LIMIT {count} OFFSET {start}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTR(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, s: u32) -> String { format!("(SELECT SLEEP({s}))") }
    fn password_table(&self) -> &'static str { "v_internal.vs_passwords" }
}
