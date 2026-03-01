use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct CrateDialect;
impl Dialect for CrateDialect {
    fn dbms(&self) -> Dbms { Dbms::CrateDb }
    fn banner_query(&self) -> &'static str { "(SELECT version['number'] FROM sys.nodes LIMIT 1)" }
    fn current_user_query(&self) -> &'static str { "CURRENT_USER" }
    fn current_db_query(&self) -> &'static str { "CURRENT_SCHEMA" }
    fn hostname_query(&self) -> &'static str { "(SELECT hostname FROM sys.nodes LIMIT 1)" }
    fn is_dba_query(&self) -> &'static str { "(SELECT superuser FROM sys.users WHERE name=CURRENT_USER)" }
    fn list_dbs(&self) -> &'static str { "SELECT schema_name FROM information_schema.schemata" }
    fn list_tables(&self, _db: &str) -> String { "SELECT table_name FROM information_schema.tables".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT column_name FROM information_schema.columns WHERE table_name='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} LIMIT {count} OFFSET {start}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("substring(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ascii({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "sys.users" }
}
