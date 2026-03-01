use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct ClickHouseDialect;
impl Dialect for ClickHouseDialect {
    fn dbms(&self) -> Dbms { Dbms::ClickHouse }
    fn banner_query(&self) -> &'static str { "version()" }
    fn current_user_query(&self) -> &'static str { "currentUser()" }
    fn current_db_query(&self) -> &'static str { "currentDatabase()" }
    fn hostname_query(&self) -> &'static str { "hostname()" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM system.users WHERE name=currentUser() AND access_type='SUPERUSER')" }
    fn list_dbs(&self) -> &'static str { "SELECT name FROM system.databases" }
    fn list_tables(&self, _db: &str) -> String { "SELECT name FROM system.tables".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT name FROM system.columns WHERE table='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} LIMIT {count} OFFSET {start}")
    }
    fn file_read(&self, p: &str) -> String { format!("(SELECT file('{p}'))") }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("substring(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("toUInt8({c})") }
    fn concat(&self, p: &[&str]) -> String { format!("concat({})", p.join(",")) }
    fn sleep(&self, s: u32) -> String { format!("sleep({s})") }
    fn password_table(&self) -> &'static str { "system.users" }
}
