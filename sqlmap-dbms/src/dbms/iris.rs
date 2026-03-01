use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct IrisDialect;
impl Dialect for IrisDialect {
    fn dbms(&self) -> Dbms { Dbms::Iris }
    fn banner_query(&self) -> &'static str { "$SYSTEM.Version.GetVersion()" }
    fn current_user_query(&self) -> &'static str { "$USERNAME" }
    fn current_db_query(&self) -> &'static str { "$NAMESPACE" }
    fn hostname_query(&self) -> &'static str { "$SYSTEM.INetInfo.HostName()" }
    fn is_dba_query(&self) -> &'static str { "$SYSTEM.Security.Check('%All','U')" }
    fn list_dbs(&self) -> &'static str { "SELECT Name FROM %SYS.Namespace" }
    fn list_tables(&self, _db: &str) -> String { "SELECT Name FROM %Dictionary.CompiledClass".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT Name FROM %Dictionary.CompiledProperty WHERE parent='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT TOP {count} {cols} FROM {t}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("$EXTRACT(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("$ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("_") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "Security.Users" }
}
