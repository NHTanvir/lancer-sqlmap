use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct AccessDialect;
impl Dialect for AccessDialect {
    fn dbms(&self) -> Dbms { Dbms::Access }
    fn banner_query(&self) -> &'static str { "'Microsoft Access'" }
    fn current_user_query(&self) -> &'static str { "CurrentUser()" }
    fn current_db_query(&self) -> &'static str { "CurrentProject().Name" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "CurrentUser()='admin'" }
    fn list_dbs(&self) -> &'static str { "''" }
    fn list_tables(&self, _db: &str) -> String { "SELECT Name FROM MSysObjects WHERE Type=1 AND Flags=0".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT Name FROM MSysObjects, MSysColumns WHERE MSysObjects.Name='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT TOP {count} {cols} FROM (SELECT TOP {} {cols} FROM {t} ORDER BY 1) ORDER BY 1 DESC", start + count)
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("MID(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASC({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("&") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "MSysAccounts" }
}
