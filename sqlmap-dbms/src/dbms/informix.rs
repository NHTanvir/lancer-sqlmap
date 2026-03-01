use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct InformixDialect;
impl Dialect for InformixDialect {
    fn dbms(&self) -> Dbms { Dbms::Informix }
    fn banner_query(&self) -> &'static str { "DBINFO('version','full')" }
    fn current_user_query(&self) -> &'static str { "USER" }
    fn current_db_query(&self) -> &'static str { "DBINFO('dbname')" }
    fn hostname_query(&self) -> &'static str { "DBINFO('hostname')" }
    fn is_dba_query(&self) -> &'static str { "EXISTS(SELECT 1 FROM sysusers WHERE username=USER AND usertype='D')" }
    fn list_dbs(&self) -> &'static str { "SELECT name FROM sysmaster:sysdatabases" }
    fn list_tables(&self, _db: &str) -> String { "SELECT tabname FROM systables WHERE tabid>=100".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT colname FROM syscolumns WHERE tabid=(SELECT tabid FROM systables WHERE tabname='{t}')") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT SKIP {start} FIRST {count} {cols} FROM {t}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTRING(({e}) FROM {p} FOR {l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "sysusers" }
}
