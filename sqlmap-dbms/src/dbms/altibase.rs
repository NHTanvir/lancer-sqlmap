use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct AltibaseDialect;
impl Dialect for AltibaseDialect {
    fn dbms(&self) -> Dbms { Dbms::Altibase }
    fn banner_query(&self) -> &'static str { "(SELECT VERSION FROM V$VERSION)" }
    fn current_user_query(&self) -> &'static str { "USER" }
    fn current_db_query(&self) -> &'static str { "(SELECT DB_NAME FROM V$DATABASE)" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM USER_ROLE_PRIVS WHERE GRANTED_ROLE='DBA')" }
    fn list_dbs(&self) -> &'static str { "SELECT DB_NAME FROM V$DATABASE" }
    fn list_tables(&self, _db: &str) -> String { "SELECT TABLE_NAME FROM SYSTEM_.SYS_TABLES_".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT COLUMN_NAME FROM SYSTEM_.SYS_COLUMNS_ WHERE TABLE_ID=(SELECT TABLE_ID FROM SYSTEM_.SYS_TABLES_ WHERE TABLE_NAME='{t}')") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} LIMIT {start},{count}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTR(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "SYSTEM_.SYS_USERS_" }
}
