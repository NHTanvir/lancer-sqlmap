use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct SapMaxDbDialect;
impl Dialect for SapMaxDbDialect {
    fn dbms(&self) -> Dbms { Dbms::SapMaxDb }
    fn banner_query(&self) -> &'static str { "(SELECT VALUE FROM SYSINFO.VERSION)" }
    fn current_user_query(&self) -> &'static str { "USER" }
    fn current_db_query(&self) -> &'static str { "(SELECT VALUE FROM SYSINFO.SYSTEM WHERE KEY='DATABASE NAME')" }
    fn hostname_query(&self) -> &'static str { "(SELECT VALUE FROM SYSINFO.SYSTEM WHERE KEY='HOST')" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM SYSINFO.USERS WHERE NAME=USER AND USERMODE='SYSADM')" }
    fn list_dbs(&self) -> &'static str { "(SELECT VALUE FROM SYSINFO.SYSTEM WHERE KEY='DATABASE NAME')" }
    fn list_tables(&self, _db: &str) -> String { "(SELECT TABLENAME FROM DOMAIN.TABLES)".into() }
    fn list_columns(&self, _db: &str, table: &str) -> String {
        format!("(SELECT COLUMNNAME FROM DOMAIN.COLUMNS WHERE TABLENAME='{table}')")
    }
    fn count_rows(&self, _db: &str, table: &str) -> String { format!("SELECT COUNT(*) FROM {table}") }
    fn dump_rows(&self, _db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {table} LIMIT {count} OFFSET {start}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String { format!("SUBSTR(({expr}),{pos},{len})") }
    fn ord(&self, ch: &str) -> String { format!("ASCII({ch})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "SYSINFO.USERS" }
}
