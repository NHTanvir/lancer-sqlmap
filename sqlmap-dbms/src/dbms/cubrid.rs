use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct CubridDialect;
impl Dialect for CubridDialect {
    fn dbms(&self) -> Dbms { Dbms::Cubrid }
    fn banner_query(&self) -> &'static str { "db_version()" }
    fn current_user_query(&self) -> &'static str { "USER" }
    fn current_db_query(&self) -> &'static str { "(SELECT 'cubrid')" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM db_user WHERE name=USER AND groups LIKE '%DBA%')" }
    fn list_dbs(&self) -> &'static str { "(SELECT 'cubrid')" }
    fn list_tables(&self, _db: &str) -> String { "SELECT class_name FROM db_class WHERE is_system_class=0".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT attr_name FROM db_attribute WHERE class_name='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} LIMIT {start},{count}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTRING(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "db_user" }
}
