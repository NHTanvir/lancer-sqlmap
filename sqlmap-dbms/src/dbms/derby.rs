use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct DerbyDialect;
impl Dialect for DerbyDialect {
    fn dbms(&self) -> Dbms { Dbms::Derby }
    fn banner_query(&self) -> &'static str { "(VALUES SYSCS_UTIL.SYSCS_GET_DATABASE_PROPERTY('DataDictionaryVersion'))" }
    fn current_user_query(&self) -> &'static str { "CURRENT_USER" }
    fn current_db_query(&self) -> &'static str { "CURRENT SCHEMA" }
    fn hostname_query(&self) -> &'static str { "''" }
    fn is_dba_query(&self) -> &'static str { "1=1" }
    fn list_dbs(&self) -> &'static str { "SELECT SCHEMANAME FROM SYS.SYSSCHEMAS" }
    fn list_tables(&self, _db: &str) -> String { "SELECT TABLENAME FROM SYS.SYSTABLES".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT COLUMNNAME FROM SYS.SYSCOLUMNS WHERE REFERENCEID=(SELECT TABLEID FROM SYS.SYSTABLES WHERE TABLENAME='{t}')") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} OFFSET {start} ROWS FETCH NEXT {count} ROWS ONLY")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTR(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "" }
}
