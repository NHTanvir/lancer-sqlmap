use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct Db2Dialect;
impl Dialect for Db2Dialect {
    fn dbms(&self) -> Dbms { Dbms::IbmDb2 }
    fn banner_query(&self) -> &'static str { "(SELECT SERVICE_LEVEL FROM SYSIBMADM.ENV_INST_INFO)" }
    fn current_user_query(&self) -> &'static str { "USER" }
    fn current_db_query(&self) -> &'static str { "CURRENT SERVER" }
    fn hostname_query(&self) -> &'static str { "(SELECT HOST_NAME FROM SYSIBMADM.ENV_SYS_INFO)" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM SYSIBMADM.AUTHORIZATIONIDS WHERE AUTHID=USER AND DBADMAUTH='Y')" }
    fn list_dbs(&self) -> &'static str { "SELECT NAME FROM SYSIBM.SYSDUMMY1" }
    fn list_tables(&self, _db: &str) -> String { "SELECT TABNAME FROM SYSCAT.TABLES WHERE TABSCHEMA NOT LIKE 'SYS%'".into() }
    fn list_columns(&self, _db: &str, t: &str) -> String { format!("SELECT COLNAME FROM SYSCAT.COLUMNS WHERE TABNAME='{t}'") }
    fn count_rows(&self, _db: &str, t: &str) -> String { format!("SELECT COUNT(*) FROM {t}") }
    fn dump_rows(&self, _db: &str, t: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM {t} ORDER BY 1 OFFSET {start} ROWS FETCH FIRST {count} ROWS ONLY")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, e: &str, p: usize, l: usize) -> String { format!("SUBSTR(({e}),{p},{l})") }
    fn ord(&self, c: &str) -> String { format!("ASCII({c})") }
    fn concat(&self, p: &[&str]) -> String { p.join("||") }
    fn sleep(&self, _s: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "SYSIBM.SYSDUMMY1" }
}
