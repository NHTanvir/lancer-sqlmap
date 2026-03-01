use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct SybaseDialect;
impl Dialect for SybaseDialect {
    fn dbms(&self) -> Dbms { Dbms::Sybase }
    fn banner_query(&self) -> &'static str { "@@VERSION" }
    fn current_user_query(&self) -> &'static str { "SUSER_NAME()" }
    fn current_db_query(&self) -> &'static str { "DB_NAME()" }
    fn hostname_query(&self) -> &'static str { "@@SERVERNAME" }
    fn is_dba_query(&self) -> &'static str { "ISNULL(USER_NAME(),'')='dbo'" }
    fn list_dbs(&self) -> &'static str { "SELECT name FROM master..sysdatabases" }
    fn list_tables(&self, db: &str) -> String { format!("SELECT name FROM {db}..sysobjects WHERE type='U'") }
    fn list_columns(&self, db: &str, table: &str) -> String {
        format!("SELECT name FROM {db}..syscolumns WHERE id=OBJECT_ID('{db}..{table}')")
    }
    fn count_rows(&self, _db: &str, table: &str) -> String { format!("SELECT COUNT(*) FROM {table}") }
    fn dump_rows(&self, _db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT {cols} FROM (SELECT TOP {count} {cols},ROW_NUMBER() OVER (ORDER BY 1) rn FROM {table}) t WHERE rn>{start}")
    }
    fn file_read(&self, _p: &str) -> String { String::new() }
    fn file_write(&self, _h: &str, _d: &str) -> String { String::new() }
    fn os_cmd(&self, _c: &str) -> String { String::new() }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String { format!("SUBSTRING(({expr}),{pos},{len})") }
    fn ord(&self, ch: &str) -> String { format!("ASCII({ch})") }
    fn concat(&self, p: &[&str]) -> String { p.join("+") }
    fn sleep(&self, s: u32) -> String { format!("WAITFOR DELAY '0:0:{s}'") }
    fn password_table(&self) -> &'static str { "master..syslogins" }
}
