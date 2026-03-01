use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct FirebirdDialect;
impl Dialect for FirebirdDialect {
    fn dbms(&self) -> Dbms { Dbms::Firebird }
    fn banner_query(&self) -> &'static str { "RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION')" }
    fn current_user_query(&self) -> &'static str { "CURRENT_USER" }
    fn current_db_query(&self) -> &'static str { "RDB$GET_CONTEXT('SYSTEM','DB_NAME')" }
    fn hostname_query(&self) -> &'static str { "RDB$GET_CONTEXT('SYSTEM','NETWORK_PROTOCOL')" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM RDB$USER_PRIVILEGES WHERE RDB$PRIVILEGE='G' AND RDB$USER=CURRENT_USER)" }
    fn list_dbs(&self) -> &'static str { "(SELECT RDB$GET_CONTEXT('SYSTEM','DB_NAME') FROM RDB$DATABASE)" }
    fn list_tables(&self, _db: &str) -> String {
        "(SELECT LIST(RDB$RELATION_NAME,',') FROM RDB$RELATIONS WHERE RDB$SYSTEM_FLAG=0)".into()
    }
    fn list_columns(&self, _db: &str, table: &str) -> String {
        format!("(SELECT LIST(RDB$FIELD_NAME,',') FROM RDB$RELATION_FIELDS WHERE RDB$RELATION_NAME='{table}')")
    }
    fn count_rows(&self, _db: &str, table: &str) -> String { format!("SELECT COUNT(*) FROM {table}") }
    fn dump_rows(&self, _db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".into() } else { cols.join(",") };
        format!("SELECT FIRST {count} SKIP {start} {cols} FROM {table}")
    }
    fn file_read(&self, _path: &str) -> String { String::new() }
    fn file_write(&self, _hex: &str, _dest: &str) -> String { String::new() }
    fn os_cmd(&self, _cmd: &str) -> String { String::new() }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String { format!("SUBSTRING(({expr}) FROM {pos} FOR {len})") }
    fn ord(&self, ch: &str) -> String { format!("ASCII_VAL({ch})") }
    fn concat(&self, parts: &[&str]) -> String { parts.join("||") }
    fn sleep(&self, _seconds: u32) -> String { "1=1".into() }
    fn password_table(&self) -> &'static str { "RDB$USERS" }
}
