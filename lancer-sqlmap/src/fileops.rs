//! High-level wrappers around `--file-read`/`--file-write` and `--os-cmd`/`--os-shell`.
//!
//! These adapt a known-working injection (vector + boundary + dialect) into
//! the dialect-specific SQL needed to do filesystem / OS work. The actual
//! HTTP traversal is owned by [`sqlmap_core::http::HttpEngine`].

use eyre::Result;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::http::HttpEngine;
use sqlmap_core::target::Target;
use sqlmap_dbms::{registry::Registry, Dialect};
use tracing::info;

pub struct FileOps<'a> {
    pub engine: &'a HttpEngine,
    pub target: &'a Target,
    pub param: &'a str,
    pub prefix: &'a str,
    pub suffix: &'a str,
    pub dialect: Box<dyn Dialect>,
}

impl<'a> FileOps<'a> {
    pub fn new(
        engine: &'a HttpEngine,
        target: &'a Target,
        param: &'a str,
        prefix: &'a str,
        suffix: &'a str,
        dbms: Dbms,
    ) -> Self {
        let dialect = Registry::get(dbms);
        Self { engine, target, param, prefix, suffix, dialect }
    }

    pub async fn read(&self, path: &str) -> Result<String> {
        if !self.dialect.dbms().supports_filesystem() {
            return Err(eyre::eyre!("{} does not support filesystem access", self.dialect.dbms()));
        }
        let sql = self.dialect.file_read(path);
        if sql.is_empty() {
            return Err(eyre::eyre!("dialect does not implement file_read"));
        }
        let payload = format!("{}{}{}", self.prefix, sql, self.suffix);
        let resp = self.engine.send_with_payload(self.target, self.param, &payload).await?;
        Ok(resp.body)
    }

    pub async fn write(&self, bytes: &[u8], dest: &str) -> Result<()> {
        if !self.dialect.dbms().supports_filesystem() {
            return Err(eyre::eyre!("{} does not support filesystem write", self.dialect.dbms()));
        }
        let hex = hex::encode(bytes);
        let sql = self.dialect.file_write(&hex, dest);
        if sql.is_empty() {
            return Err(eyre::eyre!("dialect does not implement file_write"));
        }
        let payload = format!("{}{}{}", self.prefix, sql, self.suffix);
        let _resp = self.engine.send_with_payload(self.target, self.param, &payload).await?;
        info!("wrote {} bytes to {}", bytes.len(), dest);
        Ok(())
    }

    pub async fn os_cmd(&self, cmd: &str) -> Result<String> {
        if !self.dialect.dbms().supports_os_cmd() {
            return Err(eyre::eyre!("{} does not support OS command execution", self.dialect.dbms()));
        }
        let sql = self.dialect.os_cmd(cmd);
        if sql.is_empty() {
            return Err(eyre::eyre!("dialect does not implement os_cmd"));
        }
        let payload = format!("{}{}{}", self.prefix, sql, self.suffix);
        let resp = self.engine.send_with_payload(self.target, self.param, &payload).await?;
        Ok(resp.body)
    }
}
