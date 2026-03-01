//! Resumable session store. Backed by `redb` (pure-Rust ACID KV).
//!
//! Schema (table names mirror upstream sqlmap's `session.sqlite`):
//! - `kb`           — knowledge_base entries: arbitrary serde JSON blobs keyed by `(target_hash, name)`
//! - `inj`          — working injections per `(target_hash, param)`
//! - `dump`         — partial extraction state per `(target_hash, table, row, col, pos)`
//! - `oscmd_status` — last result of `--os-cmd` invocation
//! - `msf_status`   — Metasploit handoff state
//!
//! All values are JSON-serialised so the format is grep-able and version-tolerant.

use crate::errors::{Error, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const KB: TableDefinition<&str, &str> = TableDefinition::new("kb");
const INJ: TableDefinition<&str, &str> = TableDefinition::new("inj");
const DUMP: TableDefinition<&str, &str> = TableDefinition::new("dump");
const OSCMD: TableDefinition<&str, &str> = TableDefinition::new("oscmd_status");
const MSF: TableDefinition<&str, &str> = TableDefinition::new("msf_status");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub key: String,
    pub value: serde_json::Value,
    pub updated_at: i64,
}

pub struct Session {
    db: Database,
    path: PathBuf,
}

impl Session {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref().to_path_buf();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let db = Database::create(&p)?;
        let tx = db.begin_write()?;
        {
            let _ = tx.open_table(KB)?;
            let _ = tx.open_table(INJ)?;
            let _ = tx.open_table(DUMP)?;
            let _ = tx.open_table(OSCMD)?;
            let _ = tx.open_table(MSF)?;
        }
        tx.commit()?;
        Ok(Self { db, path: p })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn put_kb(&self, key: &str, val: &serde_json::Value) -> Result<()> {
        self.put(KB, key, val)
    }
    pub fn get_kb(&self, key: &str) -> Result<Option<serde_json::Value>> {
        self.get(KB, key)
    }

    pub fn put_injection(&self, key: &str, val: &serde_json::Value) -> Result<()> {
        self.put(INJ, key, val)
    }
    pub fn get_injection(&self, key: &str) -> Result<Option<serde_json::Value>> {
        self.get(INJ, key)
    }

    pub fn put_dump(&self, key: &str, val: &serde_json::Value) -> Result<()> {
        self.put(DUMP, key, val)
    }
    pub fn get_dump(&self, key: &str) -> Result<Option<serde_json::Value>> {
        self.get(DUMP, key)
    }

    pub fn put_oscmd(&self, key: &str, val: &serde_json::Value) -> Result<()> {
        self.put(OSCMD, key, val)
    }
    pub fn get_oscmd(&self, key: &str) -> Result<Option<serde_json::Value>> {
        self.get(OSCMD, key)
    }

    pub fn put_msf(&self, key: &str, val: &serde_json::Value) -> Result<()> {
        self.put(MSF, key, val)
    }
    pub fn get_msf(&self, key: &str) -> Result<Option<serde_json::Value>> {
        self.get(MSF, key)
    }

    /// Flush — `--flush-session` semantics.
    pub fn flush(&self) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            for def in [KB, INJ, DUMP, OSCMD, MSF] {
                let mut t = tx.open_table(def)?;
                // redb does not expose a `truncate` — iterate + remove.
                let keys: Vec<String> = t.iter()?.filter_map(|kv| kv.ok().map(|(k, _)| k.value().to_string())).collect();
                for k in keys {
                    t.remove(k.as_str())?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn put<'a>(&self, def: TableDefinition<&str, &str>, key: &str, val: &serde_json::Value) -> Result<()> {
        let txt = serde_json::to_string(val)?;
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(def)?;
            t.insert(key, txt.as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    fn get<'a>(&self, def: TableDefinition<&str, &str>, key: &str) -> Result<Option<serde_json::Value>> {
        let tx = self.db.begin_read().map_err(|e| Error::storage(e.to_string()))?;
        let t = tx.open_table(def)?;
        let opt = t.get(key)?;
        Ok(match opt {
            Some(v) => Some(serde_json::from_str(v.value())?),
            None => None,
        })
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("path", &self.path).finish()
    }
}
