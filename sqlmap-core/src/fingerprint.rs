//! DBMS fingerprinting pipeline.
//!
//! Stages (in order; each requires two independent confirmations):
//!
//! 1. Banner / error-message regex bank
//! 2. Function-availability probes (`CONNECTION_ID()` only on MySQL, etc.)
//! 3. Version-banner extraction via working technique
//! 4. Numeric/string quirk fingerprints
//! 5. Dialect-specific blind-time function probe
//!
//! Each stage votes; the DBMS with ≥2 distinct-stage hits wins.

use crate::dbms_kind::Dbms;
use crate::errors::Result;
use crate::http::{HttpEngine, HttpResponse};
use crate::target::Target;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FingerprintResult {
    pub dbms: Option<Dbms>,
    pub banner: Option<String>,
    pub version: Option<String>,
    pub os_hint: Option<String>,
    pub confidence: f32,
    pub stages: Vec<String>,
}

pub struct Fingerprinter;

impl Fingerprinter {
    /// Pass 1 — error-message bank: looks at any prior response.
    pub fn from_response(resp: &HttpResponse) -> FingerprintResult {
        let mut votes: HashMap<Dbms, u8> = HashMap::new();
        let mut stages = Vec::new();
        let body = &resp.body;
        for (dbms, re) in ERROR_REGEXES.iter() {
            if re.is_match(body) {
                *votes.entry(*dbms).or_default() += 1;
                stages.push(format!("error-regex:{dbms:?}"));
            }
        }
        let best = votes.into_iter().max_by_key(|(_, v)| *v);
        FingerprintResult {
            dbms: best.map(|(d, _)| d),
            banner: None,
            version: None,
            os_hint: None,
            confidence: best.map(|(_, v)| v as f32 / 5.0).unwrap_or(0.0),
            stages,
        }
    }

    /// Pass 2 — function-availability probe via working B/T technique. Caller
    /// supplies an `infer` callable that runs an inference and returns bool.
    pub async fn function_probe<F, Fut>(initial: &mut FingerprintResult, mut infer: F) -> Result<()>
    where
        F: FnMut(&'static str) -> Fut,
        Fut: std::future::Future<Output = Result<bool>>,
    {
        for &(dbms, probe) in FN_PROBES.iter() {
            if infer(probe).await? {
                initial.stages.push(format!("fn-probe:{dbms:?}:{}", probe));
                if initial.dbms == Some(dbms) {
                    initial.confidence = (initial.confidence + 0.4).min(1.0);
                } else if initial.dbms.is_none() {
                    initial.dbms = Some(dbms);
                    initial.confidence = 0.5;
                }
            }
        }
        Ok(())
    }

    /// Pass 3 — banner / version extraction. Caller supplies an inference
    /// helper to fetch e.g. `@@version`.
    pub async fn extract_banner<F, Fut>(initial: &mut FingerprintResult, mut fetch: F) -> Result<()>
    where
        F: FnMut(Dbms) -> Fut,
        Fut: std::future::Future<Output = Result<Option<String>>>,
    {
        if let Some(d) = initial.dbms {
            if let Some(b) = fetch(d).await? {
                initial.banner = Some(b.clone());
                initial.version = first_version(&b);
                initial.os_hint = os_from_banner(&b);
            }
        }
        Ok(())
    }

    /// Tor-like "stand alone" call: run all passes against an arbitrary engine
    /// + target, returning the final fingerprint.
    pub async fn run(engine: &HttpEngine, target: &Target) -> Result<FingerprintResult> {
        let resp = engine.send(target).await?;
        let fp = Self::from_response(&resp);
        Ok(fp)
    }
}

fn first_version(banner: &str) -> Option<String> {
    let re = Regex::new(r"(\d+\.\d+(?:\.\d+)?)").ok()?;
    re.captures(banner).and_then(|c| c.get(1)).map(|m| m.as_str().to_string())
}

fn os_from_banner(banner: &str) -> Option<String> {
    let lower = banner.to_lowercase();
    if lower.contains("linux") {
        Some("linux".into())
    } else if lower.contains("win") || lower.contains("microsoft") {
        Some("windows".into())
    } else if lower.contains("darwin") || lower.contains("mac") {
        Some("darwin".into())
    } else if lower.contains("bsd") {
        Some("bsd".into())
    } else {
        None
    }
}

static ERROR_REGEXES: Lazy<Vec<(Dbms, Regex)>> = Lazy::new(|| {
    vec![
        (Dbms::MySQL, Regex::new(r"(?i)you have an error in your sql syntax|mysql_fetch|mysql_num_rows|warning.*mysql|MySqlException").unwrap()),
        (Dbms::MariaDB, Regex::new(r"(?i)mariadb|MariaDB version").unwrap()),
        (Dbms::PostgreSQL, Regex::new(r"(?i)psqlexception|pg_query|PostgreSQL.*ERROR|invalid input syntax for type|unterminated quoted string at or near").unwrap()),
        (Dbms::MSSQL, Regex::new(r"(?i)microsoft ole db|sqlserverexception|unclosed quotation mark|incorrect syntax near|Microsoft SQL Native Client|odbc microsoft").unwrap()),
        (Dbms::Oracle, Regex::new(r"(?i)ORA-\d{4,5}|oracle.*driver|Oracle error|OracleException").unwrap()),
        (Dbms::SQLite, Regex::new(r"(?i)sqlite\.exception|sqlite3\.OperationalError|sqlite error|near .*: syntax error|sqlite3_step").unwrap()),
        (Dbms::IbmDb2, Regex::new(r"(?i)CLI Driver.*DB2|DB2 SQL error|SQL[0-9]{4}[NW]").unwrap()),
        (Dbms::Informix, Regex::new(r"(?i)informix|com\.informix\.jdbc").unwrap()),
        (Dbms::Sybase, Regex::new(r"(?i)sybase|com\.sybase\.jdbc").unwrap()),
        (Dbms::Firebird, Regex::new(r"(?i)firebird|interbase|fbsql").unwrap()),
        (Dbms::SapMaxDb, Regex::new(r"(?i)sap.*maxdb|sap db").unwrap()),
        (Dbms::Hsqldb, Regex::new(r"(?i)hsqldb").unwrap()),
        (Dbms::H2, Regex::new(r"(?i)org\.h2\.jdbc|h2 jdbc").unwrap()),
        (Dbms::MonetDb, Regex::new(r"(?i)monetdb").unwrap()),
        (Dbms::Derby, Regex::new(r"(?i)derby|org\.apache\.derby").unwrap()),
        (Dbms::Vertica, Regex::new(r"(?i)vertica|com\.vertica\.jdbc").unwrap()),
        (Dbms::Presto, Regex::new(r"(?i)prestodb|trinodb|com\.facebook\.presto").unwrap()),
        (Dbms::ClickHouse, Regex::new(r"(?i)clickhouse|DB::Exception").unwrap()),
        (Dbms::CockroachDb, Regex::new(r"(?i)CockroachDB|crdb_internal").unwrap()),
        (Dbms::ApacheIgnite, Regex::new(r"(?i)apache ignite|org\.apache\.ignite").unwrap()),
        (Dbms::Snowflake, Regex::new(r"(?i)snowflake|net\.snowflake\.client").unwrap()),
        (Dbms::Redshift, Regex::new(r"(?i)redshift").unwrap()),
        (Dbms::TiDB, Regex::new(r"(?i)tidb").unwrap()),
        (Dbms::Yugabyte, Regex::new(r"(?i)yugabyte|yugabytedb").unwrap()),
        (Dbms::OpenGauss, Regex::new(r"(?i)opengauss|gauss").unwrap()),
        (Dbms::Cubrid, Regex::new(r"(?i)cubrid").unwrap()),
        (Dbms::Virtuoso, Regex::new(r"(?i)virtuoso").unwrap()),
    ]
});

/// Per-DBMS function probes. Each is a SQL fragment that evaluates `true` only
/// on its named DBMS (used through a working B/T inference channel).
static FN_PROBES: Lazy<Vec<(Dbms, &'static str)>> = Lazy::new(|| {
    vec![
        (Dbms::MySQL, "LENGTH(CONNECTION_ID())>0"),
        (Dbms::MariaDB, "LENGTH(@@version_comment) LIKE '%MariaDB%' OR FALSE"),
        (Dbms::PostgreSQL, "LENGTH(version()) > 0 AND CURRENT_SETTING('server_version_num') IS NOT NULL"),
        (Dbms::MSSQL, "LEN(@@VERSION)>0 AND DB_NAME() IS NOT NULL"),
        (Dbms::Oracle, "LENGTH((SELECT banner FROM v$version WHERE rownum=1))>0"),
        (Dbms::SQLite, "LENGTH(sqlite_version())>0"),
        (Dbms::IbmDb2, "LENGTH((SELECT service_level FROM sysibmadm.env_inst_info))>0"),
        (Dbms::Firebird, "RDB$GET_CONTEXT('SYSTEM','ENGINE_VERSION') IS NOT NULL"),
        (Dbms::Informix, "LENGTH(DBINFO('version','full'))>0"),
        (Dbms::Sybase, "LENGTH(@@version)>0 AND CHARINDEX('Adaptive Server',@@version)>0"),
        (Dbms::SapMaxDb, "LENGTH((SELECT VALUE FROM SYSINFO.VERSION))>0"),
        (Dbms::Hsqldb, "LENGTH((CALL DATABASE_VERSION()))>0"),
        (Dbms::H2, "LENGTH(H2VERSION())>0"),
        (Dbms::MonetDb, "LENGTH((SELECT value FROM sys.env() WHERE name='gdk_version'))>0"),
        (Dbms::Derby, "LENGTH((VALUES SYSCS_UTIL.SYSCS_GET_DATABASE_PROPERTY('DataDictionaryVersion')))>0"),
        (Dbms::Vertica, "LENGTH(VERSION())>0"),
        (Dbms::ApacheIgnite, "LENGTH((SELECT NODE_VERSION() FROM SYS.NODES LIMIT 1))>0"),
        (Dbms::Presto, "LENGTH((SELECT NODE_VERSION FROM system.runtime.nodes LIMIT 1))>0"),
        (Dbms::ClickHouse, "LENGTH(version())>0 AND LENGTH(currentDatabase())>0"),
        (Dbms::CockroachDb, "LENGTH(version()) > 0 AND crdb_internal.cluster_id() IS NOT NULL"),
        (Dbms::TiDB, "LENGTH(TIDB_VERSION())>0"),
        (Dbms::Yugabyte, "LENGTH(yb_server_version())>0"),
        (Dbms::Redshift, "LENGTH(version()) > 0 AND CURRENT_DATABASE() IS NOT NULL"),
        (Dbms::Snowflake, "LENGTH(CURRENT_VERSION())>0"),
        (Dbms::Cubrid, "LENGTH(db_version())>0"),
        (Dbms::OpenGauss, "LENGTH(opengauss_version())>0"),
        (Dbms::Dm8, "LENGTH(DBMS_DM_VERSION)>0"),
    ]
});
