//! DBMS identifiers. Mirrors the upstream `DBMS` enum from
//! `lib/core/enums.py` — 44 entries as of sqlmap 1.10. v1 ships Tier 1 (26);
//! v2 adds Tier 2 (18). Every variant must round-trip through `--dbms=<name>`.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Dbms {
    // ── Tier 1 (v1 parity) ──
    MySQL,
    PostgreSQL,
    MSSQL,
    Oracle,
    SQLite,
    MariaDB,
    Firebird,
    SapMaxDb,
    Sybase,
    IbmDb2,
    Informix,
    Hsqldb,
    H2,
    MonetDb,
    Derby,
    Vertica,
    Mckoi,
    Presto,
    Altibase,
    MimerSql,
    CrateDb,
    Greenplum,
    Drizzle,
    ApacheIgnite,
    CockroachDb,
    ClickHouse,
    // ── Tier 2 (v2 parity) ──
    Access,
    Percona,
    SingleStore,
    TiDB,
    Redshift,
    AuroraMySQL,
    AuroraPostgres,
    Yugabyte,
    AlloyDb,
    OpenGauss,
    Cubrid,
    CacheIntersystems,
    Iris,
    ExtremeDb,
    FrontBase,
    Raima,
    Virtuoso,
    Dm8,
    Snowflake,
    Spanner,
    Doris,
}

impl Dbms {
    /// Canonical short name accepted by `--dbms=<name>`.
    pub fn short(self) -> &'static str {
        match self {
            Self::MySQL => "mysql",
            Self::PostgreSQL => "postgresql",
            Self::MSSQL => "mssql",
            Self::Oracle => "oracle",
            Self::SQLite => "sqlite",
            Self::MariaDB => "mariadb",
            Self::Firebird => "firebird",
            Self::SapMaxDb => "maxdb",
            Self::Sybase => "sybase",
            Self::IbmDb2 => "db2",
            Self::Informix => "informix",
            Self::Hsqldb => "hsqldb",
            Self::H2 => "h2",
            Self::MonetDb => "monetdb",
            Self::Derby => "derby",
            Self::Vertica => "vertica",
            Self::Mckoi => "mckoi",
            Self::Presto => "presto",
            Self::Altibase => "altibase",
            Self::MimerSql => "mimersql",
            Self::CrateDb => "cratedb",
            Self::Greenplum => "greenplum",
            Self::Drizzle => "drizzle",
            Self::ApacheIgnite => "ignite",
            Self::CockroachDb => "cockroachdb",
            Self::ClickHouse => "clickhouse",
            Self::Access => "access",
            Self::Percona => "percona",
            Self::SingleStore => "singlestore",
            Self::TiDB => "tidb",
            Self::Redshift => "redshift",
            Self::AuroraMySQL => "aurora-mysql",
            Self::AuroraPostgres => "aurora-postgres",
            Self::Yugabyte => "yugabyte",
            Self::AlloyDb => "alloydb",
            Self::OpenGauss => "opengauss",
            Self::Cubrid => "cubrid",
            Self::CacheIntersystems => "cache",
            Self::Iris => "iris",
            Self::ExtremeDb => "extremedb",
            Self::FrontBase => "frontbase",
            Self::Raima => "raima",
            Self::Virtuoso => "virtuoso",
            Self::Dm8 => "dm8",
            Self::Snowflake => "snowflake",
            Self::Spanner => "spanner",
            Self::Doris => "doris",
        }
    }

    /// Full set of all supported DBMSes — used by `--list-dbms` and the GUI.
    pub fn all() -> &'static [Dbms] {
        &[
            Self::MySQL, Self::PostgreSQL, Self::MSSQL, Self::Oracle, Self::SQLite,
            Self::MariaDB, Self::Firebird, Self::SapMaxDb, Self::Sybase, Self::IbmDb2,
            Self::Informix, Self::Hsqldb, Self::H2, Self::MonetDb, Self::Derby,
            Self::Vertica, Self::Mckoi, Self::Presto, Self::Altibase, Self::MimerSql,
            Self::CrateDb, Self::Greenplum, Self::Drizzle, Self::ApacheIgnite,
            Self::CockroachDb, Self::ClickHouse,
            Self::Access, Self::Percona, Self::SingleStore, Self::TiDB, Self::Redshift,
            Self::AuroraMySQL, Self::AuroraPostgres, Self::Yugabyte, Self::AlloyDb,
            Self::OpenGauss, Self::Cubrid, Self::CacheIntersystems, Self::Iris,
            Self::ExtremeDb, Self::FrontBase, Self::Raima, Self::Virtuoso, Self::Dm8,
            Self::Snowflake, Self::Spanner, Self::Doris,
        ]
    }

    /// Tier 1 — the 26 DBMSes that v1 ships dialect modules for.
    pub fn tier_1() -> &'static [Dbms] {
        &[
            Self::MySQL, Self::PostgreSQL, Self::MSSQL, Self::Oracle, Self::SQLite,
            Self::MariaDB, Self::Firebird, Self::SapMaxDb, Self::Sybase, Self::IbmDb2,
            Self::Informix, Self::Hsqldb, Self::H2, Self::MonetDb, Self::Derby,
            Self::Vertica, Self::Mckoi, Self::Presto, Self::Altibase, Self::MimerSql,
            Self::CrateDb, Self::Greenplum, Self::Drizzle, Self::ApacheIgnite,
            Self::CockroachDb, Self::ClickHouse,
        ]
    }

    /// Whether file-system access (`--file-read`/`--file-write`) is ever feasible
    /// on this DBMS. Managed cloud DBs and Snowflake/Spanner are intentionally
    /// `false` — we report this up to the user rather than silently failing.
    pub fn supports_filesystem(self) -> bool {
        !matches!(
            self,
            Self::Snowflake | Self::Spanner | Self::Iris | Self::CacheIntersystems
        )
    }

    /// Whether OS command execution (`--os-cmd`/`--os-shell`) is ever feasible.
    pub fn supports_os_cmd(self) -> bool {
        matches!(
            self,
            Self::MySQL
                | Self::MariaDB
                | Self::Percona
                | Self::PostgreSQL
                | Self::Greenplum
                | Self::Yugabyte
                | Self::OpenGauss
                | Self::MSSQL
                | Self::Oracle
        )
    }
}

impl fmt::Display for Dbms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short())
    }
}

impl FromStr for Dbms {
    type Err = crate::errors::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let needle = s.trim().to_lowercase().replace('_', "-");
        for d in Self::all() {
            if d.short() == needle {
                return Ok(*d);
            }
        }
        // Common upstream aliases.
        let alias = match needle.as_str() {
            "mysql" | "mariadb" => Self::MySQL,
            "pgsql" | "postgres" => Self::PostgreSQL,
            "ms sql" | "ms-sql" | "ms_sql" | "sqlserver" | "sql-server" => Self::MSSQL,
            "ora" => Self::Oracle,
            "lite" => Self::SQLite,
            "sap" | "sap maxdb" => Self::SapMaxDb,
            "ibm" => Self::IbmDb2,
            "ibm db2" => Self::IbmDb2,
            "h2 database" => Self::H2,
            "apache derby" => Self::Derby,
            "apache ignite" => Self::ApacheIgnite,
            "cockroach" => Self::CockroachDb,
            "click" | "clickhouse" => Self::ClickHouse,
            _ => return Err(crate::errors::Error::UnsupportedDbms(s.to_string())),
        };
        Ok(alias)
    }
}
