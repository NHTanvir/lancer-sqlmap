//! Dialect registry — lookup by `Dbms` enum.

use crate::{dbms::*, Dialect};
use sqlmap_core::dbms_kind::Dbms;

pub struct Registry;

impl Registry {
    pub fn get(dbms: Dbms) -> Box<dyn Dialect> {
        match dbms {
            Dbms::MySQL | Dbms::MariaDB | Dbms::Percona | Dbms::TiDB | Dbms::SingleStore | Dbms::AuroraMySQL | Dbms::Drizzle => Box::new(MySQLDialect),
            Dbms::PostgreSQL | Dbms::Greenplum | Dbms::Redshift | Dbms::CockroachDb | Dbms::Yugabyte | Dbms::AlloyDb | Dbms::OpenGauss | Dbms::AuroraPostgres => Box::new(PostgresDialect),
            Dbms::MSSQL => Box::new(MssqlDialect),
            Dbms::Oracle | Dbms::Dm8 => Box::new(OracleDialect),
            Dbms::SQLite => Box::new(SqliteDialect),
            Dbms::Firebird => Box::new(FirebirdDialect),
            Dbms::SapMaxDb => Box::new(SapMaxDbDialect),
            Dbms::Sybase => Box::new(SybaseDialect),
            Dbms::IbmDb2 => Box::new(Db2Dialect),
            Dbms::Informix => Box::new(InformixDialect),
            Dbms::Hsqldb => Box::new(HsqldbDialect),
            Dbms::H2 => Box::new(H2Dialect),
            Dbms::MonetDb => Box::new(MonetDbDialect),
            Dbms::Derby => Box::new(DerbyDialect),
            Dbms::Vertica => Box::new(VerticaDialect),
            Dbms::Mckoi => Box::new(McKoiDialect),
            Dbms::Presto => Box::new(PrestoDialect),
            Dbms::Altibase => Box::new(AltibaseDialect),
            Dbms::MimerSql => Box::new(MimerDialect),
            Dbms::CrateDb => Box::new(CrateDialect),
            Dbms::ApacheIgnite => Box::new(IgniteDialect),
            Dbms::CockroachDb => Box::new(PostgresDialect),
            Dbms::ClickHouse => Box::new(ClickHouseDialect),
            Dbms::Access => Box::new(AccessDialect),
            Dbms::Cubrid => Box::new(CubridDialect),
            Dbms::CacheIntersystems | Dbms::Iris => Box::new(IrisDialect),
            Dbms::ExtremeDb => Box::new(ExtremeDbDialect),
            Dbms::FrontBase => Box::new(FrontBaseDialect),
            Dbms::Raima => Box::new(RaimaDialect),
            Dbms::Virtuoso => Box::new(VirtuosoDialect),
            Dbms::Snowflake => Box::new(SnowflakeDialect),
            Dbms::Spanner => Box::new(SpannerDialect),
            Dbms::Doris => Box::new(DorisDialect),
        }
    }
}
