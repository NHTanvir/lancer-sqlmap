//! Per-DBMS dialect implementations.
//!
//! Each module exposes a unit struct implementing [`crate::Dialect`].
//! All dialects are stateless so they can be `Box<dyn Dialect>`-stored in the
//! registry without per-call allocation.

pub mod mysql;
pub mod postgres;
pub mod mssql;
pub mod oracle;
pub mod sqlite;
pub mod firebird;
pub mod sapmaxdb;
pub mod sybase;
pub mod db2;
pub mod informix;
pub mod hsqldb;
pub mod h2;
pub mod monetdb;
pub mod derby;
pub mod vertica;
pub mod mckoi;
pub mod presto;
pub mod altibase;
pub mod mimer;
pub mod cratedb;
pub mod ignite;
pub mod clickhouse;
pub mod access;
pub mod cubrid;
pub mod iris;
pub mod extremedb;
pub mod frontbase;
pub mod raima;
pub mod virtuoso;
pub mod snowflake;
pub mod spanner;
pub mod doris;

pub use access::AccessDialect;
pub use altibase::AltibaseDialect;
pub use clickhouse::ClickHouseDialect;
pub use cratedb::CrateDialect;
pub use cubrid::CubridDialect;
pub use db2::Db2Dialect;
pub use derby::DerbyDialect;
pub use doris::DorisDialect;
pub use extremedb::ExtremeDbDialect;
pub use firebird::FirebirdDialect;
pub use frontbase::FrontBaseDialect;
pub use h2::H2Dialect;
pub use hsqldb::HsqldbDialect;
pub use ignite::IgniteDialect;
pub use informix::InformixDialect;
pub use iris::IrisDialect;
pub use mckoi::McKoiDialect;
pub use mimer::MimerDialect;
pub use monetdb::MonetDbDialect;
pub use mssql::MssqlDialect;
pub use mysql::MySQLDialect;
pub use oracle::OracleDialect;
pub use postgres::PostgresDialect;
pub use presto::PrestoDialect;
pub use raima::RaimaDialect;
pub use sapmaxdb::SapMaxDbDialect;
pub use snowflake::SnowflakeDialect;
pub use spanner::SpannerDialect;
pub use sqlite::SqliteDialect;
pub use sybase::SybaseDialect;
pub use vertica::VerticaDialect;
pub use virtuoso::VirtuosoDialect;
