# lancer-sqlmap

Rust clone of `sqlmap` (SQL injection exploitation framework). Part of the **Lancer ecosystem** — a complete 2026 AI-era bug bounty toolkit.

> 🚧 **Pre-release.** Workspace fully scaffolded; use only against systems you have written permission to test.

---

## What this is

A pure-Rust reimplementation of [sqlmap](https://github.com/sqlmapproject/sqlmap)
targeting 100% feature parity:

- **6 injection techniques** — Boolean-blind (B), Error-based (E),
  Union-query (U), Stacked-queries (S), Time-blind (T), Inline-query (Q).
- **44 supported DBMSes** — MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB,
  Firebird, SAP MaxDB, Sybase, IBM DB2, Informix, HSQLDB, H2, MonetDB, Derby,
  Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle,
  Apache Ignite, CockroachDB, ClickHouse, Access, Percona, SingleStore, TiDB,
  Redshift, Aurora MySQL/Postgres, Yugabyte, AlloyDB, OpenGauss, Cubrid,
  Cache/IRIS, eXtremeDB, FrontBase, Raima, Virtuoso, DM8, Snowflake, Spanner, Doris.
- **74 built-in tamper scripts** + Lua tamper loader (`--tamper=lua:my.lua`).
- **Native GUI** (eframe/egui) and full **CLI** (200+ flags).
- **Cross-tool integration** with the rest of the Lancer suite via a local
  HTTP server (`%TEMP%/lancer-sqlmap.port`).

## Workspace layout

```
lancer-sqlmap/        — binary (CLI + GUI), HTTP server, orchestrator
sqlmap-core/          — Target/Session/Http/Fingerprint/Oracle/Detector/Enumerator
sqlmap-payloads/      — YAML boundary + 6 technique payload registries
sqlmap-techniques/    — B/E/U/S/T/Q technique drivers
sqlmap-tamper/        — 74 tamper scripts + Lua loader + chain validator
sqlmap-dbms/          — 44 per-DBMS dialect modules + hash cracker + UDF helpers
sqlmap-tui/           — ratatui-based sql-shell / os-shell REPL
```

## Build

### Windows

Double-click `build.bat` or from cmd:

```cmd
build.bat
```

Output: `build\lancer-sqlmap.exe`. Double-click to open the GUI.

For a packaged dist build:

```cmd
build-windows.bat
```

Output: `dist\lancer-sqlmap-windows-x86_64\bin\lancer-sqlmap.exe`.

### Linux / macOS

```bash
./build-linux.sh
```

Output: `build/lancer-sqlmap`. Add `--install` to drop a `.desktop` entry.

### Requirements

- [Rust / Cargo](https://rustup.rs)
- (Windows) Visual C++ Build Tools 2019/2022

## Quick start

### GUI (default)

```bash
./lancer-sqlmap
```

Three-pane layout: targets on the left, findings grid in the centre, detail
on the right.

### CLI examples

```bash
# Test a single URL
./lancer-sqlmap --cli -u 'https://target/?id=1' --batch --dbs

# Import a Burp request file
./lancer-sqlmap --cli -r request.txt --batch --level 3 --risk 2 --dump

# WAF bypass with tamper chain
./lancer-sqlmap --cli -u 'https://target/?id=1' --tamper 'space2comment,charunicodeencode'

# Pivot from a Lancer scanner finding
./lancer-sqlmap pivot --finding-id F-42 --tamper space2comment --batch --dump

# Interactive SQL shell against a known channel
./lancer-sqlmap sql-shell -s session.redb

# Crack extracted hashes
./lancer-sqlmap crack-hashes --hashes dump.txt --wordlist rockyou.txt
```

### Self-test

```bash
./lancer-sqlmap --self-test
```

Validates the bundled boundary / payload / tamper registries.

## License

MIT
