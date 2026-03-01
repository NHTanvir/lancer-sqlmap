# RESEARCH DOSSIER: sqlmap

> Part of the Lancer ecosystem. A Rust clone of sqlmapproject's sqlmap — automatic SQL injection exploitation framework. Build with Claude Code.
> Upstream: github.com/sqlmapproject/sqlmap (Python 3, GPL-2.0, 1.8.x → 1.9 in 2026). ~80k LOC; 25+ supported DBMSes.

## Feature Parity Mandate

**`lancer-sqlmap` MUST ship with 100% feature parity to the upstream `sqlmap` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `sqlmap --help` (and the long-form man page / docs) must work in `lancer-sqlmap --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-sqlmap` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-sqlmap --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

sqlmap is the canonical post-detection SQL injection exploitation framework. Where Lancer's active scanner *detects* SQLi (boundary fuzzing, time-delay confirmation, error-pattern matching), sqlmap *exploits* it: once a vulnerable parameter is confirmed, sqlmap fingerprints the back-end DBMS, dumps schema/tables/columns/rows, can read and write files on the DBMS host, can pivot to an OS-level shell, can crack harvested password hashes inline (against rockyou-style wordlists), can search the database for keyword content across all tables, and can perform privilege checks plus escalation. It is the bridge between "I found a SQLi" and "I have the database, the OS, and the kingdom."

Concretely:
- **Six injection techniques**: Boolean-blind (B), Error-based (E), Union-query (U), Stacked-queries (S), Time-blind (T), Inline-query (Q). Each technique has DBMS-specific payload variants.
- **25+ DBMS fingerprints**: MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Firebird, SAP MaxDB, Sybase, IBM DB2, Informix, HSQLDB, H2, MonetDB, Apache Derby, MariaDB, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle, Apache Ignite, CockroachDB, ClickHouse.
- **Schema enumeration**: banner, current-user, current-db, hostname, is-DBA, users, password-hashes, privileges, roles, databases, tables, columns, schema, row counts, content dumping.
- **OS-level access**: read files (`LOAD_FILE`, `bfilename`, etc.), write files (`INTO OUTFILE`, `bcp`, `lo_export`), spawn OS shell (`xp_cmdshell`, `sys_exec`, UDF injection), Metasploit handoff (`--os-pwn`).
- **Hash cracking**: inline dictionary attack on extracted hashes (MySQL native, MSSQL/Sybase, Oracle, PostgreSQL md5/sha-256/scram).
- **WAF/IPS bypass**: 50+ tamper scripts mutate payloads (case randomization, comment injection, hex/unicode encoding, version-comment chaff, percentage padding, etc.).
- **Session/state**: replayable sessions (`-s session.sqlite`), HTTP request import (`-r request.txt`), proxy/Tor/HTTP2, MFA-aware cookie handling.

**Differentiation from Lancer's active scanner**: Lancer's scanner is *detection-first* — it fires a finite payload set per parameter, looks for marker oracles (boolean, error, time, content), and emits a finding. sqlmap is *exploitation-first* — it assumes you already know SQLi exists (or it does the detection too with `--level 5 --risk 3`), then drives the injection point as a query channel. In the Lancer workflow, a scanner finding flows into a `lancer sqlmap pivot --finding-id <id>` command that auto-imports parameter/headers/method into sqlmap-core and runs the exploitation phase.

## Internal architecture

**Workspace** (`Cargo.toml`):
```
[workspace]
members = [
  "lancer-sqlmap",        # CLI binary
  "sqlmap-core",           # session, target model, HTTP engine, fingerprinter
  "sqlmap-payloads",       # boundary + payload YAML registry (port of upstream XML)
  "sqlmap-techniques",     # B / E / U / S / T / Q technique drivers
  "sqlmap-tamper",         # WAF-bypass payload mutators
  "sqlmap-dbms",           # per-DBMS dialect modules (MySQL, PG, MSSQL, ...)
  "sqlmap-tui",            # interactive sql-shell / os-shell REPL
]
```

- **`lancer-sqlmap`** — clap 4 CLI binary. Parses flags, wires `sqlmap-core` Session, dispatches to detection or exploitation pipelines, renders progress (indicatif) and table output (comfy-table).
- **`sqlmap-core`** — `Target` (URL + method + params + cookies + headers + auth), `Session` (resumable state in redb), `HttpEngine` (reqwest+rustls with rate limit, retry, proxy, Tor chain, HTTP/2), `Fingerprinter` (DBMS probe pipeline), `Extractor` (binary search + bisection-based character extraction), `Detector` (boundary expansion + payload registry walker).
- **`sqlmap-payloads`** — loads YAML payload boundaries and technique-specific templates ported from upstream `xml/payloads/`. Each entry has: title, stype (technique class), level/risk gate, clause, where, vector, request payload, response grep regex, comment, DBMS scope.
- **`sqlmap-techniques`** — six driver modules implementing each technique with shared traits. Each takes `(Target, BoundaryMatch, Payload)` and returns `TechniqueResult { evidence, mode: Detection | Exploitation }`.
- **`sqlmap-tamper`** — registry of payload mutators. Each tamper is a `fn(&str) -> String` (optionally chained). Loaded by name from CLI (`--tamper=space2comment,charunicodeencode`). Optional Lua DSL via `mlua` lets users add tampers without recompile.
- **`sqlmap-dbms`** — one module per DBMS (`mysql.rs`, `postgresql.rs`, `mssql.rs`, `oracle.rs`, `sqlite.rs`, ...). Each provides: fingerprint hints (banner regex, function probes), syntax shims (string concat, substring, ascii, sleep, version), privilege query, file read/write SQL, OS command vector (if available), hash table location.
- **`sqlmap-tui`** — ratatui-based REPL for `--sql-shell` and `--os-shell`, plus a curses-style log pane.

**Key modules in `sqlmap-core/src/`:**

- `target.rs` — `Target { url, method, headers, cookies, body, params: Vec<Param>, auth: AuthSpec }`. `Param { name, value, place: GET|POST|COOKIE|HEADER|URI|JSON|XML, type: STRING|NUMBER }`.
- `session.rs` — redb-backed key-value store keyed by `(target_hash, param_name)`; persists detected boundaries, working payloads, fingerprint result, dumped data. Allows resume after Ctrl-C / network drop.
- `http.rs` — `HttpEngine` with: rate limiter (governor), retry backoff (tower-retry), proxy chain (Tor SOCKS5), MFA hook (interactive 2FA prompt), HTTP/2 multiplexing, header randomization (`--random-agent`), Cookie jar (cookie_store), JSON body native parsing (preserves typed values when fuzzing JSON).
- `fingerprint.rs` — multi-stage pipeline: (1) banner grep, (2) error-message grep, (3) function-availability probes (e.g., `@@version` vs `version()` vs `banner from v$version`), (4) numeric/string comparison quirks, (5) confirm via two independent vectors before committing.
- `boundary.rs` — port of upstream `boundaries.xml`. Each boundary = `(prefix, suffix, clause, where, ptype)` describing a syntactic context (after a string with `'`, after a numeric, inside ORDER BY, etc.). Detector walks payloads against expected boundaries based on observed input behavior.
- `extractor.rs` — character-by-character extraction engine. For boolean-blind, uses binary search on ASCII range per character. Adaptive: switches to bitwise extraction (`& 0x80`, `& 0x40`, ...) when binary search misbehaves on noisy responses.
- `oracle.rs` — response-similarity oracle: NCD/ratcliff-obershelp comparison between TRUE-response and FALSE-response baselines, with `--string`/`--not-string`/`--regexp`/`--code`/`--text-only`/`--titles` overrides.
- `detector.rs` — orchestrates boundary discovery × payload walk × technique pipeline. Implements `--level 1-5` and `--risk 1-3` gating (higher = more invasive payloads).
- `enumerator.rs` — orchestrates `--banner / --current-user / --dbs / --tables / --columns / --schema / --dump / --search`.

**Technique drivers (in `sqlmap-techniques/src/`):**

| Technique | File | Approach |
|---|---|---|
| Boolean-blind (B) | `boolean.rs` | TRUE/FALSE injected, response oracle splits content; per-char binary search; ~7-8 reqs/char |
| Error-based (E) | `error.rs` | Triggers DBMS error containing extracted data (e.g., `EXTRACTVALUE`, `XMLType`, `CTXSYS.DRITHSX.SN`) |
| Union-query (U) | `union.rs` | Appends `UNION SELECT` with matching column count; bulk extraction at 1 req per row range |
| Stacked-queries (S) | `stacked.rs` | `;` terminator + secondary query; enables INSERT/UPDATE/DELETE and `xp_cmdshell` |
| Time-blind (T) | `time.rs` | `SLEEP(N)` / `pg_sleep` / `WAITFOR DELAY`; oracle = elapsed time; statistical denoising for noisy networks |
| Inline-query (Q) | `inline.rs` | Subquery whose return value substitutes in the rendered response (e.g., `WHERE id=(SELECT ...)`) |

**Per-technique shared trait** (`sqlmap-techniques/src/lib.rs`):
```rust
pub trait Technique: Send + Sync {
    fn id(&self) -> char;                            // 'B' | 'E' | 'U' | 'S' | 'T' | 'Q'
    fn name(&self) -> &'static str;
    fn dbms_scope(&self) -> &[Dbms];                 // empty = all
    fn detect(&self, ctx: &mut DetectCtx)
        -> Result<Option<WorkingPayload>>;
    fn extract(&self, ctx: &mut ExtractCtx, query: &str)
        -> Result<ExtractResult>;
}
```

Detection vs extraction is the same code path with different inputs: detection asks "does the oracle flip when I inject this?", extraction asks "what is the value of `SUBSTR(secret, i, 1)`?". Both reuse the oracle module (`sqlmap-core::oracle`).

**Payload loading flow:**
1. CLI parses `--target` or `-r request.txt`; builds `Target`.
2. `sqlmap-payloads` lazy-loads `boundaries.yaml` + `payloads/boolean.yaml`, `error.yaml`, `union.yaml`, `stacked.yaml`, `time.yaml`, `inline.yaml`.
3. `Detector` filters payloads by `level <= --level && risk <= --risk` and DBMS scope (`--dbms` shortcut skips off-DBMS payloads).
4. For each param, walks boundaries × techniques × payloads; records first working match per technique into `Session`.
5. `Enumerator` (post-detection) picks the cheapest working technique per query (U > E > Q > B > T) and issues extraction queries.

**Why YAML over upstream XML.** Upstream sqlmap stores boundaries and payloads in XML files (`xml/boundaries.xml`, `xml/payloads/*.xml`). For the Rust port, YAML is the better choice: tighter syntax, fewer escape issues for SQL fragments containing `<`/`>`, better diffability in PRs, native `serde` derive support. The migration is mechanical:
```yaml
- title: "AND boolean-based blind - WHERE or HAVING clause"
  stype: 1                # boolean-blind
  level: 1
  risk: 1
  clause: [1, 8, 9]       # WHERE / HAVING / GROUP BY HAVING
  where: 1                # original value
  vector: "AND [INFERENCE]"
  request:
    payload: "AND [RANDNUM]=[RANDNUM]"
  response:
    comparison:
      payload: "AND [RANDNUM]=[RANDNUM2]"
  dbms: []                # all
```

**Worker pool & rate budget.** `--threads N` doesn't naïvely fan out — bandwidth/lock budget can collapse the oracle when concurrent paths cause server queueing (latency-based oracles see false positives). The clone implements a tokio-based per-target rate limiter using `governor`, with per-technique concurrency caps: boolean-blind allows full thread count (idempotent reads), time-blind reduces to 1 (serialized for clean RTT measurement), stacked-queries gated at 1 (avoid concurrent DML races).

**Tamper script registry:**
- Each tamper script implements `pub trait Tamper { fn name(&self) -> &str; fn apply(&self, payload: &str) -> String; fn priority(&self) -> u8; }`.
- Priority controls chain ordering when multiple tampers selected.
- Optional Lua tampers: `--tamper=lua:my_tamper.lua` loads via `mlua`, exposes `payload` arg, expects return string.

## Granular feature catalog

**CLI flag families (port of upstream sqlmap command line):**

*Target & request:*
- `-u/--url`, `-d/--direct` (DB connect string), `-l` (Burp/WebScarab log), `-m` (multiple targets file), `-r/--request` (HTTP request file), `-g/--google-dork`, `-c/--config-file` (sqlmap.cfg)
- `--method=GET|POST|PUT|DELETE|PATCH`
- `--data='id=1'`, `--param-del=';'`, `--cookie='PHPSESSID=..'`, `--cookie-del`, `--load-cookies`, `--drop-set-cookie`
- `--user-agent=...`, `--random-agent`, `--host=...`, `--referer=...`, `--headers='X-Foo: bar'`
- `--auth-type=Basic|Digest|NTLM|PKI`, `--auth-cred='user:pass'`, `--auth-file=pem`
- `--ignore-code=401`, `--ignore-proxy`, `--ignore-redirects`, `--ignore-timeouts`
- `--proxy=http://...`, `--proxy-cred`, `--proxy-file`, `--proxy-freq`, `--tor`, `--tor-port`, `--tor-type=SOCKS5`, `--check-tor`
- `--delay=N`, `--timeout=N`, `--retries=N`, `--retry-on=regex`, `--randomize=param`
- `--safe-url`, `--safe-post`, `--safe-req`, `--safe-freq` — pristine request between malicious ones to keep session alive
- `--skip-urlencode`, `--csrf-token`, `--csrf-url`, `--csrf-method`, `--csrf-data`, `--csrf-retries`
- `--force-ssl`, `--chunked`, `--hpp` (HTTP parameter pollution), `--eval=python expr`
- `--http2`, `--mfa-prompt` (Lancer addition for 2FA flows)

*Optimization:*
- `-o` (all opts), `--predict-output`, `--keep-alive`, `--null-connection`, `--threads=N`

*Injection:*
- `-p param`, `--skip=param`, `--skip-static`, `--param-exclude=regex`, `--param-filter=regex`
- `--dbms=mysql`, `--dbms-cred='user:pass'`, `--os=Linux|Windows`
- `--invalid-bignum`, `--invalid-logical`, `--invalid-string`
- `--no-cast`, `--no-escape`
- `--prefix='\')'`, `--suffix='--'`
- `--tamper=space2comment,between` (chain)

*Detection:*
- `--level=1-5`, `--risk=1-3`
- `--string=marker`, `--not-string=marker`, `--regexp=^Hello$`, `--code=200`
- `--smart`, `--text-only`, `--titles`

*Techniques:*
- `--technique=BEUSTQ` (any subset; default `BEUSTQ`)
- `--time-sec=N` (default 5)
- `--union-cols=1-10`, `--union-char='NULL'`, `--union-from='dual'`, `--union-values='1,2,3'`
- `--dns-domain=attacker.com` (OOB), `--second-url`, `--second-req`

*Fingerprint:*
- `-f/--fingerprint` (extensive banner/OS/arch fingerprint)

*Enumeration:*
- `-a/--all`, `-b/--banner`, `--current-user`, `--current-db`, `--hostname`, `--is-dba`
- `--users`, `--passwords`, `--privileges`, `--roles`
- `--dbs`, `--tables`, `--columns`, `--schema`, `--count`, `--dump`, `--dump-all`
- `--search`, `--comments`, `--statements`
- `-D db`, `-T table`, `-C cols`, `-X excl-col`, `-U user`
- `--exclude-sysdbs`, `--pivot-column=name`, `--where=`
- `--start=N`, `--stop=N`, `--first=N`, `--last=N`
- `--sql-query=SELECT ...`, `--sql-shell` (interactive), `--sql-file=file.sql`

*Brute force:*
- `--common-tables`, `--common-columns`, `--common-files` (dictionary-based discovery when information_schema is restricted)

*UDF injection (MySQL/PG):*
- `--udf-inject`, `--shared-lib=lib_mysqludf_sys.so`

*Filesystem:*
- `--file-read=/etc/passwd`, `--file-write=local.bin`, `--file-dest=/var/www/up.bin`

*OS access:*
- `--os-cmd='whoami'`, `--os-shell`, `--os-pwn` (Metasploit auto-exploit handoff), `--os-smbrelay`, `--os-bof`, `--priv-esc`, `--msf-path`, `--tmp-path`

*Windows registry (MSSQL):*
- `--reg-read`, `--reg-add`, `--reg-del`, `--reg-key`, `--reg-value`, `--reg-data`, `--reg-type`

*General/misc:*
- `-s session.sqlite`, `-t trafficfile`, `--batch` (non-interactive accept defaults), `--binary-fields`, `--check-internet`, `--cleanup`, `--crawl=N`, `--crawl-exclude`, `--csv-del`, `--charset=GBK`, `--dump-format=CSV|HTML|SQLITE`, `--encoding=utf-8`, `--eta`, `--flush-session`, `--forms`, `--fresh-queries`, `--har=har.json`, `--hex` (hex-encoded extraction), `--output-dir`, `--parse-errors`, `--preprocess=script.py`, `--postprocess=script.py`, `--repair`, `--save=cfg.ini`, `--scope=regex`, `--test-filter`, `--test-skip`, `--update`, `-v 0-6`, `-z compact-mnemonics`, `--alert='cmd'`, `--answers='Y'`, `--beep`, `--gpage`, `--smart`, `--wizard`

**Tamper scripts (50+ upstream, plan to port):**

`apostrophemask`, `apostrophenullencode`, `appendnullbyte`, `base64encode`, `between`, `bluecoat`, `chardoubleencode`, `charencode`, `charunicodeencode`, `charunicodeescape`, `commalesslimit`, `commalessmid`, `commentbeforeparentheses`, `concat2concatws`, `decentities`, `dotomlencode`, `dunion`, `equaltolike`, `escapequotes`, `greatest`, `halfversionedmorekeywords`, `hex2char`, `htmlencode`, `ifnull2casewhenisnull`, `ifnull2ifisnull`, `informationschemacomment`, `least`, `lowercase`, `luanginx`, `misunion`, `modsecurityversioned`, `modsecurityzeroversioned`, `multiplespaces`, `ord2ascii`, `overlongutf8`, `overlongutf8more`, `percentage`, `plus2concat`, `plus2fnconcat`, `randomcase`, `randomcomments`, `schemasplit`, `sleep2getlock`, `sp_password`, `space2comment`, `space2dash`, `space2hash`, `space2morehash`, `space2mssqlblank`, `space2mssqlhash`, `space2mysqlblank`, `space2mysqldash`, `space2plus`, `space2randomblank`, `substring2leftright`, `symboliclogical`, `unionalltounion`, `unmagicquotes`, `uppercase`, `varnish`, `versionedkeywords`, `versionedmorekeywords`, `xforwardedfor`.

**Tamper scripts (additions found in upstream `tamper/` as of 1.10, missing from list above — port to keep parity at 70+):**

- `0eunion` — prepends `0e` numeric-overflow prefix to UNION SELECT to bypass naive "starts with UNION" regex filters; sister of `dunion`/`misunion`.
- `binary` — wraps payload string literals in `BINARY(...)` cast (MySQL) to force case-sensitive comparison and defeat WAFs normalizing case.
- `equaltorlike` — `=` → `RLIKE` (regex-LIKE on MySQL); complement to `equaltolike`. Defeats WAFs blocking only `LIKE`.
- `hexentities` — encodes payload chars as HTML hex entities (`&#x41;`); HTML-context bypass for WAFs that decode decimal entities only.
- `if2case` — rewrites `IF(cond, a, b)` → `CASE WHEN cond THEN a ELSE b END`; portable across DBMSes and bypasses MySQL `IF` keyword filters.
- `luanginxmore` — extended Lua/nginx WAF bypass with additional comment-jamming patterns; complement to `luanginx`.
- `scientific` — represents numeric constants in scientific notation (`1` → `1e0`); bypasses signature-based detection of literal integers in payloads.
- `space2morecomment` — replaces space with `/**_**/` style multi-character comment; complement to `space2comment` for stricter WAFs.

**Tamper script families (catalogued for chain validation):**
- *Encoders* (terminal, must run last): `base64encode`, `htmlencode`, `hexentities`, `decentities`, `chardoubleencode`, `overlongutf8`, `overlongutf8more`, `charunicodeencode`, `charunicodeescape`.
- *Space replacers* (must run after keyword-mutators): `space2comment`, `space2morecomment`, `space2dash`, `space2hash`, `space2morehash`, `space2plus`, `space2randomblank`, `space2mssqlblank`, `space2mssqlhash`, `space2mysqlblank`, `space2mysqldash`.
- *Case mutators*: `lowercase`, `uppercase`, `randomcase`.
- *Keyword swappers*: `between`, `equaltolike`, `equaltorlike`, `greatest`, `least`, `if2case`, `ifnull2casewhenisnull`, `ifnull2ifisnull`, `concat2concatws`, `plus2concat`, `plus2fnconcat`, `substring2leftright`, `unionalltounion`, `misunion`, `dunion`, `0eunion`, `sleep2getlock`, `symboliclogical`.
- *Version-comment chaff* (MySQL): `versionedkeywords`, `versionedmorekeywords`, `halfversionedmorekeywords`, `modsecurityversioned`, `modsecurityzeroversioned`.
- *Vendor-specific*: `bluecoat`, `varnish`, `luanginx`, `luanginxmore`, `sp_password` (MSSQL).
- *Numeric encoders*: `scientific`, `binary`.
- *Header injection*: `xforwardedfor`.

**Auth types (sqlmap `AUTH_TYPE` enum — full set):**
- `basic` (HTTP Basic)
- `digest` (HTTP Digest)
- `bearer` (OAuth 2.0 Bearer token; refresh via `--refresh-token-url`)
- `ntlm` (Windows NTLM, internal SSO)
- `pki` (mTLS client cert via `--auth-file=cert.pem`)

**Web platforms (sqlmap `WEB_PLATFORM` enum — drives `--os-shell` payload selection):**
- `PHP`, `ASP`, `ASPX`, `JSP`, `CFM` — when writing a webshell via `INTO OUTFILE`, the technique chooses the right language stub for the discovered server platform (`Server:` header heuristic + file-write probe).

**Proxy types (sqlmap `PROXY_TYPE` enum):**
- `HTTP`, `HTTPS`, `SOCKS4`, `SOCKS5` (Tor uses SOCKS5).

**Supported DBMSes (25 — plan parity):**
MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, Firebird, SAP MaxDB, Sybase, IBM DB2, Informix, HSQLDB, H2, MonetDB, Apache Derby, MariaDB, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle, Apache Ignite, CockroachDB, ClickHouse.

**Full upstream DBMS matrix (40+ as of sqlmap 1.10, Jan 2026 — superset of the v1 plan parity list; v2 phases port the rest):**

Tier 1 (already in v1 plan): MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MariaDB, Firebird, SAP MaxDB, Sybase, IBM DB2, Informix, HSQLDB, H2, MonetDB, Apache Derby, Vertica, Mckoi, Presto, Altibase, MimerSQL, CrateDB, Greenplum, Drizzle, Apache Ignite, CockroachDB, ClickHouse.

Tier 2 (added upstream since 1.7, missing from v1 plan — add via `sqlmap-dbms` modules in v2):
- **Microsoft Access** (legacy `.mdb` / Jet engine; `MSysObjects` schema enumeration; no stacked queries; rare but still found on legacy gov/edu apps).
- **Percona Server** (MySQL-fork; same wire protocol; distinguishing fingerprint via `@@version_comment LIKE '%Percona%'`).
- **MemSQL / SingleStore** (MySQL-compatible distributed; quirk: no `INFORMATION_SCHEMA.STATISTICS` subset).
- **TiDB** (MySQL-compatible distributed; fingerprint via `tidb_version()` builtin).
- **Amazon Redshift** (PostgreSQL fork; distinct system catalogs `pg_catalog_redshift`; `SVV_*` views for enumeration).
- **Aurora MySQL / Aurora PostgreSQL** (AWS managed; `aurora_version()` fingerprint; managed-RDS file/OS restrictions documented).
- **YugabyteDB** (PostgreSQL-compatible distributed; `yb_*` builtins).
- **AlloyDB** (PostgreSQL-compatible GCP managed).
- **OpenGauss** (Huawei PostgreSQL fork; `gs_*` builtins; widespread in CN markets).
- **Cubrid** (Korean open-source RDBMS; quirk fingerprint via `db_version()`).
- **InterSystems Cache** + **InterSystems IRIS** (healthcare/financial; ObjectScript; `%Library.SQLPROC`).
- **eXtremeDB** (embedded in-memory; rare).
- **FrontBase** (legacy macOS RDBMS; rare).
- **Raima Database Manager** (embedded; rare).
- **Virtuoso** (RDF/SQL hybrid; `SYS_USERS`).
- **DM8** (Dameng — CN domestic RDBMS, Oracle-compatible syntax; mandatory in CN gov bids).
- **Snowflake** (cloud DWH; `INFORMATION_SCHEMA` mostly compatible; OAuth-first auth; no file/OS access ever).
- **Google Cloud Spanner** (distributed SQL; GoogleSQL dialect; managed-only; no file/OS).

Total upstream DBMS count: **44** (`DBMS` enum in `lib/core/enums.py`). v1 ships Tier 1 (26); v2 adds Tier 2 (18).

**Parameter types (sqlmap `PARAMETER` enum — required for boundary inference):**
- `Unescaped numeric` (`id=1`)
- `Single quoted string` (`id='1'`)
- `LIKE single quoted string` (`name LIKE '%x%'`)
- `Double quoted string` (`id="1"`)
- `LIKE double quoted string` (`name LIKE "%x%"`)
- `Identifier (e.g. column name)` (`ORDER BY <col>`)

Boundary registry indexes by parameter type so the detector skips obviously-wrong boundaries (e.g. no `\'` prefix when param-type is `Unescaped numeric`).

**PLACE constants (sqlmap `PLACE` enum — distinct injection points):**
- `GET`, `POST`, `URI`, `Cookie`, `User-Agent`, `Referer`, `Host`, `custom POST` (manual `--data` with `*` marker), `custom HEADER` (`--headers` with `*` marker), `JSON` (typed body), `XML` (SOAP/XML body).

The clone's `Param::place` enum must reach 11 variants to match upstream — adding the explicit `UserAgent`/`Referer`/`Host`/`CustomPost`/`CustomHeader` cases the current plan rolls under `HEADER`. The detector marks the injection site with `*` (`-r request.txt` with `id=1*` syntax).

**Six injection techniques (corrected — upstream confirms 6, internal numbering `BOOLEAN=1, ERROR=2, QUERY=3 (inline), STACKED=4, TIME=5, UNION=6`):**
The v1 plan correctly lists six (B/E/Q/S/T/U). Some upstream README copy says "five" because `QUERY` (inline) is sometimes folded into `UNION`. The clone keeps all six distinct in `sqlmap-techniques`.

**Output formats:**
- Plain stdout (default), `--dump-format=CSV`, `--dump-format=HTML`, `--dump-format=SQLITE`.
- `--har=path.har` — HAR-format request log.
- `--save=cfg.ini` — saves config for replay.
- Session redb file persists boundaries, working payloads, dumped data, fingerprint result, and partial-extraction checkpoints.

## Engineering hard parts

**Fingerprinting across 25+ DBMSes.** No single probe distinguishes all. sqlmap layers: (1) error-message regex bank (`You have an error in your SQL syntax` → MySQL family, `ORA-` → Oracle, `Microsoft OLE DB` → MSSQL, `PSQLException` → PostgreSQL, etc.), (2) function-availability probes (`CONNECTION_ID()` MySQL-only, `pg_backend_pid()` PG-only), (3) version banner extraction once a working technique exists, (4) numeric/string quirk fingerprints (Oracle `||` vs MySQL `CONCAT`), (5) dialect-specific blind-time fn (MySQL `SLEEP`, PG `pg_sleep`, MSSQL `WAITFOR DELAY`, Oracle `DBMS_LOCK.SLEEP` or heavy CPU loop). The clone follows sqlmap's "two independent confirmations" rule before committing to a DBMS — single-probe matches are too noisy on hardened apps that mangle error text.

**Time-based blind reliability over noisy networks.** Naïve `SLEEP(5)` plus 5-second threshold fails when baseline RTT itself jitters. sqlmap's algorithm: warm-up phase measures baseline mean and stddev across N concrete requests, picks delay = max(`--time-sec`, baseline_mean + 7*stddev), retries each oracle query 2x if borderline, and falls back to a longer delay if first attempt is inconclusive. The clone uses `tokio::time::Instant` for sub-ms precision and an adaptive delay PID-style controller.

**UNION column number detection.** Three strategies: (1) `ORDER BY N` until error (cheapest, ~log2(cols) requests but error oracle must work), (2) `UNION SELECT NULL,NULL,...` increasing arity (when ORDER BY suppressed), (3) `--union-cols=N` user override. Column-type detection follows: walk each position with `NULL` vs `'a'` vs `1` checking which slot tolerates string vs number — needed because MySQL union'd columns must match types or be auto-cast.

**Payload mutation against WAFs.** Tamper chain is order-sensitive. e.g., `space2comment` must run before `randomcase` (else inserted comment tokens get case-randomized into broken `/*RaNdOm*/`). Priority field plus a topological sort prevents broken combinations. Some tampers (`base64encode`, `hex2char`) are terminal — nothing chains after them. The clone validates chain compatibility at CLI parse time and warns on unsafe orderings.

**Character-by-character extraction.** Boolean-blind boils down to "ask N yes/no questions to recover one character." Naïve byte-by-byte = 256 questions; binary search = 8; bitwise extraction = 7 (one per bit). sqlmap auto-selects: binary search on stable oracles, bitwise on noisy ones (degraded oracle confidence triggers switch). For long extractions (multi-MB dumps), batches range queries (`SUBSTR(col, 1, 100)`) to amortize HTTP overhead.

**Response-similarity scoring.** When `--string`/`--regexp` not provided, oracle compares response bodies. Algorithm: Ratcliff-Obershelp ratio of "TRUE baseline" vs current response; ratio > 0.98 → TRUE, < 0.92 → FALSE, ambiguous → retry with bisection of the boundary. The clone uses `strsim` crate.

**DBMS-specific privilege checks.**
- MySQL: `SELECT super_priv FROM mysql.user WHERE user=CURRENT_USER()` (`super` ≈ DBA-equiv since 5.7) plus `file_priv` for `LOAD_FILE`/`INTO OUTFILE`.
- PostgreSQL: `SELECT rolsuper FROM pg_roles WHERE rolname=current_user`; superuser required for `COPY` to filesystem.
- MSSQL: `IS_SRVROLEMEMBER('sysadmin')`; `xp_cmdshell` requires sysadmin + enabling config.
- Oracle: `SELECT GRANTED_ROLE FROM USER_ROLE_PRIVS` for DBA role.

**File upload via SQL features.**
- MySQL: `SELECT 0xPAYLOAD INTO DUMPFILE '/var/www/u.php'` (requires `FILE` priv, secure_file_priv unset).
- PostgreSQL: `COPY (SELECT decode(...)) TO '/var/www/u.php'` or large-object `lo_import` + `lo_export`.
- MSSQL: `bcp` external + `xp_cmdshell` chunked write, or CLR assembly upload (modern).
- Oracle: `UTL_FILE.FOPEN` requires DIRECTORY object granted.
- SQLite: `writefile()` extension function (only when `LOAD_EXTENSION` allowed) or `ATTACH DATABASE 'file:'`. Niche.
- Cloud-managed RDBMSes (RDS, Cloud SQL, Azure DB) frequently disable file functions and `xp_cmdshell` by default — the clone reports this explicitly instead of silently failing.

**JSON / GraphQL / OAuth as a 2024-2026 reality.** Modern apps rarely accept naked `id=1` GET params. The clone treats `--data='{"id": 1, "filter": {"name": "x"}}'` as a typed JSON body — the fuzzer walks each leaf value, preserves sibling types, and injects via JSON-string-escaped payloads. For GraphQL, the clone detects `__schema` introspection (`POST /graphql` with `query=query{__schema{...}}`) and walks discovered fields. OAuth Bearer flows use `--auth-type=Bearer` plus `--refresh-token=<url>` so long-running runs don't lose session — token refresh happens transparently via `oauth2` crate.

**Resumability under network drops.** Long extractions (multi-MB tables) routinely die to flaky Tor exits or rate limits. Session redb commits each completed character; on resume, `Extractor` consults the partial state and starts mid-string. The clone also persists the working payload per (target, param, technique) so re-detection is skipped.

**OS command execution (modern, post-2020 reality):**
- MySQL: requires UDF injection (`lib_mysqludf_sys.so`/`.dll`), and `secure_file_priv` must allow plugin dir write.
- PostgreSQL: `COPY ... PROGRAM` (modern path) or `CREATE FUNCTION sys_exec AS '/path/to/lib'` (old).
- MSSQL: `xp_cmdshell` after `sp_configure 'show advanced options', 1; RECONFIGURE; sp_configure 'xp_cmdshell', 1; RECONFIGURE`.
- Oracle: Java SP (`DBMS_JAVA`), DBMS_SCHEDULER jobs, or external procedure (`extproc`).

## Rust library mapping

| Need | Crate | Notes |
|---|---|---|
| HTTP client | `reqwest` 0.12 (rustls feature) | Default; cookie_store + redirect policies + HTTP/2 |
| Low-level HTTP/2 | `hyper` 1.x + `h2` | When reqwest's abstraction blocks (custom frame sequences, h2c) |
| TLS | `rustls` 0.23 + `webpki-roots` | Pure-Rust, no OpenSSL hassle |
| Cookie jar | `cookie_store` 0.21 | Session cookies + Set-Cookie tracking |
| Proxy/Tor | `reqwest::Proxy` + `tor-rtcompat` (Arti) | Arti for embedded Tor; SOCKS5 proxy chain |
| Regex | `regex` 1.10 | Response-grep, error-pattern bank |
| Concurrency | `tokio` 1.40 | Multi-target/multi-param async |
| Thread pool | `rayon` 1.11 | Parallel boolean-blind per-char queries |
| CLI | `clap` 4.4 (derive) | 200+ flags; subcommand-style for `--sql-shell` |
| Config | `serde` + `serde_yaml` 0.9 | Boundary/payload XML → YAML port |
| TOML config | `toml` 0.8 | `sqlmap.cfg` analog (`lancer-sqlmap.toml`) |
| Lua tamper | `mlua` 0.10 (lua54 feature) | Optional script tampers without recompile |
| Session DB | `redb` 2.x | Pure-Rust ACID KV; replaces upstream pickle |
| Hex / base64 | `hex`, `base64` | Payload encoders, output rendering |
| String similarity | `strsim` 0.11 | Ratcliff-Obershelp oracle |
| HTML parsing | `scraper` 0.20 | `--forms` crawler, `--titles` extraction |
| Crawler | `spider` 1.x or hand-roll | `--crawl=N` |
| HAR output | `serde_json` + custom struct | `--har=path.har` |
| Hash cracking | `rayon` + `md5` + `sha2` + `sha1` + custom MySQL native hash | Inline `--passwords` cracking |
| Progress UI | `indicatif` 0.17 | ETA, per-table dump bars |
| Table render | `comfy-table` 7.x | Schema/dump rendering |
| TUI shell | `ratatui` 0.28 | `--sql-shell`/`--os-shell` REPL |
| Errors | `eyre` 0.6 | Idiomatic error model |
| Logging | `tracing` 0.1 + `tracing-subscriber` | `-v 0-6` mapping |
| GraphQL parse | `async-graphql-parser` | GraphQL endpoint detection (2024-2026 addition) |
| OAuth flow | `oauth2` 4.x | OAuth-protected target handling |
| HTTP request file parser | hand-roll + `httparse` | `-r request.txt` |
| Direct DB connect (`-d`) | `sqlx` 0.8 + `mysql_async` + `tiberius` + `oracle` crate | Optional feature flag |

Symmetric to halmos's Z3 binding: the strategic library choice here is `reqwest` + `rustls`. Upstream uses Python's `urllib3` + chunky pyOpenSSL wrappers; the Rust port gets HTTP/2, async multiplexing, and clean cancellation for free.

## Bug bounty workflows

- **Pivot from Lancer scanner finding.** Active scanner emits `Finding { id, target, param, technique_hint }`. CLI shortcut: `lancer sqlmap pivot --finding-id F-42 --tamper space2comment --batch --dump`. Auto-imports `Target`, sets `--technique` to hinted family, and runs detection-then-extraction.
- **Ad-hoc parameter testing.** Burp captures a request → save as `request.txt` → `lancer-sqlmap -r request.txt --batch --random-agent --level 3 --risk 2`. `--batch` accepts all defaults — critical for unattended runs.
- **WAF-bypass attempts.** Start with `--tamper=space2comment` (cheapest), escalate to `--tamper=space2comment,charunicodeencode,randomcase`, then to chain-with-encoding `--tamper=base64encode` (terminal). Cloudflare-style WAFs often defeated by `between`/`equaltolike` combos.
- **DB enumeration.** `--dbs` first (lists databases). Then `-D target_db --tables`. Then `-D target_db -T users --columns`. Then `-D target_db -T users -C email,password_hash --dump`. Each step writes to session — resumable.
- **Credential harvesting + hashcat handoff.** `--passwords` extracts MySQL/MSSQL/Oracle/PG hashes. sqlmap's inline cracker handles common dictionaries fast; for tough hashes (bcrypt), emit `hashcat -m MODE hash.txt wordlist.txt` command suggestion plus file-formatted hashes for direct ingestion.
- **File read for app-secret recovery.** `--file-read=/var/www/html/wp-config.php` (WordPress DB creds), `--file-read=/etc/passwd` (user enumeration), `--file-read=C:\inetpub\wwwroot\web.config` (.NET app secrets), `--file-read=/proc/self/environ` (env vars including AWS keys).
- **Pivot to OS shell → cloud metadata.** `--os-shell` → `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` — exfiltrate AWS IAM creds → full account takeover. Same play for GCP `metadata.google.internal` and Azure IMDS.
- **Replayable session for reporting.** `-s session.sqlite` → archive with bug bounty submission → triager can replay extraction non-destructively. Lancer adds `--har=session.har` for fully-replayable HTTP log.
- **Burp Suite handoff.** Lancer scanner detects → user right-clicks "Send to sqlmap" → Lancer spawns `lancer-sqlmap -r captured.req --batch --output-dir burp-handoff/`. Output dir auto-renders Markdown/HTML report attachable to a Burp issue.
- **Mass-targets (`-m targets.txt`).** Bug bounty programs with hundreds of in-scope hosts can be swept overnight with `--batch --threads 5 --random-agent`; results aggregate into per-target session dirs for the next morning's triage.
- **Stealth mode.** `--delay=3 --randomize=tracking_id --tor --random-agent --safe-url=/health` — mimics human browsing pace, refreshes a benign endpoint between malicious requests to avoid burst-detection WAFs.
- **Custom tampers for proprietary WAFs.** Bug bounty programs often have homegrown WAFs (e.g., Shopify's, Discord's). Lua tamper scripts let researchers iterate without recompile: edit `my_waf.lua`, rerun with `--tamper=lua:my_waf.lua`.

## 2024-2026 state

- **sqlmap 1.7.x (early 2024)**: minor fingerprint additions; better cookies; AWS WAF tamper chains documented in wiki.
- **sqlmap 1.8.x (2024-2025)**: HTTP/2 request handling natively (previously HTTP/1.1 only), MFA-aware session handling for OAuth/2FA flows, JSON body native parsing (preserves typed values when fuzzing JSON payload like `{"id": 1}` doesn't break int field by replacing with string), GraphQL endpoint detection (sniffs `__schema` introspection and walks fields), OAuth flow support (`--auth-type=Bearer` with refresh-token rotation).
- **sqlmap 1.9 (2026 dev)**: new DBMSes added (CockroachDB confirmed in tree as of 1.8.10; ClickHouse rumored mainline 1.9), expanded inline-query technique payload library, AI-augmented tamper script suggestions (experimental — sniff WAF response and propose tamper chain).
- Active community DBMS PRs landing for: TiDB (MySQL-compatible but with quirk fingerprints), YugabyteDB, AlloyDB (PostgreSQL-compatible managed).
- License remains GPL-2.0 throughout.

### Research note — 2026-05-31 (deep-research pass — UDF/Metasploit/auth specifics)

Direct walk of `github.com/sqlmapproject/sqlmap/wiki/Features` + `wiki/Usage` + `tamper/` directory listing + `THANKS.md` (for historical contributor → feature attribution). Items missed earlier:

- **Definitive UDF library inventory.** The MySQL/PG UDF injection paths upload exactly two functions: `sys_bineval()` (executes a base64-encoded native binary blob in-process) and `sys_exec()` (subprocess wrapper). MSSQL uses xp_cmdshell + sp_OACreate; Oracle uses `DBMS_JAVA` or `DBMS_XMLQUERY` + Java stored proc. PostgreSQL has `lo_export`/`lo_import` for file-write plus the `pg_proc` UDF path. Our `sqlmap-dbms` modules must ship reference UDF binaries pre-compiled for `amd64`/`arm64`/`win-x86_64` so users don't need a build toolchain.
- **`--os-pwn` Metasploit handoff specifics.** When pivoting to system, sqlmap shells out to `msfvenom` to craft the payload and `msfconsole -r resource.rc` to run a multi/handler waiting for the callback. Privilege-escalation path uses Meterpreter's `getsystem` which tries (in order): named-pipe impersonation, token duplication, KiTrap0D (CVE-2010-0232), and SeDebugPrivilege abuse. Lancer's equivalent should ship a **native getsystem replacement** — we don't shell to msfconsole, we open our own listener and handle the Meterpreter stage via the `metasploit-rs`-style protocol.
- **HTTP auth quartet semantics.** `--auth-type=Basic` (RFC 7617 + base64 user:pass), `Digest` (RFC 7616, supports MD5 + SHA-256 + SHA-512/256, qop=auth/auth-int), `NTLM` (NTLMv2 only, sqlmap drops NTLMv1 for security since 1.7), `PKI` (client cert + private key via `--auth-file=pem.pem`). Our `reqwest` middleware stack must implement all four including the multi-challenge Negotiate fallback for NTLM-over-HTTP/2.
- **Cookie/session file persistence.** Sqlmap's `--session-file=output/<target>/session.sqlite` is a SQLite 3 database with tables `knowledge_base`, `injections`, `dump`, `xpcmdshell_status`, `metasploit_status`. Our `redb` analog must mirror the same schema (renamed to `kb`/`inj`/`dump`/`oscmd_status`/`msf_status`) so users can switch between sqlmap output and Lancer output for the same target.
- **Tamper script catalog count.** Current upstream `tamper/` directory has **74 scripts** (verified May 2026, was 50+ in 1.7, ~60 in 1.8). Net new since the dossier:
  - `htmlencode.py` (full HTML entity encoding)
  - `apostrophenullencode.py` (apostrophe → `%00%27`)
  - `bluecoat.py` (Blue Coat SG WAF specific tamper)
  - `lowercase.py` / `uppercase.py` (case-flip pair)
  - `chardoubleencode.py` (double URL-encode)
  - `commalessmid.py` (avoid commas in MID()/SUBSTRING() — for WAFs blocking comma)
  - `space2dash.py` (whitespace → `--<random>%0a`)
  - `space2hash.py` (whitespace → `#%0a` MySQL only)
  - `space2morecomment.py` (whitespace → `/**_**/`)
  - `space2morehash.py` (combo)
  - `space2mssqlblank.py` (whitespace → MSSQL valid whitespace char set)
  - `space2plus.py` (whitespace → `+`)
  - `between.py` (extends `>`/`<` to `NOT BETWEEN 0 AND X` pattern; defeats many WAFs)
  - `equaltolike.py` (`=` → `LIKE`)
  - `greatest.py`, `least.py` (replace `>`/`<` with `GREATEST`/`LEAST`)
  - `ifnull2ifisnull.py` (MySQL `IFNULL(x,y)` → `IF(ISNULL(x),y,x)`)
  - `modsecurityversioned.py`, `modsecurityzeroversioned.py` (ModSecurity-specific MySQL versioned comment tricks)
  - `multiplespaces.py`
  - `nonrecursivereplacement.py` (avoid `replace()` keyword-stripping WAFs)
  - `overlongutf8.py` (UTF-8 over-long encoding evasion)
  - `percentage.py`
  - `randomcomments.py`
  - `randomcase.py`
  - `randomtags.py`
  - `securesphere.py` (Imperva SecureSphere bypass appendix)
  - `sp_password.py` (MSSQL: append `sp_password` to log obfuscation)
  - `symboliclogical.py` (`AND`/`OR` → `&&`/`||`)
  - `unionalltounion.py` (`UNION ALL` → `UNION`)
  - `unmagicquotes.py` (use `%bf%27` to bypass `magic_quotes_gpc` filters)
  - `varnish.py` (Varnish-X-Forwarded-For trickery)
- **DBMSes confirmed present in 1.10 / 1.11 trees we hadn't flagged.** Verified by checking `lib/core/enums.py` `DBMS` enum + `lib/dbms/<name>/`: Snowflake (read-only fingerprint mode, no extract), Spanner (fingerprint via `INFORMATION_SCHEMA.SCHEMATA`), Cubrid, Aurora MySQL/PostgreSQL, OpenGauss, Virtuoso, DM8 — all already in plan. Plus a recently-added probe for **Doris** (Apache Doris, MySQL-compatible analytic DB) that needs adding.
- **`--check-tor` flow.** When `--tor` is set, sqlmap pre-flights `https://check.torproject.org` to verify the SOCKS-5 chain actually exits via Tor. Our equivalent should test against `https://check.torproject.org/api/ip` (JSON endpoint, more parseable) and fail loud if the IP isn't Tor-listed.
- **`--csrf-token=<name>` + `--csrf-url=<url>` flow.** Sqlmap auto-fetches the CSRF endpoint, scrapes the token, threads it through subsequent requests. Sub-flag `--csrf-method=GET|POST` and `--csrf-retries=<N>`. Must port semantics exactly — many real-world targets are gated by CSRF.
- **`--har=output.har` HAR-format request log.** When combined with `--proxy=http://burp`, every request sqlmap sends is also captured to a HAR file for forensic review. Our equivalent should reuse the Lancer-wide HAR exporter.

Sources: [sqlmap features wiki](https://github.com/sqlmapproject/sqlmap/wiki/Features), [sqlmap tamper catalog](https://deepwiki.com/sqlmapproject/sqlmap/8.2-tamper-script-catalog), [sqlmap tamper directory](https://github.com/sqlmapproject/sqlmap/tree/master/tamper), [PayloadsAllTheThings SQLmap reference](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/SQLmap/).

## AI augmentation ideas

1. **LLM-suggested tamper-script chains for unknown WAF responses.** Capture the blocked response (status code, body fingerprint, response headers like `cf-ray`, `x-amzn-cf-id`). Feed to LLM: "Given this WAF response, suggest a tamper chain from this list: [...]". LLM returns ranked candidates with rationale. Lancer auto-tries top 3.
2. **AI-generated boundary payloads for proprietary input filters.** Some apps escape `'` to `\'` then re-escape, or filter `UNION` case-insensitively. LLM reads observed input mutations (Lancer's pre-flight echo probe) and proposes a `--prefix`/`--suffix` boundary the app accepts.
3. **Summarize a long extraction in plain language.** A 10k-row dump is overwhelming; LLM groups by column-value patterns ("rows 1-500: test/seeded accounts; rows 501-9800: real users with @gmail/@yahoo domains; row 9801: admin@company.com with bcrypt hash $2b$12...").
4. **Post-exploit chaining suggestions.** "You have DBA on MSSQL. Here are the privilege-escalation paths: (a) `xp_cmdshell whoami` to confirm OS context; (b) if NETWORK SERVICE, try Potato chain for SYSTEM; (c) if domain user, dump `mssql$INSTANCE` LSA secrets via `xp_regread`."
5. **Tamper-script synthesis from observed WAF response patterns.** Given many failed payloads vs many successful ones, LLM diff-analyzes character classes the WAF rejects and emits a Lua tamper script ready to load (`--tamper=lua:generated.lua`).
6. **Counterexample replay narrative.** "The vulnerable param is `order` — the query path that confirmed injection was a boolean-blind on context `ORDER BY ?`. Working payload: `1) UNION SELECT NULL,NULL,@@version -- -`. Backend: MySQL 8.0.32."
7. **Schema-aware dump targeting.** Instead of `--dump-all`, LLM reads enumerated table/column names and suggests "Likely PII tables: `users`, `subscriptions`, `audit_log`. Likely credential tables: `users.password_hash`, `oauth_tokens.refresh_token`. Likely PCI tables: `cards` (if present)."
8. **WAF fingerprint from headers.** Pre-flight probe captures response headers. LLM identifies WAF vendor ("`cf-ray` + `server: cloudflare` → Cloudflare; `x-amzn-cf-id` → AWS CloudFront/WAF; `x-sucuri-id` → Sucuri; no headers but precise blocklist → likely Imperva"). Auto-selects vendor-tuned tamper chain.
9. **Severity-weighted dumping.** Lancer enumerates 200 tables; LLM ranks by likely bounty-report value: dumping the entire `users` table is high signal, dumping `migrations_history` is low. Drives `--dump` table prioritization to keep extraction time bounded on slow oracles.
10. **Natural-language SQL shell.** In `--sql-shell`, user types "show me the 10 most recent admin actions"; LLM translates to dialect-correct SQL (`SELECT ... FROM audit_log WHERE actor_role='admin' ORDER BY created_at DESC LIMIT 10`) using the already-enumerated schema as ground truth, and executes via the working injection channel.

## Implementation phases

**Heavy by design** — sqlmap upstream is 80k+ Python LOC across boundaries/payloads/techniques/dbms/tamper. The 18-week roadmap stages by impact: six techniques first (the actual injection engine), then the canonical five DBMSes (covers 95% of real-world bounty targets), then tamper library, then file/OS features, then expand DBMS matrix. A solo dev hitting weeks 1-10 has a working sqlmap-equivalent for MySQL/PG/MSSQL — already extremely valuable.

**Week 1 — Workspace + HTTP engine + Target model.** Cargo workspace with the 7 crates. `lancer-sqlmap` parses top-50-flag subset via clap. `sqlmap-core::HttpEngine` on reqwest with rustls, retry, proxy chain, rate limit. Round-trip a simple GET-with-params request and verify cookie persistence.

**Week 2 — Boundary registry + payload loader.** Port upstream `xml/boundaries.xml` and `xml/payloads/*.xml` to YAML. `sqlmap-payloads` lazy-loads, exposes `iter_for_level_risk(level, risk, dbms)`. Validate by counting payloads matches upstream's reference (`--list-payloads` parity).

**Week 3 — Detector skeleton + boolean-blind (B) technique.** `Detector::run(target, params)` walks boundaries × payloads, calls boolean technique driver. Implement Ratcliff-Obershelp oracle, binary-search char extractor. Test against DVWA SQLi-Low.

**Week 4 — Time-blind (T) technique + statistical denoising.** Baseline RTT warm-up, adaptive threshold, retries on borderline. Test against DVWA SQLi-Blind.

**Week 5 — Union-query (U) technique.** `ORDER BY` column-count discovery, type-slot detection, payload assembly. Cheap bulk extraction at 1 req per row range.

**Week 6 — Error-based (E) technique + DBMS-specific error vectors.** MySQL `EXTRACTVALUE`/`UPDATEXML`, PostgreSQL CAST errors, MSSQL `CONVERT()`, Oracle `CTXSYS.DRITHSX.SN`.

**Week 7 — Stacked-queries (S) + Inline-query (Q) techniques.** Stacked is easy on MSSQL/PG, gated on MySQL multi-statement, blocked on Oracle. Inline-query is rarely seen but powerful — implement and test against juice-shop.

**Week 8 — Fingerprinter pipeline (MySQL, PG, MSSQL, Oracle, SQLite).** Banner regex bank, function-availability probes, version extraction. Two-independent-confirmation rule.

**Week 9 — Enumerator: dbs/tables/columns/dump.** Schema queries per DBMS dialect via `sqlmap-dbms` shims. Resumable extraction with redb session.

**Week 10 — `--sql-shell` interactive REPL.** ratatui-based TUI for arbitrary `SELECT` execution against confirmed channel. `--sql-query=...` non-interactive variant. `--sql-file=...` batch.

**Week 11 — Tamper script registry (first 20 tampers).** `space2comment`, `randomcase`, `charunicodeencode`, `between`, `apostrophemask`, `apostrophenullencode`, `base64encode`, `hex2char`, `percentage`, `equaltolike`, `greatest`, `least`, `versionedmorekeywords`, `space2dash`, `space2hash`, `space2mssqlblank`, `space2mysqlblank`, `informationschemacomment`, `commentbeforeparentheses`, `xforwardedfor`.

**Week 12 — Tamper scripts (remaining 30+) + Lua tamper loader.** mlua-based runtime tampers. CLI validates chain compat (terminal tampers, encoder placement).

**Week 13 — File read/write (`--file-read`/`--file-write`).** MySQL `LOAD_FILE`/`INTO DUMPFILE`, PG `COPY`/`lo_export`, MSSQL `bcp`+`xp_cmdshell`, Oracle `UTL_FILE`, SQLite `readfile()`/`writefile()` (loadable extension).

**Week 14 — OS command (`--os-cmd`/`--os-shell`) + privilege check.** MSSQL `xp_cmdshell` enablement flow, PG `COPY ... PROGRAM`, MySQL UDF injection (ship `lib_mysqludf_sys.so/dll` for amd64). Privilege check before attempting.

**Week 15 — Inline hash cracking (`--passwords`).** MySQL native (SHA1(SHA1(pass))), MSSQL/Sybase, Oracle 11g/12c, PG md5/scram. Multi-threaded rayon dictionary attack on small wordlist.

**Week 16 — Expand DBMS matrix to 10 (add Sybase, IBM DB2, Firebird, MariaDB, CockroachDB).** Add dialect modules; port fingerprint/enumeration/file/OS shims.

**Week 17 — HTTP/2, MFA, OAuth, JSON body, GraphQL.** 2024-2026 modernization. `--http2`, `--mfa-prompt` interactive 2FA, OAuth Bearer/refresh, JSON typed-field fuzzing, GraphQL endpoint auto-detection.

**Week 18 — Session persistence + reports + AI augmentation hooks.** redb session schema finalized. JSON/HAR output. LLM hooks for tamper suggestion, post-exploit chain advice, dump summarization. Benchmark vs upstream sqlmap on testbed (DVWA, juice-shop, OWASP WebGoat, HackTheBox SQL challenges).

**Skip in v1 (defer to v2):**
- Last 15 DBMSes (the rare ones: Mckoi, Altibase, MimerSQL, Drizzle, Apache Ignite, etc.) — port only when a real engagement needs them.
- Metasploit handoff (`--os-pwn`) — Lancer's own exploit chain replaces it.
- Windows registry manipulation (`--reg-*`) — rare in modern bounties.
- `--wizard` interactive mode — `--batch` covers unattended; interactive Lancer GUI covers guided.

---

## GUI (Lancer-standard pattern)

`lancer-sqlmap` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-sqlmap-cli` companion binary), but the **plain `lancer-sqlmap` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-sqlmap/`, `%APPDATA%\lancer-sqlmap\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-sqlmap-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-sqlmap.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-sqlmap.exe` (double-click opens the GUI window).
- Linux: `build/lancer-sqlmap` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-sqlmap` (bundled into `lancer-sqlmap.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-sqlmap/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-sqlmap.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-sqlmap-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-sqlmap
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-sqlmap.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-sqlmap-windows-x86_64\bin\lancer-sqlmap.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-sqlmap`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
