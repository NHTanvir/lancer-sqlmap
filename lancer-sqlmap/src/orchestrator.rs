//! High-level orchestrator: wires the CLI args into HttpEngine, Session,
//! Detector, Enumerator, and the GUI HTTP server.

use crate::cli::{Cli, DumpFormatArg};
use eyre::Result;
use sqlmap_core::auth::AuthSpec;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::detector::DetectGate;
use sqlmap_core::enumerator::{DumpFormat, EnumPlan};
use sqlmap_core::har::HarWriter;
use sqlmap_core::http::{HttpEngine, ProxyConfig, ProxyKind, TorConfig};
use sqlmap_core::oracle::{Oracle, OracleConfig};
use sqlmap_core::reports::{Finding, FindingSeverity, ReportBundle};
use sqlmap_core::request_file::parse_request_file;
use sqlmap_core::session::Session;
use sqlmap_core::target::{Param, ParamPlace, Target, TargetBuilder};
use sqlmap_techniques::{all_techniques, DetectCtx, Technique};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use url::Url;

pub struct Orchestrator {
    pub cli: Cli,
}

impl Orchestrator {
    pub fn new(cli: Cli) -> Self {
        Self { cli }
    }

    pub async fn run(&self) -> Result<ReportBundle> {
        let mut bundle = ReportBundle {
            started_at: chrono::Utc::now().timestamp(),
            ..Default::default()
        };

        if self.cli.list_dbms {
            for d in Dbms::all() {
                println!("{}", d.short());
            }
            return Ok(bundle);
        }
        if self.cli.list_tampers {
            for n in sqlmap_tamper::scripts::catalog() {
                println!("{n}");
            }
            return Ok(bundle);
        }
        if self.cli.self_test {
            self_test::run_self_test().await?;
            return Ok(bundle);
        }
        if self.cli.update {
            info!("update: pull mirror at https://github.com/NHTanvir/lancer-sqlmap");
            return Ok(bundle);
        }

        // ── Build target ────────────────────────────────────────────────────
        let target = self.build_target()?;

        // ── Session ─────────────────────────────────────────────────────────
        let session_path = self
            .cli
            .session_file
            .clone()
            .unwrap_or_else(|| self.cli.output_dir.join("session.redb"));
        std::fs::create_dir_all(&self.cli.output_dir).ok();
        let session = Session::open(&session_path)?;
        if self.cli.flush_session {
            session.flush()?;
        }
        bundle.session_path = Some(session_path.display().to_string());

        // ── HTTP engine ─────────────────────────────────────────────────────
        let engine = self.build_engine()?;

        if self.cli.request.check_tor {
            let ok = engine.check_tor().await.unwrap_or(false);
            if !ok {
                warn!("Tor pre-flight failed — IP not reported as Tor exit");
            }
        }

        // ── Tamper chain validation only ────────────────────────────────────
        if let Some(t) = &self.cli.injection.tamper {
            let names: Vec<&str> = t.split(',').map(|s| s.trim()).collect();
            let _chain = sqlmap_tamper::TamperChain::from_names(&names)
                .map_err(|e| eyre::eyre!("tamper chain invalid: {e}"))?;
            info!("tamper chain validated: {}", names.join(","));
        }

        // ── Detection loop ──────────────────────────────────────────────────
        let oracle_cfg = OracleConfig {
            string: self.cli.detection.string.clone(),
            not_string: self.cli.detection.not_string.clone(),
            regexp: self.cli.detection.regexp.clone(),
            code: self.cli.detection.code,
            text_only: self.cli.detection.text_only,
            titles: self.cli.detection.titles,
            ..OracleConfig::standard()
        };
        let oracle = Arc::new(parking_lot::Mutex::new(Oracle::new(oracle_cfg)));
        let gate = DetectGate {
            level: self.cli.detection.level,
            risk: self.cli.detection.risk,
            time_sec: self.cli.techniques.time_sec,
        };

        let dbms_hint = self
            .cli
            .injection
            .dbms
            .as_deref()
            .and_then(|s| Dbms::from_str(s).ok());

        let techniques = all_techniques();
        let allowed: Vec<char> = self.cli.techniques.technique.chars().collect();

        let param_name = match (&self.cli.injection.param, target.injected_index()) {
            (Some(p), _) => p.clone(),
            (None, Some(i)) => target.params[i].name.clone(),
            (None, None) => target.params.first().map(|p| p.name.clone()).unwrap_or_default(),
        };

        if param_name.is_empty() {
            warn!("no parameter to inject — pass -p <name> or use `*` marker");
            return Ok(bundle);
        }

        let mut detect_ctx = DetectCtx {
            engine: &engine,
            target: &target,
            param: &param_name,
            oracle: oracle.clone(),
            level: gate.level,
            risk: gate.risk,
            dbms_hint,
            time_sec: gate.time_sec,
        };
        for t in &techniques {
            if !allowed.contains(&t.id()) {
                continue;
            }
            info!("detecting via {}…", t.name());
            match t.detect(&mut detect_ctx).await {
                Ok(Some(wp)) => {
                    info!("✓ {} working: {}", t.name(), wp.title);
                    let id = uuid::Uuid::new_v4().to_string();
                    bundle.findings.push(Finding {
                        id,
                        title: wp.title,
                        severity: FindingSeverity::High,
                        target_url: target.url.to_string(),
                        param: param_name.clone(),
                        technique: wp.technique,
                        dbms: wp.dbms,
                        working_payload: format!("{}{}{}", wp.prefix, wp.vector, wp.suffix),
                        evidence: wp.evidence,
                        remediation: "Use parameterised queries / prepared statements; sanitise + validate input; deploy WAF; least-privilege DB user.".into(),
                        created_at: chrono::Utc::now().timestamp(),
                    });
                    break;
                }
                Ok(None) => {}
                Err(e) => warn!("{} detect error: {e}", t.name()),
            }
        }

        // ── Optional enumeration / dump (stubbed call to keep scope sane) ───
        let plan = EnumPlan {
            banner: self.cli.enumeration.banner || self.cli.enumeration.all,
            current_user: self.cli.enumeration.current_user || self.cli.enumeration.all,
            current_db: self.cli.enumeration.current_db || self.cli.enumeration.all,
            hostname: self.cli.enumeration.hostname || self.cli.enumeration.all,
            is_dba: self.cli.enumeration.is_dba,
            users: self.cli.enumeration.users,
            passwords: self.cli.enumeration.passwords,
            privileges: self.cli.enumeration.privileges,
            roles: self.cli.enumeration.roles,
            dbs: self.cli.enumeration.dbs,
            tables: self.cli.enumeration.tables,
            columns: self.cli.enumeration.columns,
            schema: self.cli.enumeration.schema,
            count: self.cli.enumeration.count,
            dump: self.cli.enumeration.dump,
            dump_all: self.cli.enumeration.dump_all,
            search: self.cli.enumeration.search.clone(),
            comments: self.cli.enumeration.comments,
            statements: self.cli.enumeration.statements,
            exclude_sysdbs: self.cli.enumeration.exclude_sysdbs,
            specific_db: self.cli.enumeration.db.clone(),
            specific_tables: self.cli.enumeration.table.iter().cloned().flat_map(|s| s.split(',').map(|x| x.to_string()).collect::<Vec<_>>()).collect(),
            specific_columns: self.cli.enumeration.cols.iter().cloned().flat_map(|s| s.split(',').map(|x| x.to_string()).collect::<Vec<_>>()).collect(),
            excluded_columns: self.cli.enumeration.exclude_cols.iter().cloned().flat_map(|s| s.split(',').map(|x| x.to_string()).collect::<Vec<_>>()).collect(),
            specific_user: self.cli.enumeration.user.clone(),
            pivot_column: self.cli.enumeration.pivot_column.clone(),
            where_clause: self.cli.enumeration.r#where.clone(),
            start: self.cli.enumeration.start,
            stop: self.cli.enumeration.stop,
            first: self.cli.enumeration.first,
            last: self.cli.enumeration.last,
            sql_query: self.cli.enumeration.sql_query.clone(),
            sql_shell: self.cli.enumeration.sql_shell,
            sql_file: self.cli.enumeration.sql_file.as_ref().map(|p| p.display().to_string()),
            common_tables: self.cli.brute.common_tables,
            common_columns: self.cli.brute.common_columns,
            common_files: self.cli.brute.common_files,
            format: match self.cli.general.dump_format {
                DumpFormatArg::Stdout => DumpFormat::Stdout,
                DumpFormatArg::Csv => DumpFormat::Csv,
                DumpFormatArg::Html => DumpFormat::Html,
                DumpFormatArg::Sqlite => DumpFormat::Sqlite,
                DumpFormatArg::Markdown => DumpFormat::Markdown,
                DumpFormatArg::Json => DumpFormat::Json,
                DumpFormatArg::Sarif => DumpFormat::Sarif,
            },
            ..EnumPlan::default()
        };
        let _enum_result = sqlmap_core::enumerator::Enumerator::execute(&plan).await?;

        bundle.finished_at = chrono::Utc::now().timestamp();
        Ok(bundle)
    }

    fn build_engine(&self) -> Result<HttpEngine> {
        let mut b = HttpEngine::builder()
            .timeout(Duration::from_secs(self.cli.request.timeout))
            .delay(Duration::from_millis(self.cli.request.delay))
            .retries(self.cli.request.retries)
            .threads(self.cli.optimization.threads)
            .keep_alive(self.cli.optimization.keep_alive)
            .http2(self.cli.request.http2)
            .drop_set_cookie(self.cli.request.drop_set_cookie)
            .ignore_redirects(self.cli.request.ignore_redirects)
            .safe_freq(self.cli.request.safe_freq)
            .null_connection(self.cli.optimization.null_connection)
            .chunked(self.cli.request.chunked)
            .hpp(self.cli.request.hpp);
        if let Some(ua) = &self.cli.request.user_agent {
            b = b.user_agent(ua);
        }
        b = b.random_agent(self.cli.request.random_agent);
        if let Some(r) = &self.cli.request.referer {
            b = b.referer(r);
        }
        for h in &self.cli.request.headers {
            if let Some((k, v)) = h.split_once(':') {
                b = b.header(k.trim(), v.trim());
            }
        }
        if self.cli.request.tor {
            b = b.tor(TorConfig {
                port: self.cli.request.tor_port,
                kind: ProxyKind::Socks5,
                check: self.cli.request.check_tor,
            });
        } else if let Some(p) = &self.cli.request.proxy {
            let url: Url = p.parse()?;
            let kind = match url.scheme() {
                "https" => ProxyKind::Https,
                "socks4" => ProxyKind::Socks4,
                "socks5" => ProxyKind::Socks5,
                _ => ProxyKind::Http,
            };
            b = b.proxy(ProxyConfig {
                url,
                kind,
                cred: self.cli.request.proxy_cred.clone(),
            });
        }
        if let (Some(kind), Some(cred)) = (&self.cli.request.auth_type, &self.cli.request.auth_cred) {
            let auth = match kind {
                crate::cli::AuthTypeArg::Basic => AuthSpec::basic(cred.clone()),
                crate::cli::AuthTypeArg::Digest => AuthSpec::digest(cred.clone()),
                crate::cli::AuthTypeArg::Ntlm => AuthSpec::ntlm(cred.clone()),
                crate::cli::AuthTypeArg::Pki => AuthSpec::pki(self.cli.request.auth_file.clone().unwrap_or_default()),
                crate::cli::AuthTypeArg::Bearer => AuthSpec::bearer(cred.clone()),
            };
            b = b.auth(auth);
        }
        if let Some(path) = &self.cli.har {
            let har = HarWriter::new(path.clone());
            b = b.har_sink(Arc::new(move |req, resp| har.record(req, resp)));
        }
        Ok(b.build()?)
    }

    fn build_target(&self) -> Result<Target> {
        if let Some(req_file) = &self.cli.target.request {
            return Ok(parse_request_file(req_file)?);
        }
        if let Some(u) = &self.cli.target.url {
            let url: Url = u.parse()?;
            let method = sqlmap_core::target::HttpMethod::parse(&self.cli.request.method)?;
            let mut tb = TargetBuilder::new().url(url).method(method);
            if let Some(c) = &self.cli.request.cookie {
                for pair in c.split(';') {
                    if let Some((k, v)) = pair.trim().split_once('=') {
                        tb = tb.cookie(k.to_string(), v.to_string());
                    }
                }
            }
            if let Some(d) = &self.cli.request.data {
                if d.starts_with('{') || d.starts_with('<') {
                    tb = tb.body(d.clone());
                } else {
                    for pair in d.split(&self.cli.request.param_del) {
                        if let Some((k, v)) = pair.split_once('=') {
                            tb = tb.param(Param::new(k.to_string(), v.to_string(), ParamPlace::Post));
                        }
                    }
                }
            }
            return Ok(tb.build()?);
        }
        Err(eyre::eyre!("missing target: pass -u <url> or -r <request.txt>"))
    }
}

mod self_test {
    use eyre::Result;
    use sqlmap_payloads::{boundaries as bnd, payloads as pyl, TechniqueId};
    use sqlmap_tamper::scripts as tamp_scripts;
    use tracing::info;

    pub async fn run_self_test() -> Result<()> {
        info!("self-test: validating bundled payload / boundary / tamper registries");
        let bs = bnd::bundled();
        info!("boundaries: {}", bs.boundaries.len());
        let ps = pyl::bundled();
        info!("boolean: {}", ps.boolean.payloads.len());
        info!("error:   {}", ps.error.payloads.len());
        info!("union:   {}", ps.union.payloads.len());
        info!("stacked: {}", ps.stacked.payloads.len());
        info!("time:    {}", ps.time.payloads.len());
        info!("inline:  {}", ps.inline.payloads.len());
        info!("tampers: {}", tamp_scripts::catalog().len());
        for name in tamp_scripts::catalog() {
            // Each tamper must construct without error.
            sqlmap_tamper::lookup(name).map_err(|e| eyre::eyre!("{name}: {e}"))?;
        }
        info!("self-test passed ✓");
        Ok(())
    }
}
