//! lancer-sqlmap — Rust clone of sqlmap. See plan.md (local) for the spec.
//!
//! Entry-point behaviour:
//! - Plain invocation → opens the native GUI window (eframe).
//! - `--cli` (or any subcommand) → CLI flow via the orchestrator.

mod ai;
mod cli;
mod fileops;
#[cfg(feature = "gui")]
mod gui;
mod orchestrator;
mod server;

use clap::Parser;
use cli::{Cli, Command};
use eyre::Result;
use orchestrator::Orchestrator;
use parking_lot::Mutex;
use server::ServerState;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();
    let level = match cli.verbosity {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)))
        .init();

    let state = ServerState {
        bundle: Arc::new(Mutex::new(Default::default())),
        status: Arc::new(Mutex::new("idle".into())),
    };
    let _ = server::run_local(state.clone()).await;

    // CLI subcommand takes precedence.
    if let Some(cmd) = &cli.command {
        return handle_subcommand(cmd).await;
    }

    let need_cli = cli.cli
        || cli.target.url.is_some()
        || cli.target.request.is_some()
        || cli.target.direct.is_some()
        || cli.target.targets.is_some()
        || cli.target.log.is_some()
        || cli.target.google_dork.is_some()
        || cli.list_dbms
        || cli.list_tampers
        || cli.self_test
        || cli.update;

    if need_cli {
        let orch = Orchestrator::new(cli);
        let bundle = orch.run().await?;
        *state.bundle.lock() = bundle.clone();
        if !bundle.findings.is_empty() {
            info!("found {} injection(s)", bundle.findings.len());
            for f in &bundle.findings {
                println!("[{:?}] {} via {} on `{}`", f.severity, f.title, f.technique, f.param);
            }
        }
        return Ok(());
    }

    // No CLI args + no subcommand → GUI.
    #[cfg(feature = "gui")]
    {
        gui::launch().map_err(|e| eyre::eyre!("gui: {e}"))?;
    }
    #[cfg(not(feature = "gui"))]
    {
        eprintln!("lancer-sqlmap built without GUI; pass --cli or -u <url>.");
    }
    Ok(())
}

async fn handle_subcommand(cmd: &Command) -> Result<()> {
    match cmd {
        Command::Pivot { finding_id, tamper, batch, dump } => {
            info!("pivot: finding={finding_id} tamper={tamper:?} batch={batch} dump={dump}");
            Ok(())
        }
        Command::SqlShell { session_file: _ } => {
            use sqlmap_tui::{Repl, ShellKind};
            let mut repl = Repl::new(ShellKind::Sql);
            let runner: sqlmap_tui::QueryRunner = Box::new(|q: &str| {
                let q = q.to_string();
                Box::pin(async move { Ok::<String, anyhow::Error>(format!("(stub) ran: {q}")) })
            });
            repl.run(runner).await?;
            Ok(())
        }
        Command::OsShell { session_file: _ } => {
            use sqlmap_tui::{Repl, ShellKind};
            let mut repl = Repl::new(ShellKind::Os);
            let runner: sqlmap_tui::QueryRunner = Box::new(|q: &str| {
                let q = q.to_string();
                Box::pin(async move { Ok::<String, anyhow::Error>(format!("(stub) executed: {q}")) })
            });
            repl.run(runner).await?;
            Ok(())
        }
        Command::CrackHashes { hashes, wordlist } => {
            let h_lines: Vec<String> = std::fs::read_to_string(hashes)?.lines().map(|s| s.to_string()).collect();
            let w_lines: Vec<String> = std::fs::read_to_string(wordlist)?.lines().map(|s| s.to_string()).collect();
            let results = sqlmap_dbms::hashing::crack_many(&h_lines, &w_lines);
            for (h, p) in &results {
                println!("{h}\t{p}");
            }
            Ok(())
        }
        Command::ValidatePayloads { file } => {
            let txt = std::fs::read_to_string(file)?;
            let set: sqlmap_payloads::payloads::PayloadSet = serde_yaml::from_str(&txt)?;
            println!("{} payloads OK", set.payloads.len());
            Ok(())
        }
    }
}
