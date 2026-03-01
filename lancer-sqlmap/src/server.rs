//! Local HTTP server used for cross-tool integration with the rest of the
//! Lancer ecosystem. Auto-allocates a port on 127.0.0.1 and writes the chosen
//! port to `%TEMP%/lancer-sqlmap.port`.
//!
//! Endpoints (`v1`):
//! - `GET  /v1/state`              — current jobs / progress
//! - `POST /v1/import`             — accept a target / file / record
//! - `GET  /v1/export?format=…`    — pull the current result set
//!
//! See the plan's "Cross-tool integration with Lancer + the other 29 clones"
//! section.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json as AxumJson};
use axum::routing::{get, post};
use axum::Router;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sqlmap_core::reports::ReportBundle;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone, Default)]
pub struct ServerState {
    pub bundle: Arc<Mutex<ReportBundle>>,
    pub status: Arc<Mutex<String>>,
}

pub async fn run_local(state: ServerState) -> Result<u16, std::io::Error> {
    let app = Router::new()
        .route("/v1/state", get(get_state))
        .route("/v1/import", post(post_import))
        .route("/v1/export", get(get_export))
        .with_state(state);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let port = listener.local_addr()?.port();
    let port_file = env::temp_dir().join("lancer-sqlmap.port");
    let _ = std::fs::write(&port_file, port.to_string());
    info!("local server bound on 127.0.0.1:{port} ({})", port_file.display());

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(port)
}

#[derive(Debug, Serialize)]
struct StateView {
    status: String,
    findings: usize,
}

async fn get_state(State(s): State<ServerState>) -> impl IntoResponse {
    let status = s.status.lock().clone();
    let findings = s.bundle.lock().findings.len();
    AxumJson(StateView { status, findings })
}

#[derive(Debug, Deserialize)]
struct ImportReq {
    url: Option<String>,
    request_file_path: Option<String>,
}

async fn post_import(
    State(s): State<ServerState>,
    AxumJson(req): AxumJson<ImportReq>,
) -> impl IntoResponse {
    let mut msg = String::new();
    if let Some(u) = req.url {
        msg.push_str(&format!("queued URL {u}; "));
    }
    if let Some(p) = req.request_file_path {
        msg.push_str(&format!("queued request file {p}"));
    }
    *s.status.lock() = msg.clone();
    (StatusCode::ACCEPTED, msg)
}

#[derive(Debug, Deserialize)]
struct ExportParams {
    format: Option<String>,
}

async fn get_export(
    State(s): State<ServerState>,
    Query(p): Query<ExportParams>,
) -> impl IntoResponse {
    let bundle = s.bundle.lock().clone();
    match p.format.as_deref().unwrap_or("json") {
        "json" => AxumJson(serde_json::json!(bundle)).into_response(),
        "csv" => {
            let mut s = String::from("id,title,severity,target,param,technique\n");
            for f in &bundle.findings {
                s.push_str(&format!(
                    "{},{},{:?},{},{},{}\n",
                    f.id, f.title.replace(',', ";"), f.severity, f.target_url, f.param, f.technique
                ));
            }
            (StatusCode::OK, s).into_response()
        }
        "markdown" => {
            let mut s = String::from("# lancer-sqlmap findings\n\n");
            for f in &bundle.findings {
                s.push_str(&format!("- **{}** ({:?}) `{}` via `{}`\n", f.title, f.severity, f.param, f.technique));
            }
            (StatusCode::OK, s).into_response()
        }
        _ => (StatusCode::BAD_REQUEST, "unknown format".to_string()).into_response(),
    }
}

/// Discover other Lancer tools by scanning `%TEMP%/lancer-*.port`.
pub fn discover_peers() -> HashMap<String, u16> {
    let mut out = HashMap::new();
    let temp = env::temp_dir();
    if let Ok(rd) = std::fs::read_dir(&temp) {
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if let Some(rest) = name.strip_prefix("lancer-") {
                if let Some(tool) = rest.strip_suffix(".port") {
                    if let Ok(s) = std::fs::read_to_string(ent.path()) {
                        if let Ok(p) = s.trim().parse::<u16>() {
                            out.insert(tool.to_string(), p);
                        }
                    }
                }
            }
        }
    }
    out
}
