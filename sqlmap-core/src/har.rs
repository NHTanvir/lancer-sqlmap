//! HAR-format request log writer.
//!
//! Format: <https://www.softwareishard.com/blog/har-12-spec/>. Used by
//! `--har=output.har`. Writes append-friendly (each entry flushed immediately
//! so a crashed run still leaves an analysable log).

use crate::http::{HttpRequest, HttpResponse};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HarLog {
    pub log: HarRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarRoot {
    pub version: String,
    pub creator: HarCreator,
    pub entries: Vec<HarEntry>,
}

impl Default for HarRoot {
    fn default() -> Self {
        Self {
            version: "1.2".into(),
            creator: HarCreator { name: "lancer-sqlmap".into(), version: "0.1".into() },
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarCreator {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEntry {
    pub started_date_time: String,
    pub time: u128,
    pub request: HarRequest,
    pub response: HarResponse,
    pub timings: HarTimings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    pub http_version: String,
    pub headers: Vec<HarKV>,
    pub query_string: Vec<HarKV>,
    pub post_data: Option<HarPostData>,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<HarKV>,
    pub content: HarContent,
    pub redirect_url: String,
    pub headers_size: i64,
    pub body_size: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarContent {
    pub size: i64,
    pub mime_type: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarKV {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarPostData {
    pub mime_type: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarTimings {
    pub send: i64,
    pub wait: i64,
    pub receive: i64,
}

#[derive(Clone)]
pub struct HarWriter {
    inner: Arc<Mutex<HarLog>>,
    path: PathBuf,
}

impl HarWriter {
    pub fn new(path: PathBuf) -> Self {
        Self { inner: Arc::new(Mutex::new(HarLog::default())), path }
    }

    pub fn record(&self, req: &HttpRequest, resp: &HttpResponse) {
        let started = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(req.time)
            .unwrap_or_else(|| chrono::Utc::now())
            .to_rfc3339();
        let entry = HarEntry {
            started_date_time: started,
            time: resp.elapsed_ms,
            request: HarRequest {
                method: req.method.clone(),
                url: req.url.clone(),
                http_version: "HTTP/1.1".into(),
                headers: req.headers.iter().map(|(k, v)| HarKV { name: k.clone(), value: v.clone() }).collect(),
                query_string: Vec::new(),
                post_data: req.body.clone().map(|t| HarPostData { mime_type: "application/x-www-form-urlencoded".into(), text: t }),
                headers_size: -1,
                body_size: req.body.as_ref().map(|s| s.len() as i64).unwrap_or(-1),
            },
            response: HarResponse {
                status: resp.status,
                status_text: String::new(),
                http_version: "HTTP/1.1".into(),
                headers: resp.headers.iter().map(|(k, v)| HarKV { name: k.clone(), value: v.clone() }).collect(),
                content: HarContent {
                    size: resp.body.len() as i64,
                    mime_type: resp.headers.get("content-type").cloned().unwrap_or_default(),
                    text: resp.body.clone(),
                },
                redirect_url: resp.headers.get("location").cloned().unwrap_or_default(),
                headers_size: -1,
                body_size: resp.body.len() as i64,
            },
            timings: HarTimings { send: 0, wait: resp.elapsed_ms as i64, receive: 0 },
        };
        let mut log = self.inner.lock();
        log.log.entries.push(entry);
        if let Ok(txt) = serde_json::to_string_pretty(&*log) {
            let _ = std::fs::write(&self.path, txt);
        }
    }
}
