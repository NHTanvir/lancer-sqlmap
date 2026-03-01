//! Target / Param / ParamPlace model.
//!
//! Mirrors upstream `PLACE` (11 distinct injection points) and `PARAMETER`
//! (6 parameter types used for boundary inference).

use crate::auth::AuthSpec;
use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use url::Url;

/// HTTP method. We bucket the rare ones (`HEAD`/`OPTIONS`) under `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.trim().to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            other => return Err(Error::InvalidTarget(format!("bad HTTP method: {other}"))),
        })
    }
}

/// Eleven PLACE variants — matches upstream sqlmap's enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamPlace {
    Get,
    Post,
    Uri,
    Cookie,
    UserAgent,
    Referer,
    Host,
    /// `--data` with a `*` injection marker.
    CustomPost,
    /// `--headers` with a `*` injection marker.
    CustomHeader,
    /// Typed JSON body leaf.
    Json,
    /// SOAP / XML body leaf.
    Xml,
}

impl ParamPlace {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Uri => "URI",
            Self::Cookie => "Cookie",
            Self::UserAgent => "User-Agent",
            Self::Referer => "Referer",
            Self::Host => "Host",
            Self::CustomPost => "(custom) POST",
            Self::CustomHeader => "(custom) HEADER",
            Self::Json => "JSON",
            Self::Xml => "XML",
        }
    }
    /// `true` when the place is a request header — used by the engine to know
    /// whether to encode/URL-quote vs inject literally.
    pub fn is_header(self) -> bool {
        matches!(self, Self::UserAgent | Self::Referer | Self::Host | Self::CustomHeader | Self::Cookie)
    }
}

/// PARAMETER enum — used by the boundary registry to prune obviously-wrong
/// boundaries (e.g., no `\'` prefix when ptype is `Numeric`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ParamType {
    /// `id=1`
    Numeric,
    /// `id='1'`
    SingleQuotedString,
    /// `name LIKE '%x%'`
    LikeSingleQuotedString,
    /// `id="1"`
    DoubleQuotedString,
    /// `name LIKE "%x%"`
    LikeDoubleQuotedString,
    /// `ORDER BY <col>`
    Identifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: String,
    pub place: ParamPlace,
    pub ptype: ParamType,
    /// `true` if this is the active injection point (`*` marker from `-r`).
    pub injected: bool,
    /// JSON / XML pointer when `place == Json | Xml`.
    pub path: Option<String>,
}

impl Param {
    pub fn new(name: impl Into<String>, value: impl Into<String>, place: ParamPlace) -> Self {
        let value: String = value.into();
        let ptype = infer_ptype(&value);
        Self {
            name: name.into(),
            value,
            place,
            ptype,
            injected: false,
            path: None,
        }
    }
}

fn infer_ptype(v: &str) -> ParamType {
    let t = v.trim();
    if t.parse::<i128>().is_ok() || t.parse::<f64>().is_ok() {
        ParamType::Numeric
    } else if t.starts_with('\'') && t.ends_with('\'') {
        ParamType::SingleQuotedString
    } else if t.starts_with('"') && t.ends_with('"') {
        ParamType::DoubleQuotedString
    } else {
        // Default: anything else is treated as a numeric on the first probe and
        // re-classified after the boundary walk finds a working quote shape.
        ParamType::Numeric
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub url: Url,
    pub method: HttpMethod,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub body: Option<String>,
    pub params: Vec<Param>,
    pub auth: Option<AuthSpec>,
    /// Optional CSRF token endpoint + field name (`--csrf-url` / `--csrf-token`).
    pub csrf: Option<CsrfConfig>,
    /// `--safe-url` / `--safe-post` / `--safe-req` keepalive request.
    pub safe_req: Option<SafeRequest>,
    /// `--second-url` / `--second-req` — request to issue after the malicious
    /// one so the oracle can observe its effect.
    pub second_req: Option<SecondRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfConfig {
    pub url: Url,
    pub token_name: String,
    pub method: HttpMethod,
    pub data: Option<String>,
    pub retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeRequest {
    pub url: Url,
    pub data: Option<String>,
    /// Every N malicious requests, fire one safe one (`--safe-freq`).
    pub freq: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecondRequest {
    pub url: Url,
    pub method: HttpMethod,
    pub data: Option<String>,
}

impl Target {
    /// Stable fingerprint used as the redb session key — invariant under
    /// trailing-slash / query-order normalization.
    pub fn target_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        self.url.host_str().unwrap_or("").hash(&mut h);
        self.url.port_or_known_default().unwrap_or(0).hash(&mut h);
        let mut path = self.url.path().trim_end_matches('/').to_string();
        path.hash(&mut h);
        self.method.as_str().hash(&mut h);
        let mut params: Vec<_> = self.params.iter().map(|p| (p.name.clone(), p.place)).collect();
        params.sort();
        for (n, p) in params {
            n.hash(&mut h);
            p.as_str().hash(&mut h);
        }
        h.finish()
    }

    /// Index of the currently-injected param, if any.
    pub fn injected_index(&self) -> Option<usize> {
        self.params.iter().position(|p| p.injected)
    }
}

/// Convenience builder used by the CLI plumbing.
#[derive(Debug, Default)]
pub struct TargetBuilder {
    url: Option<Url>,
    method: HttpMethod,
    headers: BTreeMap<String, String>,
    cookies: BTreeMap<String, String>,
    body: Option<String>,
    params: Vec<Param>,
    auth: Option<AuthSpec>,
}

impl Default for HttpMethod {
    fn default() -> Self {
        Self::Get
    }
}

impl TargetBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn url(mut self, u: Url) -> Self {
        // If the URL has query params, pull them into Params automatically.
        for (k, v) in u.query_pairs() {
            self.params.push(Param::new(k.into_owned(), v.into_owned(), ParamPlace::Get));
        }
        self.url = Some(u);
        self
    }
    pub fn method(mut self, m: HttpMethod) -> Self {
        self.method = m;
        self
    }
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
    pub fn cookie(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.cookies.insert(name.into(), value.into());
        self
    }
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }
    pub fn param(mut self, p: Param) -> Self {
        self.params.push(p);
        self
    }
    pub fn auth(mut self, a: AuthSpec) -> Self {
        self.auth = Some(a);
        self
    }
    pub fn build(self) -> Result<Target> {
        let url = self.url.ok_or_else(|| Error::InvalidTarget("missing URL".into()))?;
        Ok(Target {
            url,
            method: self.method,
            headers: self.headers,
            cookies: self.cookies,
            body: self.body,
            params: self.params,
            auth: self.auth,
            csrf: None,
            safe_req: None,
            second_req: None,
        })
    }
}
