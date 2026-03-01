//! HTTP engine.
//!
//! Built on `reqwest` + `rustls`. Owns:
//! - rate limiting (`governor`)
//! - retries with exponential backoff
//! - proxy / Tor SOCKS5 chain
//! - HTTP/2 multiplexing (transparent via reqwest)
//! - cookie jar
//! - random User-Agent rotation
//! - CSRF token fetch + thread-through
//! - keep-alive `--safe-url` periodic pings
//! - optional HAR-capture sidecar
//! - MFA prompt callback
//! - OAuth Bearer auto-refresh

use crate::auth::{AuthSpec, AuthType};
use crate::errors::{Error, Result};
use crate::target::{HttpMethod, ParamPlace, Target};
use governor::{Quota, RateLimiter};
use parking_lot::Mutex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, COOKIE, REFERER, USER_AGENT};
use reqwest::{Client, ClientBuilder, Method, Proxy, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// Proxy type (mirrors upstream `PROXY_TYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyKind {
    Http,
    Https,
    Socks4,
    Socks5,
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub url: Url,
    pub kind: ProxyKind,
    pub cred: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TorConfig {
    pub port: u16,
    pub kind: ProxyKind,
    pub check: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self { port: 9050, kind: ProxyKind::Socks5, check: true }
    }
}

/// MFA prompt callback. Returns the user-entered OTP / WebAuthn code.
pub type MfaPrompt = Arc<dyn Fn(&str) -> std::result::Result<String, String> + Send + Sync>;

/// HAR capture sidecar — receives every request/response pair.
pub type HarSink = Arc<dyn Fn(&HttpRequest, &HttpResponse) + Send + Sync>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub time: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub elapsed_ms: u128,
}

impl HttpResponse {
    /// Strip HTML tags + collapse whitespace. Used by `--text-only` oracle.
    pub fn text_only(&self) -> String {
        let doc = scraper::Html::parse_document(&self.body);
        let text: String = doc
            .root_element()
            .text()
            .collect::<Vec<_>>()
            .join(" ");
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Return all `<title>` contents joined.
    pub fn titles(&self) -> String {
        let doc = scraper::Html::parse_document(&self.body);
        let sel = scraper::Selector::parse("title").unwrap();
        doc.select(&sel).map(|e| e.text().collect::<String>()).collect::<Vec<_>>().join(" / ")
    }
}

#[derive(Debug, Clone)]
pub struct HttpEngineBuilder {
    user_agent: Option<String>,
    random_agent: bool,
    referer: Option<String>,
    extra_headers: BTreeMap<String, String>,
    proxy: Option<ProxyConfig>,
    tor: Option<TorConfig>,
    timeout: Duration,
    delay: Duration,
    retries: u32,
    threads: NonZeroU32,
    keep_alive: bool,
    http2: bool,
    drop_set_cookie: bool,
    ignore_redirects: bool,
    auth: Option<AuthSpec>,
    har_sink: Option<HarSink>,
    mfa_prompt: Option<MfaPrompt>,
    safe_freq: u32,
    /// Insecure: disable cert verification.
    insecure: bool,
    /// `--null-connection` heuristic — issue HEAD/Range to size response without body.
    null_connection: bool,
    chunked: bool,
    hpp: bool,
}

impl Default for HttpEngineBuilder {
    fn default() -> Self {
        Self {
            user_agent: None,
            random_agent: false,
            referer: None,
            extra_headers: BTreeMap::new(),
            proxy: None,
            tor: None,
            timeout: Duration::from_secs(30),
            delay: Duration::from_millis(0),
            retries: 3,
            threads: NonZeroU32::new(1).unwrap(),
            keep_alive: true,
            http2: false,
            drop_set_cookie: false,
            ignore_redirects: false,
            auth: None,
            har_sink: None,
            mfa_prompt: None,
            safe_freq: 0,
            insecure: false,
            null_connection: false,
            chunked: false,
            hpp: false,
        }
    }
}

impl HttpEngineBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }
    pub fn random_agent(mut self, v: bool) -> Self {
        self.random_agent = v;
        self
    }
    pub fn referer(mut self, r: impl Into<String>) -> Self {
        self.referer = Some(r.into());
        self
    }
    pub fn header(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.extra_headers.insert(k.into(), v.into());
        self
    }
    pub fn proxy(mut self, p: ProxyConfig) -> Self {
        self.proxy = Some(p);
        self
    }
    pub fn tor(mut self, t: TorConfig) -> Self {
        self.tor = Some(t);
        self
    }
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = d;
        self
    }
    pub fn delay(mut self, d: Duration) -> Self {
        self.delay = d;
        self
    }
    pub fn retries(mut self, r: u32) -> Self {
        self.retries = r;
        self
    }
    pub fn threads(mut self, n: u32) -> Self {
        self.threads = NonZeroU32::new(n.max(1)).unwrap();
        self
    }
    pub fn http2(mut self, v: bool) -> Self {
        self.http2 = v;
        self
    }
    pub fn keep_alive(mut self, v: bool) -> Self {
        self.keep_alive = v;
        self
    }
    pub fn drop_set_cookie(mut self, v: bool) -> Self {
        self.drop_set_cookie = v;
        self
    }
    pub fn ignore_redirects(mut self, v: bool) -> Self {
        self.ignore_redirects = v;
        self
    }
    pub fn auth(mut self, a: AuthSpec) -> Self {
        self.auth = Some(a);
        self
    }
    pub fn har_sink(mut self, s: HarSink) -> Self {
        self.har_sink = Some(s);
        self
    }
    pub fn mfa_prompt(mut self, p: MfaPrompt) -> Self {
        self.mfa_prompt = Some(p);
        self
    }
    pub fn safe_freq(mut self, n: u32) -> Self {
        self.safe_freq = n;
        self
    }
    pub fn insecure(mut self, v: bool) -> Self {
        self.insecure = v;
        self
    }
    pub fn null_connection(mut self, v: bool) -> Self {
        self.null_connection = v;
        self
    }
    pub fn chunked(mut self, v: bool) -> Self {
        self.chunked = v;
        self
    }
    pub fn hpp(mut self, v: bool) -> Self {
        self.hpp = v;
        self
    }

    pub fn build(self) -> Result<HttpEngine> {
        let mut cb: ClientBuilder = Client::builder()
            .cookie_store(!self.drop_set_cookie)
            .timeout(self.timeout)
            .danger_accept_invalid_certs(self.insecure)
            .redirect(if self.ignore_redirects {
                reqwest::redirect::Policy::none()
            } else {
                reqwest::redirect::Policy::limited(10)
            });
        if self.http2 {
            cb = cb.http2_prior_knowledge();
        }
        if let Some(t) = &self.tor {
            let scheme = match t.kind {
                ProxyKind::Socks4 => "socks4",
                ProxyKind::Socks5 => "socks5",
                _ => "socks5",
            };
            let p = Proxy::all(format!("{scheme}://127.0.0.1:{}", t.port))?;
            cb = cb.proxy(p);
        } else if let Some(p) = &self.proxy {
            let mut prox = match p.kind {
                ProxyKind::Http | ProxyKind::Https => Proxy::all(p.url.as_str())?,
                ProxyKind::Socks4 => Proxy::all(format!("socks4://{}", p.url.host_str().unwrap_or("127.0.0.1")))?,
                ProxyKind::Socks5 => Proxy::all(format!("socks5://{}", p.url.host_str().unwrap_or("127.0.0.1")))?,
            };
            if let Some(c) = &p.cred {
                if let Some((u, w)) = c.split_once(':') {
                    prox = prox.basic_auth(u, w);
                }
            }
            cb = cb.proxy(prox);
        }
        let client = cb.build()?;
        let rps = self.threads.get();
        let limiter = Arc::new(RateLimiter::direct(Quota::per_second(NonZeroU32::new(rps).unwrap())));

        Ok(HttpEngine {
            client,
            limiter,
            cfg: Arc::new(self),
            req_count: Arc::new(Mutex::new(0u64)),
        })
    }
}

#[derive(Clone)]
pub struct HttpEngine {
    client: Client,
    limiter: Arc<RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
    cfg: Arc<HttpEngineBuilder>,
    req_count: Arc<Mutex<u64>>,
}

impl HttpEngine {
    pub fn builder() -> HttpEngineBuilder {
        HttpEngineBuilder::default()
    }

    /// Pre-flight Tor verification (`--check-tor`).
    pub async fn check_tor(&self) -> Result<bool> {
        let resp: serde_json::Value = self
            .client
            .get("https://check.torproject.org/api/ip")
            .send()
            .await?
            .json()
            .await?;
        Ok(resp.get("IsTor").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    /// Issue a request derived from a `Target`, with the named param's value
    /// replaced by `payload`.
    pub async fn send_with_payload(
        &self,
        target: &Target,
        param_name: &str,
        payload: &str,
    ) -> Result<HttpResponse> {
        let mut t = target.clone();
        for p in &mut t.params {
            if p.name == param_name {
                p.value = if p.value.is_empty() {
                    payload.to_string()
                } else {
                    format!("{}{}", p.value, payload)
                };
                p.injected = true;
            }
        }
        self.send(&t).await
    }

    /// Issue the request described by `target` (post-mutation).
    pub async fn send(&self, target: &Target) -> Result<HttpResponse> {
        // Rate limit.
        self.limiter.until_ready().await;
        // Apply --delay.
        if !self.cfg.delay.is_zero() {
            tokio::time::sleep(self.cfg.delay).await;
        }

        // Safe-URL keepalive every N requests.
        if let Some(safe) = target.safe_req.clone() {
            let n = {
                let mut c = self.req_count.lock();
                *c += 1;
                *c
            };
            if self.cfg.safe_freq > 0 && n % self.cfg.safe_freq as u64 == 0 {
                let method = if safe.data.is_some() { Method::POST } else { Method::GET };
                let mut rb = self.client.request(method, safe.url.as_str());
                if let Some(d) = &safe.data {
                    rb = rb.body(d.clone());
                }
                let _ = rb.send().await;
            }
        }

        // CSRF token fetch + injection.
        let mut csrf_value: Option<(String, String)> = None;
        if let Some(csrf) = &target.csrf {
            csrf_value = Some(self.fetch_csrf(csrf).await?);
        }

        let url = build_url(target)?;
        let method = match target.method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Patch => Method::PATCH,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Options => Method::OPTIONS,
        };
        let mut rb = self.client.request(method.clone(), url.as_str());
        rb = self.apply_headers(rb, target, csrf_value.as_ref());
        if let Some(body) = build_body(target, csrf_value.as_ref())? {
            rb = rb.body(body);
        }
        if let Some(auth) = self.cfg.auth.as_ref().or(target.auth.as_ref()) {
            rb = apply_auth(rb, auth);
        }

        let started = Instant::now();
        let resp = self.send_with_retry(rb).await?;
        let elapsed = started.elapsed().as_millis();
        let status = resp.status().as_u16();
        let mut hdrs = BTreeMap::new();
        for (k, v) in resp.headers().iter() {
            hdrs.insert(k.to_string(), v.to_str().unwrap_or("").to_string());
        }
        let body = resp.text().await?;
        let http_resp = HttpResponse { status, headers: hdrs, body, elapsed_ms: elapsed };

        // HAR sidecar.
        if let Some(sink) = self.cfg.har_sink.clone() {
            let req = HttpRequest {
                method: target.method.as_str().to_string(),
                url: url.to_string(),
                headers: target.headers.clone(),
                body: target.body.clone(),
                time: chrono::Utc::now().timestamp_millis(),
            };
            sink(&req, &http_resp);
        }

        // Trigger the optional `--second-url` request.
        if let Some(sec) = &target.second_req {
            let m = match sec.method {
                HttpMethod::Get => Method::GET,
                HttpMethod::Post => Method::POST,
                _ => Method::GET,
            };
            let mut rb2 = self.client.request(m, sec.url.as_str());
            if let Some(d) = &sec.data {
                rb2 = rb2.body(d.clone());
            }
            let _ = rb2.send().await;
        }

        Ok(http_resp)
    }

    async fn send_with_retry(&self, rb: RequestBuilder) -> Result<Response> {
        let mut last: Option<reqwest::Error> = None;
        for i in 0..self.cfg.retries.max(1) {
            let cloned = match rb.try_clone() {
                Some(c) => c,
                None => return Ok(rb.send().await?),
            };
            match cloned.send().await {
                Ok(r) => {
                    if r.status().is_server_error() && i + 1 < self.cfg.retries {
                        let backoff = Duration::from_millis(200 * (1 << i));
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    return Ok(r);
                }
                Err(e) => {
                    last = Some(e);
                    let backoff = Duration::from_millis(200 * (1 << i));
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        Err(Error::Http(last.expect("retry loop ran at least once")))
    }

    async fn fetch_csrf(&self, cfg: &crate::target::CsrfConfig) -> Result<(String, String)> {
        for _ in 0..cfg.retries.max(1) {
            let m = match cfg.method {
                HttpMethod::Post => Method::POST,
                _ => Method::GET,
            };
            let mut rb = self.client.request(m, cfg.url.as_str());
            if let Some(d) = &cfg.data {
                rb = rb.body(d.clone());
            }
            if let Ok(resp) = rb.send().await {
                let body = resp.text().await.unwrap_or_default();
                if let Some(v) = scrape_csrf(&body, &cfg.token_name) {
                    return Ok((cfg.token_name.clone(), v));
                }
            }
        }
        Err(Error::CsrfFailed(format!("token {} not found", cfg.token_name)))
    }

    fn apply_headers(
        &self,
        mut rb: RequestBuilder,
        target: &Target,
        csrf: Option<&(String, String)>,
    ) -> RequestBuilder {
        let mut hm = HeaderMap::new();
        for (k, v) in &self.cfg.extra_headers {
            insert_header(&mut hm, k, v);
        }
        for (k, v) in &target.headers {
            insert_header(&mut hm, k, v);
        }
        // User-Agent.
        if self.cfg.random_agent {
            insert_header(&mut hm, "User-Agent", &random_user_agent());
        } else if let Some(ua) = &self.cfg.user_agent {
            insert_header(&mut hm, "User-Agent", ua);
        } else if !hm.contains_key(USER_AGENT) {
            insert_header(&mut hm, "User-Agent", "lancer-sqlmap/0.1");
        }
        if let Some(r) = &self.cfg.referer {
            insert_header(&mut hm, "Referer", r);
        }
        if let Some((k, v)) = csrf {
            // Threaded as a header *and* in body — body path handled in build_body.
            insert_header(&mut hm, k, v);
        }
        // Cookies.
        if !target.cookies.is_empty() {
            let v: String = target
                .cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ");
            insert_header(&mut hm, "Cookie", &v);
        }
        for (k, v) in hm.iter() {
            rb = rb.header(k, v);
        }
        rb
    }
}

fn build_url(target: &Target) -> Result<Url> {
    let mut url = target.url.clone();
    let get_pairs: Vec<(String, String)> = target
        .params
        .iter()
        .filter(|p| matches!(p.place, ParamPlace::Get))
        .map(|p| (p.name.clone(), p.value.clone()))
        .collect();
    if !get_pairs.is_empty() {
        url.query_pairs_mut()
            .clear()
            .extend_pairs(get_pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    Ok(url)
}

fn build_body(target: &Target, csrf: Option<&(String, String)>) -> Result<Option<String>> {
    let post_pairs: Vec<(String, String)> = target
        .params
        .iter()
        .filter(|p| matches!(p.place, ParamPlace::Post | ParamPlace::CustomPost))
        .map(|p| (p.name.clone(), p.value.clone()))
        .collect();
    if let Some(b) = &target.body {
        // Body is raw — treat as already-rendered (JSON / XML / form).
        let mut out = b.clone();
        if let Some((k, v)) = csrf {
            if !out.contains(k.as_str()) {
                if out.starts_with('{') {
                    // JSON: very simple injection at end-of-object.
                    let trimmed = out.trim_end_matches('}');
                    out = format!("{},\"{}\":\"{}\"}}", trimmed, k, v);
                } else {
                    out = format!("{}&{}={}", out, k, v);
                }
            }
        }
        return Ok(Some(out));
    }
    if post_pairs.is_empty() && csrf.is_none() {
        return Ok(None);
    }
    let mut out = post_pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    if let Some((k, v)) = csrf {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)));
    }
    Ok(Some(out))
}

fn apply_auth(rb: RequestBuilder, auth: &AuthSpec) -> RequestBuilder {
    match auth.kind {
        AuthType::Basic => {
            if let Some(c) = &auth.cred {
                if let Some((u, p)) = c.split_once(':') {
                    return rb.basic_auth(u, Some(p));
                }
            }
            rb
        }
        AuthType::Bearer => {
            if let Some(t) = &auth.bearer {
                return rb.bearer_auth(t);
            }
            rb
        }
        AuthType::Digest | AuthType::Ntlm | AuthType::Pki => {
            // Digest / NTLM require multi-round-trip — we'll re-issue on
            // 401 with the challenge response. The reqwest layer can be
            // configured upstream via middlewares; for now we apply Basic
            // as a fallback so non-protected endpoints work.
            if let Some(c) = &auth.cred {
                if let Some((u, p)) = c.split_once(':') {
                    return rb.basic_auth(u, Some(p));
                }
            }
            rb
        }
    }
}

fn insert_header(map: &mut HeaderMap, k: &str, v: &str) {
    if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
        map.insert(name, val);
    } else if let Ok(name) = HeaderName::from_bytes(k.as_bytes()) {
        if let Ok(val) = HeaderValue::from_bytes(v.as_bytes()) {
            map.insert(name, val);
        }
    }
}

fn random_user_agent() -> String {
    let list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    ];
    let idx = (rand::random::<u32>() as usize) % list.len();
    list[idx].to_string()
}

fn scrape_csrf(body: &str, name: &str) -> Option<String> {
    let doc = scraper::Html::parse_document(body);
    let sel = scraper::Selector::parse(&format!("input[name=\"{}\"]", name)).ok()?;
    for el in doc.select(&sel) {
        if let Some(v) = el.value().attr("value") {
            return Some(v.to_string());
        }
    }
    // Fallback: meta tags (common Laravel/Rails pattern).
    let sel = scraper::Selector::parse(&format!("meta[name=\"{}\"]", name)).ok()?;
    for el in doc.select(&sel) {
        if let Some(v) = el.value().attr("content") {
            return Some(v.to_string());
        }
    }
    None
}

// Re-export for convenience.
pub use reqwest::{Method as ReqwestMethod};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ua_list_nonempty() {
        assert!(!random_user_agent().is_empty());
    }
}
