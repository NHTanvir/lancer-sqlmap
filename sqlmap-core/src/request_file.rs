//! `-r request.txt` parser.
//!
//! Accepts a raw Burp/ZAP/cURL-dump HTTP/1.1 request and returns a fully
//! populated [`crate::target::Target`]. Recognises the `*` injection marker
//! in any value position.

use crate::errors::{Error, Result};
use crate::target::{HttpMethod, Param, ParamPlace, ParamType, Target};
use std::collections::BTreeMap;
use std::path::Path;
use url::Url;

pub fn parse_request_file(path: impl AsRef<Path>) -> Result<Target> {
    let text = std::fs::read_to_string(path.as_ref())?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<Target> {
    let mut lines = text.lines();
    let request_line = lines.next().ok_or_else(|| Error::RequestFile("empty file".into()))?;
    let mut parts = request_line.split_whitespace();
    let method_s = parts.next().ok_or_else(|| Error::RequestFile("missing method".into()))?;
    let path = parts.next().ok_or_else(|| Error::RequestFile("missing path".into()))?;
    let method = HttpMethod::parse(method_s)?;

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut cookies: BTreeMap<String, String> = BTreeMap::new();
    let mut body = String::new();
    let mut in_body = false;

    for line in lines {
        if !in_body {
            if line.is_empty() {
                in_body = true;
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().to_string();
                let v = v.trim().to_string();
                if k.eq_ignore_ascii_case("cookie") {
                    for pair in v.split(';') {
                        if let Some((ck, cv)) = pair.trim().split_once('=') {
                            cookies.insert(ck.to_string(), cv.to_string());
                        }
                    }
                } else {
                    headers.insert(k, v);
                }
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }

    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .ok_or_else(|| Error::RequestFile("missing Host header".into()))?;

    let scheme = if headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("x-forwarded-proto") && v.eq_ignore_ascii_case("https"))
    {
        "https"
    } else {
        "http"
    };
    let raw_url = format!("{}://{}{}", scheme, host, path);
    let url: Url = raw_url.parse()?;

    let mut params: Vec<Param> = Vec::new();
    for (k, v) in url.query_pairs() {
        let injected = v.contains('*');
        let value = v.replace('*', "");
        let mut p = Param::new(k.into_owned(), value, ParamPlace::Get);
        p.injected = injected;
        params.push(p);
    }
    let body_trim = body.trim_end_matches('\n').to_string();
    if !body_trim.is_empty() {
        // Form-encoded body fast path.
        if !body_trim.starts_with('{') && !body_trim.starts_with('<') {
            for pair in body_trim.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    let injected = v.contains('*');
                    let value = v.replace('*', "");
                    let mut p = Param::new(k.to_string(), value, ParamPlace::Post);
                    p.injected = injected;
                    params.push(p);
                }
            }
        }
    }

    // Cookies as injectable parameters.
    for (k, v) in &cookies {
        let injected = v.contains('*');
        let value = v.replace('*', "");
        let mut p = Param::new(k.clone(), value, ParamPlace::Cookie);
        p.injected = injected;
        params.push(p);
    }

    // Headers as injectable parameters when they carry a `*` marker.
    for (k, v) in &headers {
        if v.contains('*') {
            let place = match k.to_lowercase().as_str() {
                "user-agent" => ParamPlace::UserAgent,
                "referer" => ParamPlace::Referer,
                "host" => ParamPlace::Host,
                _ => ParamPlace::CustomHeader,
            };
            let value = v.replace('*', "");
            let mut p = Param::new(k.clone(), value, place);
            p.injected = true;
            params.push(p);
        }
    }

    if params.iter().all(|p| !p.injected) {
        // No explicit marker — flag all GET/POST params as candidates.
        for p in &mut params {
            p.injected = matches!(p.place, ParamPlace::Get | ParamPlace::Post);
            if p.injected {
                break;
            }
        }
    }

    Ok(Target {
        url,
        method,
        headers,
        cookies,
        body: if body_trim.is_empty() { None } else { Some(body_trim) },
        params,
        auth: None,
        csrf: None,
        safe_req: None,
        second_req: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_get() {
        let req = "GET /vuln?id=1*&name=foo HTTP/1.1\nHost: example.com\nUser-Agent: test\n\n";
        let t = parse(req).unwrap();
        assert_eq!(t.params.len(), 2);
        let inj = t.injected_index().unwrap();
        assert_eq!(t.params[inj].name, "id");
    }
}
