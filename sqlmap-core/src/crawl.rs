//! Minimal crawler used for `--crawl=N` and `--forms`.
//!
//! Single-process BFS up to depth `N` from a seed URL, restricted to the same
//! origin (`--scope=regex` can override). Form parsing emits one `Target` per
//! `<form>` element with inferred method + parameter list.

use crate::errors::Result;
use crate::http::HttpEngine;
use crate::target::{HttpMethod, Param, ParamPlace, Target};
use std::collections::{HashSet, VecDeque};
use url::Url;

pub struct Crawler {
    pub depth: u32,
    pub max_pages: usize,
    pub scope: Option<regex::Regex>,
    pub exclude: Option<regex::Regex>,
}

impl Default for Crawler {
    fn default() -> Self {
        Self { depth: 1, max_pages: 250, scope: None, exclude: None }
    }
}

impl Crawler {
    pub async fn crawl(&self, engine: &HttpEngine, seed: Url) -> Result<Vec<Url>> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(Url, u32)> = VecDeque::new();
        queue.push_back((seed.clone(), 0));
        let host = seed.host_str().unwrap_or("").to_string();
        let mut out = Vec::new();

        while let Some((url, d)) = queue.pop_front() {
            if visited.len() >= self.max_pages || d > self.depth {
                continue;
            }
            if !visited.insert(url.to_string()) {
                continue;
            }
            if let Some(s) = &self.scope {
                if !s.is_match(url.as_str()) {
                    continue;
                }
            }
            if let Some(e) = &self.exclude {
                if e.is_match(url.as_str()) {
                    continue;
                }
            }
            out.push(url.clone());

            let target = simple_get(&url);
            let resp = match engine.send(&target).await {
                Ok(r) => r,
                Err(_) => continue,
            };
            for link in extract_links(&resp.body) {
                if let Ok(abs) = url.join(&link) {
                    if abs.host_str().unwrap_or("") == host {
                        queue.push_back((abs, d + 1));
                    }
                }
            }
        }
        Ok(out)
    }

    /// Parse `<form>` elements out of a response body and return one `Target`
    /// per form ready for injection.
    pub fn forms(&self, base: &Url, html: &str) -> Vec<Target> {
        let doc = scraper::Html::parse_document(html);
        let form_sel = scraper::Selector::parse("form").unwrap();
        let input_sel = scraper::Selector::parse("input, textarea, select").unwrap();
        let mut out = Vec::new();
        for form in doc.select(&form_sel) {
            let action = form.value().attr("action").unwrap_or("");
            let method = form
                .value()
                .attr("method")
                .map(|m| HttpMethod::parse(m).unwrap_or(HttpMethod::Get))
                .unwrap_or(HttpMethod::Get);
            let url = match base.join(action) {
                Ok(u) => u,
                Err(_) => continue,
            };
            let mut params = Vec::new();
            for input in form.select(&input_sel) {
                let name = match input.value().attr("name") {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let value = input.value().attr("value").unwrap_or("").to_string();
                let place = if matches!(method, HttpMethod::Get) { ParamPlace::Get } else { ParamPlace::Post };
                params.push(Param::new(name, value, place));
            }
            out.push(Target {
                url,
                method,
                headers: Default::default(),
                cookies: Default::default(),
                body: None,
                params,
                auth: None,
                csrf: None,
                safe_req: None,
                second_req: None,
            });
        }
        out
    }
}

fn simple_get(u: &Url) -> Target {
    Target {
        url: u.clone(),
        method: HttpMethod::Get,
        headers: Default::default(),
        cookies: Default::default(),
        body: None,
        params: Vec::new(),
        auth: None,
        csrf: None,
        safe_req: None,
        second_req: None,
    }
}

fn extract_links(html: &str) -> Vec<String> {
    let doc = scraper::Html::parse_document(html);
    let sel = scraper::Selector::parse("a[href]").unwrap();
    doc.select(&sel)
        .filter_map(|e| e.value().attr("href").map(|s| s.to_string()))
        .collect()
}
