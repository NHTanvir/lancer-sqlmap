//! AI augmentation hooks.
//!
//! These are pluggable trait objects; the binary ships no provider by
//! default. The GUI exposes a "configure AI" dialog that sets an env var
//! `LANCER_LLM_ENDPOINT` and `LANCER_LLM_TOKEN` consumed by the optional
//! `LlmClient` impl.
//!
//! The seven plan items map to:
//! - [`suggest_tamper_chain`]    — LLM-suggested chains for unknown WAFs
//! - [`suggest_boundary`]        — LLM-generated boundary payloads
//! - [`summarize_dump`]          — natural-language summary of a dump
//! - [`suggest_postexploit`]     — post-exploit chain suggestions
//! - [`synthesize_tamper`]       — Lua tamper synthesis from observed traffic
//! - [`replay_narrative`]        — counter-example replay narrative
//! - [`prioritise_tables`]       — schema-aware dump targeting
//! - [`fingerprint_waf_headers`] — WAF vendor identification from headers
//! - [`severity_rank_tables`]    — severity-weighted ranking
//! - [`nl_to_sql`]               — natural-language SQL shell translation

use sqlmap_core::reports::Finding;
use std::collections::BTreeMap;

pub trait LlmClient: Send + Sync {
    fn complete(&self, system: &str, user: &str) -> anyhow::Result<String>;
}

pub fn suggest_tamper_chain(client: &dyn LlmClient, waf_headers: &BTreeMap<String, String>, blocked_body_excerpt: &str) -> anyhow::Result<Vec<String>> {
    let system = "You suggest sqlmap tamper-script chains. Return a comma-separated list, no commentary.";
    let user = format!(
        "WAF response headers: {:?}\nBlocked body excerpt: {}\nKnown tampers: {}\nSuggest a chain.",
        waf_headers,
        blocked_body_excerpt,
        sqlmap_tamper::scripts::catalog().join(",")
    );
    let resp = client.complete(system, &user)?;
    Ok(resp.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

pub fn suggest_boundary(client: &dyn LlmClient, observed_mutations: &str) -> anyhow::Result<(String, String)> {
    let system = "Suggest a SQL injection boundary as JSON: {\"prefix\": \"...\", \"suffix\": \"...\"}.";
    let user = format!("Observed input mutations: {}", observed_mutations);
    let resp = client.complete(system, &user)?;
    let v: serde_json::Value = serde_json::from_str(&resp)?;
    Ok((
        v.get("prefix").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        v.get("suffix").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    ))
}

pub fn summarize_dump(client: &dyn LlmClient, rows: &[Vec<String>]) -> anyhow::Result<String> {
    let system = "Summarise this extracted table in 4 bullet points. Focus on PII / credentials / payment data.";
    let user = serde_json::to_string(rows)?;
    client.complete(system, &user)
}

pub fn suggest_postexploit(client: &dyn LlmClient, dbms: &str, is_dba: bool) -> anyhow::Result<Vec<String>> {
    let system = "List post-exploit options for the given DBMS context. One per line.";
    let user = format!("DBMS={dbms} is_dba={is_dba}");
    Ok(client.complete(system, &user)?.lines().map(|s| s.to_string()).collect())
}

pub fn synthesize_tamper(client: &dyn LlmClient, blocked_samples: &[String], allowed_samples: &[String]) -> anyhow::Result<String> {
    let system = "Generate a Lua function `tamper(payload)` that mutates the blocked patterns into allowed ones. Return ONLY Lua code.";
    let user = serde_json::to_string(&serde_json::json!({"blocked": blocked_samples, "allowed": allowed_samples}))?;
    client.complete(system, &user)
}

pub fn replay_narrative(client: &dyn LlmClient, f: &Finding) -> anyhow::Result<String> {
    let system = "Narrate this finding in 2-3 sentences explaining the injection step-by-step.";
    let user = serde_json::to_string(f)?;
    client.complete(system, &user)
}

pub fn prioritise_tables(client: &dyn LlmClient, tables: &[String]) -> anyhow::Result<Vec<String>> {
    let system = "Rank these table names by likely bug-bounty value, highest first. One per line.";
    let user = tables.join("\n");
    Ok(client.complete(system, &user)?.lines().map(|s| s.to_string()).collect())
}

pub fn fingerprint_waf_headers(headers: &BTreeMap<String, String>) -> Option<&'static str> {
    let l = |k: &str| headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(k));
    if l("cf-ray") || headers.values().any(|v| v.to_lowercase().contains("cloudflare")) {
        return Some("Cloudflare");
    }
    if l("x-amzn-cf-id") || l("x-amz-cf-id") {
        return Some("AWS CloudFront/WAF");
    }
    if l("x-sucuri-id") {
        return Some("Sucuri");
    }
    if l("x-iinfo") || headers.values().any(|v| v.to_lowercase().contains("incapsula")) {
        return Some("Imperva Incapsula");
    }
    if l("x-akamai-transformed") || l("akamai-grn") {
        return Some("Akamai");
    }
    if l("x-distil-cs") {
        return Some("Distil / Imperva Bot");
    }
    if headers.values().any(|v| v.to_lowercase().contains("barracuda")) {
        return Some("Barracuda");
    }
    if headers.values().any(|v| v.to_lowercase().contains("f5") || v.to_lowercase().contains("bigip")) {
        return Some("F5 BIG-IP / ASM");
    }
    None
}

pub fn nl_to_sql(client: &dyn LlmClient, schema: &str, nl: &str) -> anyhow::Result<String> {
    let system = "Translate the user's request into ONE SQL SELECT statement valid against the provided schema. Return SQL only.";
    let user = format!("schema:\n{schema}\n\nrequest:\n{nl}");
    client.complete(system, &user)
}
