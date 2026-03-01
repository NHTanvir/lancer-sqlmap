//! GraphQL endpoint detection + walker (2024-2026 modernization).
//!
//! Heuristic: POST `{ "query": "{ __schema { types { name } } }" }` and check
//! for a `__schema` field in the JSON response. If so, enumerate operations
//! and emit injection candidates per field that accepts an `ID`/`String`/`Int`
//! argument.

use crate::errors::Result;
use crate::http::{HttpEngine, HttpResponse};
use crate::target::{HttpMethod, Param, ParamPlace, Target};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLSchemaSummary {
    pub queries: Vec<String>,
    pub mutations: Vec<String>,
    pub injection_candidates: Vec<String>,
}

pub async fn introspect(engine: &HttpEngine, endpoint: &Url) -> Result<Option<GraphQLSchemaSummary>> {
    let query = r#"{"query":"{ __schema { queryType { fields { name args { name type { name kind } } } } mutationType { fields { name args { name type { name kind } } } } } }"}"#;
    let mut t = Target {
        url: endpoint.clone(),
        method: HttpMethod::Post,
        headers: Default::default(),
        cookies: Default::default(),
        body: Some(query.to_string()),
        params: vec![],
        auth: None,
        csrf: None,
        safe_req: None,
        second_req: None,
    };
    t.headers.insert("Content-Type".into(), "application/json".into());
    let resp: HttpResponse = engine.send(&t).await?;
    if !resp.body.contains("\"__schema\"") {
        return Ok(None);
    }
    let parsed: serde_json::Value = serde_json::from_str(&resp.body)?;
    let queries = field_names(&parsed, "queryType");
    let mutations = field_names(&parsed, "mutationType");
    let mut candidates = Vec::new();
    for op in queries.iter().chain(&mutations) {
        candidates.push(op.clone());
    }
    Ok(Some(GraphQLSchemaSummary { queries, mutations, injection_candidates: candidates }))
}

fn field_names(v: &serde_json::Value, root: &str) -> Vec<String> {
    let arr = v.pointer(&format!("/data/__schema/{}/fields", root)).cloned();
    let Some(serde_json::Value::Array(items)) = arr else { return Vec::new() };
    items
        .into_iter()
        .filter_map(|e| e.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect()
}

/// Convert one field name into a synthetic injectable `Target` against the
/// endpoint. Useful for the detector to walk like a normal param.
pub fn field_target(endpoint: &Url, field: &str) -> Target {
    let body = format!(r#"{{"query":"{{ {field}(id:\"1*\") {{ id }} }}"}}"#);
    let mut params = Vec::new();
    let mut p = Param::new("id", "1", ParamPlace::Json);
    p.injected = true;
    p.path = Some(format!("/{field}/id"));
    params.push(p);
    let mut t = Target {
        url: endpoint.clone(),
        method: HttpMethod::Post,
        headers: Default::default(),
        cookies: Default::default(),
        body: Some(body),
        params,
        auth: None,
        csrf: None,
        safe_req: None,
        second_req: None,
    };
    t.headers.insert("Content-Type".into(), "application/json".into());
    t
}
