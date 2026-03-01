//! Boolean-blind technique driver (B).
//!
//! Detection: inject a TRUE-payload and a FALSE-payload and verify the
//! oracle splits the two responses. Extraction: per-char binary search via
//! `sqlmap-core::extractor::Extractor::extract_string`.

use crate::{ConcurrencyCap, DetectCtx, ExtractCtx, Technique, WorkingPayload};
use async_trait::async_trait;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::errors::Result;
use sqlmap_core::extractor::{ExtractCtx as CoreExtractCtx, ExtractMode, ExtractResult, Extractor};
use sqlmap_core::oracle::OracleVerdict;
use sqlmap_payloads::{payloads as pyl, TechniqueId};
use sqlmap_payloads::boundaries as bnd;
use sqlmap_core::util::{expand_placeholders, PlaceholderCtx};

#[derive(Debug, Default, Clone)]
pub struct BooleanTechnique;

#[async_trait]
impl Technique for BooleanTechnique {
    fn id(&self) -> char { 'B' }
    fn name(&self) -> &'static str { "Boolean-based blind" }
    fn dbms_scope(&self) -> &'static [Dbms] { &[] }

    async fn detect(&self, ctx: &mut DetectCtx<'_>) -> Result<Option<WorkingPayload>> {
        let registry = pyl::bundled();
        let boundaries = bnd::bundled();
        for boundary in boundaries.iter_for(ctx.level) {
            for payload in registry.iter_for(TechniqueId::Boolean, ctx.level, ctx.risk, ctx.dbms_hint.map(|d| d.short())) {
                let ph = PlaceholderCtx::default();
                let true_payload_raw = expand_placeholders(&payload.request.payload, &ph);
                let false_payload_raw = match &payload.response.comparison {
                    Some(c) => expand_placeholders(&c.payload, &ph),
                    None => continue,
                };
                let true_full = format!("{}{}{}", boundary.prefix, true_payload_raw, boundary.suffix);
                let false_full = format!("{}{}{}", boundary.prefix, false_payload_raw, boundary.suffix);

                let t_resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &true_full).await?;
                {
                    let mut o = ctx.oracle.lock();
                    o.set_true_baseline(&t_resp);
                }
                let f_resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &false_full).await?;
                {
                    let mut o = ctx.oracle.lock();
                    o.set_false_baseline(&f_resp);
                }
                // Re-verify the true payload reads TRUE on the new oracle.
                let t_resp2 = ctx.engine.send_with_payload(ctx.target, ctx.param, &true_full).await?;
                let verdict = ctx.oracle.lock().judge(&t_resp2);
                if matches!(verdict, Ok(OracleVerdict::True)) {
                    return Ok(Some(WorkingPayload {
                        technique: 'B',
                        title: payload.title.clone(),
                        vector: payload.vector.clone(),
                        prefix: boundary.prefix.clone(),
                        suffix: boundary.suffix.clone(),
                        dbms: ctx.dbms_hint,
                        evidence: format!("boundary={:?} payload={}", boundary.comment, true_full),
                    }));
                }
            }
        }
        Ok(None)
    }

    async fn extract(&self, ctx: &mut ExtractCtx<'_>, query: &str) -> Result<ExtractResult> {
        let mut core_ctx = CoreExtractCtx {
            engine: ctx.engine.clone(),
            target: ctx.target.clone(),
            param: ctx.param.to_string(),
            payload_template: format!("[PREFIX]{}[SUFFIX]", ctx.working_vector.replace("[INFERENCE]", "[INFERENCE]")),
            working_boundary_prefix: ctx.working_prefix.clone(),
            working_boundary_suffix: ctx.working_suffix.clone(),
            oracle: ctx.oracle.clone(),
            start_pos: 1,
            max_len: 65_536,
            mode: ExtractMode::BinarySearch,
        };
        Extractor::extract_string(&mut core_ctx, query).await
    }
}
