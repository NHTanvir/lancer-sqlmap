//! Stacked-queries technique driver (S).
//!
//! Stacks `;<query>` onto the original. Idempotency caveat: this is the only
//! technique that can mutate state, so the orchestrator gates it at
//! `--threads=1` by default.

use crate::{ConcurrencyCap, DetectCtx, ExtractCtx, Technique, WorkingPayload};
use async_trait::async_trait;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::errors::{Error, Result};
use sqlmap_core::extractor::ExtractResult;
use sqlmap_core::util::{expand_placeholders, PlaceholderCtx};
use sqlmap_payloads::{boundaries as bnd, payloads as pyl, TechniqueId};
use std::time::Instant;

#[derive(Debug, Default, Clone)]
pub struct StackedTechnique;

#[async_trait]
impl Technique for StackedTechnique {
    fn id(&self) -> char { 'S' }
    fn name(&self) -> &'static str { "Stacked queries" }
    fn dbms_scope(&self) -> &'static [Dbms] { &[] }
    fn concurrency_cap(&self) -> ConcurrencyCap { ConcurrencyCap::One }

    async fn detect(&self, ctx: &mut DetectCtx<'_>) -> Result<Option<WorkingPayload>> {
        let reg = pyl::bundled();
        let boundaries = bnd::bundled();
        for boundary in boundaries.iter_for(ctx.level) {
            for payload in reg.iter_for(TechniqueId::Stacked, ctx.level, ctx.risk, ctx.dbms_hint.map(|d| d.short())) {
                let ph = PlaceholderCtx { sleep_time: ctx.time_sec, ..Default::default() };
                let raw = expand_placeholders(&payload.request.payload, &ph);
                let full = format!("{}{}{}", boundary.prefix, raw, boundary.suffix);
                // For sleep-bearing stacked payloads we measure latency.
                let started = Instant::now();
                let _resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
                let elapsed = started.elapsed().as_secs_f32();
                if payload.response.time.is_some() && elapsed >= ctx.time_sec as f32 * 0.9 {
                    return Ok(Some(WorkingPayload {
                        technique: 'S',
                        title: payload.title.clone(),
                        vector: payload.vector.clone(),
                        prefix: boundary.prefix.clone(),
                        suffix: boundary.suffix.clone(),
                        dbms: ctx.dbms_hint,
                        evidence: format!("delay {:.2}s", elapsed),
                    }));
                }
            }
        }
        Ok(None)
    }

    async fn extract(&self, _ctx: &mut ExtractCtx<'_>, _q: &str) -> Result<ExtractResult> {
        Err(Error::Other("stacked-only — use --sql-shell to interact directly".into()))
    }
}
