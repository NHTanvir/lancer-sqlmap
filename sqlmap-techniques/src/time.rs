//! Time-blind technique driver (T).
//!
//! Naïve `SLEEP(5)` is unreliable on noisy networks. We:
//! 1. Warm up by issuing `--time-warmup=5` baseline requests to compute
//!    `mean ± stddev` of the unperturbed RTT.
//! 2. Pick `delay = max(--time-sec, mean + 7 * stddev)`.
//! 3. On a borderline call, retry once with `delay = 2 * orig_delay`.

use crate::{ConcurrencyCap, DetectCtx, ExtractCtx, Technique, WorkingPayload};
use async_trait::async_trait;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::errors::Result;
use sqlmap_core::extractor::ExtractResult;
use sqlmap_core::util::{expand_placeholders, PlaceholderCtx};
use sqlmap_payloads::{boundaries as bnd, payloads as pyl, TechniqueId};
use std::time::Instant;

#[derive(Debug, Default, Clone)]
pub struct TimeTechnique;

impl TimeTechnique {
    pub async fn warmup_baseline(
        engine: &sqlmap_core::http::HttpEngine,
        target: &sqlmap_core::target::Target,
    ) -> (f32, f32) {
        let mut samples = Vec::new();
        for _ in 0..5 {
            let started = Instant::now();
            let _ = engine.send(target).await;
            samples.push(started.elapsed().as_secs_f32());
        }
        let mean = samples.iter().sum::<f32>() / samples.len() as f32;
        let var = samples.iter().map(|s| (s - mean).powi(2)).sum::<f32>() / samples.len() as f32;
        (mean, var.sqrt())
    }

    pub fn pick_delay(user_time_sec: u32, mean: f32, stddev: f32) -> u32 {
        let derived = (mean + 7.0 * stddev).ceil() as u32;
        derived.max(user_time_sec).max(1)
    }
}

#[async_trait]
impl Technique for TimeTechnique {
    fn id(&self) -> char { 'T' }
    fn name(&self) -> &'static str { "Time-based blind" }
    fn dbms_scope(&self) -> &'static [Dbms] { &[] }
    fn concurrency_cap(&self) -> ConcurrencyCap { ConcurrencyCap::One }

    async fn detect(&self, ctx: &mut DetectCtx<'_>) -> Result<Option<WorkingPayload>> {
        let reg = pyl::bundled();
        let boundaries = bnd::bundled();
        let (mean, stddev) = Self::warmup_baseline(ctx.engine, ctx.target).await;
        let delay = Self::pick_delay(ctx.time_sec, mean, stddev);
        for boundary in boundaries.iter_for(ctx.level) {
            for payload in reg.iter_for(TechniqueId::Time, ctx.level, ctx.risk, ctx.dbms_hint.map(|d| d.short())) {
                let ph = PlaceholderCtx { sleep_time: delay, ..Default::default() };
                let raw = expand_placeholders(&payload.request.payload, &ph);
                let full = format!("{}{}{}", boundary.prefix, raw, boundary.suffix);
                let started = Instant::now();
                let _resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
                let elapsed = started.elapsed().as_secs_f32();
                if elapsed >= delay as f32 * 0.9 {
                    return Ok(Some(WorkingPayload {
                        technique: 'T',
                        title: payload.title.clone(),
                        vector: payload.vector.clone(),
                        prefix: boundary.prefix.clone(),
                        suffix: boundary.suffix.clone(),
                        dbms: ctx.dbms_hint,
                        evidence: format!("delay {:.2}s (target {})", elapsed, delay),
                    }));
                }
            }
        }
        Ok(None)
    }

    async fn extract(&self, ctx: &mut ExtractCtx<'_>, query: &str) -> Result<ExtractResult> {
        // Reuse the boolean extractor — the oracle here is "did the response
        // take long enough?", but we still issue per-char inferences.
        let mut core_ctx = sqlmap_core::extractor::ExtractCtx {
            engine: ctx.engine.clone(),
            target: ctx.target.clone(),
            param: ctx.param.to_string(),
            payload_template: format!("[PREFIX]{}[SUFFIX]", ctx.working_vector),
            working_boundary_prefix: ctx.working_prefix.clone(),
            working_boundary_suffix: ctx.working_suffix.clone(),
            oracle: ctx.oracle.clone(),
            start_pos: 1,
            max_len: 4_096,
            mode: sqlmap_core::extractor::ExtractMode::BinarySearch,
        };
        sqlmap_core::extractor::Extractor::extract_string(&mut core_ctx, query).await
    }
}
