//! Error-based technique driver (E).
//!
//! Each payload provides a regex (`response.grep`) that captures the
//! extracted value from a DBMS error message. Detection succeeds when the
//! regex matches; extraction is one HTTP round-trip per query (much faster
//! than boolean-blind).

use crate::{DetectCtx, ExtractCtx, Technique, WorkingPayload};
use async_trait::async_trait;
use regex::Regex;
use sqlmap_core::dbms_kind::Dbms;
use sqlmap_core::errors::{Error, Result};
use sqlmap_core::extractor::ExtractResult;
use sqlmap_core::util::{expand_placeholders, PlaceholderCtx};
use sqlmap_payloads::{boundaries as bnd, payloads as pyl, TechniqueId};

#[derive(Debug, Default, Clone)]
pub struct ErrorTechnique;

#[async_trait]
impl Technique for ErrorTechnique {
    fn id(&self) -> char { 'E' }
    fn name(&self) -> &'static str { "Error-based" }
    fn dbms_scope(&self) -> &'static [Dbms] { &[] }

    async fn detect(&self, ctx: &mut DetectCtx<'_>) -> Result<Option<WorkingPayload>> {
        let reg = pyl::bundled();
        let boundaries = bnd::bundled();
        for boundary in boundaries.iter_for(ctx.level) {
            for payload in reg.iter_for(TechniqueId::Error, ctx.level, ctx.risk, ctx.dbms_hint.map(|d| d.short())) {
                let ph = PlaceholderCtx::default();
                let raw = expand_placeholders(&payload.request.payload, &ph);
                let full = format!("{}{}{}", boundary.prefix, raw, boundary.suffix);
                let resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
                let Some(grep) = payload.response.grep.as_deref() else { continue };
                let re = match Regex::new(grep) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                if re.is_match(&resp.body) {
                    return Ok(Some(WorkingPayload {
                        technique: 'E',
                        title: payload.title.clone(),
                        vector: payload.vector.clone(),
                        prefix: boundary.prefix.clone(),
                        suffix: boundary.suffix.clone(),
                        dbms: ctx.dbms_hint,
                        evidence: format!("error matched: {}", grep),
                    }));
                }
            }
        }
        Ok(None)
    }

    async fn extract(&self, ctx: &mut ExtractCtx<'_>, query: &str) -> Result<ExtractResult> {
        // The working vector contains [INFERENCE] — we substitute the actual query.
        let inference = format!("({})", query);
        let raw = ctx.working_vector.replace("[INFERENCE]", &inference);
        let full = format!("{}{}{}", ctx.working_prefix, raw, ctx.working_suffix);
        let resp = ctx.engine.send_with_payload(ctx.target, ctx.param, &full).await?;
        // Pull the value out of the first grep regex from the bundled payload set
        // matching this DBMS — search across all error payloads to be robust.
        let reg = pyl::bundled();
        for p in reg.error.payloads.iter() {
            if let Some(grep) = &p.response.grep {
                if let Ok(re) = Regex::new(grep) {
                    if let Some(cap) = re.captures(&resp.body) {
                        if let Some(m) = cap.get(1) {
                            return Ok(ExtractResult { data: m.as_str().to_string(), queries: 1, truncated: false });
                        }
                    }
                }
            }
        }
        Err(Error::ExtractionFailed { pos: 0, reason: "no error-grep match".into() })
    }
}
