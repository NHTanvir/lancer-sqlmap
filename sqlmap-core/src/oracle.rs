//! Response oracle.
//!
//! Decides whether a given response represents the TRUE or FALSE branch of a
//! boolean injection. Strategy stack (first match wins):
//!
//! 1. `--string=marker`  / `--not-string=marker` literal match
//! 2. `--regexp=^Hello$` regex match
//! 3. `--code=200` status-code match
//! 4. `--text-only` strip-tags + ratcliff-obershelp similarity
//! 5. `--titles` `<title>` similarity
//! 6. default: ratcliff-obershelp on the raw body
//!
//! Thresholds: similarity > `true_ratio` → TRUE; < `false_ratio` → FALSE;
//! otherwise INCONCLUSIVE (caller retries with a wider boundary).

use crate::errors::{Error, Result};
use crate::http::HttpResponse;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OracleConfig {
    pub string: Option<String>,
    pub not_string: Option<String>,
    pub regexp: Option<String>,
    pub code: Option<u16>,
    pub text_only: bool,
    pub titles: bool,
    /// Above-this ratio = TRUE.
    pub true_ratio: f64,
    /// Below-this ratio = FALSE.
    pub false_ratio: f64,
}

impl OracleConfig {
    pub fn standard() -> Self {
        Self {
            string: None,
            not_string: None,
            regexp: None,
            code: None,
            text_only: false,
            titles: false,
            true_ratio: 0.98,
            false_ratio: 0.92,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OracleVerdict {
    True,
    False,
    Inconclusive,
}

#[derive(Debug, Clone)]
pub struct Oracle {
    cfg: OracleConfig,
    baseline_true: Option<String>,
    baseline_false: Option<String>,
}

impl Oracle {
    pub fn new(cfg: OracleConfig) -> Self {
        Self { cfg, baseline_true: None, baseline_false: None }
    }

    /// Record the TRUE-baseline response (e.g., the response to `1=1`).
    pub fn set_true_baseline(&mut self, resp: &HttpResponse) {
        self.baseline_true = Some(self.text_for_compare(resp));
    }

    pub fn set_false_baseline(&mut self, resp: &HttpResponse) {
        self.baseline_false = Some(self.text_for_compare(resp));
    }

    /// Verdict the response against the current baselines / hints.
    pub fn judge(&self, resp: &HttpResponse) -> Result<OracleVerdict> {
        if let Some(code) = self.cfg.code {
            return Ok(if resp.status == code { OracleVerdict::True } else { OracleVerdict::False });
        }
        if let Some(needle) = &self.cfg.string {
            return Ok(if resp.body.contains(needle) { OracleVerdict::True } else { OracleVerdict::False });
        }
        if let Some(needle) = &self.cfg.not_string {
            return Ok(if !resp.body.contains(needle) { OracleVerdict::True } else { OracleVerdict::False });
        }
        if let Some(re) = &self.cfg.regexp {
            let re = Regex::new(re)?;
            return Ok(if re.is_match(&resp.body) { OracleVerdict::True } else { OracleVerdict::False });
        }
        let text = self.text_for_compare(resp);
        match (&self.baseline_true, &self.baseline_false) {
            (Some(t), _) => {
                let sim = strsim::sorensen_dice(t, &text);
                Ok(verdict_from_ratio(sim, self.cfg.true_ratio, self.cfg.false_ratio))
            }
            (None, Some(f)) => {
                let sim = strsim::sorensen_dice(f, &text);
                // Inverted: high sim to FALSE baseline → FALSE.
                Ok(verdict_from_ratio(1.0 - sim, self.cfg.true_ratio, self.cfg.false_ratio))
            }
            _ => Err(Error::OracleInconclusive("no baseline established".into())),
        }
    }

    fn text_for_compare(&self, resp: &HttpResponse) -> String {
        if self.cfg.titles {
            resp.titles()
        } else if self.cfg.text_only {
            resp.text_only()
        } else {
            resp.body.clone()
        }
    }
}

fn verdict_from_ratio(sim: f64, t_ratio: f64, f_ratio: f64) -> OracleVerdict {
    if sim >= t_ratio {
        OracleVerdict::True
    } else if sim <= f_ratio {
        OracleVerdict::False
    } else {
        OracleVerdict::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_oracle() {
        let cfg = OracleConfig { code: Some(200), ..OracleConfig::standard() };
        let mut o = Oracle::new(cfg);
        let r1 = HttpResponse { status: 200, ..Default::default() };
        let r2 = HttpResponse { status: 500, ..Default::default() };
        assert_eq!(o.judge(&r1).unwrap(), OracleVerdict::True);
        assert_eq!(o.judge(&r2).unwrap(), OracleVerdict::False);
    }
}
