//! Tamper chain orchestration.

use crate::{lookup, Result, Tamper, TamperError, TamperFamily};

/// Ordered chain of tamper scripts, validated for chain-compat invariants.
pub struct TamperChain {
    items: Vec<Box<dyn Tamper>>,
}

impl TamperChain {
    /// Build a chain from `--tamper=foo,bar,baz`. Resolves each name, sorts by
    /// priority (higher first → earlier in pipeline), and validates safety:
    ///
    /// 1. Any terminal tamper (encoders) must be the very last entry.
    /// 2. Case mutators (`randomcase`/`lowercase`/`uppercase`) must run after
    ///    keyword swappers so the mutator doesn't break inserted keywords.
    pub fn from_names(names: &[&str]) -> Result<Self> {
        let mut items: Vec<Box<dyn Tamper>> = Vec::new();
        for n in names {
            items.push(lookup(n)?);
        }
        items.sort_by_key(|t| std::cmp::Reverse(t.priority()));
        // Terminal-encoder check.
        for (i, t) in items.iter().enumerate() {
            if t.is_terminal() && i + 1 != items.len() {
                return Err(TamperError::TerminalNotLast(t.name().to_string()));
            }
        }
        // Case mutator after keyword swapper check.
        let mut last_keyword: Option<&'static str> = None;
        for t in &items {
            if matches!(t.family(), TamperFamily::KeywordSwapper) {
                last_keyword = Some(t.name());
            }
            if matches!(t.family(), TamperFamily::CaseMutator) {
                if let Some(kw) = last_keyword {
                    return Err(TamperError::CaseBeforeKeyword(
                        t.name().to_string(),
                        kw.to_string(),
                    ));
                }
            }
        }
        Ok(Self { items })
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.items.iter().map(|t| t.name()).collect()
    }

    pub fn apply(&self, payload: &str) -> String {
        let mut s = payload.to_string();
        for t in &self.items {
            s = t.apply(&s);
        }
        s
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
