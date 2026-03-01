//! Random-token helpers + URL/body encoding utilities used by the payload
//! templating engine and the boundary walker.

use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::Rng;
use regex::Regex;

/// Generate an N-digit random integer fitting in u32.
pub fn rand_num(digits: usize) -> u64 {
    let mut rng = rand::thread_rng();
    let mut n: u64 = 0;
    for i in 0..digits.max(1) {
        let d = rng.gen_range(if i == 0 { 1..10 } else { 0..10 });
        n = n * 10 + d as u64;
    }
    n
}

/// Random ASCII string used for [RANDSTR] payload tokens.
pub fn rand_str(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

/// Expand the placeholder tokens upstream sqlmap uses inside payload
/// templates: `[RANDNUM]`, `[RANDNUM1..9]`, `[RANDSTR]`, `[DELIMITER]`,
/// `[SLEEPTIME]`, `[INFERENCE]`, `[ORIGVALUE]`, `[COL]`, `[GENERIC_SQL_COMMENT]`.
pub fn expand_placeholders(template: &str, ctx: &PlaceholderCtx<'_>) -> String {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\[([A-Z_0-9]+)\]").unwrap());
    let mut out = template.to_string();
    // Run a few passes — RANDNUM expansions can introduce new ones.
    for _ in 0..3 {
        let mut replaced = false;
        out = RE
            .replace_all(&out, |caps: &regex::Captures<'_>| {
                let name = &caps[1];
                replaced = true;
                match name {
                    "RANDNUM" => rand_num(6).to_string(),
                    "RANDNUM1" => rand_num(1).to_string(),
                    "RANDNUM2" => rand_num(2).to_string(),
                    "RANDNUM3" => rand_num(3).to_string(),
                    "RANDNUM4" => rand_num(4).to_string(),
                    "RANDNUM5" => rand_num(5).to_string(),
                    "RANDNUM6" => rand_num(6).to_string(),
                    "RANDNUM7" => rand_num(7).to_string(),
                    "RANDNUM8" => rand_num(8).to_string(),
                    "RANDNUM9" => rand_num(9).to_string(),
                    "RANDSTR" => rand_str(8),
                    "DELIMITER" => ctx.delimiter.to_string(),
                    "SLEEPTIME" => ctx.sleep_time.to_string(),
                    "INFERENCE" => ctx.inference.to_string(),
                    "ORIGVALUE" => ctx.orig_value.to_string(),
                    "COL" => ctx.col.to_string(),
                    "GENERIC_SQL_COMMENT" => "-- -".to_string(),
                    "SPACE" => " ".to_string(),
                    other => format!("[{other}]"),
                }
            })
            .into_owned();
        if !replaced {
            break;
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct PlaceholderCtx<'a> {
    pub delimiter: &'a str,
    pub sleep_time: u32,
    pub inference: &'a str,
    pub orig_value: &'a str,
    pub col: &'a str,
}

impl<'a> Default for PlaceholderCtx<'a> {
    fn default() -> Self {
        Self {
            delimiter: "DELIM",
            sleep_time: 5,
            inference: "1=1",
            orig_value: "",
            col: "1",
        }
    }
}

/// URL-encode a value the same way upstream does (`+` for space in body,
/// `%20` in path).
pub fn urlenc_body(v: &str) -> String {
    urlencoding::encode(v).replace("%20", "+")
}

pub fn urlenc_path(v: &str) -> String {
    urlencoding::encode(v).into_owned()
}

/// Hex-encode a payload as `0xDEADBEEF` (MySQL/MSSQL friendly).
pub fn hex_payload(s: &str) -> String {
    format!("0x{}", hex::encode(s.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_expand() {
        let s = expand_placeholders(
            "AND [RANDNUM]=[RANDNUM2]",
            &PlaceholderCtx::default(),
        );
        assert!(s.starts_with("AND "));
        assert!(s.contains("="));
    }

    #[test]
    fn sleeptime_token() {
        let s = expand_placeholders("SELECT sleep([SLEEPTIME])", &PlaceholderCtx { sleep_time: 7, ..Default::default() });
        assert_eq!(s, "SELECT sleep(7)");
    }
}
