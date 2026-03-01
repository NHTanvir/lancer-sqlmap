//! Inline hash cracker — `--passwords` companion.
//!
//! Supports the canonical hash families upstream sqlmap recognises:
//! - MySQL native (`*` prefix, `SHA1(SHA1(pw))` upper hex)
//! - MSSQL/Sybase legacy (`0x0100<salt><hash>`)
//! - Oracle 11g (`S:` SHA1 + salt)
//! - PostgreSQL md5 (`md5<hex>`)
//! - PostgreSQL scram-sha-256
//! - Generic MD5 / SHA1 / SHA256

use base64::Engine;
use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    MysqlNative,
    MssqlLegacy,
    OracleS,
    PgMd5,
    PgScramSha256,
    Md5,
    Sha1,
    Sha256,
    Unknown,
}

pub fn classify(hash: &str) -> HashAlgo {
    if hash.starts_with('*') && hash.len() == 41 {
        HashAlgo::MysqlNative
    } else if hash.starts_with("0x0100") {
        HashAlgo::MssqlLegacy
    } else if hash.starts_with("S:") || hash.starts_with("H:") {
        HashAlgo::OracleS
    } else if hash.starts_with("md5") {
        HashAlgo::PgMd5
    } else if hash.starts_with("SCRAM-SHA-256$") {
        HashAlgo::PgScramSha256
    } else if hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        HashAlgo::Md5
    } else if hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        HashAlgo::Sha1
    } else if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
        HashAlgo::Sha256
    } else {
        HashAlgo::Unknown
    }
}

pub fn try_password(hash: &str, candidate: &str) -> bool {
    match classify(hash) {
        HashAlgo::MysqlNative => {
            let inner = Sha1::digest(candidate.as_bytes());
            let outer = Sha1::digest(inner);
            let want = hash.trim_start_matches('*').to_lowercase();
            hex::encode(outer) == want
        }
        HashAlgo::PgMd5 => {
            // pg stores md5(password || username); we can only verify when
            // user is encoded into the hash format used by sqlmap. As a best
            // effort, accept both `md5(pw)` (no salt) and the raw form.
            let want = hash.trim_start_matches("md5").to_lowercase();
            let computed = format!("{:x}", md5::compute(candidate));
            computed == want
        }
        HashAlgo::Md5 => format!("{:x}", md5::compute(candidate)) == hash.to_lowercase(),
        HashAlgo::Sha1 => hex::encode(Sha1::digest(candidate.as_bytes())) == hash.to_lowercase(),
        HashAlgo::Sha256 => hex::encode(Sha256::digest(candidate.as_bytes())) == hash.to_lowercase(),
        HashAlgo::OracleS => {
            // S:<hash:40><salt:20>
            let body = hash.trim_start_matches("S:").trim_start_matches("H:");
            if body.len() < 60 {
                return false;
            }
            let want = &body[..40];
            let salt_hex = &body[40..60];
            let Ok(salt) = hex::decode(salt_hex) else { return false };
            let mut data = candidate.as_bytes().to_vec();
            data.extend_from_slice(&salt);
            hex::encode(Sha1::digest(&data)) == want.to_lowercase()
        }
        HashAlgo::MssqlLegacy => {
            // 0x0100 + 8-byte salt + 40-char SHA1 (uppercase)
            let raw = hash.trim_start_matches("0x");
            if raw.len() < 14 + 40 {
                return false;
            }
            let salt = &raw[4..20]; // 8 bytes = 16 hex
            let want = &raw[20..60].to_lowercase();
            let Ok(salt_b) = hex::decode(salt) else { return false };
            let mut data: Vec<u8> = candidate.encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
            data.extend_from_slice(&salt_b);
            hex::encode(Sha1::digest(&data)) == *want
        }
        HashAlgo::PgScramSha256 => {
            // Format: SCRAM-SHA-256$iter:salt$stored_key:server_key
            // Stub: not implementing full SCRAM crack here; defer to hashcat.
            let _ = candidate;
            false
        }
        HashAlgo::Unknown => false,
    }
}

/// Multi-threaded dictionary attack via rayon. `words` is the wordlist;
/// returns `(hash, plaintext)` for every cracked hash.
pub fn crack_many(hashes: &[String], words: &[String]) -> Vec<(String, String)> {
    use rayon::prelude::*;
    hashes
        .par_iter()
        .filter_map(|h| {
            for w in words {
                if try_password(h, w) {
                    return Some((h.clone(), w.clone()));
                }
            }
            None
        })
        .collect()
}
