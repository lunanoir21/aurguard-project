//! VirusTotal integration for committed binaries.
//!
//! aurguard never uploads anything. It works in two modes, both keyed off the
//! SHA-256 hashes that [`crate::srcscan`] computes for prebuilt binaries found
//! in a package tree:
//!
//! - **Offline (always on):** emit an `INFO` finding per binary carrying its
//!   SHA-256 and a `virustotal.com/gui/file/<hash>` link, so a user with no API
//!   key can check it by hand. Nothing leaves the machine.
//! - **API (opt-in):** with a key (config `[virustotal]` or `AURGUARD_VT_KEY`)
//!   and `--vt`/`enabled`, look each hash up via the VirusTotal v3 API. A hash
//!   flagged by engines becomes `VT_FLAGGED` (Critical); a known-clean hash and
//!   an unknown hash become `INFO`. Looking a hash up discloses it to a third
//!   party, which is why this path is never taken implicitly.

use crate::i18n::{self, Lang};
use crate::report::{Finding, Severity};
use crate::srcscan::Binary;

/// GUI URL prefix for a manual, no-API lookup by file hash.
pub const GUI_BASE: &str = "https://www.virustotal.com/gui/file/";
/// v3 API endpoint prefix for a file report by hash.
const API_BASE: &str = "https://www.virustotal.com/api/v3/files/";

/// Build the offline `VT_HINT` findings — SHA-256 + a check-by-hand link for
/// every committed binary that hashed. Sends nothing over the network.
pub fn offline_hints(bins: &[Binary], lang: Lang) -> Vec<Finding> {
    bins.iter()
        .filter_map(|b| {
            let h = b.sha256.as_ref()?;
            let arg = format!("{} → {GUI_BASE}{h}", b.path);
            Some(localized(Severity::Info, "VT_HINT", lang, &arg))
        })
        .collect()
}

/// Aggregated detection stats for one hash.
#[derive(Debug, Clone, Copy, Default)]
pub struct Verdict {
    /// Engines flagging the file as malicious.
    pub malicious: u64,
    /// Engines flagging the file as suspicious.
    pub suspicious: u64,
    /// Total engines that produced a verdict.
    pub total: u64,
    /// Whether VirusTotal had any record of the hash.
    pub found: bool,
}

/// Look one hash up via the VirusTotal v3 API.
pub async fn query(api_key: &str, hash: &str) -> anyhow::Result<Verdict> {
    let resp = reqwest::Client::new()
        .get(format!("{API_BASE}{hash}"))
        .header("x-apikey", api_key)
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Verdict::default());
    }
    let v: serde_json::Value = resp.error_for_status()?.json().await?;
    let stats = &v["data"]["attributes"]["last_analysis_stats"];
    let g = |k: &str| stats[k].as_u64().unwrap_or(0);
    let malicious = g("malicious");
    let suspicious = g("suspicious");
    let total = malicious + suspicious + g("undetected") + g("harmless") + g("timeout");
    Ok(Verdict {
        malicious,
        suspicious,
        total,
        found: true,
    })
}

/// Query every committed binary and turn the verdicts into findings. Network +
/// privacy sensitive — only called when the user opts in. Requests are spaced
/// slightly to stay friendly to the free-tier rate limit.
pub async fn api_findings(api_key: &str, bins: &[Binary], lang: Lang) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, b) in bins.iter().enumerate() {
        let Some(hash) = &b.sha256 else { continue };
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
        let finding = match query(api_key, hash).await {
            Ok(v) if v.found && (v.malicious > 0 || v.suspicious > 0) => {
                let arg = format!(
                    "{}: {}/{} engines",
                    b.path,
                    v.malicious + v.suspicious,
                    v.total
                );
                localized(Severity::Critical, "VT_FLAGGED", lang, &arg)
            }
            Ok(v) if v.found => {
                let arg = format!("{}: 0/{} engines", b.path, v.total);
                localized(Severity::Info, "VT_CLEAN", lang, &arg)
            }
            Ok(_) => localized(Severity::Info, "VT_UNKNOWN", lang, &b.path),
            Err(e) => localized(
                Severity::Info,
                "VT_ERROR",
                lang,
                &format!("{}: {e}", b.path),
            ),
        };
        out.push(finding);
    }
    out
}

/// Build a localized finding for a VT result code carrying `arg`.
fn localized(severity: Severity, code: &'static str, lang: Lang, arg: &str) -> Finding {
    let tpl = i18n::finding(lang, code).unwrap_or("{}");
    Finding::meta(severity, code, i18n::fill(tpl, Some(arg))).with_arg(arg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bin(path: &str, hash: Option<&str>) -> Binary {
        Binary {
            path: path.into(),
            kind: "ELF",
            sha256: hash.map(|h| h.into()),
        }
    }

    #[test]
    fn offline_hint_carries_hash_and_link() {
        let bins = vec![bin("payload", Some("abc123"))];
        let f = offline_hints(&bins, Lang::En);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].code, "VT_HINT");
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].message.contains("abc123"));
        assert!(f[0].message.contains(GUI_BASE));
    }

    #[test]
    fn offline_hint_skips_unhashed() {
        let bins = vec![bin("big", None)];
        assert!(offline_hints(&bins, Lang::En).is_empty());
    }
}
