//! Core security-report types: findings, severities, and the aggregated
//! [`Report`] that ties package metadata to the result of static analysis.
//!
//! These types are the shared vocabulary between the analyzer
//! ([`crate::pkgbuild`]) and the renderers ([`crate::ui`]). They are all
//! `serde`-serializable so `--json` is a near-free projection of the same data
//! the human panel is built from.

use serde::Serialize;
use std::fmt;

/// How serious a single [`Finding`] is.
///
/// Ordering matters: `Info < Warn < Critical`. The overall package [`Risk`] is
/// derived from the maximum severity across all findings, so the derived
/// `Ord`/`PartialOrd` on this enum is load-bearing — keep the variants in
/// ascending order of seriousness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Context worth knowing, not a concern on its own.
    Info,
    /// Worth a human review before installing.
    Warn,
    /// Blocked by default; install only on explicit override.
    Critical,
}

impl Severity {
    /// Fixed-width label used in the report panel (`"INFO"`, `"WARN"`,
    /// `"CRITICAL"`).
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Leading glyph for the finding line (`ℹ`, `⚠`, `✖`).
    pub fn glyph(self) -> &'static str {
        match self {
            Severity::Info => "ℹ",
            Severity::Warn => "⚠",
            Severity::Critical => "✖",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The overall risk class of a package, derived from its findings.
///
/// Drives the confirmation prompt wording and the process exit code in
/// report-only (`-I`) mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Risk {
    /// No findings at or above `Warn`.
    Clean,
    /// At least one `Warn`, no `Critical`.
    Risky,
    /// At least one `Critical` finding.
    Critical,
}

impl Risk {
    /// Map this risk to a process exit code for `-I` mode:
    /// `Clean = 0`, `Risky = 10`, `Critical = 20`.
    pub fn exit_code(self) -> i32 {
        match self {
            Risk::Clean => 0,
            Risk::Risky => 10,
            Risk::Critical => 20,
        }
    }
}

/// A single result from static analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Severity bucket.
    pub severity: Severity,
    /// Stable machine code, e.g. `"CURL_PIPE_SH"`. Useful for `--json`
    /// consumers and for suppressing specific rules in future versions.
    pub code: &'static str,
    /// Human-readable, single-line description (localized when a language is
    /// configured; English otherwise).
    pub message: String,
    /// 1-based line in the PKGBUILD the finding refers to, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// The dynamic detail of the finding (host, count, path…), kept separate so
    /// it can be slotted into a localized template. Not serialized.
    #[serde(skip)]
    pub arg: Option<String>,
}

impl Finding {
    /// Build a finding with a source line.
    pub fn at(
        severity: Severity,
        code: &'static str,
        message: impl Into<String>,
        line: usize,
    ) -> Self {
        Finding {
            severity,
            code,
            message: message.into(),
            line: Some(line),
            arg: None,
        }
    }

    /// Build a finding with no associated line (metadata-derived signals).
    pub fn meta(severity: Severity, code: &'static str, message: impl Into<String>) -> Self {
        Finding {
            severity,
            code,
            message: message.into(),
            line: None,
            arg: None,
        }
    }

    /// Attach the dynamic detail used to fill a localized template.
    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.arg = Some(arg.into());
        self
    }
}

/// A classified source host extracted from a PKGBUILD `source=()` array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceHost {
    /// Bare host, e.g. `github.com`.
    pub host: String,
    /// Whether the host is on the trusted allowlist.
    pub trusted: bool,
}

/// The full security report for one package: metadata + classified sources +
/// findings, plus the derived overall [`Risk`].
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Package name.
    pub package: String,
    /// `pkgver-pkgrel`, e.g. `126.0-1`.
    pub version: String,
    /// Maintainer username, or `None` if orphaned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maintainer: Option<String>,
    /// First-submitted timestamp (RFC3339), used to estimate account age.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maintainer_since: Option<String>,
    /// Community vote count.
    pub votes: u64,
    /// Last-modified timestamp (RFC3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// Human phrase for the last update, e.g. `"2 days ago"`.
    pub last_update_human: String,
    /// Human phrase for maintainer tenure, e.g. `"since 2009"`.
    pub maintainer_since_human: String,
    /// Overall risk class.
    pub risk: Risk,
    /// Classified source hosts.
    pub sources: Vec<SourceHost>,
    /// All findings, sorted most-severe first.
    pub findings: Vec<Finding>,
}

impl Report {
    /// Recompute [`Risk`] from the current findings and sort findings
    /// most-severe-first (stable within a severity). Call after all findings
    /// are pushed.
    pub fn finalize(&mut self) {
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        self.risk = self
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .map_or(Risk::Clean, |max| match max {
                Severity::Critical => Risk::Critical,
                Severity::Warn => Risk::Risky,
                Severity::Info => Risk::Clean,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_with(findings: Vec<Finding>) -> Report {
        let mut r = Report {
            package: "x".into(),
            version: "1-1".into(),
            maintainer: None,
            maintainer_since: None,
            votes: 0,
            last_modified: None,
            last_update_human: "now".into(),
            maintainer_since_human: "unknown".into(),
            risk: Risk::Clean,
            sources: vec![],
            findings,
        };
        r.finalize();
        r
    }

    #[test]
    fn severity_orders_ascending() {
        assert!(Severity::Info < Severity::Warn);
        assert!(Severity::Warn < Severity::Critical);
    }

    #[test]
    fn risk_clean_when_empty() {
        assert_eq!(report_with(vec![]).risk, Risk::Clean);
    }

    #[test]
    fn risk_clean_with_only_info() {
        let r = report_with(vec![Finding::meta(Severity::Info, "I", "info")]);
        assert_eq!(r.risk, Risk::Clean);
    }

    #[test]
    fn risk_risky_with_warn() {
        let r = report_with(vec![Finding::meta(Severity::Warn, "W", "warn")]);
        assert_eq!(r.risk, Risk::Risky);
    }

    #[test]
    fn risk_critical_dominates_and_sorts_first() {
        let r = report_with(vec![
            Finding::meta(Severity::Warn, "W", "warn"),
            Finding::at(Severity::Critical, "C", "crit", 14),
            Finding::meta(Severity::Info, "I", "info"),
        ]);
        assert_eq!(r.risk, Risk::Critical);
        assert_eq!(r.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn exit_codes() {
        assert_eq!(Risk::Clean.exit_code(), 0);
        assert_eq!(Risk::Risky.exit_code(), 10);
        assert_eq!(Risk::Critical.exit_code(), 20);
    }
}
