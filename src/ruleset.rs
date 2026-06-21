//! T2.1 — external, updatable signature ruleset (`docs/SECURITY-ROADMAP.md`).
//!
//! The built-in database in [`crate::rules`] ships compiled into the binary —
//! shipping a new signature means a new release. This module layers
//! additional signatures on top without recompiling: every `*.toml` file
//! under `$XDG_CONFIG_HOME/aurguard/rules.d/` is loaded at startup and merged
//! with the built-ins by `code` — a rule here with the same `code` as a
//! built-in **overrides** it (the built-in is skipped for that code), and a
//! new `code` is simply added. Each match is reported under the stable
//! `CUSTOM_RULE` code (same bucket as `[signatures.custom]` in
//! `config.toml`), since the rule's own `code` is data, not a `'static`
//! string the [`crate::report::Finding`] type can borrow.
//!
//! `aurguard --update-rules` fetches the TOML file named by `[ruleset]
//! rules_url` in `config.toml` over HTTPS, parses and validates it *before*
//! touching disk, and refuses to install a `version` that is not strictly
//! greater than the one already on disk (no silent downgrade).
//!
//! File format:
//!
//! ```toml
//! version = 3
//! [[rule]]
//! code      = "CRYPTO_MINER"
//! severity  = "critical"          # critical | warn | info
//! tags      = ["miner"]
//! message   = "Cryptocurrency miner signature"
//! clauses   = [["xmrig", "stratum+tcp"], ["-o", "--url"]]   # CNF: AND of ORs
//! not       = ["$pkgdir"]
//! ```

use crate::report::{Finding, Severity};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Default source for `--update-rules`: the project's own community ruleset,
/// pinned to a single trusted host (raw GitHub content on `main`).
pub const DEFAULT_RULES_URL: &str =
    "https://raw.githubusercontent.com/lunanoir21/aurguard-project/main/rules.d/community.toml";

/// One signature rule loaded from TOML — the dynamic counterpart of
/// [`crate::rules::SigRule`].
#[derive(Debug, Clone, Deserialize)]
pub struct UserRule {
    /// The code this rule represents (shown in the finding message, and
    /// matched against built-in codes for the override rule).
    pub code: String,
    #[serde(default)]
    severity: Option<String>,
    /// Free-form classification tags (not currently rendered, kept for parity
    /// with `SigRule` and future filtering).
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    message: Option<String>,
    /// CNF condition: every inner list is a clause (OR of alternatives); all
    /// clauses must match for the rule to fire.
    #[serde(default)]
    clauses: Vec<Vec<String>>,
    /// Any of these substrings present vetoes the match.
    #[serde(default)]
    not: Vec<String>,
}

impl UserRule {
    fn severity(&self) -> Severity {
        match self
            .severity
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("critical") => Severity::Critical,
            Some("info") => Severity::Info,
            _ => Severity::Warn,
        }
    }

    fn message(&self) -> &str {
        match &self.message {
            Some(m) if !m.is_empty() => m,
            _ => &self.code,
        }
    }

    /// Evaluate against one lower-cased line, returning the salient match.
    fn evaluate(&self, lower: &str) -> Option<String> {
        if self.not.iter().any(|n| lower.contains(n.as_str())) {
            return None;
        }
        let mut salient: Option<String> = None;
        for clause in &self.clauses {
            let hit = clause.iter().find(|alt| lower.contains(alt.as_str()))?;
            if salient.is_none() {
                salient = Some(hit.clone());
            }
        }
        salient
    }

    /// Reject a rule too malformed to be evaluated safely — an empty `code`,
    /// no clauses (would never match, but also never warn the user why), or a
    /// clause with no alternatives.
    fn validate(&self) -> Result<()> {
        if self.code.trim().is_empty() {
            bail!("rule has an empty code");
        }
        if self.clauses.is_empty() {
            bail!("rule '{}' has no clauses (would never match)", self.code);
        }
        if self.clauses.iter().any(|c| c.is_empty()) {
            bail!("rule '{}' has an empty clause", self.code);
        }
        Ok(())
    }
}

/// One `rules.d/*.toml` file: a `version` plus the rules it carries.
#[derive(Debug, Clone, Default, Deserialize)]
struct RuleFile {
    #[serde(default)]
    version: u32,
    #[serde(default, rename = "rule")]
    rules: Vec<UserRule>,
}

impl RuleFile {
    fn parse(text: &str) -> Result<Self> {
        let file: RuleFile = toml::from_str(text).context("invalid TOML")?;
        for r in &file.rules {
            r.validate()?;
        }
        Ok(file)
    }
}

/// The merged, loaded ruleset: every rule from every file under `rules.d/`,
/// plus the set of `code`s they override (fed to
/// [`crate::rules::scan_line_except`] so the built-in pass skips them).
#[derive(Debug, Clone, Default)]
pub struct Ruleset {
    rules: Vec<UserRule>,
    /// Built-in codes a loaded rule re-defines.
    pub overridden: HashSet<String>,
}

impl Ruleset {
    /// Default directory: `$XDG_CONFIG_HOME/aurguard/rules.d/` (next to
    /// `config.toml`).
    pub fn default_dir() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("aurguard").join("rules.d"))
    }

    /// Load every `*.toml` file in `dir`. A missing directory yields an empty
    /// ruleset; a file that fails to parse or validate is skipped with a
    /// warning on stderr rather than aborting the whole run — one bad file
    /// should not take every signature down with it.
    pub fn load_dir(dir: &Path) -> Self {
        let mut rules = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Ruleset::default();
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
            .collect();
        paths.sort();
        for path in paths {
            match std::fs::read_to_string(&path)
                .map_err(anyhow::Error::from)
                .and_then(|s| RuleFile::parse(&s))
            {
                Ok(file) => rules.extend(file.rules),
                Err(e) => eprintln!("  \u{26a0}  {}: {e:#}", path.display()),
            }
        }
        let overridden = rules.iter().map(|r| r.code.clone()).collect();
        Ruleset { rules, overridden }
    }

    /// Run every loaded rule over one (comment-stripped, lower-cased) line.
    /// Always reports under `CUSTOM_RULE` (see module docs) with the rule's
    /// own `code` folded into the message and `arg`.
    pub fn scan_line(&self, lower: &str, lineno: usize, findings: &mut Vec<Finding>) {
        for r in &self.rules {
            if let Some(token) = r.evaluate(lower) {
                findings.push(
                    Finding::at(
                        r.severity(),
                        "CUSTOM_RULE",
                        format!("{}: {} ({token})", r.code, r.message()),
                        lineno,
                    )
                    .with_arg(format!("{}:{token}", r.code)),
                );
            }
        }
    }

    /// Fetch `url` over HTTPS, parse-and-validate the body, and only then
    /// install it as `<rules_dir>/community.toml`. Refuses a non-HTTPS URL
    /// and refuses to overwrite an installed file with one at an equal or
    /// lower `version`. Returns `(old_version, new_version)`; `old_version`
    /// is `0` for a first-time install.
    pub async fn update(url: &str, rules_dir: &Path) -> Result<(u32, u32)> {
        if !url.starts_with("https://") {
            bail!("refusing a non-HTTPS ruleset URL: {url}");
        }
        let body = reqwest::get(url)
            .await
            .with_context(|| format!("fetching {url}"))?
            .error_for_status()
            .with_context(|| format!("fetching {url}"))?
            .text()
            .await
            .context("reading ruleset response body")?;
        let file = RuleFile::parse(&body).context("the fetched ruleset failed validation")?;

        std::fs::create_dir_all(rules_dir)
            .with_context(|| format!("creating {}", rules_dir.display()))?;
        let dest = rules_dir.join("community.toml");
        let old_version = std::fs::read_to_string(&dest)
            .ok()
            .and_then(|s| RuleFile::parse(&s).ok())
            .map(|f| f.version)
            .unwrap_or(0);
        if old_version > 0 && file.version <= old_version {
            bail!(
                "fetched ruleset version {} is not newer than the installed version {old_version} — refusing to downgrade",
                file.version
            );
        }
        std::fs::write(&dest, &body).with_context(|| format!("writing {}", dest.display()))?;
        Ok((old_version, file.version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aurguard-ruleset-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parses_and_matches_cnf() {
        let toml = r#"
            version = 1
            [[rule]]
            code = "TEST_WEBHOOK"
            severity = "critical"
            message = "test webhook exfil"
            clauses = [["webhook.site"], ["curl", "wget"]]
        "#;
        let file = RuleFile::parse(toml).unwrap();
        assert_eq!(file.rules.len(), 1);
        let mut findings = Vec::new();
        let rs = Ruleset {
            rules: file.rules,
            overridden: HashSet::new(),
        };
        rs.scan_line("curl https://webhook.site/abc", 5, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "CUSTOM_RULE");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("TEST_WEBHOOK"));
    }

    #[test]
    fn not_vetoes_match() {
        let toml = r#"
            version = 1
            [[rule]]
            code = "TEST_RULE"
            clauses = [["danger"]]
            not = ["$pkgdir"]
        "#;
        let file = RuleFile::parse(toml).unwrap();
        let rs = Ruleset {
            rules: file.rules,
            overridden: HashSet::new(),
        };
        let mut findings = Vec::new();
        rs.scan_line("echo danger > $pkgdir/out", 1, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn rejects_empty_clauses() {
        let toml = r#"
            version = 1
            [[rule]]
            code = "BAD"
            clauses = []
        "#;
        assert!(RuleFile::parse(toml).is_err());
    }

    #[test]
    fn rejects_empty_code() {
        let toml = r#"
            version = 1
            [[rule]]
            code = ""
            clauses = [["x"]]
        "#;
        assert!(RuleFile::parse(toml).is_err());
    }

    #[test]
    fn load_dir_merges_files_and_skips_bad_ones() {
        let d = tmpdir();
        std::fs::write(
            d.join("a.toml"),
            r#"
                version = 1
                [[rule]]
                code = "FROM_A"
                clauses = [["aaa"]]
            "#,
        )
        .unwrap();
        std::fs::write(d.join("b.toml"), "not valid toml {{{").unwrap();
        std::fs::write(d.join("ignored.txt"), "code = 1").unwrap();
        let rs = Ruleset::load_dir(&d);
        assert_eq!(rs.rules.len(), 1);
        assert!(rs.overridden.contains("FROM_A"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn load_dir_missing_is_empty() {
        let rs = Ruleset::load_dir(Path::new("/nonexistent/aurguard-rules-d-test"));
        assert!(rs.rules.is_empty());
        assert!(rs.overridden.is_empty());
    }
}
