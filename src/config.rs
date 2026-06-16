//! User configuration: extra trusted domains, suppressed rule codes, and the
//! default install policy.
//!
//! Loaded from `$XDG_CONFIG_HOME/aurguard/config.toml` (falling back to
//! `~/.config/aurguard/config.toml`). A missing file yields [`Config::default`]
//! — configuration is entirely optional.
//!
//! Example `config.toml`:
//!
//! ```toml
//! [trust]
//! extra_domains = ["git.mycompany.com", "downloads.example.org"]
//!
//! [rules]
//! ignore = ["VCS_SOURCE"]          # finding codes to suppress globally
//!
//! [policy]
//! fail_on = "critical"             # clean | risky | critical
//! ```

use crate::i18n::Lang;
use crate::report::Risk;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;

/// Fully-resolved configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Interface settings (language, color).
    pub ui: Ui,
    /// Trust-related settings.
    pub trust: Trust,
    /// Rule suppression.
    pub rules: Rules,
    /// Install policy / CI gating.
    pub policy: Policy,
    /// VirusTotal integration.
    pub virustotal: VirusTotal,
}

/// `[virustotal]` section.
///
/// Looking a hash up on VirusTotal sends it to a third party, so the API lookup
/// is strictly opt-in (`enabled = true` here, or `--vt` on the command line).
/// The offline hash hint — printing the SHA-256 plus a VT link to check by hand
/// — needs no key and sends nothing.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct VirusTotal {
    /// VirusTotal API key. The `AURGUARD_VT_KEY` environment variable overrides
    /// it. Without a key, only the offline hint is shown.
    pub api_key: Option<String>,
    /// Query the VirusTotal API automatically when committed binaries are found.
    pub enabled: bool,
}

impl VirusTotal {
    /// Resolve the effective API key: `AURGUARD_VT_KEY` env wins, else config.
    pub fn key(&self) -> Option<String> {
        std::env::var("AURGUARD_VT_KEY")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or_else(|| self.api_key.clone().filter(|s| !s.trim().is_empty()))
    }
}

/// `[ui]` section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Ui {
    /// Interface language.
    pub lang: Lang,
    /// Force color on/off; `None` means auto-detect from the terminal.
    pub color: Option<bool>,
}

/// `[trust]` section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Trust {
    /// Additional host suffixes treated as trusted, beyond the built-in
    /// allowlist. Matched the same way (exact host or `.suffix`).
    pub extra_domains: Vec<String>,
}

/// `[rules]` section.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Rules {
    /// Finding codes (e.g. `"VCS_SOURCE"`) to drop from every report.
    pub ignore: Vec<String>,
}

/// `[policy]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Lowest risk that should block a non-interactive install. Parsed from
    /// `"clean" | "risky" | "critical"`; defaults to `critical`.
    pub fail_on: FailOn,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            fail_on: FailOn::Critical,
        }
    }
}

/// Severity threshold for `--skip-confirm` / CI gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    /// Block on any finding at all.
    Clean,
    /// Block on `Risky` or `Critical`.
    Risky,
    /// Block only on `Critical` (default).
    Critical,
}

impl FailOn {
    /// Whether a package at `risk` should be blocked under this threshold.
    pub fn blocks(self, risk: Risk) -> bool {
        match self {
            FailOn::Clean => risk != Risk::Clean,
            FailOn::Risky => matches!(risk, Risk::Risky | Risk::Critical),
            FailOn::Critical => risk == Risk::Critical,
        }
    }
}

impl std::str::FromStr for FailOn {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "clean" => Ok(FailOn::Clean),
            "risky" | "warn" => Ok(FailOn::Risky),
            "critical" => Ok(FailOn::Critical),
            other => anyhow::bail!("invalid fail-on value '{other}' (clean|risky|critical)"),
        }
    }
}

impl Config {
    /// Default config-file path under the user's config dir.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("aurguard").join("config.toml"))
    }

    /// Load configuration from the default path, returning defaults if the file
    /// does not exist. Returns an error only on a malformed file.
    pub fn load() -> Result<Self> {
        match Self::default_path() {
            Some(p) => Self::load_from(&p),
            None => Ok(Self::default()),
        }
    }

    /// Load configuration from a specific path (defaults if absent).
    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s)
                .with_context(|| format!("failed to parse config {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read config {}", path.display())),
        }
    }

    /// Whether `code` is suppressed by `[rules].ignore`.
    pub fn ignores(&self, code: &str) -> bool {
        self.rules
            .ignore
            .iter()
            .any(|c| c.eq_ignore_ascii_case(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let toml = r#"
            [trust]
            extra_domains = ["git.acme.com"]
            [rules]
            ignore = ["VCS_SOURCE", "STALE"]
            [policy]
            fail_on = "risky"
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.trust.extra_domains, vec!["git.acme.com"]);
        assert!(cfg.ignores("vcs_source"));
        assert!(cfg.ignores("STALE"));
        assert!(!cfg.ignores("EVAL"));
        assert_eq!(cfg.policy.fail_on, FailOn::Risky);
    }

    #[test]
    fn empty_config_is_default() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.policy.fail_on, FailOn::Critical);
        assert!(cfg.trust.extra_domains.is_empty());
    }

    #[test]
    fn failon_blocks_matrix() {
        assert!(FailOn::Clean.blocks(Risk::Risky));
        assert!(!FailOn::Clean.blocks(Risk::Clean));
        assert!(FailOn::Risky.blocks(Risk::Critical));
        assert!(!FailOn::Risky.blocks(Risk::Clean));
        assert!(FailOn::Critical.blocks(Risk::Critical));
        assert!(!FailOn::Critical.blocks(Risk::Risky));
    }

    #[test]
    fn failon_from_str() {
        assert_eq!("critical".parse::<FailOn>().unwrap(), FailOn::Critical);
        assert_eq!("warn".parse::<FailOn>().unwrap(), FailOn::Risky);
        assert!("bogus".parse::<FailOn>().is_err());
    }

    #[test]
    fn virustotal_section_parses() {
        let toml = r#"
            [virustotal]
            api_key = "deadbeef"
            enabled = true
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.virustotal.enabled);
        // No env override set here, so the config key is used.
        assert_eq!(cfg.virustotal.key().as_deref(), Some("deadbeef"));
    }

    #[test]
    fn virustotal_key_defaults_none() {
        let cfg = Config::default();
        assert!(!cfg.virustotal.enabled);
        // Guard against a stray env var in the test environment.
        if std::env::var_os("AURGUARD_VT_KEY").is_none() {
            assert!(cfg.virustotal.key().is_none());
        }
    }
}
