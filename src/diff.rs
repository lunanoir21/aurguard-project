//! Approved-PKGBUILD tracking.
//!
//! When a user approves and installs a package, aurguard records the SHA-256 of
//! the exact `PKGBUILD` (plus any `.install` scripts) it analyzed. On a later
//! run, if the package was approved before but the content now differs, a
//! `PKGBUILD_CHANGED` finding is raised — surfacing silent upstream edits even
//! when no individual rule fires.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One approval record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// SHA-256 (hex) of the canonical analyzed content.
    pub digest: String,
    /// RFC3339 timestamp of the approval.
    pub approved_at: String,
}

/// The on-disk approvals store, keyed by package name.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Approvals {
    #[serde(default)]
    packages: BTreeMap<String, Approval>,
}

/// Compute the canonical digest for a package's analyzed content.
///
/// Hashes the `PKGBUILD` followed by each `.install` script (name + body) in a
/// fixed order so the digest is stable across runs.
pub fn digest(pkgbuild: &str, install_scripts: &[(String, String)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"PKGBUILD\0");
    hasher.update(pkgbuild.as_bytes());
    let mut scripts: Vec<&(String, String)> = install_scripts.iter().collect();
    scripts.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, body) in scripts {
        hasher.update(b"\0INSTALL\0");
        hasher.update(name.as_bytes());
        hasher.update(b"\0");
        hasher.update(body.as_bytes());
    }
    let bytes = hasher.finalize();
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

impl Approvals {
    /// Path of the approvals file under the user's data dir.
    fn path() -> Result<PathBuf> {
        let base = dirs::data_dir()
            .or_else(dirs::home_dir)
            .context("could not determine a data directory")?;
        Ok(base.join("aurguard").join("approvals.json"))
    }

    /// Load the store, or an empty one if it does not exist yet.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(serde_json::from_str(&s).unwrap_or_default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).context("failed to read approvals store"),
        }
    }

    /// Previously-approved digest for `package`, if any.
    pub fn approved_digest(&self, package: &str) -> Option<&str> {
        self.packages.get(package).map(|a| a.digest.as_str())
    }

    /// Record (or update) an approval for `package` with `digest` and persist.
    pub fn approve(&mut self, package: &str, digest: String) -> Result<()> {
        self.packages.insert(
            package.to_string(),
            Approval {
                digest,
                approved_at: chrono::Utc::now().to_rfc3339(),
            },
        );
        self.save()
    }

    /// Persist the store to disk.
    fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, json).context("failed to write approvals store")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let a = digest("pkgver=1", &[]);
        let b = digest("pkgver=1", &[]);
        let c = digest("pkgver=2", &[]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn digest_includes_install_scripts() {
        let base = digest("x", &[]);
        let with = digest(
            "x",
            &[("foo.install".into(), "post_install(){ :; }".into())],
        );
        assert_ne!(base, with);
    }

    #[test]
    fn install_script_order_independent() {
        let s1 = vec![
            ("a.install".to_string(), "1".to_string()),
            ("b.install".into(), "2".into()),
        ];
        let s2 = vec![
            ("b.install".to_string(), "2".to_string()),
            ("a.install".into(), "1".into()),
        ];
        assert_eq!(digest("p", &s1), digest("p", &s2));
    }
}
