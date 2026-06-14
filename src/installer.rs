//! The install path: dependency preflight, **clone-first** analysis, build via
//! `makepkg`, temp cleanup, and a local ledger for `-Q`.
//!
//! ## Why clone-first
//!
//! Earlier designs fetched the `PKGBUILD` from cgit for analysis but then
//! `git clone`d the repo separately to build — two reads that can disagree
//! (a race, or a different ref), letting a benign-looking analysis front a
//! malicious build (a TOCTOU bypass). [`ClonedRepo`] closes that gap: it clones
//! once, analysis reads the working tree, and `makepkg` builds that exact tree.
//!
//! aurguard performs **no sandboxing**. On confirmation, `makepkg` runs the
//! PKGBUILD with the invoking user's privileges, exactly as a manual build
//! would.

use crate::pkgbuild::{referenced_install_files, PkgSources};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::process::Command;

/// External commands aurguard shells out to.
const REQUIRED_BINARIES: &[&str] = &["git", "makepkg"];

/// Verify required external tools are on `PATH`.
pub fn preflight() -> Result<()> {
    for bin in REQUIRED_BINARIES {
        if which(bin).is_none() {
            bail!("aurguard requires '{bin}'. Are you running Arch Linux?");
        }
    }
    Ok(())
}

/// Resolve a binary on `PATH`.
fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|p| p.is_file())
}

/// A freshly-cloned AUR repository in a temp dir. The clone is removed when the
/// value is dropped, so analysis and build operate on one consistent tree.
pub struct ClonedRepo {
    dir: PathBuf,
}

impl ClonedRepo {
    /// `git clone --depth=1 https://aur.archlinux.org/<pkg>.git` into a fresh
    /// temp dir.
    pub async fn clone(package: &str) -> Result<Self> {
        let dir = make_tempdir(package)?;
        let repo = ClonedRepo { dir };
        let url = format!("https://aur.archlinux.org/{package}.git");
        let status = Command::new("git")
            .arg("clone")
            .arg("--depth=1")
            .arg(&url)
            .arg(&repo.dir)
            .stdin(Stdio::null())
            .status()
            .await
            .context("failed to spawn git")?;
        if !status.success() {
            bail!("git clone failed for '{package}' (does the package exist?)");
        }
        Ok(repo)
    }

    /// Path of the working tree.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Read the analyzable sources (`PKGBUILD` + referenced `.install` scripts)
    /// from the cloned tree.
    pub fn read_sources(&self) -> Result<PkgSources> {
        let pkgbuild_path = self.dir.join("PKGBUILD");
        let pkgbuild = std::fs::read_to_string(&pkgbuild_path)
            .with_context(|| format!("no PKGBUILD in cloned repo {}", self.dir.display()))?;
        let mut install_scripts = Vec::new();
        for name in referenced_install_files(&pkgbuild) {
            // Guard against path traversal in the referenced filename.
            let safe = Path::new(&name)
                .file_name()
                .map(|f| f.to_string_lossy().to_string());
            if let Some(fname) = safe {
                let p = self.dir.join(&fname);
                if let Ok(body) = std::fs::read_to_string(&p) {
                    install_scripts.push((fname, body));
                }
            }
        }
        Ok(PkgSources {
            pkgbuild,
            install_scripts,
        })
    }

    /// Run `makepkg -si` in the cloned tree, inheriting stdio so the user can
    /// answer pacman's sudo prompt and watch the build.
    pub async fn build(&self) -> Result<()> {
        let status = Command::new("makepkg")
            .arg("-si")
            .current_dir(&self.dir)
            .status()
            .await
            .context("failed to spawn makepkg")?;
        if !status.success() {
            bail!("makepkg exited with status {}", status.code().unwrap_or(-1));
        }
        Ok(())
    }
}

impl Drop for ClonedRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Create `/tmp/aurguard-<pkg>-<timestamp>` and return its path.
fn make_tempdir(package: &str) -> Result<PathBuf> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let safe: String = package
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = std::env::temp_dir().join(format!("aurguard-{safe}-{ts}"));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create temp dir {}", dir.display()))?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Local ledger (for `-Q`)
// ---------------------------------------------------------------------------

/// One ledger entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Package name.
    pub package: String,
    /// RFC3339 install timestamp.
    pub installed_at: String,
}

/// Path of the ledger file under the user's data dir.
fn ledger_path() -> Result<PathBuf> {
    let base = dirs::data_dir()
        .or_else(dirs::home_dir)
        .context("could not determine a data directory")?;
    Ok(base.join("aurguard").join("installed.json"))
}

/// Append `package` to the ledger (deduplicated, newest timestamp wins).
pub fn record_installed(package: &str) -> Result<()> {
    let path = ledger_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let mut entries = read_ledger().unwrap_or_default();
    entries.retain(|e| e.package != package);
    entries.push(LedgerEntry {
        package: package.to_string(),
        installed_at: chrono::Utc::now().to_rfc3339(),
    });
    let json = serde_json::to_string_pretty(&entries)?;
    std::fs::write(&path, json)
        .with_context(|| format!("failed to write ledger {}", path.display()))?;
    Ok(())
}

/// Read all ledger entries, or an empty list if the ledger does not yet exist.
pub fn read_ledger() -> Result<Vec<LedgerEntry>> {
    let path = ledger_path()?;
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(serde_json::from_str(&s).unwrap_or_default()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).context("failed to read ledger"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_finds_sh() {
        assert!(which("sh").is_some() || which("env").is_some());
    }

    #[test]
    fn which_missing_is_none() {
        assert!(which("definitely-not-a-real-binary-xyz123").is_none());
    }

    #[test]
    fn tempdir_name_is_sanitized() {
        let dir = make_tempdir("evil/../name").unwrap();
        let name = dir.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("aurguard-evil____name-"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_sources_from_dir() {
        let dir = make_tempdir("test-read").unwrap();
        std::fs::write(dir.join("PKGBUILD"), "pkgname=x\ninstall=x.install\n").unwrap();
        std::fs::write(dir.join("x.install"), "post_install() { :; }").unwrap();
        let repo = ClonedRepo { dir };
        let sources = repo.read_sources().unwrap();
        assert!(sources.pkgbuild.contains("pkgname=x"));
        assert_eq!(sources.install_scripts.len(), 1);
        assert_eq!(sources.install_scripts[0].0, "x.install");
    }
}
