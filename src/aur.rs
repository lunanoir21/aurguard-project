//! AUR RPC (v5) client and raw `PKGBUILD` fetcher.
//!
//! Two endpoints are used, both public and key-free:
//! - `rpc/v5/info` for package metadata.
//! - `cgit/.../plain/PKGBUILD` for the raw build script text.

use crate::pkgbuild::{referenced_install_files, PkgSources};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::time::Duration;

/// Base URL of the AUR instance. Overridable in tests via constructor.
const DEFAULT_BASE: &str = "https://aur.archlinux.org";

/// Wall-clock timeout applied to every HTTP request.
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

/// One package entry from the RPC `info` response `results` array.
///
/// Field names mirror the AUR RPC schema (PascalCase on the wire), remapped to
/// snake_case here via `serde(rename_all)`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageInfo {
    /// Package name (`pkgname`).
    pub name: String,
    /// Upstream version (`pkgver`).
    pub version: String,
    /// Maintainer username; absent for orphaned packages.
    pub maintainer: Option<String>,
    /// Unix timestamp of first submission (account/package age proxy).
    pub first_submitted: i64,
    /// Unix timestamp of last modification.
    pub last_modified: i64,
    /// Community vote count.
    pub num_votes: u64,
    /// Path suffix for the git repo / snapshot (`URLPath`). Parsed for
    /// completeness; not yet surfaced in the report.
    #[serde(rename = "URLPath")]
    #[allow(dead_code)]
    pub url_path: Option<String>,
}

/// Envelope of the RPC `info` response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
struct RpcResponse {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    results: Vec<PackageInfo>,
}

/// A single hit from the RPC `search` endpoint (fewer fields than `info`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SearchHit {
    /// Package name.
    pub name: String,
    /// Version string.
    pub version: String,
    /// Short description, if any.
    pub description: Option<String>,
    /// Community vote count.
    pub num_votes: u64,
    /// Out-of-date flag (Unix timestamp when flagged), if set.
    pub out_of_date: Option<i64>,
}

/// Envelope of the RPC `search` response.
#[derive(Debug, Deserialize)]
struct SearchResponse {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    results: Vec<SearchHit>,
}

/// HTTP client bound to one AUR base URL.
pub struct AurClient {
    http: reqwest::Client,
    base: String,
}

impl AurClient {
    /// Construct a client against the production AUR instance.
    pub fn new() -> Result<Self> {
        Self::with_base(DEFAULT_BASE)
    }

    /// Construct a client against an arbitrary base URL (used in tests).
    pub fn with_base(base: impl Into<String>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("aurguard/", env!("CARGO_PKG_VERSION")))
            .timeout(HTTP_TIMEOUT)
            .build()
            .context("failed to build HTTP client")?;
        Ok(AurClient {
            http,
            base: base.into(),
        })
    }

    /// Fetch metadata for a single package via the RPC `info` endpoint.
    ///
    /// Returns a clear error if the package does not exist on the AUR.
    pub async fn info(&self, package: &str) -> Result<PackageInfo> {
        let url = format!("{}/rpc/v5/info?arg[]={}", self.base, urlencode(package));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("network error fetching info for '{package}'"))?;

        if !resp.status().is_success() {
            bail!("AUR RPC returned HTTP {} for '{package}'", resp.status());
        }

        let body: RpcResponse = resp
            .json()
            .await
            .context("failed to parse AUR RPC response")?;

        if body.kind == "error" {
            bail!(
                "AUR RPC error: {}",
                body.error.unwrap_or_else(|| "unknown".into())
            );
        }

        body.results
            .into_iter()
            .next()
            .with_context(|| format!("package '{package}' not found on the AUR"))
    }

    /// Fetch the raw `PKGBUILD` text for a package from the cgit plain
    /// endpoint.
    pub async fn pkgbuild(&self, package: &str) -> Result<String> {
        let url = format!(
            "{}/cgit/aur.git/plain/PKGBUILD?h={}",
            self.base,
            urlencode(package)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("network error fetching PKGBUILD for '{package}'"))?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("no PKGBUILD found for '{package}' (does the package exist?)");
        }
        if !resp.status().is_success() {
            bail!(
                "cgit returned HTTP {} for '{package}' PKGBUILD",
                resp.status()
            );
        }

        resp.text().await.context("failed to read PKGBUILD body")
    }

    /// Search the AUR for packages whose **name** contains `term`.
    ///
    /// Results are sorted by vote count (descending) and capped at `limit`.
    /// Used as a "did you mean…" fallback when an exact `info` lookup misses.
    pub async fn search_by_name(&self, term: &str, limit: usize) -> Result<Vec<SearchHit>> {
        let url = format!("{}/rpc/v5/search/{}?by=name", self.base, urlencode(term));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("network error searching for '{term}'"))?;
        if !resp.status().is_success() {
            bail!("AUR search returned HTTP {} for '{term}'", resp.status());
        }
        let body: SearchResponse = resp
            .json()
            .await
            .context("failed to parse AUR search response")?;
        if body.kind == "error" {
            bail!(
                "AUR search error: {}",
                body.error.unwrap_or_else(|| "unknown".into())
            );
        }
        let mut hits = body.results;
        hits.sort_by(|a, b| b.num_votes.cmp(&a.num_votes).then(a.name.cmp(&b.name)));
        hits.truncate(limit);
        Ok(hits)
    }

    /// Fetch an arbitrary plain file from a package's AUR repo (e.g. a
    /// `.install` scriptlet). Returns `Ok(None)` if the file is absent.
    pub async fn fetch_file(&self, package: &str, filename: &str) -> Result<Option<String>> {
        let url = format!(
            "{}/cgit/aur.git/plain/{}?h={}",
            self.base,
            urlencode(filename),
            urlencode(package)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("network error fetching {filename} for '{package}'"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            bail!("cgit returned HTTP {} for {filename}", resp.status());
        }
        Ok(Some(resp.text().await.context("failed to read file body")?))
    }

    /// Fetch the full analyzable source set for `package`: the `PKGBUILD` plus
    /// every `.install` scriptlet it references.
    pub async fn sources(&self, package: &str) -> Result<PkgSources> {
        let pkgbuild = self.pkgbuild(package).await?;
        let mut install_scripts = Vec::new();
        for name in referenced_install_files(&pkgbuild) {
            if let Some(body) = self.fetch_file(package, &name).await? {
                install_scripts.push((name, body));
            }
        }
        Ok(PkgSources {
            pkgbuild,
            install_scripts,
        })
    }
}

/// Minimal percent-encoder for the package-name query parameter.
///
/// AUR package names are restricted to a small charset; this escapes anything
/// outside `[A-Za-z0-9._+-]` defensively so a malformed argument cannot break
/// out of the query string.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_info_envelope() {
        let json = r#"{
            "type": "multiinfo",
            "resultcount": 1,
            "results": [{
                "Name": "firefox",
                "Version": "126.0-1",
                "Maintainer": "heftig",
                "FirstSubmitted": 1234567890,
                "LastModified": 1700000000,
                "NumVotes": 2847,
                "URLPath": "/cgit/aur.git/snapshot/firefox.tar.gz"
            }]
        }"#;
        let resp: RpcResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.kind, "multiinfo");
        let pkg = &resp.results[0];
        assert_eq!(pkg.name, "firefox");
        assert_eq!(pkg.version, "126.0-1");
        assert_eq!(pkg.maintainer.as_deref(), Some("heftig"));
        assert_eq!(pkg.num_votes, 2847);
    }

    #[test]
    fn parses_orphaned_package_without_maintainer() {
        let json = r#"{
            "type": "multiinfo",
            "resultcount": 1,
            "results": [{
                "Name": "orphan",
                "Version": "1.0-1",
                "Maintainer": null,
                "FirstSubmitted": 1,
                "LastModified": 2,
                "NumVotes": 0
            }]
        }"#;
        let resp: RpcResponse = serde_json::from_str(json).unwrap();
        assert!(resp.results[0].maintainer.is_none());
    }

    #[test]
    fn parses_search_response() {
        let json = r#"{
            "type": "search",
            "resultcount": 2,
            "results": [
                {"Name": "opencode-bin", "Version": "1.0-1", "Description": "AI agent", "NumVotes": 12, "OutOfDate": null},
                {"Name": "opencode-git", "Version": "1.0.r1-1", "Description": null, "NumVotes": 3, "OutOfDate": 1700000000}
            ]
        }"#;
        let resp: SearchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.kind, "search");
        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.results[0].name, "opencode-bin");
        assert_eq!(resp.results[0].num_votes, 12);
        assert!(resp.results[1].out_of_date.is_some());
    }

    #[test]
    fn urlencode_escapes_unsafe() {
        assert_eq!(urlencode("foo-bar.1"), "foo-bar.1");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("x&y=z"), "x%26y%3Dz");
    }
}
