//! T2.4 source-tree scan — committed prebuilt binaries.
//!
//! A legitimate AUR package ships *recipes*: it fetches source and compiles it.
//! A prebuilt executable checked straight into the package repo is a classic
//! malware-delivery shortcut — the maintainer (or a hijacker) hands you an
//! opaque blob that `package()` simply copies into place, with nothing to
//! review. This pass walks the cloned tree and flags any file whose contents or
//! extension identify it as a compiled binary, hashing each one so it can be
//! looked up on VirusTotal (see [`crate::vt`]).
//!
//! It runs wherever a real tree exists: the clone-first `-S` flow and a local
//! `--file` analysis (which scans the `PKGBUILD`'s own directory). Pure
//! metadata/`-I` lookups never see a tree.

use crate::i18n::{self, Lang};
use crate::report::{Finding, Severity};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Directories never worth scanning (VCS metadata, build output).
const SKIP_DIRS: &[&str] = &[".git", ".svn", "src", "pkg", "target"];

/// File extensions that are compiled artifacts regardless of magic bytes.
const BINARY_EXTS: &[&str] = &[
    "so", "a", "o", "dll", "dylib", "exe", "pyc", "pyd", "class", "wasm", "ko", "bin",
];

/// Cap the walk so a pathological tree cannot stall analysis.
const MAX_FILES: usize = 4000;
/// Skip hashing absurdly large files (still report them).
const MAX_HASH_BYTES: u64 = 64 * 1024 * 1024;

/// A committed binary found in the package tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binary {
    /// Path relative to the tree root.
    pub path: String,
    /// Detected format (`"ELF"`, `"PE/EXE"`, `"binary"`, …).
    pub kind: &'static str,
    /// Lower-case hex SHA-256 of the file, or `None` if it could not be read.
    pub sha256: Option<String>,
}

impl Binary {
    /// The `COMMITTED_BINARY` finding for this file, localized to `lang`.
    pub fn finding(&self, lang: Lang) -> Finding {
        let arg = match &self.sha256 {
            Some(h) => format!("{} ({}) sha256:{h}", self.path, self.kind),
            None => format!("{} ({})", self.path, self.kind),
        };
        let tpl = i18n::finding(lang, "COMMITTED_BINARY")
            .unwrap_or("Prebuilt binary committed in the package tree: {}");
        Finding::meta(
            Severity::Critical,
            "COMMITTED_BINARY",
            i18n::fill(tpl, Some(&arg)),
        )
        .with_arg(arg)
    }
}

/// Flag any committed binary whose SHA-256 appears in the user's `[ioc].hashes`
/// blocklist as an `IOC_MATCH` (Critical) — a local, no-API known-bad check.
pub fn match_known_bad(bins: &[Binary], hashes: &[String], lang: Lang) -> Vec<Finding> {
    if hashes.is_empty() {
        return Vec::new();
    }
    let blocked: std::collections::HashSet<String> = hashes
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    bins.iter()
        .filter_map(|b| {
            let h = b.sha256.as_ref()?;
            blocked.contains(h).then(|| {
                let arg = format!("{} sha256:{h}", b.path);
                let tpl =
                    i18n::finding(lang, "IOC_MATCH").unwrap_or("Matches a known-bad indicator: {}");
                Finding::meta(Severity::Critical, "IOC_MATCH", i18n::fill(tpl, Some(&arg)))
                    .with_arg(arg)
            })
        })
        .collect()
}

/// Walk the package tree rooted at `dir`, returning every committed binary with
/// its SHA-256.
pub fn scan_tree(dir: &Path) -> Vec<Binary> {
    let mut bins = Vec::new();
    let mut budget = MAX_FILES;
    walk(dir, dir, &mut budget, &mut bins);
    bins
}

fn walk(root: &Path, dir: &Path, budget: &mut usize, out: &mut Vec<Binary>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(root, &path, budget, out);
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        *budget -= 1;
        if let Some(kind) = classify(&path, &name) {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
            out.push(Binary {
                path: rel.into_owned(),
                kind,
                sha256: sha256_file(&path),
            });
        }
    }
}

/// Identify a file as a compiled binary by magic bytes, then by extension.
fn classify(path: &Path, name: &str) -> Option<&'static str> {
    if let Some(kind) = magic(path) {
        return Some(kind);
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some(e) if BINARY_EXTS.contains(&e) => Some("binary"),
        _ => None,
    }
}

/// Sniff the leading bytes for a known executable/object format.
fn magic(path: &Path) -> Option<&'static str> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 8];
    let n = f.read(&mut buf).ok()?;
    let b = &buf[..n];
    if b.starts_with(b"\x7fELF") {
        Some("ELF")
    } else if b.starts_with(b"MZ") {
        Some("PE/EXE")
    } else if b.starts_with(b"\x00asm") {
        Some("WASM")
    } else if b.starts_with(b"!<arch>") {
        Some("ar archive")
    } else if b.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
        || b.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        || b.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
    {
        Some("Mach-O")
    } else {
        None
    }
}

/// Stream a file through SHA-256, returning lower-case hex. `None` on I/O error
/// or when the file is implausibly large.
fn sha256_file(path: &Path) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    if f.metadata().map(|m| m.len()).unwrap_or(0) > MAX_HASH_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aurguard-srcscan-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn flags_elf_binary_with_hash() {
        let d = tmpdir();
        let mut f = std::fs::File::create(d.join("helper")).unwrap();
        f.write_all(b"\x7fELF\x02\x01\x01\x00rest").unwrap();
        let bins = scan_tree(&d);
        assert_eq!(bins.len(), 1, "{bins:?}");
        assert_eq!(bins[0].kind, "ELF");
        assert_eq!(bins[0].sha256.as_ref().unwrap().len(), 64);
        assert_eq!(bins[0].finding(Lang::En).code, "COMMITTED_BINARY");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn flags_by_extension() {
        let d = tmpdir();
        std::fs::write(d.join("payload.so"), b"not really elf").unwrap();
        assert!(scan_tree(&d).iter().any(|b| b.kind == "binary"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn text_sources_are_clean() {
        let d = tmpdir();
        std::fs::write(d.join("PKGBUILD"), b"pkgname=x\nbuild() { :; }\n").unwrap();
        std::fs::write(d.join("x.patch"), b"--- a\n+++ b\n").unwrap();
        assert!(scan_tree(&d).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn skips_git_dir() {
        let d = tmpdir();
        let git = d.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        std::fs::File::create(git.join("index"))
            .unwrap()
            .write_all(b"\x7fELF")
            .unwrap();
        assert!(scan_tree(&d).is_empty());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn hash_is_stable() {
        let d = tmpdir();
        std::fs::write(d.join("a.bin"), b"\x7fELFsame").unwrap();
        let h1 = scan_tree(&d)[0].sha256.clone();
        let h2 = scan_tree(&d)[0].sha256.clone();
        assert_eq!(h1, h2);
        assert!(h1.is_some());
        std::fs::remove_dir_all(&d).ok();
    }
}
