//! T2.4 source-tree scan — committed prebuilt binaries.
//!
//! A legitimate AUR package ships *recipes*: it fetches source and compiles it.
//! A prebuilt executable checked straight into the package repo is a classic
//! malware-delivery shortcut — the maintainer (or a hijacker) hands you an
//! opaque blob that `package()` simply copies into place, with nothing to
//! review. This pass walks the cloned tree and flags any file whose contents or
//! extension identify it as a compiled binary.
//!
//! It runs only where a real tree exists: the clone-first `-S` flow and the
//! `--file` sibling directory. Pure metadata/`-I` lookups never see a tree.

use crate::i18n::{self, Lang};
use crate::report::{Finding, Severity};
use std::path::Path;

/// Directories never worth scanning (VCS metadata, build output).
const SKIP_DIRS: &[&str] = &[".git", ".svn", "src", "pkg", "target"];

/// File extensions that are compiled artifacts regardless of magic bytes.
const BINARY_EXTS: &[&str] = &[
    "so", "a", "o", "dll", "dylib", "exe", "pyc", "pyd", "class", "wasm", "ko", "bin",
];

/// Cap the walk so a pathological tree cannot stall analysis.
const MAX_FILES: usize = 4000;

/// Scan the package tree rooted at `dir` for committed binaries, returning
/// localized [`Finding`]s (`COMMITTED_BINARY`, Critical).
pub fn scan_tree(dir: &Path, lang: Lang) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut budget = MAX_FILES;
    walk(dir, dir, lang, &mut budget, &mut findings);
    findings
}

fn walk(root: &Path, dir: &Path, lang: Lang, budget: &mut usize, out: &mut Vec<Finding>) {
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
            walk(root, &path, lang, budget, out);
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        *budget -= 1;
        if let Some(kind) = classify(&path, &name) {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
            let arg = format!("{rel} ({kind})");
            let tpl = i18n::finding(lang, "COMMITTED_BINARY")
                .unwrap_or("Prebuilt binary committed in the package tree: {}");
            out.push(
                Finding::meta(
                    Severity::Critical,
                    "COMMITTED_BINARY",
                    i18n::fill(tpl, Some(&arg)),
                )
                .with_arg(arg),
            );
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
    fn flags_elf_binary() {
        let d = tmpdir();
        let mut f = std::fs::File::create(d.join("helper")).unwrap();
        f.write_all(b"\x7fELF\x02\x01\x01\x00rest").unwrap();
        let found = scan_tree(&d, Lang::En);
        assert!(
            found.iter().any(|x| x.code == "COMMITTED_BINARY"),
            "{found:?}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn flags_by_extension() {
        let d = tmpdir();
        std::fs::write(d.join("payload.so"), b"not really elf").unwrap();
        let found = scan_tree(&d, Lang::En);
        assert!(
            found.iter().any(|x| x.code == "COMMITTED_BINARY"),
            "{found:?}"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn text_sources_are_clean() {
        let d = tmpdir();
        std::fs::write(d.join("PKGBUILD"), b"pkgname=x\nbuild() { :; }\n").unwrap();
        std::fs::write(d.join("x.patch"), b"--- a\n+++ b\n").unwrap();
        let found = scan_tree(&d, Lang::En);
        assert!(found.is_empty(), "{found:?}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn skips_git_dir() {
        let d = tmpdir();
        let git = d.join(".git");
        std::fs::create_dir_all(&git).unwrap();
        let mut f = std::fs::File::create(git.join("index")).unwrap();
        f.write_all(b"\x7fELF").unwrap();
        let found = scan_tree(&d, Lang::En);
        assert!(found.is_empty(), "{found:?}");
        std::fs::remove_dir_all(&d).ok();
    }
}
