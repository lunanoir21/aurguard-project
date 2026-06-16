//! aurguard — AUR package security guard (library crate).
//!
//! This crate exposes the pieces the `aurguard` binary wires together, so the
//! analyzer can be embedded and integration-tested independently of the CLI:
//!
//! - [`aur`] — AUR RPC client + raw file fetchers.
//! - [`pkgbuild`] — static analysis of `PKGBUILD` + `.install` scripts.
//! - [`astscan`] — tree-sitter-bash AST pass that hardens detection against
//!   obfuscation and string/comment false positives.
//! - [`decode`] — decode-and-rescan of base64/hex blobs + entropy.
//! - [`ioc`] — known-bad indicator blocklist + crypto-wallet detection.
//! - [`normalize`] — constant-fold anti-evasion (unquote/IFS/escape folding).
//! - [`srcscan`] — committed prebuilt-binary detection over the source tree.
//! - [`taint`] — dataflow taint from untrusted input to execution sinks.
//! - [`vt`] — VirusTotal hash hints (offline) + optional API lookups.
//! - [`report`] — findings, severities, and the aggregated [`report::Report`].
//! - [`config`] — user configuration (trusted domains, rule ignores, policy).
//! - [`diff`] — approved-PKGBUILD ledger for change tracking.
//! - [`installer`] — clone-first build flow via `makepkg`.
//! - [`ui`] — terminal rendering and prompts.

pub mod astscan;
pub mod aur;
pub mod config;
pub mod decode;
pub mod diff;
pub mod i18n;
pub mod installer;
pub mod ioc;
pub mod normalize;
pub mod pkgbuild;
pub mod report;
pub mod rules;
pub mod srcscan;
pub mod taint;
pub mod ui;
pub mod vt;
pub mod wizard;

pub use config::Config;
pub use i18n::Lang;
pub use pkgbuild::{analyze, analyze_with, PkgSources, ScanOpts};
pub use report::{Finding, Report, Risk, Severity};
