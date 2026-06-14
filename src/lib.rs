//! aurguard — AUR package security guard (library crate).
//!
//! This crate exposes the pieces the `aurguard` binary wires together, so the
//! analyzer can be embedded and integration-tested independently of the CLI:
//!
//! - [`aur`] — AUR RPC client + raw file fetchers.
//! - [`pkgbuild`] — static analysis of `PKGBUILD` + `.install` scripts.
//! - [`astscan`] — tree-sitter-bash AST pass that hardens detection against
//!   obfuscation and string/comment false positives.
//! - [`report`] — findings, severities, and the aggregated [`report::Report`].
//! - [`config`] — user configuration (trusted domains, rule ignores, policy).
//! - [`diff`] — approved-PKGBUILD ledger for change tracking.
//! - [`installer`] — clone-first build flow via `makepkg`.
//! - [`ui`] — terminal rendering and prompts.

pub mod astscan;
pub mod aur;
pub mod config;
pub mod diff;
pub mod i18n;
pub mod installer;
pub mod pkgbuild;
pub mod report;
pub mod ui;
pub mod wizard;

pub use config::Config;
pub use i18n::Lang;
pub use pkgbuild::{analyze, PkgSources};
pub use report::{Finding, Report, Risk, Severity};
