//! YARA-style signature rules for known-malicious shapes in build scripts.
//!
//! This is a small, dependency-free rule engine modelled on YARA: each
//! [`SigRule`] has a name (`code`), a severity, descriptive `tags`, and a
//! condition expressed in conjunctive normal form (CNF) over case-insensitive
//! string matches — every *clause* must match, and a clause matches when *any*
//! of its alternatives is present. Rules can also declare negative `not`
//! strings that veto a match (e.g. writes into `$pkgdir` are legitimate
//! packaging, not persistence).
//!
//! Matching is purely textual and best-effort; it complements — and never
//! replaces — the AST pass in [`crate::astscan`] and the heuristics in
//! [`crate::pkgbuild`]. The engine runs over both the `PKGBUILD` and any
//! root-privileged `.install` scriptlets.

use crate::i18n;
use crate::report::{Finding, Severity};

/// A single YARA-style signature rule.
pub struct SigRule {
    /// Stable finding code (also the i18n key).
    pub code: &'static str,
    pub severity: Severity,
    /// Free-form classification tags (malware family / behaviour).
    pub tags: &'static [&'static str],
    /// English message template; `{}` is filled with the salient match.
    pub msg: &'static str,
    /// CNF condition: every clause must match; a clause matches if any
    /// alternative is a substring of the lower-cased line.
    pub clauses: &'static [&'static [&'static str]],
    /// If any of these substrings is present, the rule does not fire.
    pub not: &'static [&'static str],
}

impl SigRule {
    /// Evaluate against one lower-cased line. Returns the salient matched
    /// token (from the first clause) when the rule fires.
    fn evaluate(&self, lower: &str) -> Option<String> {
        if self.not.iter().any(|n| lower.contains(n)) {
            return None;
        }
        let mut salient: Option<String> = None;
        for clause in self.clauses {
            let hit = clause.iter().find(|alt| lower.contains(**alt))?;
            if salient.is_none() {
                salient = Some((*hit).to_string());
            }
        }
        salient
    }
}

/// Run every signature rule over a single (comment-stripped, lower-cased) line,
/// pushing a [`Finding`] for each match. The message is authored in English and
/// carries the salient match as `arg`; `pkgbuild::localize` rewrites it for
/// non-English interfaces from the i18n catalog using that same `arg`.
pub fn scan_line(lower: &str, lineno: usize, findings: &mut Vec<Finding>) {
    for rule in RULES {
        if let Some(token) = rule.evaluate(lower) {
            let message = i18n::fill(rule.msg, Some(&token));
            findings.push(Finding::at(rule.severity, rule.code, message, lineno).with_arg(token));
        }
    }
}

/// Number of active signature rules (exposed for tests / about screens).
pub fn rule_count() -> usize {
    RULES.len()
}

use Severity::{Critical, Warn};

/// The built-in signature database.
pub const RULES: &[SigRule] = &[
    SigRule {
        code: "CRYPTO_MINER",
        severity: Critical,
        tags: &["miner", "coinminer"],
        msg: "Cryptocurrency miner signature ({})",
        clauses: &[&[
            "xmrig",
            "stratum+tcp",
            "stratum+ssl",
            "minerd",
            "cpuminer",
            "cryptonight",
            "randomx",
            "--donate-level",
            "nicehash",
            "ethminer",
            "phoenixminer",
            "minexmr",
            "supportxmr",
            "nanopool",
            "hashvault",
        ]],
        not: &[],
    },
    SigRule {
        code: "DISCORD_EXFIL",
        severity: Critical,
        tags: &["exfil", "c2"],
        msg: "Data exfiltration to a Discord webhook",
        clauses: &[&["discord.com/api/webhooks", "discordapp.com/api/webhooks"]],
        not: &[],
    },
    SigRule {
        code: "TELEGRAM_EXFIL",
        severity: Critical,
        tags: &["exfil", "c2"],
        msg: "Data exfiltration via the Telegram bot API",
        clauses: &[&["api.telegram.org/bot"]],
        not: &[],
    },
    SigRule {
        code: "PASTE_PAYLOAD",
        severity: Warn,
        tags: &["dropper"],
        msg: "Payload fetched from an ephemeral paste host: {}",
        clauses: &[
            &[
                "pastebin.com/raw",
                "hastebin.com/raw",
                "transfer.sh",
                "0x0.st",
                "termbin.com",
                "ix.io",
                "paste.ee",
                "controlc.com",
                "anonfiles.com",
            ],
            &["curl", "wget", "fetch", "http"],
        ],
        not: &[],
    },
    SigRule {
        code: "SSH_KEY_INJECT",
        severity: Critical,
        tags: &["backdoor", "persistence"],
        msg: "Writes an SSH authorized_keys entry (backdoor access)",
        clauses: &[
            &["authorized_keys"],
            &[">>", ">", "tee", "echo", "cat", "printf", "install", "cp"],
        ],
        not: &["$pkgdir", "${pkgdir", "$srcdir", "${srcdir"],
    },
    SigRule {
        code: "CRON_PERSIST",
        severity: Critical,
        tags: &["persistence"],
        msg: "Installs a cron job for persistence",
        clauses: &[
            &[
                "crontab",
                "/etc/cron",
                "/var/spool/cron",
                "cron.d/",
                "cron.daily",
                "cron.hourly",
            ],
            &[">>", ">", "tee", "crontab -", "echo", "install", "cp"],
        ],
        not: &["$pkgdir", "${pkgdir", "$srcdir", "${srcdir"],
    },
    SigRule {
        code: "SYSTEMD_PERSIST",
        severity: Warn,
        tags: &["persistence"],
        msg: "Enables or starts a systemd service from the build",
        clauses: &[&[
            "systemctl enable",
            "systemctl --now enable",
            "systemctl start",
            "systemctl daemon-reload",
        ]],
        not: &["$pkgdir", "${pkgdir"],
    },
    SigRule {
        code: "CRED_HARVEST",
        severity: Critical,
        tags: &["stealer"],
        msg: "Reads sensitive credentials or keys ({})",
        clauses: &[
            &[
                "id_rsa",
                ".aws/credentials",
                "wallet.dat",
                ".gnupg",
                ".ssh/id_",
                "keystore",
                ".config/gcloud",
                "cookies.sqlite",
                "login data",
                ".docker/config.json",
                ".netrc",
                ".npmrc",
            ],
            &[
                "cp ", "tar", "curl", "wget", "cat ", "zip", "scp", "rsync", "nc ", "base64", "mv ",
            ],
        ],
        not: &["$pkgdir", "${pkgdir"],
    },
    SigRule {
        code: "ENV_EXFIL",
        severity: Critical,
        tags: &["exfil", "stealer"],
        msg: "Sends environment or system secrets over the network",
        clauses: &[
            &["curl", "wget", "nc ", "/dev/tcp", "scp", "ncat"],
            &[
                "printenv",
                "$(env)",
                "`env`",
                "env |",
                "/etc/passwd",
                "/etc/shadow",
            ],
        ],
        not: &[],
    },
    SigRule {
        code: "DISABLE_SECURITY",
        severity: Critical,
        tags: &["defense-evasion"],
        msg: "Disables a security control ({})",
        clauses: &[&[
            "setenforce 0",
            "iptables -f",
            "ufw disable",
            "systemctl stop firewalld",
            "systemctl disable firewalld",
            "systemctl stop apparmor",
            "aa-disable",
            "selinux=disabled",
            "nftables -f",
        ]],
        not: &[],
    },
    SigRule {
        code: "INSECURE_FETCH",
        severity: Warn,
        tags: &["mitm"],
        msg: "Downloads with TLS verification disabled",
        clauses: &[
            &["curl", "wget"],
            &[" -k ", " -k\"", " --insecure", "--no-check-certificate"],
        ],
        not: &[],
    },
    SigRule {
        code: "PIP_INDEX_HIJACK",
        severity: Warn,
        tags: &["supply-chain"],
        msg: "Installs Python packages from a non-default index",
        clauses: &[
            &["pip install", "pip3 install", "pip download"],
            &["--index-url", "--extra-index-url", "-i http"],
        ],
        not: &[],
    },
];
