//! aurguard — AUR package security guard (binary entry point).
//!
//! Thin CLI over the [`aurguard`] library: parses flags, loads config, and
//! dispatches to report-only (`-I`/`--file`), clone-first install (`-S`), or
//! ledger query (`-Q`).

use anyhow::{Context, Result};
use aurguard::aur::{AurClient, PackageInfo};
use aurguard::config::{Config, FailOn};
use aurguard::diff::{self, Approvals};
use aurguard::i18n::{self, Lang, K};
use aurguard::installer::{self, ClonedRepo};
use aurguard::pkgbuild::{self, PkgSources};
use aurguard::report::Report;
use aurguard::ui::{self, UiOptions};
use aurguard::wizard;
use clap::Parser;
use std::path::PathBuf;

/// Command-line interface. Pacman-style short flags select the operation.
#[derive(Parser, Debug)]
#[command(
    name = "aurguard",
    version,
    about = "AUR package security guard — analyze before you install.",
    long_about = None,
    disable_help_flag = true
)]
struct Cli {
    /// Print help (localized to the configured language).
    #[arg(short = 'h', long = "help")]
    help: bool,

    /// Analyze and (on confirmation) install AUR package(s).
    #[arg(short = 'S', long = "sync", value_name = "PACKAGE", num_args = 1..)]
    sync: Vec<String>,

    /// Show the security report without installing.
    #[arg(short = 'I', long = "info", value_name = "PACKAGE", num_args = 1..)]
    info: Vec<String>,

    /// List packages installed via aurguard.
    #[arg(short = 'Q', long = "query")]
    query: bool,

    /// Run the interactive setup wizard (choose language, policy, …).
    #[arg(long = "setup")]
    setup: bool,

    /// Analyze a local PKGBUILD file instead of fetching from the AUR.
    #[arg(long = "file", value_name = "PATH")]
    file: Option<PathBuf>,

    /// Interface language for this run (en|tr|fr|es|az). Overrides config.
    #[arg(long = "lang", value_name = "LANG")]
    lang: Option<String>,

    /// Disable colored output.
    #[arg(long = "no-color")]
    no_color: bool,

    /// Output the report as JSON (implies --no-color).
    #[arg(long = "json")]
    json: bool,

    /// Auto-accept the install unless findings meet the fail-on threshold.
    #[arg(long = "skip-confirm")]
    skip_confirm: bool,

    /// Risk threshold that blocks a non-interactive install
    /// (clean|risky|critical). Overrides the config policy.
    #[arg(long = "fail-on", value_name = "SEVERITY")]
    fail_on: Option<String>,

    /// Package name(s) given without a flag: show the report (like -I), or
    /// suggest packages whose name contains the term if there is no exact match.
    #[arg(value_name = "PACKAGE")]
    packages: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let exit = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("  \u{2716}  {e:#}");
            1
        }
    };
    std::process::exit(exit);
}

/// Dispatch the selected operation. Returns the process exit code.
async fn run(cli: Cli) -> Result<i32> {
    if cli.setup {
        return wizard::run();
    }

    let mut config = Config::load().context("loading configuration")?;
    if let Some(s) = &cli.lang {
        // CLI override flows into config so the analyzer localizes too.
        config.ui.lang = s.parse::<Lang>()?;
    }
    let lang = config.ui.lang;

    // Localized help: explicit --help, or no operation selected.
    let no_op = !cli.query
        && cli.file.is_none()
        && cli.info.is_empty()
        && cli.sync.is_empty()
        && cli.packages.is_empty();
    if cli.help || no_op {
        print!("{}", i18n::help_text(lang));
        return Ok(0);
    }

    let opts = UiOptions::new(cli.no_color || cli.json, config.ui.color, lang);

    if cli.query {
        return query(opts);
    }
    if let Some(path) = cli.file.clone() {
        return analyze_file(&path, &cli, &config, opts);
    }
    if !cli.sync.is_empty() {
        return sync(&cli.sync.clone(), &cli, &config, opts).await;
    }
    // Both -I packages and bare positional packages are report-only lookups.
    let report_targets: Vec<String> = cli.info.iter().chain(&cli.packages).cloned().collect();
    if !report_targets.is_empty() {
        return info(&report_targets, &cli, &config, opts).await;
    }

    unreachable!("no_op already handled above")
}

/// Effective fail-on threshold: CLI override, else config policy.
fn fail_on(cli: &Cli, config: &Config) -> Result<FailOn> {
    match &cli.fail_on {
        Some(s) => s.parse::<FailOn>(),
        None => Ok(config.policy.fail_on),
    }
}

/// Render or JSON-emit a report.
fn present(report: &Report, cli: &Cli, opts: UiOptions) -> Result<()> {
    if cli.json {
        ui::print_json(report)?;
    } else {
        ui::render_report(report, opts);
    }
    Ok(())
}

/// `--file`: analyze a local PKGBUILD (plus sibling `.install` scripts).
fn analyze_file(
    path: &std::path::Path,
    cli: &Cli,
    config: &Config,
    opts: UiOptions,
) -> Result<i32> {
    let pkgbuild = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut install_scripts = Vec::new();
    for name in pkgbuild::referenced_install_files(&pkgbuild) {
        if let Some(fname) = std::path::Path::new(&name).file_name() {
            let p = dir.join(fname);
            if let Ok(body) = std::fs::read_to_string(&p) {
                install_scripts.push((fname.to_string_lossy().to_string(), body));
            }
        }
    }
    let sources = PkgSources {
        pkgbuild,
        install_scripts,
    };
    let report = pkgbuild::analyze(None, &sources, config, None, chrono::Utc::now());
    present(&report, cli, opts)?;
    Ok(report.risk.exit_code())
}

/// `-I`: report only for one or more packages. Exit code reflects the worst
/// risk across them.
async fn info(packages: &[String], cli: &Cli, config: &Config, opts: UiOptions) -> Result<i32> {
    let client = AurClient::new()?;
    let approvals = Approvals::load().unwrap_or_default();
    let mut worst = 0;

    for pkg in packages {
        match info_one(pkg, cli, config, opts, &client, &approvals).await {
            Ok(code) => worst = worst.max(code),
            Err(e) => {
                ui::error(&format!("{pkg}: {e:#}"), opts);
                worst = worst.max(1);
            }
        }
    }
    Ok(worst)
}

/// Outcome of the network lookup for a query.
enum Lookup {
    /// Exact package found.
    Found(PackageInfo),
    /// No exact match, but similar packages exist (search fallback).
    Suggestions(Vec<aurguard::aur::SearchHit>),
}

/// Look up `query`: exact `info`, else an AUR name search. Errors only when the
/// package is missing *and* nothing similar exists.
async fn lookup(query: &str, client: &AurClient) -> Result<Lookup> {
    match client.info(query).await {
        Ok(meta) => Ok(Lookup::Found(meta)),
        Err(e) => {
            let hits = client.search_by_name(query, 12).await.unwrap_or_default();
            if hits.is_empty() {
                Err(e)
            } else {
                Ok(Lookup::Suggestions(hits))
            }
        }
    }
}

/// Resolve a query to package metadata, prompting with suggestions when there
/// is no exact match. Runs the network lookup under a spinner, then prompts
/// (spinner stopped) so the picker reads cleanly. `None` = user cancelled.
async fn resolve(
    query: &str,
    interactive: bool,
    quiet: bool,
    opts: UiOptions,
    client: &AurClient,
) -> Result<Option<PackageInfo>> {
    let sp = (!quiet).then(|| {
        ui::spinner(
            &i18n::fill(i18n::t(opts.lang, K::Fetching), Some(query)),
            opts,
        )
    });
    let result = lookup(query, client).await;
    if let Some(sp) = sp {
        ui::finish_spinner(sp);
    }

    match result? {
        Lookup::Found(meta) => Ok(Some(meta)),
        Lookup::Suggestions(hits) => match ui::pick_suggestion(query, &hits, interactive, opts) {
            Some(name) => {
                let sp = (!quiet).then(|| {
                    ui::spinner(
                        &i18n::fill(i18n::t(opts.lang, K::Fetching), Some(&name)),
                        opts,
                    )
                });
                let meta = client.info(&name).await;
                if let Some(sp) = sp {
                    ui::finish_spinner(sp);
                }
                Ok(Some(meta?))
            }
            None => Ok(None),
        },
    }
}

/// Report for a single package in `-I` mode.
async fn info_one(
    pkg: &str,
    cli: &Cli,
    config: &Config,
    opts: UiOptions,
    client: &AurClient,
    approvals: &Approvals,
) -> Result<i32> {
    let meta = match resolve(pkg, !cli.json, cli.json, opts, client).await? {
        Some(m) => m,
        None => return Ok(0),
    };
    let sources = client.sources(&meta.name).await?;
    let prior = approvals.approved_digest(&meta.name);
    let report = pkgbuild::analyze(Some(&meta), &sources, config, prior, chrono::Utc::now());
    present(&report, cli, opts)?;
    Ok(report.risk.exit_code())
}

/// `-S`: clone-first analyze, confirm, then build each package.
async fn sync(packages: &[String], cli: &Cli, config: &Config, opts: UiOptions) -> Result<i32> {
    installer::preflight()?;
    let threshold = fail_on(cli, config)?;
    let client = AurClient::new()?;
    let mut approvals = Approvals::load().unwrap_or_default();
    let mut exit = 0;

    for pkg in packages {
        match sync_one(pkg, cli, config, threshold, opts, &client, &mut approvals).await {
            Ok(()) => {}
            Err(e) => {
                ui::error(&format!("{pkg}: {e:#}"), opts);
                exit = 1;
            }
        }
    }
    Ok(exit)
}

/// Install flow for a single package, sharing one clone for analysis and build.
async fn sync_one(
    pkg: &str,
    cli: &Cli,
    config: &Config,
    threshold: FailOn,
    opts: UiOptions,
    client: &AurClient,
    approvals: &mut Approvals,
) -> Result<()> {
    let interactive = !cli.json && !cli.skip_confirm;
    let meta = match resolve(pkg, interactive, cli.json, opts, client).await? {
        Some(m) => m,
        None => return Ok(()),
    };
    let name = meta.name.clone();

    // Clone once; analysis and build both read this exact tree (no TOCTOU).
    let sp = (!cli.json).then(|| {
        ui::spinner(
            &i18n::fill(i18n::t(opts.lang, K::Cloning), Some(&name)),
            opts,
        )
    });
    let repo = ClonedRepo::clone(&name).await?;
    let sources = repo.read_sources()?;
    if let Some(sp) = sp {
        ui::finish_spinner(sp);
    }

    let prior = approvals.approved_digest(&name).map(|s| s.to_string());
    let report = pkgbuild::analyze(
        Some(&meta),
        &sources,
        config,
        prior.as_deref(),
        chrono::Utc::now(),
    );
    present(&report, cli, opts)?;

    if !decide(&report, cli, threshold, opts) {
        return Ok(());
    }

    repo.build().await?;

    // Record approval digest + ledger entry on success.
    let digest = diff::digest(&sources.pkgbuild, &sources.install_scripts);
    approvals.approve(&name, digest).ok();
    installer::record_installed(&name).ok();
    ui::success(
        &i18n::fill(i18n::t(opts.lang, K::Installed), Some(&name)),
        opts,
    );
    Ok(())
}

/// Decide whether to proceed with an install given flags, policy, and risk.
fn decide(report: &Report, cli: &Cli, threshold: FailOn, opts: UiOptions) -> bool {
    if cli.skip_confirm {
        if threshold.blocks(report.risk) {
            ui::error(
                &format!(
                    "{:?} risk meets the --fail-on threshold; refusing to auto-install.",
                    report.risk
                ),
                opts,
            );
            return false;
        }
        return true;
    }
    if cli.json {
        // Non-interactive JSON mode never installs implicitly.
        return false;
    }
    ui::confirm_install(report, opts)
}

/// `-Q`: list packages recorded in the local ledger.
fn query(opts: UiOptions) -> Result<i32> {
    let entries = installer::read_ledger()?;
    if entries.is_empty() {
        ui::error("No packages installed via aurguard yet.", opts);
        return Ok(0);
    }
    for e in entries {
        println!("{}\t{}", e.package, e.installed_at);
    }
    Ok(0)
}
