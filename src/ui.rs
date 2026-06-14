//! Terminal presentation: spinners, the box-drawing report panel, confirmation
//! prompts, and the JSON projection.
//!
//! All human output goes to **stderr** so that `makepkg`'s build output on
//! stdout stays clean and pipeable. Color is centrally gated by [`UiOptions`]
//! so `--no-color` and `--json` fully suppress ANSI codes.

use crate::aur::SearchHit;
use crate::i18n::{fill, t, Lang, K};
use crate::report::{Report, Risk, Severity};
use anyhow::Result;
use colored::{Color, Colorize};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, BufRead, Write};
use std::time::Duration;

/// Inner width of the report panel (characters between the border bars).
const PANEL_WIDTH: usize = 60;

/// Column width of the label gutter (fits the longest localized label).
const LABEL_W: usize = 14;

/// Presentation options resolved from CLI flags and config.
#[derive(Debug, Clone, Copy)]
pub struct UiOptions {
    /// Emit ANSI colors.
    pub color: bool,
    /// Interface language.
    pub lang: Lang,
}

impl UiOptions {
    /// Resolve options. `no_color` (from `--no-color`/`--json`) forces color
    /// off; otherwise `color_override` (config) wins, else auto-detect the TTY.
    pub fn new(no_color: bool, color_override: Option<bool>, lang: Lang) -> Self {
        let color = if no_color {
            false
        } else {
            color_override.unwrap_or_else(atty_stderr)
        };
        // `colored` reads this global too; keep them in sync.
        colored::control::set_override(color);
        UiOptions { color, lang }
    }
}

/// Whether stderr is a terminal (gates color auto-detection).
fn atty_stderr() -> bool {
    use is_terminal::IsTerminal;
    std::io::stderr().is_terminal()
}

/// Start a dim, dot-style spinner with `msg`. Returns the handle; call
/// [`finish_spinner`] to clear it.
pub fn spinner(msg: &str, opts: UiOptions) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(90));
    let style = if opts.color {
        ProgressStyle::with_template("{spinner:.dim} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "✓"])
    } else {
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_strings(&[".", "..", "...", "..", "."])
    };
    pb.set_style(style);
    pb.set_message(msg.to_string());
    pb
}

/// Clear a spinner so it leaves no residue on the terminal.
pub fn finish_spinner(pb: ProgressBar) {
    pb.finish_and_clear();
}

/// Render the security report panel to stderr.
pub fn render_report(report: &Report, opts: UiOptions) {
    let mut out = io::stderr().lock();
    // Ignore write errors to stderr — nothing useful to do if it fails.
    let _ = write_report(&mut out, report, opts);
}

/// Write the panel into an arbitrary sink (extracted for testability).
pub fn write_report<W: Write>(w: &mut W, report: &Report, opts: UiOptions) -> io::Result<()> {
    let pad = |label: &str, value: String| -> String {
        let line = format!("  {label:<LABEL_W$} {value}");
        pad_line(&line)
    };

    let lang = opts.lang;
    // Top border: "┌─ <title> <dashes>┐", sized so the interior spans exactly
    // PANEL_WIDTH visible cells regardless of title length.
    let header = t(lang, K::ReportTitle);
    // interior cells used: "─ " (2) + title + " " (1) before the filler dashes.
    let fill = PANEL_WIDTH.saturating_sub(header.chars().count() + 3);
    writeln!(w)?;
    writeln!(w, "  ┌─ {} {}┐", title(header, opts), "─".repeat(fill))?;
    writeln!(w, "  │{}│", " ".repeat(PANEL_WIDTH))?;

    let maint = match &report.maintainer {
        Some(m) => format!("{}  ({})", m, report.maintainer_since_human),
        None if report.maintainer_since_human == "local" => t(lang, K::LocalFile).to_string(),
        None => t(lang, K::Orphaned).to_string(),
    };

    writeln!(
        w,
        "  │{}│",
        pad(
            t(lang, K::LabelPackage),
            format!("{} {}", report.package, report.version)
        )
    )?;
    writeln!(w, "  │{}│", pad(t(lang, K::LabelMaintainer), maint))?;
    writeln!(
        w,
        "  │{}│",
        pad(t(lang, K::LabelVotes), group_thousands(report.votes))
    )?;
    writeln!(
        w,
        "  │{}│",
        pad(
            t(lang, K::LabelLastUpdate),
            report.last_update_human.clone()
        )
    )?;
    writeln!(w, "  │{}│", pad_line(""))?;

    // Sources line.
    let sources = if report.sources.is_empty() {
        t(lang, K::NoneDeclared).to_string()
    } else {
        report
            .sources
            .iter()
            .map(|s| {
                let mark = if s.trusted {
                    mark_ok(opts)
                } else {
                    mark_bad(opts)
                };
                format!("{} {}", s.host, mark)
            })
            .collect::<Vec<_>>()
            .join("   ")
    };
    // Source marks contain ANSI; pad on the visible length.
    let src_prefix = format!("  {:<LABEL_W$} ", t(lang, K::LabelSources));
    writeln!(w, "  │{}│", pad_visible(&src_prefix, &sources))?;

    if report.findings.is_empty() {
        writeln!(
            w,
            "  │{}│",
            pad(
                t(lang, K::LabelFindings),
                colorize(t(lang, K::NoneDetected), Color::Green, opts)
            )
        )?;
    } else {
        writeln!(
            w,
            "  │{}│",
            pad_line(&format!("  {}", t(lang, K::LabelFindings)))
        )?;
        // Fixed visible prefix: 2 spaces + glyph + 2 spaces + 9-wide severity.
        const PREFIX: usize = 2 + 1 + 2 + 9;
        let avail = PANEL_WIDTH.saturating_sub(PREFIX);
        for f in &report.findings {
            let glyph = colorize(f.severity.glyph(), severity_color(f.severity), opts);
            let sev = colorize(
                &format!("{:<9}", f.severity.label()),
                severity_color(f.severity),
                opts,
            );
            let loc = f.line.map(|l| format!(" (line {l})")).unwrap_or_default();
            // Message + location is plain text; truncate to fit before coloring.
            let text = truncate_visible(&format!("{}{}", f.message, loc), avail);
            let body = format!("  {glyph}  {sev}{text}");
            writeln!(w, "  │{}│", pad_visible_raw(&body))?;
        }
    }

    writeln!(w, "  │{}│", " ".repeat(PANEL_WIDTH))?;
    writeln!(w, "  └{}┘", "─".repeat(PANEL_WIDTH))?;
    writeln!(w)?;
    Ok(())
}

/// Print the report as pretty JSON to stdout. Used by `--json`.
pub fn print_json(report: &Report) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{json}");
    Ok(())
}

/// Prompt the user to confirm an install, wording and default keyed to risk.
///
/// Returns `true` to proceed. Reads a single line from stdin; EOF or any
/// non-`y` answer is treated as "no". For `Critical`, the default is firmly No.
pub fn confirm_install(report: &Report, opts: UiOptions) -> bool {
    let lang = opts.lang;
    let prompt = match report.risk {
        Risk::Clean => format!(
            "  {}",
            fill(t(lang, K::PromptInstall), Some(&report.package))
        ),
        Risk::Risky => format!(
            "  {}  {}",
            colorize("⚠", Color::Yellow, opts),
            t(lang, K::PromptRisky)
        ),
        Risk::Critical => format!(
            "  {}  {}",
            colorize("✖", Color::Red, opts),
            t(lang, K::PromptCritical)
        ),
    };

    eprint!("{prompt}");
    let _ = io::stderr().flush();

    let mut line = String::new();
    let stdin = io::stdin();
    if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
        eprintln!();
        return false; // EOF → No
    }
    is_affirmative(line.trim())
}

/// Whether `s` is an affirmative answer in any supported language.
fn is_affirmative(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "y" | "yes" | "e" | "evet" | "o" | "oui" | "s" | "si" | "sí" | "b" | "bəli" | "beli"
    )
}

/// Show "did you mean…" suggestions for `query` and, when `interactive`, let
/// the user pick one. Returns the chosen package name, or `None` to cancel.
///
/// In non-interactive mode the list is printed for reference and `None` is
/// returned (aurguard never auto-picks a different package).
pub fn pick_suggestion(
    query: &str,
    hits: &[SearchHit],
    interactive: bool,
    opts: UiOptions,
) -> Option<String> {
    let lang = opts.lang;
    let mut err = io::stderr().lock();
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {}  {}",
        colorize("?", Color::Yellow, opts),
        fill(t(lang, K::SuggestHeader), Some(query))
    );
    let _ = writeln!(err);

    let width = hits.len().to_string().len();
    for (i, h) in hits.iter().enumerate() {
        let votes = format!(
            "{} {}",
            group_thousands(h.num_votes),
            t(lang, K::SuggestVotes)
        );
        let ood = if h.out_of_date.is_some() {
            colorize(t(lang, K::SuggestOutOfDate), Color::Red, opts)
        } else {
            String::new()
        };
        let desc = h
            .description
            .as_deref()
            .map(|d| truncate_visible(d, 52))
            .unwrap_or_default();
        let _ = writeln!(
            err,
            "  {:>w$}  {} {}   {:>12}{}",
            colorize(&(i + 1).to_string(), Color::Cyan, opts),
            colorize(&h.name, Color::Green, opts),
            h.version,
            votes,
            ood,
            w = width
        );
        if !desc.is_empty() {
            let _ = writeln!(err, "  {:>w$}  {}", "", desc.dimmed(), w = width);
        }
    }
    let _ = writeln!(err);

    if !interactive {
        let _ = writeln!(
            err,
            "  {}",
            fill(t(lang, K::SuggestRerun), Some(&hits[0].name))
        );
        return None;
    }

    let _ = write!(
        err,
        "  {}",
        fill(t(lang, K::SuggestSelect), Some(&hits.len().to_string()))
    );
    let _ = err.flush();

    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        let _ = writeln!(err);
        return None;
    }
    match line.trim().parse::<usize>() {
        Ok(n) if n >= 1 && n <= hits.len() => Some(hits[n - 1].name.clone()),
        _ => None,
    }
}

/// Print a success line to stderr.
pub fn success(msg: &str, opts: UiOptions) {
    eprintln!("  {}  {}", colorize("✓", Color::Green, opts), msg);
}

/// Print an error line to stderr.
pub fn error(msg: &str, opts: UiOptions) {
    eprintln!("  {}  {}", colorize("✖", Color::Red, opts), msg);
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

/// Map a severity to its display color.
fn severity_color(sev: Severity) -> Color {
    match sev {
        Severity::Info => Color::Blue,
        Severity::Warn => Color::Yellow,
        Severity::Critical => Color::Red,
    }
}

/// Apply color when enabled, else return the string unchanged.
fn colorize(s: &str, color: Color, opts: UiOptions) -> String {
    if opts.color {
        s.color(color).to_string()
    } else {
        s.to_string()
    }
}

/// Bold the panel title when color is on.
fn title(s: &str, opts: UiOptions) -> String {
    if opts.color {
        s.bold().to_string()
    } else {
        s.to_string()
    }
}

/// Green check mark.
fn mark_ok(opts: UiOptions) -> String {
    colorize("✓", Color::Green, opts)
}

/// Red cross mark.
fn mark_bad(opts: UiOptions) -> String {
    colorize("✗", Color::Red, opts)
}

/// Group an integer with thousands separators: `2847 → "2,847"`.
fn group_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i != 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// Right-pad a plain (ANSI-free) line to the panel width.
fn pad_line(s: &str) -> String {
    let len = s.chars().count();
    if len >= PANEL_WIDTH {
        truncate_visible(s, PANEL_WIDTH)
    } else {
        format!("{s}{}", " ".repeat(PANEL_WIDTH - len))
    }
}

/// Pad a label + ANSI-bearing value, accounting only for visible width.
fn pad_visible(prefix: &str, ansi_value: &str) -> String {
    let visible = prefix.chars().count() + visible_len(ansi_value);
    let body = format!("{prefix}{ansi_value}");
    if visible >= PANEL_WIDTH {
        body
    } else {
        format!("{body}{}", " ".repeat(PANEL_WIDTH - visible))
    }
}

/// Pad a fully-built ANSI line to panel width by visible length.
fn pad_visible_raw(ansi_line: &str) -> String {
    let visible = visible_len(ansi_line);
    if visible >= PANEL_WIDTH {
        ansi_line.to_string()
    } else {
        format!("{ansi_line}{}", " ".repeat(PANEL_WIDTH - visible))
    }
}

/// Count visible characters in a string, skipping ANSI escape sequences.
fn visible_len(s: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for c in s.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else if c == '\u{1b}' {
            in_escape = true;
        } else {
            count += 1;
        }
    }
    count
}

/// Truncate a plain string to `max` visible chars with an ellipsis.
fn truncate_visible(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Finding, SourceHost};

    fn sample(findings: Vec<Finding>, sources: Vec<SourceHost>) -> Report {
        let mut r = Report {
            package: "firefox".into(),
            version: "126.0-1".into(),
            maintainer: Some("heftig".into()),
            maintainer_since: None,
            votes: 2847,
            last_modified: None,
            last_update_human: "2 days ago".into(),
            maintainer_since_human: "since 2009".into(),
            risk: Risk::Clean,
            sources,
            findings,
        };
        r.finalize();
        r
    }

    #[test]
    fn group_thousands_works() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(42), "42");
        assert_eq!(group_thousands(2847), "2,847");
        assert_eq!(group_thousands(1_000_000), "1,000,000");
    }

    #[test]
    fn visible_len_skips_ansi() {
        let colored = "\u{1b}[31m✖\u{1b}[0m";
        assert_eq!(visible_len(colored), 1);
        assert_eq!(visible_len("abc"), 3);
    }

    #[test]
    fn render_smoke_clean() {
        let opts = UiOptions {
            color: false,
            lang: Lang::En,
        };
        let report = sample(
            vec![],
            vec![SourceHost {
                host: "github.com".into(),
                trusted: true,
            }],
        );
        let mut buf = Vec::new();
        write_report(&mut buf, &report, opts).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("firefox 126.0-1"));
        assert!(s.contains("heftig"));
        assert!(s.contains("2,847"));
        assert!(s.contains("None detected"));
        assert!(s.contains("┌─"));
        assert!(s.contains("└"));
    }

    #[test]
    fn render_smoke_with_findings() {
        let opts = UiOptions {
            color: false,
            lang: Lang::En,
        };
        let report = sample(
            vec![
                Finding::meta(Severity::Warn, "LOW_VOTES", "Low community trust (2 votes)"),
                Finding::at(Severity::Critical, "CURL_PIPE_SH", "curl piped to bash", 14),
            ],
            vec![SourceHost {
                host: "unknown-site.ru".into(),
                trusted: false,
            }],
        );
        let mut buf = Vec::new();
        write_report(&mut buf, &report, opts).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("CRITICAL"));
        assert!(s.contains("line 14"));
        assert!(s.contains("unknown-site.ru"));
    }

    #[test]
    fn panel_lines_are_aligned() {
        // Every interior line must close its right border at the same column.
        let opts = UiOptions {
            color: false,
            lang: Lang::En,
        };
        let report = sample(
            vec![Finding::at(Severity::Critical, "X", "some finding", 3)],
            vec![SourceHost {
                host: "github.com".into(),
                trusted: true,
            }],
        );
        let mut buf = Vec::new();
        write_report(&mut buf, &report, opts).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let expected = 2 + 1 + PANEL_WIDTH + 1; // indent + bar + body + bar
        for line in s.lines().filter(|l| l.starts_with("  │")) {
            assert_eq!(line.chars().count(), expected, "misaligned: {line:?}");
        }
        // Top and bottom borders must match the interior width too.
        let top = s.lines().find(|l| l.starts_with("  ┌")).unwrap();
        let bottom = s.lines().find(|l| l.starts_with("  └")).unwrap();
        assert_eq!(top.chars().count(), expected, "top border: {top:?}");
        assert_eq!(
            bottom.chars().count(),
            expected,
            "bottom border: {bottom:?}"
        );
    }
}
