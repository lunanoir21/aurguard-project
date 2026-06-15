# aurguard — Security Roadmap (Tier 1 + Tier 2)

This document is the **spec and base ruleset** for the next wave of detection
work. It is written before implementation so the finding codes, severities, and
matching semantics are fixed up front and stay consistent across modules.

## Detection model (current → target)

Today analysis is **line-local**: the AST pass (`astscan`), textual heuristics
(`pkgbuild`), and the YARA-style signature engine (`rules`) each look at one line
(or the whole document for a few rules) at a time. That misses three classes of
evasion:

1. **Encoding** — payload hidden in a base64/hex blob that is decoded at runtime.
2. **Splitting** — a malicious command assembled across lines/variables, or
   broken up with quotes/`${IFS}` so no single line matches.
3. **Out-of-PKGBUILD** — malware that lives in the cloned source tree (a shell
   script, a `setup.py`, or a committed binary), not in the `PKGBUILD` itself.

Tier 1 attacks evasion (decode, fold, taint, entropy). Tier 2 adds
intelligence and integrity (updatable signatures, IOCs, version delta, source
scan). All passes feed the **same** `Finding { severity, code, message, line,
arg }` pipeline and the i18n catalog.

### Severity contract (unchanged)

`Info < Warn < Critical`. A package's risk is the max severity of its findings.
A new pass must **never silently downgrade** an existing finding; it may only add
findings or, for delta analysis, re-tag an existing one as newly-introduced.

### False-positive contract

Every new rule that can fire on legitimate packaging MUST honour the
`$pkgdir`/`$srcdir` veto already used by `rules::SigRule::not`. New passes are
expected to *raise* precision, so each ships with a focused unit test plus at
least one "clean package stays clean" guard.

---

## Tier 1 — anti-evasion

### T1.1 Decode-and-rescan — `decode.rs`

**Goal:** decode embedded blobs and re-run the existing matchers on the result.

Base rules:

- **Blob detection.** A token is a candidate when it is a contiguous run of the
  base64 alphabet `[A-Za-z0-9+/=]` of length ≥ 24 with a valid base64 length, or
  a hex run `[0-9a-fA-F]` of length ≥ 40, or a `\xNN`-escape sequence of ≥ 8
  bytes.
- **Decode.** base64 → bytes; hex → bytes. Keep only if ≥ 80 % of decoded bytes
  are printable ASCII or newline (otherwise it is real binary data, not a script).
- **Rescan.** Run `rules::scan_line` + `pkgbuild::scan_dangerous_line` over the
  decoded text. Any inner hit is re-emitted under a wrapper code so the user sees
  *both* "there was a hidden blob" and *what* it contained.
- **Recursion.** Decode nested blobs up to **depth 3**; stop earlier if no blob.

Findings:

| Code              | Severity | Meaning                                                        |
| ----------------- | -------- | ------------------------------------------------------------- |
| `DECODED_THREAT`  | Critical | A decoded blob contained another dangerous pattern (`arg` = inner code) |
| `ENCODED_BLOB`    | Warn     | A decodable blob with no inner hit (suspicious but not proven) |

### T1.2 Normalize / constant-fold — `normalize.rs`

**Goal:** defeat token-splitting before matching.

Base rules — `normalize(line, vars) -> String` applies, in order:

1. Remove empty quote pairs that only split tokens: `""`, `''` → removed
   (`h""ttp` → `http`). Backslash-escapes of word chars: `\b` → `b`.
2. Collapse `${IFS}` and `$IFS` → a single space.
3. Substitute variables that have a **single literal definition** from `vars`
   (built by the taint pass below): `${name}`/`$name` → value. Cap expansion to
   2 rounds to avoid loops.
4. Lower-case for matching only (display keeps the raw line).

Rule: matchers run on **both** raw and normalized text. If a pattern matches the
normalized form but **not** the raw form, additionally emit `EVASION_NORMALIZED`
(Warn) — assembling a command only after de-obfuscation is itself a signal.

### T1.3 Dataflow / taint — extends `astscan.rs` (new `taint.rs`)

**Goal:** catch `u=…evil…; curl $u | sh` style cross-line attacks.

Base rules:

- **Var table.** From AST `variable_assignment` nodes collect `name → value`
  (last write wins; arrays joined). Exposed to `normalize`.
- **Taint sources.** A value is tainted if it contains a URL, a command
  substitution running `curl`/`wget`/`fetch`, a decoded blob (T1.1), or is
  derived (`b=$a`) from a tainted var. Fixpoint, max 5 iterations.
- **Sinks.** `eval`, pipe-into-shell, `sh -c`/`bash -c`, `source`/`.`, and direct
  execution of a variable (`$cmd`, `"$x"`).
- **Rule `TAINTED_EXEC` (Critical):** a sink consumes a tainted variable.
  `arg` names the variable. This is independent of (and additive to) the existing
  `CURL_PIPE_SH`/`EVAL` line rules.

### T1.4 Entropy — folded into `decode.rs`

Base rules:

- Shannon entropy (bits/char) over each quoted string or token of length ≥ 40.
- Exclude known-benign high-entropy: checksum lines (`*sums=`), full URLs, and
  git commit hashes on `source=`/`*sums=` lines.
- **Rule `HIGH_ENTROPY_BLOB` (Warn)** when entropy > 4.3 and length ≥ 40.
- If the same token also decodes (T1.1), suppress `HIGH_ENTROPY_BLOB` in favour
  of the stronger `DECODED_THREAT`/`ENCODED_BLOB`.

---

## Tier 2 — intelligence & integrity

### T2.1 External updatable ruleset — `ruleset.rs`

**Goal:** ship/upgrade signatures without recompiling.

Base rules:

- **Format (TOML).** `~/.config/aurguard/rules.d/*.toml`:
  ```toml
  version = 3            # ruleset revision
  [[rule]]
  code      = "CRYPTO_MINER"
  severity  = "critical" # info|warn|critical
  tags      = ["miner"]
  message   = "Cryptocurrency miner signature ({})"
  clauses   = [["xmrig", "stratum+tcp"], ["-o", "--url"]]   # CNF
  not       = ["$pkgdir"]
  ```
- **Merge.** Built-in `rules::RULES` is the floor. A user/remote rule with the
  same `code` **overrides** the built-in (allows tuning); a new `code` is added.
- **`aurguard --update-rules`.** Fetch a versioned ruleset from the configured
  `rules_url` (default: project raw URL) into `rules.d/`, parse-and-validate into
  the in-memory model **before** replacing the file. Never apply a ruleset that
  fails to parse. Print old→new `version`.
- **Trust.** The fetch is over HTTPS to a pinned host; a malformed or
  lower-`version` ruleset is rejected. (No silent downgrade.)

### T2.2 IOC blocklist — `ioc.rs`

Base rules:

- **`ioc.toml`** (bundled seed + updatable): `domains`, `ip_cidrs`, `sha256`,
  and `wallet_regexes`.
- Match IOCs against: extracted source hosts, every URL token, and free tokens in
  the script.
- **`IOC_MATCH` (Critical):** a token matches a known-bad domain/IP/hash; `arg`
  is the indicator.
- **`WALLET_ADDRESS` (Warn):** a BTC (`bc1…`/`1…`/`3…`), ETH (`0x` + 40 hex), or
  XMR (`4…`/`8…`, 95 chars) address literal appears — strong miner/exfil signal in
  a build script. Seeded regexes ship in-binary so this works with no feed.

### T2.3 AUR version delta + maintainer change — extends `diff.rs` + `installer.rs`

Base rules (we already clone-first, so the git history is local):

- **Delta.** Analyze `PKGBUILD` at `HEAD` and at `HEAD~1` (when present). A
  finding present now but absent before is **newly introduced**:
  - **`DELTA_NEW_RISK` (Warn, escalates to Critical if the inner finding is
    Critical):** `arg` = inner code. Surfaced in its own report section.
- **Maintainer.** Store last-seen `Maintainer` in the approvals ledger.
  - **`MAINTAINER_CHANGED` (Warn):** RPC maintainer differs from the stored one.
  - Escalate to **Critical** when a maintainer change coincides with a **new
    source domain** in the same delta (classic account-takeover supply-chain).

### T2.4 Source-tree + committed-binary scan — `srcscan.rs`, called from `installer.rs`

Base rules (runs on the cloned tree, excluding `.git`):

- **Text files.** Files matching `*.sh`, `*.bash`, `Makefile`, `*.mk`,
  `configure`, `*.install`, `setup.py`, `build.rs`, `*.py`, `*.js`, `*.pl`,
  `*.rb` are scanned with `rules::scan_line` + decode + taint. Inner hits are
  re-emitted with the file path in `arg`.
- **Committed binaries.** Any file whose leading bytes are an executable magic
  (`\x7fELF`, `MZ`, Mach-O `\xfe\xed\xfa..`/`\xcf\xfa\xed\xfe`) that is **not** a
  build product (i.e. present in the source checkout) →
  **`COMMITTED_BINARY` (Critical):** prebuilt executables in an AUR source tree
  are a top malware vector; `arg` = path.
- **Caps.** Skip files > 5 MiB and known-data extensions (images, archives,
  fonts) to bound work.

---

## Implementation order & guardrails

1. `decode.rs` (T1.1 + T1.4) — self-contained, no new deps.
2. `normalize.rs` (T1.2) — pure function, unit-tested in isolation.
3. `taint.rs` (T1.3) — reuses the tree-sitter parser already loaded by `astscan`.
4. `ruleset.rs` (T2.1) — TOML loader; `--update-rules` flag in `main.rs`.
5. `ioc.rs` (T2.2) — seeded data + matcher.
6. delta + maintainer (T2.3) — extend `diff.rs`/`installer.rs`.
7. `srcscan.rs` (T2.4) — walk the clone in `installer.rs`.

Each step lands with: new i18n entries for every new code in all 5 languages,
unit + integration tests (including a clean-package guard), and `cargo fmt` +
`clippy -D warnings` + `test` green before moving on. No new runtime dependency
is added without checking it cross-compiles to `aarch64` (CI matrix).

### New finding codes (summary)

`DECODED_THREAT`, `ENCODED_BLOB`, `EVASION_NORMALIZED`, `TAINTED_EXEC`,
`HIGH_ENTROPY_BLOB`, `IOC_MATCH`, `WALLET_ADDRESS`, `DELTA_NEW_RISK`,
`MAINTAINER_CHANGED`, `COMMITTED_BINARY`.
