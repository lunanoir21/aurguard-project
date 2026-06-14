# aurguard — Build Tasks

Status legend: ⬜ todo · 🔨 in progress · ✅ done

## Phase 0 — Scaffolding
- ✅ T0.1  Create `Cargo.toml` with deps + release profile (`opt-level=z`, `strip`, `lto`)
- ✅ T0.2  Create `LICENSE` (MIT)
- ✅ T0.3  Create `.gitignore`
- ✅ T0.4  Create module skeleton (`main`, `aur`, `pkgbuild`, `report`, `ui`, `installer`)

## Phase 1 — Core types & errors
- ✅ T1.1  `report.rs`: `Severity`, `Finding`, `Risk`, `Report` types + JSON serde
- ✅ T1.2  CLI definition in `main.rs` via clap derive (all flags/commands)

## Phase 2 — AUR client
- ✅ T2.1  `aur.rs`: RPC v5 `info` request + response structs
- ✅ T2.2  `aur.rs`: PKGBUILD raw fetch (cgit plain endpoint)
- ✅ T2.3  Error handling: package-not-found, network, non-200

## Phase 3 — Static analyzer
- ✅ T3.1  `pkgbuild.rs`: source URL extraction + host classification
- ✅ T3.2  CRITICAL rules (eval, base64|sh, curl|sh, http source, IP url, chmod+exec)
- ✅ T3.3  WARN rules (unknown domain, /tmp exec, install(), git clone, maintainer age, low votes)
- ✅ T3.4  INFO rules (stale, pkgrel churn, git+ source)
- ✅ T3.5  Aggregate findings → overall `Risk`

## Phase 4 — UI
- ✅ T4.1  `ui.rs`: spinner helpers (indicatif, dim dot style)
- ✅ T4.2  Box-drawing report panel renderer (color + `--no-color`)
- ✅ T4.3  Confirmation prompts per risk level
- ✅ T4.4  JSON output path

## Phase 5 — Installer
- ✅ T5.1  `installer.rs`: dependency preflight (git, makepkg)
- ✅ T5.2  temp dir + git clone + `makepkg -si` + cleanup
- ✅ T5.3  Installed-package ledger for `-Q` query

## Phase 6 — Wiring & polish
- ✅ T6.1  `main.rs`: dispatch `-S` / `-I` / `-Q`, async flow, exit codes
- ✅ T6.2  Doc comments on all public items
- ✅ T6.3  Unit tests: each CRITICAL rule, AUR parse, report render smoke

## Phase 7 — Distribution
- ✅ T7.1  npm wrapper (`package.json` + `install.js`)
- ✅ T7.2  GitHub Actions: `ci.yml` + `release.yml`

## Phase 8 — Verify
- ✅ T8.1  `cargo fmt --check`
- ✅ T8.2  `cargo clippy -- -D warnings` → zero
- ✅ T8.3  `cargo test` → green
- ✅ T8.4  `cargo build --release` → binary

## Phase 9 — Advanced hardening (roadmap)
- ✅ T9.1  Split into `lib.rs` + thin `main.rs`; add `tests/` integration suite
- ✅ T9.2  TOCTOU fix: `ClonedRepo` — clone once, analyze + build the same tree
- ✅ T9.3  Fetch + analyze `.install` scriptlets (root-privileged hooks)
- ✅ T9.4  `pkgver()`/function bodies covered (AST scans whole script)
- ✅ T9.5  `astscan.rs` — tree-sitter-bash AST pass (obfuscation-resistant eval/pipe)
- ✅ T9.6  SKIP-checksum + widened decoder/downloader detection
- ✅ T9.7  Download-then-exec (two-line fetch+run) detection
- ✅ T9.8  `diff.rs` — approved-PKGBUILD SHA-256 ledger → `PKGBUILD_CHANGED`
- ✅ T9.9  `config.rs` — trusted domains, rule ignores, `fail_on` policy
- ✅ T9.10 Inline `# aurguard:ignore CODE` / `:ignore-all` directives
- ✅ T9.11 `--file` local analysis (offline, CI for your own PKGBUILDs)
- ✅ T9.12 `--fail-on <sev>` threshold + batch `-S/-I pkg1 pkg2 …` (resilient)
- ✅ T9.13 `is-terminal` for TTY detection (dropped raw `isatty` extern)
- ✅ T9.14 `install.sh` — build, install binary, write default config

## Phase 10 — Re-verify (advanced)
- ✅ T10.1 `cargo clippy -- -D warnings` → zero
- ✅ T10.2 `cargo test` → 54 unit + 7 integration green
- ✅ T10.3 Live: `--file` malicious sample → all CRITICALs + .install caught
- ✅ T10.4 Live: batch `-I`, `--json`, `--fail-on` validation
- ✅ T10.5 `install.sh` end-to-end → `aurguard` on PATH

## Phase 11 — Search fallback ("did you mean…")
- ✅ T11.1 `aur::search_by_name` — RPC v5 search, sort by votes, cap 12
- ✅ T11.2 `ui::pick_suggestion` — numbered list (votes/desc/out-of-date) + prompt
- ✅ T11.3 `resolve()` — exact `info`, else search; spinner stops before prompt
- ✅ T11.4 Wire into `-S` and `-I`; chosen name drives clone/approve/ledger
- ✅ T11.5 Live: `aurguard -S opencode` → 12 matches, pick → opencode-bin report

## Phase 12 — Deeper security rules
- ✅ T12.1 REVERSE_SHELL (/dev/tcp, nc -e, bash -i to socket, mkfifo backpipe)
- ✅ T12.2 SUID_BIT (chmod u+s / 4755)
- ✅ T12.3 SYSTEM_PATH_WRITE (writes to /etc,/usr,… outside $pkgdir/$srcdir)
- ✅ T12.4 HOME_PERSIST (.bashrc, .ssh/authorized_keys, crontab, autostart)
- ✅ T12.5 USER_MGMT (useradd/usermod/sudoers/visudo)
- ✅ T12.6 DESTRUCTIVE (rm -rf /, dd to disk, mkfs, fork bomb)
- ✅ T12.7 PYTHON_ENC_EXEC (python/perl/ruby -c with exec/base64)
- ✅ T12.8 ANTI_FORENSIC (history -c, chattr +i, shred logs)
- ✅ T12.9 OBFUSCATION (\\xNN hex escapes, ${IFS})
- ✅ T12.10 URL_SHORTENER (bit.ly, tinyurl, … hide real host)

## Phase 13 — i18n + setup wizard
- ✅ T13.1 `i18n.rs` — Lang {En,Tr,Fr,Es,Az} + UI + finding catalogs
- ✅ T13.2 `Finding.arg` + localize pass (templates keep dynamic detail)
- ✅ T13.3 Localized panel labels, prompts, suggestions, relative time
- ✅ T13.4 `config [ui] lang/color`; `--lang` per-run override
- ✅ T13.5 `wizard.rs` — `aurguard --setup` (language-first, writes config.toml)
- ✅ T13.6 Localized affirmatives (e/o/s/b…) in prompts
- ✅ T13.7 Live: Türkçe panel, Azərbaycan wizard, fr/az finding messages
- ✅ T13.8 74 tests green (62 unit + 12 integration), clippy/fmt clean

## Phase 14 — Release CI (npm + crates.io)
- ✅ T14.1 `release.yml`: version synced from `v*` tag → Cargo.toml + package.json
- ✅ T14.2 aarch64 build sets `CC_*` so tree-sitter-bash C cross-compiles
- ✅ T14.3 npm publish via `secrets.NPM_TOKEN`, `--provenance`, `id-token: write`
- ✅ T14.4 crates.io publish via `secrets.CARGO_REGISTRY_TOKEN`
- ✅ T14.5 Missing-token steps skip cleanly (no failed pipeline)
- ✅ T14.6 Least-privilege perms; YAML validated
- ⬜ T14.7 USER: add `NPM_TOKEN` (and `CARGO_REGISTRY_TOKEN`) repo secrets
