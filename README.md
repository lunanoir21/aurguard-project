<h1 align="center">aurguard</h1>

<p align="center"><strong>AUR package security guard — analyze before you install.</strong></p>

<p align="center">
  <img alt="MIT License" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Arch%20Linux-1793D1?logo=archlinux&logoColor=white">
  <img alt="Built with Rust" src="https://img.shields.io/badge/built%20with-Rust-CE412B?logo=rust&logoColor=white">
  <img alt="Languages" src="https://img.shields.io/badge/i18n-en%20·%20tr%20·%20fr%20·%20es%20·%20az-9558B2">
  <a href="https://github.com/lunanoir21/aurguard-project/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/lunanoir21/aurguard-project/actions/workflows/ci.yml/badge.svg"></a>
</p>

`aurguard` is a small, fast CLI that sits between you and the [Arch User Repository](https://aur.archlinux.org/). Before any package touches `makepkg`, it fetches the package metadata and the raw `PKGBUILD`, runs a static security analysis, and shows you a clean report. You decide whether to install — with the risks in front of you.

No API keys. No telemetry. No accounts. Just the public AUR RPC API and offline static analysis. The whole interface is available in **English, Türkçe, Français, Español, and Azərbaycan**.

---

## Why

The AUR is community-maintained and **unvetted by design**. A `PKGBUILD` is an arbitrary bash script that runs on your machine with your permissions. Most are fine. Some are not. The standard advice — "always read the PKGBUILD" — is correct but rarely followed, because reading shell scripts for malicious patterns is tedious and easy to get wrong.

`aurguard` automates the first pass: it flags the patterns that matter (piped-to-shell installers, obfuscated payloads, plain-HTTP sources, suspiciously new maintainers) and surfaces the trust signals (votes, maintainer age, last update) so the read is fast and the decision is informed.

It does **not** replace reading the script yourself for anything sensitive. It raises the floor, not the ceiling.

---

## Install

### From source (recommended)

```sh
git clone https://github.com/lunanoir21/aurguard-project.git
cd aurguard-project
./install.sh
```

`install.sh` builds the release binary, installs it to `~/.local/bin` (override
with `PREFIX=/usr/local ./install.sh` for a system-wide install), writes a
default config to `~/.config/aurguard/config.toml`, and tells you if anything is
missing from your `PATH`. Re-run it any time to upgrade; `./install.sh
--uninstall` removes the binary.

### From crates.io

```sh
cargo install aurguard
```

### From npm

```sh
npm install -g aurguard
```

The npm package is a thin launcher with **no install script**. The prebuilt
binary ships as a platform-specific optional dependency
(`aurguard-linux-x64` / `aurguard-linux-arm64`); npm installs only the one
matching your os/cpu. Nothing is downloaded or executed at install time — so
there is **no `postinstall` / `allow-scripts` prompt and no remote-code
supply-chain surface** (the same property aurguard checks for in AUR packages).
The `aurguard` package itself has **zero runtime dependencies**.

> **Build note:** the analyzer embeds the `tree-sitter-bash` grammar, so building
> from source needs a C compiler (`cc`/`gcc`) in addition to the Rust toolchain.

### Requirements

`aurguard` analyzes any package, but **installing** requires an Arch-based system with:

- `git`
- `makepkg` (from `pacman`'s `base-devel`)

If these are missing, `aurguard` tells you clearly and exits:

```
✖  aurguard requires 'makepkg'. Are you running Arch Linux?
```

---

## Usage

<p align="center">
  <img src="assets/demo.gif" alt="aurguard demo — analyzing AUR packages" width="820">
</p>

```
aurguard <package>...       Show the report (no flag = like -I); suggests
                            matches if there is no exact name
aurguard -S <package>...    Analyze and install AUR package(s)
aurguard -I <package>...     Show the security report only (no install)
aurguard --file <PATH>      Analyze a local PKGBUILD (offline)
aurguard --setup            Interactive setup wizard (language, policy, …)
aurguard -Q                 List packages installed via aurguard
aurguard --version          Print version
aurguard --help             Print help
```

`-S` and `-I` accept multiple packages; one bad package does not abort the rest.

**No exact match? aurguard searches.** If a name isn't found, it falls back to an
AUR name search and shows the matching packages (sorted by votes, with
descriptions) so you can pick the one you meant:

```
$ aurguard -S opencode

  ?  No exact match for 'opencode'. 12 similar packages on the AUR:

   1  opencode-bin 1.17.6-1            46 votes
      The AI coding agent built for the terminal.
   2  opencode-desktop-bin 1.17.6-1    11 votes
      OpenCode desktop client
   …
  Select a package to use [1-12], or Enter to cancel:
```

### Options

| Flag                  | Effect                                                              |
| --------------------- | ------------------------------------------------------------------ |
| `--file <PATH>`       | Analyze a local `PKGBUILD` (plus sibling `.install` files), offline |
| `--lang <code>`       | Interface language for this run: `en` \| `tr` \| `fr` \| `es` \| `az` |
| `--setup`             | Run the interactive setup wizard, then exit                        |
| `--no-color`          | Disable all ANSI color codes (for logs / dumb terminals)           |
| `--json`              | Emit the report as JSON instead of the panel (for scripting)       |
| `--skip-confirm`      | Auto-accept unless findings meet the fail-on threshold             |
| `--fail-on <sev>`     | Threshold that blocks `--skip-confirm`: `clean` \| `risky` \| `critical` |

### Examples

```sh
# Analyze + install, with a confirmation prompt
aurguard -S yay

# Several at once
aurguard -S yay paru-bin

# Just look — report only, never installs
aurguard -I some-sketchy-pkg

# Lint your OWN PKGBUILD before pushing it — no network, great for CI
aurguard --file ./PKGBUILD --json

# CI / scripting: machine-readable output
aurguard -I yay --json --no-color

# Trust low/medium-risk packages, block anything Risky or worse
aurguard -S ripgrep-bin --skip-confirm --fail-on risky
```

---

## How it works

Running `aurguard -S <package>` walks through these steps:

```
1. Fetch package info
   GET https://aur.archlinux.org/rpc/v5/info?arg[]=<package>
   → name, version, maintainer, first_submitted, last_modified, num_votes

2. git clone the AUR repo into a temp dir  ← clone-FIRST (see note below)

3. Analyze the cloned PKGBUILD + every referenced .install scriptlet
   → static analysis → list of Findings

4. Render the Security Report panel

5. Prompt for confirmation
   CLEAN    → "Install <package>? [y/N]"
   RISKY    → "⚠  This package has security risks. Install anyway? [y/N]"
   CRITICAL → "✖  Critical risks detected. Install anyway? [y/N]"  (default N)

6. On "y": makepkg -si in the SAME cloned tree → record approval → clean up
   On "n"/Enter: exit 0, nothing installed
```

All diagnostic output goes to **stderr**; only `makepkg`'s build output goes to **stdout**, so piping stays clean.

> **Why clone-first?** A naive design fetches the PKGBUILD for analysis but then
> clones a *separate* copy to build — two reads that can disagree (a race, or a
> moved ref), letting a clean-looking analysis front a malicious build (a TOCTOU
> bypass). aurguard clones **once** and analyzes and builds the exact same tree.
> (`-I` and `--file` never build, so they read directly without cloning.)

### Static analysis

Analysis layers four passes over the build sources (the `PKGBUILD` **and** any
`.install` scriptlets, which run as root on install):

1. **AST pass** — the script is parsed with `tree-sitter-bash`. Because commands,
   pipelines, and command substitutions are real syntax nodes, detection of
   `eval` and pipe-into-shell is robust against quoting tricks (`b""ash`),
   string/comment noise, and here-docs that fool plain substring matching.
2. **Textual rules** — source URLs, checksums, `/tmp` staging, `chmod +x`,
   fetch-then-run, and `git clone` of untrusted repos.
3. **Signature database** — a YARA-style engine (`src/rules.rs`) matches named
   malware signatures: crypto miners, Discord/Telegram exfiltration, credential
   harvesting, SSH/cron persistence, and defense-evasion, with `not`-string
   vetoes to stay quiet on legitimate `$pkgdir` packaging.
4. **Metadata & history** — votes, maintainer age, staleness, `pkgrel` churn,
   plus change-tracking against your last approval.

Each match becomes a `Finding { severity, code, message, line }`. The package's
overall risk is the highest severity among its findings. Findings can be
suppressed globally (config) or inline with `# aurguard:ignore <CODE>`.

Severity levels: **INFO** · **WARN** · **CRITICAL**.

---

## Security checks

### CRITICAL — block by default

| Code              | What it detects                                          | Why it matters                                        |
| ----------------- | -------------------------------------------------------- | ----------------------------------------------------- |
| `EVAL`            | `eval` as a real command (AST-verified)                  | Classic obfuscation / dynamic code execution          |
| `BASE64_PIPE_SH`  | a decoder (`base64`, `xxd`, `openssl`, `gzip`, …) piped to a shell | Hidden payload decoded and run inline        |
| `CURL_PIPE_SH`    | a downloader (`curl`, `wget`, …) piped to a shell        | Remote code executed without inspection               |
| `DOWNLOAD_EXEC`   | a file downloaded, then run on a later line              | Two-step fetch-then-run                                |
| `INSECURE_SOURCE` | a `source=()` entry over plain `http://` or `ftp://`     | Tamperable download — no transport integrity          |
| `IP_SOURCE`       | a URL pointing at a raw IP address (`http://1.2.3.4/…`)  | Evades domain reputation; common in throwaway hosts   |
| `CHMOD_EXEC`      | `chmod +x <file>` immediately followed by executing it   | Drop-and-run pattern                                  |
| `REVERSE_SHELL`   | `/dev/tcp`, `nc -e`, `bash -i` to a socket, `mkfifo` backpipe | Call-home remote control                          |
| `SUID_BIT`        | `chmod u+s` / `4755` on a binary                         | Privilege-escalation backdoor                         |
| `SYSTEM_PATH_WRITE` | writes to `/etc`, `/usr`, `/boot`, … outside `$pkgdir`  | Tampers with the live system, not the package         |
| `USER_MGMT`       | `useradd`/`usermod`/`sudoers`/`visudo`                   | Account or privilege tampering                        |
| `DESTRUCTIVE`     | `rm -rf /`, `dd` to a disk, `mkfs`, fork bomb            | Data-destroying command                               |
| `PYTHON_ENC_EXEC` | `python/perl/ruby -c` with `exec`/base64                 | Encoded inline payload in an interpreter              |

All of the above are detected inside `.install` scriptlets too (which run as root).

### Signature database — YARA-style

In addition to the heuristics above, aurguard ships a small **YARA-style
signature engine** (`src/rules.rs`). Each rule is a named signature with a
severity, classification tags, and a condition in conjunctive normal form
(every clause must match; a clause matches if any alternative is present),
plus negative `not` strings that veto false positives — e.g. a cron file
installed into `$pkgdir` is legitimate packaging, not persistence. The same
ruleset runs over the `PKGBUILD` and over root-privileged `.install` scripts.

| Code               | Severity   | What it detects                                              |
| ------------------ | ---------- | ------------------------------------------------------------ |
| `CRYPTO_MINER`     | CRITICAL   | `xmrig`, `stratum+tcp`, `minerd`, `randomx`, known mining pools |
| `DISCORD_EXFIL`    | CRITICAL   | data sent to a Discord webhook                               |
| `TELEGRAM_EXFIL`   | CRITICAL   | exfiltration via the Telegram bot API                       |
| `SSH_KEY_INJECT`   | CRITICAL   | writing an `authorized_keys` entry outside `$pkgdir`         |
| `CRON_PERSIST`     | CRITICAL   | installing a cron job for persistence                       |
| `CRED_HARVEST`     | CRITICAL   | reading `id_rsa`, `.aws/credentials`, `wallet.dat`, `.netrc`, … |
| `ENV_EXFIL`        | CRITICAL   | piping `printenv`/`/etc/passwd` into a network command       |
| `DISABLE_SECURITY` | CRITICAL   | `setenforce 0`, `iptables -F`, `ufw disable`, stopping firewalld |
| `PASTE_PAYLOAD`    | WARN       | fetching from `pastebin/raw`, `transfer.sh`, `0x0.st`, …      |
| `SYSTEMD_PERSIST`  | WARN       | enabling/starting a systemd service from the build           |
| `INSECURE_FETCH`   | WARN       | `curl -k` / `wget --no-check-certificate` (TLS off)          |
| `PIP_INDEX_HIJACK` | WARN       | `pip install --index-url` pointing at a non-default index    |

### WARN — review recommended

| Code               | What it detects                                         | Why it matters                                        |
| ------------------ | ------------------------------------------------------- | ----------------------------------------------------- |
| `UNKNOWN_SOURCE`   | a source domain outside the trusted allowlist           | e.g. `Unknown source domain: xyz.ru`                  |
| `CHECKSUM_SKIP`    | `*sums=('SKIP')` on a downloaded (non-VCS) source        | Integrity of the download is unverified               |
| `INSTALL_HOOK`     | an `install()` function or `install=` directive          | Extra pacman scriptlet — runs as root                 |
| `INSTALL_NETWORK`  | network access from inside an `.install` scriptlet       | Root-time network fetch is a strong red flag          |
| `TMP_EXEC`         | write to `/tmp` then execute from `/tmp`                 | Staging area for transient payloads                   |
| `GIT_CLONE_UNKNOWN`| `git clone` of an untrusted repo at build time           | Pulls unpinned external code                          |
| `PKGBUILD_CHANGED` | content differs from your last approval                  | Surfaces silent upstream edits even with no other hit |
| `NEW_MAINTAINER`   | maintainer/package age < 6 months                        | Low track record (from `first_submitted`)             |
| `LOW_VOTES`        | `num_votes` < 5                                          | Low community trust                                   |
| `URL_SHORTENER`    | a source behind `bit.ly`/`tinyurl`/…                     | Hides the real download host                          |
| `HOME_PERSIST`     | writes to `.bashrc`, `.ssh/authorized_keys`, crontab, autostart | User-level persistence mechanism              |
| `ANTI_FORENSIC`    | `history -c`, `chattr +i`, shredding logs                | Covers tracks after running                           |
| `OBFUSCATION`      | `\xNN` hex escapes or `${IFS}` word-splitting            | Hiding the real command from a reader                 |

**Trusted source domains:** `github.com`, `gitlab.com`, `archlinux.org`, `sourceforge.net`, `gnu.org`, `kernel.org`, `pypi.org`, `npmjs.com`, `crates.io` — extendable via config.

### INFO — context, not concern

| Code           | What it detects                                  | Why it's noted                                    |
| -------------- | ------------------------------------------------ | ------------------------------------------------- |
| `STALE`        | last updated > 1 year ago                        | Possibly unmaintained                             |
| `PKGREL_CHURN` | `pkgrel` > 3 on the same `pkgver`                | Unusual churn                                     |
| `VCS_SOURCE`   | `source=()` uses a `vcs+` URL (e.g. `git+https`) | Built from VCS HEAD, not a pinned release tarball |

---

## Setup wizard

The fastest way to configure aurguard is the interactive wizard:

```sh
aurguard --setup
```

It asks for your **interface language**, the install **policy**, color
preference, and any extra trusted domains, then writes the config for you. The
language question comes first, so the rest of the wizard is shown in your
language.

## Languages

aurguard's interface — panel labels, prompts, the wizard, suggestions, and the
finding descriptions — is fully localized in:

**English · Türkçe · Français · Español · Azərbaycan**

Set it persistently via the wizard or config (`[ui].lang`), or per-run with
`--lang`:

```sh
aurguard -I yay --lang tr      # Türkçe
aurguard --file ./PKGBUILD --lang az
```

The JSON output (`--json`) keeps stable English-derived `code`s, so scripts work
regardless of the chosen language.

## Configuration

Optional, at `~/.config/aurguard/config.toml` (written by the wizard or
`install.sh`). Every section is optional:

```toml
[ui]
# Interface language: en | tr | fr | es | az
lang = "en"
# Force color on/off; omit for auto-detection.
color = true

[trust]
# Extra domains treated as trusted sources (matched as host or .suffix).
extra_domains = ["git.mycompany.com", "downloads.example.org"]

[rules]
# Finding codes to suppress globally.
ignore = ["VCS_SOURCE", "STALE"]

[policy]
# Risk that blocks a non-interactive (--skip-confirm) install.
# One of: clean | risky | critical
fail_on = "critical"
```

You can also silence a single finding inline in a `PKGBUILD`:

```bash
eval "$cfg"   # aurguard:ignore EVAL
some_line     # aurguard:ignore-all
```

---

## Example: a risky package

```
  ┌─ aurguard — Security Report ───────────────────────────────┐
  │                                                            │
  │  Package      shady-tool 1.0-1                             │
  │  Maintainer   newuser99  (since 3 months ago)             │
  │  Votes        2                                            │
  │  Last update  1 day ago                                    │
  │                                                            │
  │  Sources      unknown-site.ru ✗                            │
  │                                                            │
  │  Findings                                                  │
  │  ⚠  WARN      Unknown source domain: unknown-site.ru       │
  │  ⚠  WARN      Low community trust (2 votes)                │
  │  ✖  CRITICAL  curl piped to bash detected (line 14)        │
  │                                                            │
  └────────────────────────────────────────────────────────────┘

  ✖  Critical risks detected. Install anyway? [y/N]
```

---

## JSON output

`--json` emits a machine-readable report — useful in CI gates or wrapping `aurguard` in other tooling:

```jsonc
{
  "package": "shady-tool",
  "version": "1.0-1",
  "maintainer": "newuser99",
  "maintainer_since": "2026-03-01T00:00:00Z",
  "votes": 2,
  "last_modified": "2026-06-13T00:00:00Z",
  "risk": "CRITICAL",
  "sources": [
    { "host": "unknown-site.ru", "trusted": false }
  ],
  "findings": [
    { "severity": "WARN",     "code": "UNKNOWN_SOURCE", "message": "Unknown source domain: unknown-site.ru", "line": 6 },
    { "severity": "WARN",     "code": "LOW_VOTES",       "message": "Low community trust (2 votes)",          "line": null },
    { "severity": "CRITICAL", "code": "CURL_PIPE_SH",    "message": "curl piped to bash detected",            "line": 14 }
  ]
}
```

The process exit code mirrors the risk in `-I` mode, so a CI job can fail on `CRITICAL` without parsing JSON.

---

## Project layout

```
aurguard/
├── src/
│   ├── lib.rs         Library root — re-exports the analyzer
│   ├── main.rs        Thin CLI over the library
│   ├── aur.rs         AUR RPC client + PKGBUILD/.install fetchers
│   ├── pkgbuild.rs    Static analyzer (sources, rules, metadata)
│   ├── astscan.rs     tree-sitter-bash AST pass (obfuscation-resistant)
│   ├── config.rs      User config (language, trusted domains, ignores, policy)
│   ├── diff.rs        Approved-PKGBUILD SHA-256 change tracking
│   ├── i18n.rs        Message catalogs (en/tr/fr/es/az)
│   ├── wizard.rs      Interactive `--setup` wizard
│   ├── report.rs      Findings, severities, the Report type
│   ├── ui.rs          Terminal panel, spinner, prompts, JSON
│   └── installer.rs   Clone-first build flow + ledger
├── tests/
│   └── integration.rs End-to-end analyzer tests on PKGBUILD fixtures
├── npm/               npm wrapper (package.json + install.js)
├── .github/workflows/ ci.yml + release.yml
├── install.sh         Build + install + write default config
├── Cargo.toml
├── README.md
└── LICENSE            MIT
```

---

## Tech stack

| Concern             | Crate                                |
| ------------------- | ------------------------------------ |
| CLI parsing         | `clap` (derive)                      |
| HTTP                | `reqwest` (async, `rustls-tls`)      |
| Async runtime       | `tokio`                              |
| JSON / config       | `serde` + `serde_json` + `toml`      |
| Bash AST            | `tree-sitter` + `tree-sitter-bash`   |
| Hashing (diff)      | `sha2`                               |
| Dates               | `chrono`                             |
| Colors / spinners   | `colored` + `indicatif`              |
| TTY detection       | `is-terminal`                        |
| Errors              | `anyhow`                             |

---

## Building from source

```sh
git clone https://github.com/lunanoir21/aurguard-project.git
cd aurguard-project
cargo build --release
# binary at target/release/aurguard
```

### Quality bar

- `cargo fmt --check` — formatted
- `cargo clippy -- -D warnings` — zero warnings
- `cargo test` — 65 unit + 14 integration tests: every CRITICAL rule, the YARA-style signature database, the AST pass, config/ignore handling, diff tracking, localization, AUR parsing, and a report-render smoke test
- No raw `unwrap()` in non-test code — all errors flow through `anyhow`
- Release profile tuned for size: `opt-level = "z"`, `lto`, `strip = true`

---

## Releasing (CI)

Two GitHub Actions workflows drive this:

- **`ci.yml`** — on every push/PR: `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.
- **`release.yml`** — on a `v*` tag: builds stripped `x86_64` + `aarch64` binaries,
  attaches them to the GitHub Release, then publishes to **crates.io** and **npm**.
  The crate and npm versions are synced from the tag automatically (tag `v0.2.0`
  → version `0.2.0`).

### Secrets to add

In the repo: **Settings → Secrets and variables → Actions → New repository secret**.

| Secret                  | Used for       | Required                    |
| ----------------------- | -------------- | --------------------------- |
| `NPM_TOKEN`             | `npm publish`  | for npm publishing          |
| `CARGO_REGISTRY_TOKEN`  | `cargo publish`| for crates.io publishing    |

Create `NPM_TOKEN` as an **Automation** token at npmjs.com
(*Access Tokens → Generate New Token → Automation*). If a token is absent, that
publish step **skips cleanly** instead of failing — so you can ship to one
registry without the other.

> npm publishing uses `--provenance` (signed supply-chain attestation), which
> requires a **public** repo and the `id-token: write` permission already set in
> the workflow. For a private repo, drop `--provenance` from `release.yml`.

To cut a release:

```sh
git tag v0.2.0
git push origin v0.2.0
```

---

## Security & trust model

- **What aurguard trusts:** the AUR RPC API over HTTPS, and the bytes of the `PKGBUILD` it downloads.
- **What it does NOT do:** it does not sandbox, containerize, or otherwise contain the build. When you approve an install, `makepkg` runs the `PKGBUILD` with your user's permissions, exactly as if you ran it by hand.
- **Static analysis is best-effort.** Pattern matching catches known shapes of abuse; a determined attacker can obfuscate around any fixed ruleset. A `None detected` result means "no known-bad patterns," not "proven safe."
- **Read the PKGBUILD yourself** for anything privileged or unfamiliar. `aurguard -I <package>` is built for exactly that quick pre-read.

---

## Roadmap

**Shipped beyond the initial cut:** clone-first (TOCTOU-safe) installs,
`.install` scriptlet analysis, a `tree-sitter-bash` AST pass, approval-based
change tracking (`PKGBUILD_CHANGED`), user config, inline ignores, `--file`
offline analysis, `--fail-on`, and batch operations.

**Still out of scope:**

- Sandboxed / containerized builds
- GPG signature verification of sources and maintainers
- Recursive analysis of transitive AUR dependencies
- A graphical UI

---

## License

MIT © aurguard contributors. See [LICENSE](./LICENSE).
