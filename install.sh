#!/usr/bin/env bash
#
# aurguard installer — build from source, install the binary, and write a
# default config so `aurguard` works from your shell.
#
# Usage:
#   ./install.sh                 # build release + install to ~/.local/bin
#   PREFIX=/usr/local ./install.sh   # system-wide (uses sudo for the copy)
#   ./install.sh --uninstall     # remove the installed binary
#
set -euo pipefail

# ---- pretty output --------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
  GRN=$(printf '\033[32m'); YLW=$(printf '\033[33m'); RST=$(printf '\033[0m')
else
  BOLD=""; DIM=""; RED=""; GRN=""; YLW=""; RST=""
fi
info()  { printf '%s∙%s %s\n' "$DIM" "$RST" "$1"; }
ok()    { printf '%s✓%s %s\n' "$GRN" "$RST" "$1"; }
warn()  { printf '%s⚠%s %s\n' "$YLW" "$RST" "$1"; }
die()   { printf '%s✖%s %s\n' "$RED" "$RST" "$1" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_NAME="aurguard"

# ---- install location -----------------------------------------------------
# Default to a user-writable dir; PREFIX overrides for system installs.
if [ -n "${PREFIX:-}" ]; then
  BIN_DIR="$PREFIX/bin"
else
  BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
fi
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/aurguard"
CONFIG_FILE="$CONFIG_DIR/config.toml"

# A copy that uses sudo only when the target dir is not writable.
copy_bin() {
  local src="$1" dst="$2"
  if [ -w "$(dirname "$dst")" ] || mkdir -p "$(dirname "$dst")" 2>/dev/null; then
    install -Dm755 "$src" "$dst"
  else
    info "elevated permissions needed for $dst"
    sudo install -Dm755 "$src" "$dst"
  fi
}

# ---- uninstall ------------------------------------------------------------
if [ "${1:-}" = "--uninstall" ]; then
  target="$BIN_DIR/$BIN_NAME"
  if [ -e "$target" ]; then
    rm -f "$target" 2>/dev/null || sudo rm -f "$target"
    ok "removed $target"
  else
    warn "no binary at $target"
  fi
  info "config left in place: $CONFIG_FILE"
  exit 0
fi

printf '%saurguard installer%s\n\n' "$BOLD" "$RST"

# ---- prerequisites --------------------------------------------------------
command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust: https://rustup.rs"
ok "found cargo ($(cargo --version | awk '{print $2}'))"

command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 \
  || die "a C compiler (cc/gcc) is required to build the bash grammar"

for tool in git makepkg; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "found $tool"
  else
    warn "$tool not found — analysis works, but installing packages will not"
  fi
done

# ---- build ----------------------------------------------------------------
info "building release binary (this may take a minute)…"
( cd "$SCRIPT_DIR" && cargo build --release --quiet )
BUILT="$SCRIPT_DIR/target/release/$BIN_NAME"
[ -x "$BUILT" ] || die "build did not produce $BUILT"
ok "built $(du -h "$BUILT" | awk '{print $1}') binary"

# ---- install binary -------------------------------------------------------
copy_bin "$BUILT" "$BIN_DIR/$BIN_NAME"
ok "installed to $BIN_DIR/$BIN_NAME"

# ---- default config -------------------------------------------------------
if [ ! -f "$CONFIG_FILE" ]; then
  mkdir -p "$CONFIG_DIR"
  cat > "$CONFIG_FILE" <<'TOML'
# aurguard configuration. All sections are optional.

[trust]
# Extra domains treated as trusted sources (matched as host or .suffix).
extra_domains = []

[rules]
# Finding codes to suppress globally, e.g. ["VCS_SOURCE", "STALE"].
ignore = []

[policy]
# Risk that blocks a non-interactive (--skip-confirm) install.
# One of: clean | risky | critical
fail_on = "critical"
TOML
  ok "wrote default config: $CONFIG_FILE"
else
  info "config already exists: $CONFIG_FILE (left unchanged)"
fi

# ---- PATH check -----------------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ok "$BIN_DIR is on your PATH" ;;
  *)
    warn "$BIN_DIR is not on your PATH"
    if [ -n "${FISH_VERSION:-}" ] || [ "$(basename "${SHELL:-}")" = "fish" ]; then
      printf '   add it with:\n   %sfish_add_path %s%s\n' "$BOLD" "$BIN_DIR" "$RST"
    else
      printf '   add this to your shell rc:\n   %sexport PATH="%s:$PATH"%s\n' "$BOLD" "$BIN_DIR" "$RST"
    fi
    ;;
esac

printf '\n%sDone.%s Try: %saurguard -I yay%s\n' "$GRN" "$RST" "$BOLD" "$RST"
printf '   Pick a language / set preferences: %saurguard --setup%s\n' "$BOLD" "$RST"
