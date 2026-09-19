#!/bin/sh
# install.sh — install waxseal from GitHub.
#
#   curl -fsSL https://raw.githubusercontent.com/srivtx/waxseal/main/install.sh | sh
#
# Installs the `waxseal` binary globally with Bun. Pass a git ref as the
# first argument to pin a branch, tag, or commit:
#
#   curl -fsSL https://raw.githubusercontent.com/srivtx/waxseal/main/install.sh | sh -s v0.1.0
set -eu

REPO="srivtx/waxseal"
BIN="waxseal"
REF="${1:-main}"

info() { printf '%s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

case "$REF" in
  -h|--help)
    cat >&2 <<EOF
Install $BIN from GitHub.

  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh -s <git-ref>

<git-ref> may be a branch, tag, or commit (default: main).
Requires Bun (https://bun.sh); installs into Bun's global bin directory.
EOF
    exit 0
    ;;
esac

command -v bun >/dev/null 2>&1 || die "Bun is required to install $BIN.
Install it first, then re-run this script:
  curl -fsSL https://bun.sh/install | bash"

info "Installing $BIN ($REF) from github.com/$REPO ..."
bun add -g "github:$REPO#$REF"

if ! command -v "$BIN" >/dev/null 2>&1; then
  BIN_DIR="$(bun pm bin -g 2>/dev/null || true)"
  info ""
  info "$BIN was installed but is not on your PATH."
  if [ -n "$BIN_DIR" ]; then
    info "Add this to your shell profile and restart your shell:"
    info "  export PATH=\"$BIN_DIR:\$PATH\""
  fi
  exit 1
fi

info "Installed $BIN $("$BIN" --version 2>/dev/null || true)"
info "Run '$BIN --help' to get started."
