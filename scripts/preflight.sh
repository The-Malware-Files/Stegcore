#!/usr/bin/env bash
# scripts/preflight.sh — local equivalent of the CI gates.
#
# Run before pushing a meaningful change. The cheap subset runs in
# seconds (fmt + clippy + scoped tests + secret/coauthor hooks). The
# `--full` flag additionally replays the Linux CI matrix locally via
# `act`, which catches Linux-specific failures before they cost runner
# minutes.
#
# Usage:
#   ./scripts/preflight.sh           # cheap subset (~30s)
#   ./scripts/preflight.sh --full    # plus act replay (~5 min)
#
# Requirements (cheap subset): standard Rust toolchain, node, jq.
# Requirements (--full):       nektos/act + Docker.

set -euo pipefail

FULL=0
[[ "${1:-}" = "--full" ]] && FULL=1

REPO=$(git rev-parse --show-toplevel)
cd "$REPO"

GREEN=$(tput setaf 2 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

step() { echo "${BOLD}==> $1${RESET}"; }
ok()   { echo "${GREEN}✓ $1${RESET}"; }
fail() { echo "${RED}✗ $1${RESET}"; exit 1; }

# ── Cheap subset ────────────────────────────────────────────────────────────

if [[ -f Cargo.toml ]]; then
    step "cargo fmt --all --check"
    cargo fmt --all --check || fail "cargo fmt failed"
    ok "fmt"

    step "cargo clippy -p stegcore-engine -p stegcore-core -p stegcore-cli -- -D warnings"
    cargo clippy -p stegcore-engine -p stegcore-core -p stegcore-cli --all-targets -- -D warnings || fail "clippy failed"
    ok "clippy"

    step "cargo test --workspace"
    cargo test --workspace || fail "tests failed"
    ok "tests"

    if command -v cargo-deny >/dev/null 2>&1; then
        step "cargo deny check (licenses, bans, sources)"
        cargo deny --workspace --all-features check licenses bans sources \
            || fail "cargo-deny failed"
        ok "deny"
    else
        echo "${YELLOW}skipped: cargo-deny not installed (install with 'cargo install cargo-deny --locked')${RESET}"
    fi

    if command -v cargo-audit >/dev/null 2>&1; then
        step "cargo audit"
        cargo audit || fail "cargo audit failed"
        ok "audit"
    else
        echo "${YELLOW}skipped: cargo-audit not installed${RESET}"
    fi
fi

if [[ -f frontend/package.json ]]; then
    step "frontend typecheck"
    (cd frontend && npx tsc --noEmit) || fail "frontend typecheck failed"
    ok "frontend tsc"

    if [[ -f frontend/playwright.config.ts ]] || [[ -f frontend/playwright.config.js ]]; then
        step "playwright e2e"
        (cd frontend && npm run e2e) || fail "playwright failed"
        ok "playwright"
    fi
fi

# ── Full (act replay) ──────────────────────────────────────────────────────

if [[ $FULL -eq 1 ]]; then
    if ! command -v act >/dev/null 2>&1; then
        echo "${RED}act not installed.${RESET}"
        echo "  Install: brew install act (or see https://github.com/nektos/act)"
        exit 1
    fi
    step "act -j audit"
    act -j audit || fail "act audit failed"
    ok "act audit"

    step "act -j rust (matrix: ubuntu only)"
    act -j rust --matrix os:ubuntu-latest || fail "act rust failed"
    ok "act rust"
fi

echo
echo "${GREEN}${BOLD}preflight: all gates passed${RESET}"
