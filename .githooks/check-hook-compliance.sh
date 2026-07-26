#!/usr/bin/env bash
#
# check-hook-compliance.sh — when a change touches the machinery that enforces
# the rules, check the change against THIS repo before it lands.
#
# WHY
#
# Hooks, .baseline-hook-config and CLAUDE.md are fleet-wide artefacts that live
# in per-project copies. The failure mode is always the same shape: a fix is
# written once against one repo's assumptions and then propagated to eleven
# others where those assumptions do not hold.
#
# Two real examples from 2026-07-26, both caught by hand, which is the problem:
#
#   - A wholesale hook copy would have deleted the database-render drift guard
#     that career-ops carries inline in its managed pre-commit. Nothing would
#     have said so.
#   - `PRIVATE_REMOTES='origin'` is correct in ten repos and actively wrong in
#     senbonzakura, where `origin` is the PUBLIC GitHub repo and the hub is
#     called `olympus`. The same literal string means opposite things.
#
# A human noticing is not a control. So the checks below are the ones a machine
# can actually make: does it still parse, does it still refer to things that
# exist HERE, and is it quietly deleting something this project added.
#
# This does NOT check that the change is a good idea. It checks that it is
# coherent with the repo it is landing in.
#
# Usage:  check-hook-compliance.sh [--staged]
#   --staged  examine the staged versions (hook use). Default: working tree.
#
# Exit 0 clean, 1 on a finding.

set -uo pipefail

RED=$(tput setaf 1 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true)
BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

STAGED=0
[ "${1:-}" = "--staged" ] && STAGED=1

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0

WATCHED='^(\.githooks/|\.baseline-hook-config$|\.baseline-hook-allow$|CLAUDE\.md$|AGENTS\.md$)'

if [ "$STAGED" = 1 ]; then
    changed=$(git diff --cached --name-only --diff-filter=d | grep -E "$WATCHED" || true)
else
    changed=$(git status --porcelain | awk '{print $NF}' | grep -E "$WATCHED" || true)
fi
[ -n "$changed" ] || exit 0

findings=0
note() { printf '%s\n' "  $*"; }
fail() { findings=$((findings + 1)); printf '%s\n' "${RED}✗${RESET} $*"; }
pass() { printf '%s\n' "${GREEN}✓${RESET} $*"; }

echo
echo "${BOLD}hook-compliance: enforcement machinery changed, checking it against this repo${RESET}"
for f in $changed; do note "changed: $f"; done
echo

# ── 1. Every changed shell file still parses ────────────────────────────────
# A hook with a syntax error does not fail loudly; git reports the hook as
# failed and people reach for --no-verify. A broken gate becomes a disabled one.
for f in $changed; do
    case "$f" in .githooks/*) ;; *) continue ;; esac
    [ -f "$f" ] || continue
    if bash -n "$f" 2>/dev/null; then
        pass "$f parses"
    else
        fail "$f has a syntax error:"
        bash -n "$f" 2>&1 | sed 's/^/      /'
    fi
done

# ── 2. The config this repo actually has is readable by the hook ────────────
# The hooks parse .baseline-hook-config rather than executing it. A line the
# grammar rejects makes the hook refuse every commit, so a typo in the config
# is a repo-wide outage, not a warning.
if [ -f .baseline-hook-config ] && [ -f .githooks/pre-commit ]; then
    # Lift the parser out of the real hook, so this checks the grammar the hook
    # actually applies rather than a second copy of it that could drift.
    # The region runs from its banner comment to the closing brace of
    # load_baseline_hook_config, NOT to the first `}` in the file, which belongs
    # to a helper defined partway through.
    parser=$(mktemp)
    awk '
        /^# ── Baseline config loading/ { on = 1 }
        on { print }
        /^load_baseline_hook_config\(\) \{/ { infn = 1 }
        infn && /^\}$/ { exit }
    ' .githooks/pre-commit > "$parser"

    if ! grep -q '^load_baseline_hook_config() {' "$parser" || ! bash -n "$parser" 2>/dev/null; then
        # A check that could not run has not passed. Saying "✓" here would be
        # the exact failure this whole file exists to prevent.
        fail "could not extract the config parser from .githooks/pre-commit"
        note "the config grammar was NOT checked; this hook may be an older lineage"
    else
        out=$(bash -c '. "$1"; load_baseline_hook_config "$2"' _ "$parser" .baseline-hook-config 2>&1)
        if echo "$out" | grep -q "not an assignment\|bad key name\|refusing to set\|unterminated"; then
            fail ".baseline-hook-config would be REFUSED by the hook:"
            echo "$out" | sed 's/^/      /'
        else
            pass ".baseline-hook-config parses"
            [ -n "$out" ] && echo "$out" | sed 's/^/      note: /'
        fi
    fi
    rm -f "$parser"
fi

# ── 3. Remote names in the config exist in THIS repo ────────────────────────
# The senbonzakura case: a remote name copied from another project silently
# names nothing, and a deny-first gate that allow-lists a non-existent remote
# blocks every push instead of allowing the intended one.
if [ -f .baseline-hook-config ]; then
    declared=$(grep -oP "^PRIVATE_REMOTES=['\"]?\K[^'\"]*" .baseline-hook-config 2>/dev/null | head -1 || true)
    if [ -n "${declared// /}" ]; then
        have=$(git remote 2>/dev/null)
        missing=""
        for r in $declared; do
            echo "$have" | grep -qx "$r" || missing="$missing $r"
        done
        if [ -n "$missing" ]; then
            fail "PRIVATE_REMOTES names remote(s) this repo does not have:$missing"
            note "this repo has: $(echo "$have" | tr '\n' ' ')"
            note "a name that matches nothing is not an allowance, it is a block"
        else
            pass "PRIVATE_REMOTES ($declared) all exist here"
        fi
        # And the reverse: a remote nobody classified is treated as public,
        # which is the safe default but worth saying out loud once.
        for r in $have; do
            echo " $declared " | grep -q " $r " || \
                note "remote '$r' is not declared private, so it is treated as public"
        done
    fi
fi

# ── 4. A managed hook is not quietly losing project-specific code ───────────
# Propagation deletes. This does not try to judge what a deletion means; it
# surfaces removed lines so the deletion is a decision rather than a side
# effect.
for f in $changed; do
    case "$f" in .githooks/*) ;; *) continue ;; esac
    if [ "$STAGED" = 1 ]; then
        removed=$(git diff --cached -- "$f" | grep -c '^-[^-]' || true)
    else
        removed=$(git diff -- "$f" | grep -c '^-[^-]' || true)
    fi
    [ "${removed:-0}" -eq 0 ] && continue
    echo "${YELLOW}!${RESET} $f removes $removed line(s). Confirm none of it is this project's own:"
    if [ "$STAGED" = 1 ]; then
        git diff --cached -- "$f" | grep '^-[^-]' | head -12 | sed 's/^/      /'
    else
        git diff -- "$f" | grep '^-[^-]' | head -12 | sed 's/^/      /'
    fi
    [ "$removed" -gt 12 ] && note "... and $((removed - 12)) more"
done

# ── 5. A hook that calls a fragment has the fragment ────────────────────────
# The gate is split across two files; half of it installed is a gate that never
# fires, and never firing looks exactly like passing.
for f in $changed; do
    case "$f" in .githooks/*) ;; *) continue ;; esac
    [ -f "$f" ] || continue
    while IFS= read -r frag; do
        [ -n "$frag" ] || continue
        if [ -x ".githooks/$frag" ]; then
            pass "$f calls $frag, which is present and executable"
        else
            fail "$f calls .githooks/$frag, which is missing or not executable"
            note "the gate would silently never fire"
        fi
    done < <(grep -oP '\$repo_root/\.githooks/\K[a-z-]+\.sh' "$f" | sort -u)
done

echo
if [ "$findings" -eq 0 ]; then
    echo "${GREEN}${BOLD}hook-compliance: no findings${RESET}"
    exit 0
fi
echo "${RED}${BOLD}hook-compliance: $findings finding(s)${RESET}"
echo "Fix them, or if a finding is wrong here, say why in the commit message."
echo "Bypass (last resort, record the reason): SKIP_HOOK_COMPLIANCE=1 git commit ..."
exit 1
