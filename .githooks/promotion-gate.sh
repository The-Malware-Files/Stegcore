#!/usr/bin/env bash
# promotion-gate.sh — the HARD half of the panel and planning gates.
#
# ADR 63 picked "a layered gate (soft per-cluster nudge, hard pre-push block)"
# and explicitly rejected the row reading "One SessionStart reminder, no hard
# gate", whose recorded con is "a dev-to-main promotion can still ship
# uninspected work". The rejected row is what actually shipped. For a year the
# soft nudge printed every session, CLAUDE.md stated the hard block as fact, and
# `PANEL_GATE_ENABLED` was read by nothing but the config's own known-key list.
# This file is the missing half.
#
# It fires only on a promotion to main or master. Routine work on dev is
# untouched, which is the whole point of a layered gate.
#
# TWO CHECKS.
#
#   1. PANEL. A panel artefact under private/reviews/ must exist and must carry
#      a `covers: <sha>` line naming a commit that leaves nothing unreviewed
#      between it and the tip being promoted.
#
#   2. PLANNING. private/for-hephaestus.md must exist, and must parse when a
#      validator is available. A project with no plan is invisible to the
#      morning brief and to the Sunday review no matter what lands in it, so
#      promoting work from it publishes something nothing is tracking.
#
# WHY THERE IS NO CONFIG SWITCH. ADR 67: "Config may parameterise what is
# checked, never whether checking happens." A repo-tracked file that could set
# PANEL_GATE_ENABLED=0 would be a gate that anything inside the blast radius can
# disable, which is not a gate. Both bypasses below are environment-only, so
# they live outside the tree being pushed and leave a reason in the shell the
# operator typed.
#
# WHY ITS OWN FILE. pre-push is meant to be byte-identical across the fleet and
# has never managed it: five field variants across twelve repos as of
# 2026-07-26. The private-material gate was moved out for exactly this reason.
# One small artefact is replaceable and diffable at a glance.
#
# FAIL CLOSED, but only on what it actually measures. A gate that cannot measure
# must say so rather than fall quiet, and for a HARD gate saying so means
# refusing. The one deliberate exception is the plan parser: refusing every push
# from a machine that has not built `telos` would block ROG and atlas over a
# missing build artefact, so a missing validator downgrades the parse check to a
# loud warning while the existence check stays hard.
#
# Usage: promotion-gate.sh <sha-being-promoted> [<sha> ...]
set -uo pipefail

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$repo_root" || exit 0

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[31m'; YEL=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=""; YEL=""; BOLD=""; RESET=""
fi

refuse() { echo "${RED}${BOLD}REFUSED${RESET}: $*"; }

# ── Check 1: the panel ──────────────────────────────────────────────────────
panel_gate() {
    [ "${SKIP_PANEL_GATE:-0}" = "1" ] && {
        echo "${YEL}panel gate bypassed${RESET} (SKIP_PANEL_GATE=1)."; return 0; }

    local last base since
    last=$(ls -1t private/reviews/*panel*.md 2>/dev/null | head -1)

    if [ -z "$last" ]; then
        refuse "promotion to main with no panel review on record."
        echo
        echo "ADR 63 makes the multi-persona panel the gate on a dev to main"
        echo "promotion. This repo has no artefact under private/reviews/."
        echo
        echo "Fix:  run /panel, then record the synthesis at"
        echo "      private/reviews/$(date +%F)-panel-<cluster>.md"
        echo "      with a line reading   covers: $(git rev-parse --short HEAD)"
        echo
        echo "Bypass (last resort, state the reason out loud):"
        echo "  SKIP_PANEL_GATE=1 git push origin main"
        return 1
    fi

    base=$(grep -oiE 'covers:[[:space:]]*[0-9a-f]{7,40}' "$last" 2>/dev/null \
           | grep -oiE '[0-9a-f]{7,40}' | head -1)

    if [ -z "$base" ]; then
        refuse "the latest panel artefact does not say what it covers."
        echo
        echo "  $(basename "$last") has no 'covers: <sha>' line, so there is no"
        echo "  way to tell what was reviewed or what has landed since. Absence"
        echo "  and malfunction must not share a representation, so this refuses"
        echo "  rather than assuming the review was complete."
        echo
        echo "Fix:  add   covers: <sha>   to that file (the commit the panel read up to)."
        echo "Bypass:  SKIP_PANEL_GATE=1 git push origin main"
        return 1
    fi

    if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
        refuse "the panel artefact claims to cover ${base}, which is not a commit here."
        echo "  A rebase, or a wrong sha. Correct $(basename "$last")."
        echo "Bypass:  SKIP_PANEL_GATE=1 git push origin main"
        return 1
    fi

    local sha rc=0
    for sha in "$@"; do
        since=$(git rev-list --count "${base}..${sha}" 2>/dev/null)
        if [ -z "$since" ]; then
            refuse "cannot count commits between ${base} and ${sha}."
            echo "  The gate could not measure, so it will not pass."
            rc=1; continue
        fi
        if [ "$since" -gt 0 ]; then
            refuse "${since} commit(s) being promoted that no panel has read."
            echo
            echo "  reviewed up to: ${base}  ($(basename "$last"))"
            echo "  promoting:      $(git rev-parse --short "$sha")"
            echo
            git log --oneline "${base}..${sha}" 2>/dev/null | head -12 | sed 's/^/    /'
            [ "$since" -gt 12 ] && echo "    ... and $(( since - 12 )) more"
            echo
            echo "Fix:  run /panel over this cluster, write the synthesis to"
            echo "      private/reviews/$(date +%F)-panel-<cluster>.md, and give it"
            echo "      a line reading   covers: $(git rev-parse --short "$sha")"
            echo
            echo "Bypass, for a genuine hotfix (ADR 63 anticipates this; if it"
            echo "becomes routine, that is the signal to refine what counts as a"
            echo "reviewable cluster, not to weaken the gate):"
            echo "  SKIP_PANEL_GATE=1 git push origin main"
            rc=1
        fi
    done
    return $rc
}

# ── Check 2: the planning file ──────────────────────────────────────────────
planning_gate() {
    [ "${SKIP_PLANNING_GATE:-0}" = "1" ] && {
        echo "${YEL}planning gate bypassed${RESET} (SKIP_PLANNING_GATE=1)."; return 0; }

    local plan="private/for-hephaestus.md"

    if [ ! -f "$plan" ]; then
        refuse "promotion to main from a project with no plan."
        echo
        echo "  $plan does not exist, so this project is invisible to the"
        echo "  morning brief and to the Sunday review. Promoting work out of it"
        echo "  publishes something nothing is tracking."
        echo
        echo "Fix:  open a session here. The SessionStart planning gate prints the"
        echo "      exact shape and the questions to ask before writing it."
        echo
        echo "Bypass:  SKIP_PLANNING_GATE=1 git push origin main"
        return 1
    fi

    # Existence is not enough. A plan carrying the colon-space YAML trap parses
    # as nothing and leaves the project just as invisible, and until 2026-07-30
    # the SessionStart gate could not see that at all: it reads the file with
    # sed, and sed will pull a fresh `checked:` line out of a file no parser can
    # read. Ask the real validator.
    #
    # Binary looked up in a HARDCODED order and honoured from the environment
    # only, never from repo config (ADR 67, BHC_EXEC_KEYS).
    local telos=""
    local c
    for c in "${TELOS_BIN:-}" telos "$HOME/.local/bin/telos" \
             "$HOME/the-factory/hephaestus/target/release/telos"; do
        [ -n "$c" ] || continue
        if command -v "$c" >/dev/null 2>&1; then telos=$(command -v "$c"); break; fi
    done

    if [ -z "$telos" ]; then
        echo "${YEL}WARNING${RESET}: no telos binary, so ${plan} was NOT checked for parse errors."
        echo "  Only its existence was verified. To close this on this machine:"
        echo "    ln -sfn ~/the-factory/hephaestus/target/release/telos ~/.local/bin/telos"
        return 0
    fi

    local me bad
    me=$(basename "$repo_root")
    bad=$("$telos" check --root "$(dirname "$repo_root")" 2>/dev/null \
          | grep -E "^FAIL[[:space:]]+${me}:" | head -1)
    if [ -n "$bad" ]; then
        refuse "the planning file does not parse, so this project is invisible to the brief."
        echo
        echo "  ${bad}"
        echo
        echo "  The usual cause is a value containing a colon followed by a space,"
        echo "  which YAML reads as a nested mapping:"
        echo "      - text: Headless GNOME host: Mutter capture      <- BREAKS"
        echo "      - text: \"Headless GNOME host: Mutter capture\"    <- correct"
        echo
        echo "Fix:  edit ${plan}, then run 'telos check' until it is clean."
        echo "Bypass:  SKIP_PLANNING_GATE=1 git push origin main"
        return 1
    fi
    return 0
}

rc=0
panel_gate "$@"    || rc=1
planning_gate      || rc=1
exit $rc
