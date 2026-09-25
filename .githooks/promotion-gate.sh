#!/usr/bin/env bash
# Author:  Daniel Iwugo
# Comment: Christ is King
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

    # The committed receipt is the authority when it exists, and the SAME script
    # CI runs decides coverage, so the local verdict and the server verdict can
    # never disagree. Two implementations of one rule is how the gate ended up
    # meaning different things in different places: the local half took the
    # single mtime-newest artefact (so its answer depended on file timestamps and
    # was not reproducible across machines) while the server half scanned every
    # attestation and kept the best ancestor.
    # A checker that EXISTS but cannot run is a defect, not an absence. Without
    # this, chmod -x on one file silently downgrades the gate from "verify the
    # signed receipt" to "grep a markdown file for a line anyone can type", and
    # nothing says so. The same shape was fixed for the hook fragments in
    # `gate_frag`; this sibling call site was missed, which is how an incomplete
    # fix survives: the pattern was corrected where it was noticed rather than
    # everywhere it lived.
    if [ -e scripts/check-panel-attestation.sh ] && [ ! -x scripts/check-panel-attestation.sh ]; then
        refuse "the panel attestation checker exists but is not executable."
        echo "  scripts/check-panel-attestation.sh cannot run, so the receipt cannot"
        echo "  be verified. Refusing rather than falling back to the weaker check."
        echo "Fix:  chmod +x scripts/check-panel-attestation.sh"
        return 1
    fi
    if [ -f .panel/attestations.toml ]; then
        if [ ! -x scripts/check-panel-attestation.sh ]; then
            refuse "there is a panel attestation receipt but no checker to read it."
            echo "  .panel/attestations.toml exists and scripts/check-panel-attestation.sh"
            echo "  does not, so the strongest available evidence would be ignored."
            return 1
        fi
        local sha rc=0
        for sha in "$@"; do
            scripts/check-panel-attestation.sh "$sha" main || rc=1
        done
        return $rc
    fi

    local last base since
    # No receipt: fall back to reading the artefacts directly. Every artefact is
    # considered, not merely the newest by mtime, and the one covering the most
    # recent ancestor wins.
    last=""
    base=""
    local f cand line
    for f in private/reviews/*panel*.md; do
        [ -f "$f" ] || continue

        # A BRIEF IS NOT A PANEL. The glob matches any *panel*.md, and four of the
        # twelve artefacts present on 2026-09-21 were `-panel-brief` documents:
        # the thing written BEFORE the personas read anything. One of them,
        # 2026-09-14, carried a covers: line and zero findings, so the gate that
        # hard-blocks dev to main could be satisfied by the INPUT to a review.
        # Found while running the panel it was supposed to gate.
        #
        # A synthesis is recognised by carrying findings or a verdict. That is a
        # property of the document rather than of its filename, so renaming a
        # brief does not smuggle it through, and a real synthesis with an unusual
        # name still counts.
        #
        # The pattern was widened after testing it against all twelve artefacts
        # present on 2026-09-21, which is the only reason it is right: the first
        # version looked for "findings" and an `F-` code, and wrongly excluded two
        # genuine syntheses that head their findings `C-1` and open with "## 0. The
        # verdict". A detector tested only against the document that prompted it
        # would have shipped with that.
        #
        # The direction of error is deliberate. A synthesis wrongly skipped makes
        # this gate STRICTER, which fails safe; a brief wrongly accepted makes it
        # weaker, which is the defect being fixed. So the test is narrow enough to
        # keep excluding every brief and no narrower.
        # TWO TESTS, because one was not enough and the corpus said so. A positive
        # marker alone still accepted a genuine brief, since a brief TELLS the
        # personas to report findings and so contains the word. The second test
        # excludes a document that instructs reviewers rather than recording them.
        #
        # Measured against all thirteen artefacts present on 2026-09-21: the
        # positive marker alone gave one false accept; a disposition word such as
        # FIXED gave three, because briefs cite past fixes; a convergence count
        # alone gave seven false rejects. The pair below gives zero and zero.
        if ! grep -qiE \
            '^#+ .*(finding|convergen|disposition|verdict)|^#+ .*[A-Z]-[0-9]|^\| *[A-Z]-[0-9]|\bCONVERGENCE\b' \
            "$f" 2>/dev/null; then
            continue
        fi
        if grep -qiE \
            'You are one of|you will not see|^#+ .*How to report|What the panel should attack' \
            "$f" 2>/dev/null; then
            continue
        fi

        line=$(grep -oiE 'covers:[[:space:]]*[^[:space:]]+' "$f" 2>/dev/null | head -1)
        [ -n "$line" ] || continue

        # A RANGE IS NOT AN END SHA, and the old parser took the first hex run out
        # of whatever followed `covers:`. 2026-09-14 wrote `covers: 7e7d05a..HEAD`,
        # so the value extracted was the BASE: the commit the review STARTED at.
        # This gate then computed "nothing unreviewed between it and the tip" from
        # the wrong end of the range, and `HEAD` in a durable record is not a fact
        # at all, because it meant something different on the day it was written
        # and nothing can recover what.
        #
        # Refused loudly rather than parsed leniently. A record of what was
        # reviewed is the one place a generous parser is wrong: it turns a
        # malformed claim into a confident one.
        case "$line" in
            *..* | *HEAD* | *head*)
                refuse "$(basename "$f") records a RANGE, not the commit it covered."
                echo
                echo "  found:  $line"
                echo
                echo "  A covers: line must name ONE commit: the tip the panel actually"
                echo "  read. A range is ambiguous and this gate would take its BASE,"
                echo "  which is the commit the review started at, so everything the"
                echo "  panel covered would read as unreviewed. 'HEAD' is worse: it is"
                echo "  not recoverable once the day has passed."
                echo
                echo "  Fix:  covers: $(git rev-parse --short HEAD)"
                return 1
                ;;
        esac

        cand=$(printf '%s' "$line" | grep -oiE '[0-9a-f]{7,40}' | head -1)
        [ -n "$cand" ] || continue
        git cat-file -e "${cand}^{commit}" 2>/dev/null || continue
        # Keep the candidate that is furthest forward in history.
        if [ -z "$base" ] || git merge-base --is-ancestor "$base" "$cand" 2>/dev/null; then
            base="$cand"; last="$f"
        fi
    done
    if [ -n "$base" ]; then
        panel_gate_report "$base" "$last" "$@"
        return $?
    fi
    last=$(ls -1 private/reviews/*panel*.md 2>/dev/null | head -1)

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

    panel_gate_report "$base" "$last" "$@"
}

# Report on a resolved (base, artefact) pair against every sha being pushed.
panel_gate_report() {
    local base="$1" last="$2"; shift 2
    local sha rc=0 since
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
