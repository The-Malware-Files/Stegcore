#!/usr/bin/env bash
#
# check-orchestration-standard.sh — run orchestration through holst, not through
# another one-off script.
#
# WHY
#
# holst exists because ad-hoc orchestration kept being rewritten: a deploy
# script here, a watchdog there, a poll loop in a third place, each with its own
# idea of how a job is queued, how failure is reported, and who terminates the
# rented hardware. holst has the queue, the dependency-gated ready set, the
# per-machine workers, live streaming, and resume.
#
# The cost of going around it is not theoretical. On 2026-07-26 a compass
# baseline was run through a hand-rolled harness because the harness was already
# there. The orchestrator blocked on an install that had silently stalled, so
# the watchdog was never armed, so nothing would have terminated the rented pod;
# a stale run kept executing alongside its own replacement; and the failure was
# only noticed because someone went looking. Every one of those is a thing holst
# already handles.
#
# WHAT IT FLAGS
#
# A staged file that drives rented compute or fans work out across machines, and
# is not part of holst or a holst spec. The signals are deliberately narrow, so
# this stays a gate rather than noise: the RunPod API surface, and the
# deploy-then-poll-then-terminate shape that is exactly what holst owns.
#
# It does NOT flag calling holst, writing a holst spec, or a script that merely
# ssh's somewhere. Talking to a machine is not orchestration; scheduling work
# across machines and paying for it by the hour is.
#
# Usage:  check-orchestration-standard.sh [--staged]
# Exit 0 clean, 1 on a finding.

set -uo pipefail

RED=$(tput setaf 1 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0

if [ "${1:-}" = "--staged" ]; then
    files=$(git diff --cached --name-only --diff-filter=d 2>/dev/null)
else
    files=$(git status --porcelain 2>/dev/null | awk '{print $NF}')
fi
[ -n "$files" ] || exit 0

# Paths that ARE the standard, or its specs, or its documentation.
_exempt() {
    case "$1" in
        crates/holst/*|*/crates/holst/*) return 0 ;;
        *holst*.toml|*holst*.md|*holst*.rs) return 0 ;;
        docs/decisions/*|docs/*.md|*/DEFERRED.md|private/*) return 0 ;;
        .githooks/*) return 0 ;;
        # The gate is its own counter-example: it must contain the patterns it
        # searches for. Exempt the canonical copies as well as the installed
        # ones, or the check refuses the commit that ships it.
        */claude-setup/hooks/*|tools/claude-setup/hooks/*) return 0 ;;
    esac
    return 1
}

# The narrow signal set. Renting compute by the hour, or driving a fleet of
# machines through a bespoke loop.
RENTED='api\.runpod\.io|podFindAndDeployOnDemand|RUNPOD_API_KEY|podTerminate|vast\.ai|lambdalabs\.com'

hits=""
for f in $files; do
    [ -f "$f" ] || continue
    _exempt "$f" && continue
    if grep -qE "$RENTED" "$f" 2>/dev/null; then
        hits="$hits $f"
    fi
done

[ -n "${hits// /}" ] || exit 0

echo
echo "${RED}${BOLD}ORCHESTRATION STANDARD: holst owns this${RESET}"
echo
echo "These staged files drive rented compute directly:"
for f in $hits; do echo "    $f"; done
echo
echo "${BOLD}The standard:${RESET} anything that rents compute or schedules a run"
echo "across machines goes through holst. holst already owns the queue, the"
echo "dependency-gated ready set, per-machine workers, live streaming, resume,"
echo "and the teardown that stops a rented box billing after the work ends."
echo
echo "A hand-rolled harness re-implements those badly and usually omits the"
echo "teardown, which is the one that costs money when it is missing."
echo
echo "${BOLD}Instead:${RESET} write a holst spec and run it."
echo "    holst run <spec>.toml --db <run>.db"
echo
echo "${YELLOW}If this genuinely is not orchestration${RESET} (a credential rotation"
echo "helper, a cost query, a one-line status check), say so in the commit"
echo "message and pass the bypass with that reason recorded:"
echo "  SKIP_ORCHESTRATION_STANDARD=1 git commit ..."
echo
exit 1
