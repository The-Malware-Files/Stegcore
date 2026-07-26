#!/usr/bin/env bash
#
# private-remote-gate.sh — refuse to push private material to a remote that has
# not been declared private.
#
# WHY THIS EXISTS
#
# A repo often keeps private material out of git through `.git/info/exclude`.
# That file is per clone and is never committed, so the protection does not
# survive a fresh clone, does not reach a second machine, and cannot be
# reviewed. Anything that commits without running hooks (an autosave timer, a
# CI job) walks straight past it.
#
# This gate therefore sits at the last moment before bytes leave the machine,
# and keys on WHICH REMOTE they are leaving for. That is the boundary that
# actually matters: content on the wrong remote cannot be recalled.
#
# Rationale in full, including the audit that produced it, is recorded
# separately in the operator's decision log. This file deliberately carries the
# mechanism rather than the history, because it ships to public repos too.
#
# DENY-FIRST
#
# A remote is public unless the project says otherwise. `PRIVATE_REMOTES` is the
# allow list; an unset value means no remote may receive private material, which
# fails loudly rather than silently permitting. This is the same evaluation
# order the rest of the baseline uses: broad deny, narrow allow.
#
# WHAT IT DOES NOT DO
#
# It checks two things per pushed ref: the tip tree (what the remote will serve
# after the push) and every commit the push introduces. A file that appeared and
# disappeared inside history the remote ALREADY has is not re-detected, because
# rescanning full history on every push costs more than it buys. Use
# `git log --all --name-only` for that, once, when adopting the gate.
#
# CONFIGURATION (.baseline-hook-config)
#
#   PRIVATE_REMOTE_GATE_ENABLED=1              # 0 disables the gate entirely
#   PRIVATE_REMOTES='origin'                   # space separated remote NAMES
#   PRIVATE_PATHS='private DEFERRED.md ...'    # space separated pathspecs
#
# Invoked by the baseline pre-push hook as:
#   private-remote-gate.sh <remote-name> <local_sha>:<remote_sha> ...
#
# Exits 0 to allow, 1 to refuse.

set -eu

RED=$(tput setaf 1 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
BOLD=$(tput bold 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

remote="${1:-}"
[ -n "$remote" ] || exit 0
shift || true
[ "$#" -gt 0 ] || exit 0

# Default set: the private-directory convention, plus the per-project state
# files that tooling tends to leave at the repo root. Override per project.
PRIVATE_PATHS="${PRIVATE_PATHS:-private private-* DEFERRED.md .project-state.md .hephaestus-sync.toml OPERATOR_ACTIONS.md catastrophic}"

# Deny-first: absence of an allow list is not an allowance.
for r in ${PRIVATE_REMOTES:-}; do
    [ "$r" = "$remote" ] && exit 0
done

zero=$(git hash-object --stdin </dev/null | tr '0-9a-f' '0')

# Word splitting on PRIVATE_PATHS is deliberate: the knob is a space separated
# pathspec list, matching how PRIVATE_DIRS is already expressed.
# shellcheck disable=SC2086
set -f
read -r -a _paths <<<"$PRIVATE_PATHS"
set +f

OFFENDING=""
for pair in "$@"; do
    ls="${pair%%:*}"
    rs="${pair##*:}"
    [ -n "$ls" ] || continue
    [ "$ls" = "$zero" ] && continue          # a deletion pushes no content

    # What the remote will serve once this lands.
    tip=$(git ls-tree -r --name-only "${ls}^{tree}" -- "${_paths[@]}" 2>/dev/null || true)

    # What this push introduces. Walked commit by commit rather than as a
    # two-endpoint diff, because a file added in one commit and removed in the
    # next is invisible to the endpoints and still lands in the remote's
    # history, permanently, where the whole point of the gate is that it never
    # arrives.
    #
    # `--diff-filter=d` excludes deletions: a push whose only crime is REMOVING
    # private material is the push you want to succeed. Without this the gate
    # blocks its own remedy, then keeps blocking every later push whose range
    # still spans the removal.
    if [ "$rs" = "$zero" ]; then
        intro=$(git log --format= --name-only --diff-filter=d \
                "$ls" --not --remotes -- "${_paths[@]}" 2>/dev/null || true)
    else
        intro=$(git log --format= --name-only --diff-filter=d \
                "${rs}..${ls}" -- "${_paths[@]}" 2>/dev/null || true)
    fi

    for f in $tip $intro; do
        case " $OFFENDING " in *" $f "*) continue ;; esac
        OFFENDING="$OFFENDING $f"
    done
done

# shellcheck disable=SC2086
set -- $OFFENDING
[ "$#" -eq 0 ] && exit 0

url=$(git remote get-url "$remote" 2>/dev/null || echo "unknown")

echo
echo "${RED}${BOLD}REFUSED${RESET}: private material in a push to '${remote}'."
echo
echo "  remote '${remote}' -> ${url}"
echo "  '${remote}' is not listed in PRIVATE_REMOTES, so it is treated as public."
echo
echo "${BOLD}Files that would reach it:${RESET}"
for f in "$@"; do echo "    $f"; done
echo
echo "${BOLD}Fix one of these:${RESET}"
echo "  - Pushing to the wrong remote? Push to one you declared private."
echo "  - Is '${remote}' genuinely private (a self-hosted hub, a private"
echo "    GitHub repo)? Declare it in .baseline-hook-config:"
echo "        PRIVATE_REMOTES='origin ${remote}'"
echo "  - Is one of those files not actually private? Narrow the list:"
echo "        PRIVATE_PATHS='private DEFERRED.md'"
echo "  - Should the file simply not be in git? Add it to .gitignore, or to"
echo "    .git/info/exclude when naming it publicly would itself reveal"
echo "    something, then remove it from the index."
echo
echo "${YELLOW}Bypass (last resort, record the reason):${RESET}"
echo "  SKIP_PRIVATE_REMOTE_GATE=1 git push ${remote} ..."
echo
exit 1
