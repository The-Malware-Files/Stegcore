#!/usr/bin/env bash
# Author:  Daniel Iwugo
# Comment: Christ is King
# branch-gate.sh — every project has exactly two branches: main and dev.
#
# Called from pre-push with the destination branch names of the refs being
# pushed. Refuses the push when a name is neither, and says what to do instead.
#
# The rule (operator, 2026-07-31): feature work goes in `dev`; `dev` promotes to
# `main` when a release is cut. There is no third branch. A branch that looks
# like it wants to be a feature branch is a directory of commits on dev.
#
# Four decisions this encodes:
#   1. Block the PUSH, not the branch. A non-conforming branch may exist locally
#      for as long as it is useful; what it may not do is reach a remote, where
#      it becomes something another machine, another session, or a CI run has to
#      reason about.
#   2. Detached HEAD is exempt by construction. This gate reads the DESTINATION
#      branch name, so a rebase, a bisect or a checkout of a bare sha never
#      reaches it: those states push nothing, or push to a named branch that is
#      judged on its own name.
#   3. `master` is tolerated with a loud warning rather than refused. Two repos
#      on the fleet are still on `master` and refusing them would break their
#      only path to a remote before the rename has happened. The warning is the
#      pressure; the rename is the fix.
#   4. Never auto-create and never auto-rename. A gate that quietly rewrites the
#      operator's branch layout is worse than the drift it corrects.
#
# AMENDED 2026-09-21 (operator). One narrow exception, and the reasoning is
# worth keeping because the amendment looks like a relaxation and is not.
#
# The two-branch rule assumes ONE remote. A repo with two remotes whose
# branches carry DIFFERENT TREES is forced by this very rule to call both of
# them `dev`, and then nothing in git distinguishes them. Stegcore is the case:
# its forgejo `origin/dev` tracks 115 paths that its GitHub `dev` ignores, and
# merging the two destroyed 101 files on 2026-09-16. The only fix is to name
# them apart, and this gate refused every name that would have done it.
#
# So the rule has not been loosened; it has gained the ability to express a
# distinction it previously could not, and which its own strictness created.
#
# `DISTINCT_TREE_BRANCHES` in .baseline-hook-config names branches that carry a
# different tree. It is NOT an escape hatch for feature branches, and three
# properties keep it from becoming one:
#
#   - Exact names only. No globs, no prefixes. A wildcard would make this a
#     switch for whether the gate runs, which ADR 67 forbids; a list of names
#     is a statement of WHAT conforms, which ADR 67 allows.
#   - Every allowed push SAYS SO, naming the declaration that permitted it. A
#     silent allowlist is how a gate quietly stops being one.
#   - It is committed. The alternative people actually reach for is
#     SKIP_BRANCH_GATE=1, which leaves no trace anywhere and is invisible to
#     review. A declaration in a tracked file is strictly more accountable than
#     the bypass it replaces.
#
# The bypass remains, environment-only, and expects a stated reason:
#
#   SKIP_BRANCH_GATE=1 git push ...

set -uo pipefail

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=''; YELLOW=''; BOLD=''; RESET=''
fi

[ "${SKIP_BRANCH_GATE:-0}" = "1" ] && exit 0
[ "$#" -eq 0 ] && exit 0

OFFENDING=()
LEGACY=()
DECLARED=()

# Passed explicitly by pre-push rather than read from a sourced file: the
# config loader writes shell variables with `printf -v` and never exports, so a
# child process sees nothing unless it is handed it. Splitting on whitespace is
# the whole grammar; a name containing whitespace is not a branch name.
_declared=" ${DISTINCT_TREE_BRANCHES:-} "

for branch in "$@"; do
    case "$branch" in
        main|dev) ;;
        master) LEGACY+=("$branch") ;;
        *)
            # Exact match against the declared list. `case` with a literal
            # pattern would honour globs in the CONFIG, which is the one thing
            # this must not do.
            if [ "${_declared#* "$branch" }" != "$_declared" ]; then
                DECLARED+=("$branch")
            else
                OFFENDING+=("$branch")
            fi
            ;;
    esac
done

# Announced every time, never silent. An allowlist nobody sees fire is
# indistinguishable from a gate that stopped running.
if [ "${#DECLARED[@]}" -gt 0 ]; then
    for b in "${DECLARED[@]}"; do
        echo "${YELLOW}branch-gate${RESET}: allowing '${BOLD}${b}${RESET}', declared in"
        echo "  .baseline-hook-config as carrying a tree distinct from 'dev'."
        echo "  This is not a feature branch exemption. If that is what it has"
        echo "  become, remove the declaration rather than adding to it."
    done
    echo
fi

# The legacy warning fires whether or not the push is refused: a repo can be
# both on `master` and pushing a stray branch, and the operator wants to hear
# about both in one go rather than one per push.
if [ "${#LEGACY[@]}" -gt 0 ]; then
    echo "${YELLOW}${BOLD}WARNING${RESET}: pushing to 'master'."
    echo "Every project on the fleet is meant to name its release branch 'main'."
    echo "This push is allowed so the repo is not stranded, but the rename is owed:"
    echo "  git branch -m master main"
    echo "  git push origin -u main"
    echo "  # then retarget the default branch in the forge, and delete master"
    echo
fi

if [ "${#OFFENDING[@]}" -eq 0 ]; then
    exit 0
fi

echo "${RED}${BOLD}REFUSED${RESET}: pushing a branch that is neither 'main' nor 'dev'."
echo
echo "Branches failing the check:"
for b in "${OFFENDING[@]}"; do
    echo "  - ${BOLD}${b}${RESET}"
done
echo
echo "Every project has exactly two branches. Routine work, including anything"
echo "that feels like it wants a feature branch, lands on 'dev'. 'dev' promotes"
echo "to 'main' when a release is cut."
echo
echo "To land this work:"
echo "  git checkout dev"
echo "  git merge <branch>        # or cherry-pick the commits you want"
echo "  git push origin dev"
echo
echo "The branch may keep existing locally. This gate blocks the push, not the"
echo "branch, so nothing you have made is lost by stopping here."
echo
echo "If this branch carries a DIFFERENT TREE rather than different work, for"
echo "instance a private hub branch that a second remote needs to keep apart"
echo "from 'dev', declare it instead of bypassing:"
echo
echo "  # .baseline-hook-config"
echo "  DISTINCT_TREE_BRANCHES='${OFFENDING[0]}'"
echo
echo "That is committed and visible in review, and every push it allows says so."
echo
echo "Bypass (last resort, leaves no trace, with recorded reason):"
echo "  SKIP_BRANCH_GATE=1 git push ..."
exit 1
