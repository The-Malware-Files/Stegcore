#!/usr/bin/env bash
# Author:  Daniel Iwugo
# Comment: Christ is King
# empty-remote-gate.sh — refuse a push to a commitless remote until somebody has
# read that remote's visibility.
#
# Designed to be called from `pre-push`. It is NOT wired into `pre-push` by the
# commit that introduced it; that call is the operator's to place.
#
# Usage:  empty-remote-gate.sh <remote-name> [<remote-url>]
#
# ── THE FAILURE THIS CLOSES, reported by a peer 2026-09-21 ─────────────────
#
# **A push to an empty remote is a CREATE, and a create needs to know the
# visibility.** A documentation site describing an unpublished corpus was pushed
# to a remote that held no refs. The push behaved like every other push:
# fast forward, no prompt, no warning. What it actually did was create a
# repository, and on that host a created repository is public by default.
#
# That is a publication event wearing a git push's clothes, and **publication is
# not undone by deleting the repository.** By the time the mistake is visible the
# content has been served, crawled, and possibly mirrored. Every other git
# mistake has a recovery path; this one does not, which is what makes a gate
# worth its false positives here and not elsewhere.
#
# ── WHY "EMPTY" IS THE TRIGGER AND NOT "PUBLIC" ───────────────────────────
#
# A remote that already holds refs was already created by somebody who made that
# decision, and pushing another commit to it changes nothing about who can read
# it. So a remote with refs exits 0 silently: this gate has one subject and that
# subject is creates.
#
# ── THE BRANCH THAT MATTERS: "I COULD NOT LOOK" ───────────────────────────
#
# Three outcomes, and the third is the reason this script exists rather than a
# two line check:
#
#   PRIVATE                 allow, with a note
#   PUBLIC                  refuse, loudly
#   COULD NOT BE DETERMINED refuse, and say that it could not be determined
#
# **An unauthenticated API check returns 403 rather than 404 on some hosts**, so
# an error, an empty body and a refusal all arrive looking alike. On 2026-09-21
# exactly that happened against a forgejo instance. If "I could not look"
# renders as "it is fine", the gate is worse than absent: it puts a green tick on
# the one case nobody checked.
#
# So the unknown branch refuses. It is the uncomfortable choice and it is the
# only honest one, because the cost of a wrong allow here is permanent and the
# cost of a wrong refusal is one environment variable.
#
# ── WHAT IT DOES NOT CATCH, stated rather than left to be discovered ──────
#
# `git ls-remote --heads` lists branches. A remote holding only tags reads as
# empty here and gets the visibility check it did not strictly need, which is
# the harmless direction.
#
# Visibility can only be established for github.com today, via `gh repo view`.
# Every other host, including the fleet's own forgejo, lands in the unknown
# branch and is refused. That is a real cost and it is deliberate: the
# alternative is a host specific guess, and a guess is what this gate exists to
# prevent. When a forgejo route is found, it goes here.
#
# It also cannot tell a private repository whose content is nonetheless public
# by some other route. It answers one question: is the repository this push would
# CREATE readable by the world.
#
# ── THE ESCAPE HATCH, because a gate with no bypass gets deleted ──────────
#
#   EMPTY_REMOTE_OK=1 git push ...
#
# A reason is expected, and the variable will carry it if you give it one:
#
#   EMPTY_REMOTE_OK="new private mirror, checked in the web UI" git push ...
#
# The reason is printed to stderr so it lands in the terminal record beside the
# push it permitted. An unexplained bypass is allowed and says so, because a
# bypass that is itself refusable is a gate with no bypass.
set -uo pipefail

GATE_VERSION="2026-09-21.1"
note() { printf '[empty-remote-gate %s] %s\n' "$GATE_VERSION" "$*" >&2; }

ALLOW=0
REFUSE=1

remote=${1:-}
remote_url=${2:-}

# ── The bypass, first, so a refusal can never trap the operator ────────────
if [ -n "${EMPTY_REMOTE_OK:-}" ]; then
    if [ "${EMPTY_REMOTE_OK}" = "1" ]; then
        note "BYPASSED with no reason given. Allowing the push. A reason belongs in EMPTY_REMOTE_OK so the record says why."
    else
        note "BYPASSED, reason as given: ${EMPTY_REMOTE_OK}"
    fi
    exit $ALLOW
fi

if [ -z "$remote" ]; then
    cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: no remote was named.

  This gate decides whether a push would CREATE a repository, and it cannot
  answer that about a remote nobody named. Called from pre-push, the remote is
  the hook's first argument.

    empty-remote-gate.sh <remote-name> [<remote-url>]

  Not a real create?  EMPTY_REMOTE_OK="<why>" git push ...
MSG
    exit $REFUSE
fi

if ! command -v git >/dev/null 2>&1; then
    cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: git is not on PATH.

  Whether the remote holds any refs COULD NOT BE DETERMINED, so whether this
  push is a create could not be determined either. That is not the same as a
  remote that is safe, and it is not being reported as one.

  Bypass:  EMPTY_REMOTE_OK="<why>" git push ...
MSG
    exit $REFUSE
fi

if [ -z "$remote_url" ]; then
    remote_url=$(git remote get-url "$remote" 2>/dev/null || printf '%s' "$remote")
fi

# ── 1. Does the remote hold any refs? Only a create is this gate's business ──
#
# An empty body from a SUCCESSFUL ls-remote means no branches. An ls-remote that
# failed means nothing at all was learned, and those two must not share a code
# path (principle 17).
if ! refs=$(git ls-remote --heads "$remote" 2>/dev/null); then
    cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: could not read the remote's refs.

  remote: $remote
     url: $remote_url

  \`git ls-remote --heads\` failed, so whether this remote already holds
  branches COULD NOT BE DETERMINED. An unreachable remote and an empty one look
  identical from here, and only one of them makes this push a create.

  This is refused rather than allowed because a create against a public host is
  a publication, and publication is not undone by deleting the repository.

  If the remote is simply unreachable, the push was going to fail anyway. Check
  the network, the auth, and the remote name, then push again.

  Bypass:  EMPTY_REMOTE_OK="<why>" git push ...
MSG
    exit $REFUSE
fi

if printf '%s' "$refs" | grep -q .; then
    # Already created by somebody who decided to. Not this gate's subject.
    exit $ALLOW
fi

note "the remote '$remote' holds no branches, so this push would CREATE it. Establishing its visibility before allowing."

# ── 2. Can the visibility be established? ─────────────────────────────────
case "$remote_url" in
    *github.com*) host=github ;;
    *)
        cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: this push would create a repository and its visibility COULD NOT BE DETERMINED.

  remote: $remote
     url: $remote_url

  The remote holds no branches, so this push is a create. Only github.com can
  be checked from here, with \`gh repo view\`, and this is not a github.com URL.

  It is refused rather than allowed because "I could not look" and "it is fine"
  must not render the same. On 2026-09-21 an unauthenticated check against a
  forgejo instance answered 403 rather than 404, which reads as an error, an
  empty repository and a refusal all at once.

  Read the visibility yourself, in the host's web UI, then say so:

    EMPTY_REMOTE_OK="checked in the web UI, the repo is private" git push ...

  If the repository turns out to be public and the content is not meant to be:
  do not push. Publication is not undone by deleting the repository.
MSG
        exit $REFUSE
        ;;
esac

if ! command -v gh >/dev/null 2>&1; then
    cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: this push would create a github.com repository and its visibility COULD NOT BE DETERMINED.

  remote: $remote
     url: $remote_url

  The \`gh\` CLI is the only route this gate has to github.com's visibility and
  it is not installed, so nothing was learned. That is not the same as a remote
  that is safe.

  Either install gh and authenticate it, or read the visibility in the web UI
  and say so:

    EMPTY_REMOTE_OK="checked in the web UI, the repo is private" git push ...
MSG
    exit $REFUSE
fi

# owner/repo out of the URL. Both SSH and HTTPS spellings, with or without .git.
slug=$(printf '%s' "$remote_url" \
    | sed -E 's#^[a-z+]+://##; s#^[^@]*@##; s#^github\.com[:/]##; s#\.git$##; s#/+$##')
case "$slug" in
    */*) ;;
    *)
        cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: this push would create a repository and its visibility COULD NOT BE DETERMINED.

  remote: $remote
     url: $remote_url

  The owner/repo could not be read out of that URL, so \`gh repo view\` was
  never called and nothing was learned about the visibility.

  Bypass, once you have read it yourself:
    EMPTY_REMOTE_OK="<what you read, and where>" git push ...
MSG
        exit $REFUSE
        ;;
esac

if ! gh_out=$(gh repo view "$slug" --json visibility 2>&1); then
    cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: this push would create $slug and its visibility COULD NOT BE DETERMINED.

  \`gh repo view $slug --json visibility\` failed. What it said:

    $gh_out

  A 403 from an unauthenticated check, a 404 for a repository that does not
  exist yet, and a network failure all arrive here looking alike, and none of
  them means public or private. So nothing is being claimed about this
  repository.

  Authenticate gh (\`gh auth status\`), or read the visibility in the web UI and
  say so:

    EMPTY_REMOTE_OK="checked in the web UI, the repo is private" git push ...
MSG
    exit $REFUSE
fi

# jq when it is there; otherwise read the one field out of the JSON directly,
# because a missing jq must not turn a determinable answer into an unknown one.
if command -v jq >/dev/null 2>&1; then
    visibility=$(printf '%s' "$gh_out" | jq -r '.visibility // ""' 2>/dev/null || printf '')
else
    visibility=$(printf '%s' "$gh_out" | sed -n 's/.*"visibility"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
fi
visibility=$(printf '%s' "$visibility" | tr '[:lower:]' '[:upper:]')

case "$visibility" in
    PRIVATE)
        note "ALLOWED: $slug does not exist yet or holds no branches, and github.com reports its visibility as PRIVATE. This push creates a private repository."
        exit $ALLOW
        ;;
    PUBLIC)
        cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: this push would publish to a PUBLIC repository.

  remote: $remote
    repo: $slug
     url: $remote_url

  The remote holds no branches, so this push CREATES its contents, and
  github.com reports that repository as PUBLIC. Everything in the pushed refs
  becomes world readable the moment this completes.

  **Publication is not undone by deleting the repository.** By the time it is
  noticed the content has been served and may already be crawled and mirrored.
  Every other git mistake has a recovery path. This one does not.

  Before doing anything else, decide whether the content is meant to be public:

    * it is not  ->  do not push. Make the repository private first, or push to
                     a private remote instead.
    * it is      ->  say so, and the push goes through:
                     EMPTY_REMOTE_OK="deliberate publication of <what>" git push ...

  A documentation site describing an unpublished corpus is the case that
  produced this gate. It read as an ordinary fast forward.
MSG
        exit $REFUSE
        ;;
    "")
        cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: this push would create $slug and its visibility COULD NOT BE DETERMINED.

  \`gh repo view\` succeeded and its answer carried no visibility field. What it
  returned:

    $gh_out

  An answer that does not contain the fact asked for is not a reassuring
  answer, so nothing is being claimed about this repository.

  Bypass, once you have read it yourself:
    EMPTY_REMOTE_OK="<what you read, and where>" git push ...
MSG
        exit $REFUSE
        ;;
    *)
        cat >&2 <<MSG
[empty-remote-gate $GATE_VERSION] REFUSED: this push would create $slug and its visibility is a value this gate does not understand.

  github.com reported:  $visibility

  That is neither PRIVATE nor PUBLIC. It may be an organisation's INTERNAL
  visibility, which is readable by everybody in that organisation, or it may be
  something newer than this gate.

  It is refused rather than guessed at, because guessing is what this gate
  exists to prevent. Decide who should be able to read this, then say so:

    EMPTY_REMOTE_OK="$visibility is intended here, because <why>" git push ...
MSG
        exit $REFUSE
        ;;
esac
