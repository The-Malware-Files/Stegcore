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
#   PRIVATE_REMOTES='origin'                   # space separated remote NAMES
#   PRIVATE_PATHS='private DEFERRED.md ...'    # space separated pathspecs
#   PUBLISHED_TOOLCHAIN='.githooks'            # toolchain paths this repo serves
#
# There is deliberately NO key that turns this gate off. `PRIVATE_REMOTE_GATE_ENABLED`
# was documented here until 2026-08-11 and had already been removed from the
# code, so the header advertised a disable switch that did not exist, which is
# the worst of both: a reader looking for the escape hatch finds one, sets it,
# and believes the gate is off when it is not. Per ADR 67, config says what is
# checked and never whether. The bypass is environment only and expects a reason:
#   SKIP_PRIVATE_REMOTE_GATE=1 git push
#
# PRIVATE_PATHS REPLACES the default set, it does not extend it, so a project
# that overrides it to publish one path must restate the rest. That is
# deliberate: an extend-only knob makes it impossible to publish anything, and
# a silent replace makes it too easy to drop the whole toolchain guard by
# accident. Restating is the visible middle. The default set is below.
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

# pre-push passes PRIVATE_REMOTES and PRIVATE_PATHS in as environment, having
# already parsed the config. Any OTHER caller (the autosave timer, a human
# running this by hand, a future gate) gets neither, and deny-first then treats
# every remote as public and refuses everything. That is safe but useless, and
# it is why the autosave could not simply call this file.
#
# So when the knobs are absent, load them here using the hook's OWN parser,
# lifted out of the sibling pre-push rather than reimplemented, so this can
# never drift from what pre-push does. Same technique check-hook-compliance.sh
# uses. If anything about the extraction fails we fall through with the knobs
# unset, which lands on deny-first: the failure direction stays correct.
if [ -z "${PRIVATE_REMOTES+x}" ]; then
    _prg_hook="$(git rev-parse --show-toplevel 2>/dev/null)/.githooks/pre-push"
    _prg_cfg="$(git rev-parse --show-toplevel 2>/dev/null)/.baseline-hook-config"
    if [ -r "$_prg_hook" ] && [ -r "$_prg_cfg" ]; then
        _prg_s=$(grep -n '^BHC_BLOCKED_KEYS="' "$_prg_hook" | head -1 | cut -d: -f1)
        _prg_e=$(awk '/^load_baseline_hook_config\(\) \{/{f=1} f&&/^\}$/{print NR; exit}' "$_prg_hook")
        if [ -n "$_prg_s" ] && [ -n "$_prg_e" ]; then
            _prg_tmp=$(mktemp)
            sed -n "${_prg_s},${_prg_e}p" "$_prg_hook" > "$_prg_tmp"
            # shellcheck disable=SC1090
            . "$_prg_tmp" 2>/dev/null && load_baseline_hook_config "$_prg_cfg" >/dev/null 2>&1
            rm -f "$_prg_tmp"
        fi
    fi
fi

# Default set: the private-directory convention, the per-project state files
# that tooling tends to leave at the repo root, and the operator toolchain
# itself. Override per project.
#
# The toolchain entries were added 2026-08-10 after a public repo was found
# serving a tracked `.githooks/pre-commit` whose forbidden-string regex was an
# inventory of exactly what it existed to suppress: product names, an internal
# hostname, a hosting region, key NAMES and two unpublished detection concepts.
# No key values, and none needed. A config that enumerates what it protects is
# a map to it.
#
# This gate did not fire, because it only ever guarded `private/`-style paths.
# The toolchain could be published freely and nothing objected. Deny-first means
# the tooling is refused by default and a project that genuinely intends to
# publish it says so; the reverse default puts the burden in the wrong place,
# and the anya repo is what that costs.
#
# `scripts/hooks` rather than `scripts`: the session hooks are operator state,
# while `scripts/` at large is ordinary product tooling in most repos and
# blanket-refusing it would train people to override the gate wholesale.
PRIVATE_PATHS="${PRIVATE_PATHS:-private private-* DEFERRED.md .project-state.md .hephaestus-sync.toml OPERATOR_ACTIONS.md catastrophic}"

# The toolchain is a FLOOR, unioned in after the knob is read, not part of the
# default the knob replaces.
#
# Making it part of the default was a bug, found in review before it shipped
# anywhere. `PRIVATE_PATHS` replaces rather than extends, so a project that had
# already set the knob for its own reasons kept its narrow list and silently
# opted out of the fix. One repo on this fleet was in exactly that state, and it
# was one of the repos the fix was written for. An override written months ago,
# for unrelated reasons, must not be able to turn off a protection added later.
#
# That is ADR 67 applied to a path list: config may say WHAT is checked, never
# WHETHER. Omission is not a decision, so it cannot disable anything. Publishing
# a toolchain path is a real decision, so it has to be stated, by NAMING the
# path in PUBLISHED_TOOLCHAIN. A project that genuinely serves its hooks
# publicly says which ones, and the statement is visible in review.
TOOLCHAIN_FLOOR=".githooks .baseline-hook-config .baseline-hook-allow .baseline-version .claude CLAUDE.md AGENTS.md scripts/hooks"

for _f in $TOOLCHAIN_FLOOR; do
    _published=0
    for _p in ${PUBLISHED_TOOLCHAIN:-}; do
        [ "$_p" = "$_f" ] && _published=1
    done
    [ "$_published" = 1 ] && continue
    case " $PRIVATE_PATHS " in
        *" $_f "*) ;;
        *) PRIVATE_PATHS="$PRIVATE_PATHS $_f" ;;
    esac
done

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

    # A scan that could not run has not passed.
    #
    # Every scan below used to end in `2>/dev/null || true`. Any pathspec git
    # rejected therefore made the command exit 128 with its error swallowed,
    # left OFFENDING empty, and exited 0 while pre-push printed "all gates
    # passed". Demonstrated end to end on 2026-08-11: one misspelt magic word in
    # a committed PRIVATE_PATHS,
    #
    #     PRIVATE_PATHS=':(bogus)x'
    #
    # put private/ on a public remote in silence. It needs no malice either;
    # `:(exclud)private` and `:(glob,bogus)x` do it by typo, and this file's own
    # header promises the opposite property, that config may say what is checked
    # and never whether.
    #
    # Failing closed here is cheap: a genuine scan returns 0 with empty output
    # when there is nothing to report, so non-zero really does mean "did not
    # run".
    _scan() {
        local _out _rc
        _out=$(git "$@" 2>&1); _rc=$?
        if [ "$_rc" -ne 0 ]; then
            echo "${RED}${BOLD}REFUSED${RESET}: the private-material scan could not run." >&2
            echo "  git exited ${_rc}: ${_out}" >&2
            echo "  This usually means PRIVATE_PATHS carries an invalid pathspec." >&2
            echo "  The gate refuses rather than passing a push it never inspected." >&2
            exit 1
        fi
        printf '%s\n' "$_out"
    }

    # What the remote will serve once this lands.
    tip=$(_scan ls-tree -r --name-only "${ls}^{tree}" -- "${_paths[@]}")

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
        # A brand-new branch on THIS remote. The exclusion set must be scoped to
        # the remote being pushed to, and to nothing else.
        #
        # `--not --remotes` was wrong twice over. It counted refs from EVERY
        # remote, so the ordinary two-remote workflow (push the branch to the
        # private hub, then push it to the public one) made the second push scan
        # zero commits: the commits were already "known" via the private remote's
        # refs. It also counted the autosave's `wip/` refs, which are a local
        # safety net and not publication, so any branch the ten-minute timer had
        # touched scanned nothing either. In both cases a file added in one
        # commit and removed in the next passed the gate and landed permanently
        # in the public remote's history, which is the exact leak this file
        # exists to prevent.
        #
        # When the target remote has no local refs at all (never fetched, or a
        # genuinely first push), there is nothing legitimately "already there",
        # so the honest answer is to scan the branch's full history rather than
        # fall back to an empty exclusion set that reduces to the same bug.
        _known=$(git for-each-ref --format='%(refname)' "refs/remotes/$remote" 2>/dev/null \
                 | grep -v '/wip/' || true)
        if [ -n "$_known" ]; then
            # shellcheck disable=SC2086
            intro=$(_scan log --format= --name-only --diff-filter=d \
                    "$ls" --not $_known -- "${_paths[@]}")
        else
            intro=$(_scan log --format= --name-only --diff-filter=d \
                    "$ls" -- "${_paths[@]}")
        fi
    else
        intro=$(_scan log --format= --name-only --diff-filter=d \
                "${rs}..${ls}" -- "${_paths[@]}")
    fi

    for f in $tip $intro; do
        case " $OFFENDING " in *" $f "*) continue ;; esac
        OFFENDING="$OFFENDING $f"
    done
done

# ── A CLIENT NAME IN PROSE IS NOT A PATH ────────────────────────────────────
#
# Everything above matches PATHS. On 2026-09-14 a panel found a real client's
# name committed in a COMMENT in scripts/hooks/cache-reaper.sh, in seventeen
# repositories and in the scaffolding template, and then again twice in an ADR.
# The file was not private, the directory was not private, and the name was
# three words into a sentence about something else, so every check here passed
# it. The only content-level detector on the fleet lived inside one project's
# test suite and searched two of that project's own directories.
#
# The control existed and was pointed at the wrong tree.
#
# THE DERIVATION IS THE USEFUL HALF. The forbidden names are READ from wherever
# the project already records its clients, so a new engagement becomes forbidden
# in public prose the moment somebody writes it down. Nobody extends a list, and
# a list nobody maintains is the failure mode of every enumeration this fleet
# has written.
#
# THE RESIDUE, stated here rather than left for somebody to find: this catches
# the names somebody already wrote down. Neither this hook nor its author knows
# what a different string would find. It is a strictly better floor than
# matching paths alone and it is NOT a solution to the class.
#
# Configured, and empty by default, because a default that named one project's
# files would be exactly the coupling that put the only existing detector in the
# wrong tree:
#
#   PRIVATE_NAME_SOURCES='mjolnir/traps.toml private/clients.txt'
#
NAME_OFFENDING=""
NAME_SOURCES="${PRIVATE_NAME_SOURCES:-}"
if [ -z "$NAME_SOURCES" ]; then
    # ANNOUNCED, not silent. An unset source list means this half of the gate is
    # not running, and "not checked" and "checked and clean" must never be the
    # same observable. Once per push, to stderr, without refusing.
    echo "[private-remote-gate] note: PRIVATE_NAME_SOURCES is unset, so no content check ran." >&2
    echo "                     Only PATHS were checked. Set it in .baseline-hook-config." >&2
else
    # A stem is the bare label of a domain-shaped token: `resolvehealthware`
    # from `resolvehealthware.com`. Extensions and reserved TLDs are dropped so
    # the check does not fire on `example.com` or `.local`.
    #
    # THE SUFFIX MUST BE A TLD, not merely two or more letters. Matching
    # `label.anything` pulled `readme` out of `README.md` and `in-scope` out of
    # a sentence ending in a full stop, and a gate whose findings are two thirds
    # noise is one people learn to bypass. Measured against this repository's
    # own history on 2026-09-14: three findings, one real.
    #
    # An allowlist of TLDs rather than a denylist of file extensions, because
    # the TLDs a client actually uses are a short reviewable set and the
    # extensions a repository contains are not. Same inversion the network half
    # of the Aegis classifier uses: enumerate what is ours, not what is theirs.
    _tlds='com|net|org|io|co|uk|dev|ai|app|cloud|tech|health|care|group|ltd|llc|inc|eu|de|fr|nl|us|ca|au|nz|za|ie|se|no|fi|es|it|ch|at|be|dk|pl|pt|gr|com\.au|co\.uk|co\.za|org\.uk'
    _stems=$(
        for f in $NAME_SOURCES; do
            [ -r "$f" ] || continue
            grep -ohE "[A-Za-z][A-Za-z0-9-]{2,}\.($_tlds)\b" "$f" 2>/dev/null
        done | sed 's/\..*$//' | tr 'A-Z' 'a-z' | sort -u
    )

    # A STEM THAT IS AN ORDINARY WORD IS WORSE THAN NO STEM.
    #
    # A gate that refuses ordinary words is one people learn to bypass, and then
    # there is no gate. The obvious defence is a minimum length, and MEASURED on
    # 2026-09-14 that is not enough on its own: of 200 randomly chosen
    # EIGHT-character English words, 52 already appear in this repository's docs
    # and scripts, so a client stem that happens to be an eight-letter word
    # would fire on roughly a quarter of pushes.
    #
    # So the length floor stays as a cheap first filter and the real test is
    # whether the stem is a word. Where no dictionary exists the check degrades
    # to length alone AND SAYS SO, because a silently weaker check is the thing
    # this whole file is about.
    _min="${PRIVATE_NAME_MIN_STEM:-6}"
    _dict=""
    for d in /usr/share/dict/british-english /usr/share/dict/american-english /usr/share/dict/words; do
        [ -r "$d" ] && { _dict="$d"; break; }
    done
    if [ -z "$_dict" ] && [ -n "$_stems" ]; then
        echo "[private-remote-gate] note: no system dictionary, so stems are filtered by length" >&2
        echo "                     (>= $_min) alone. A stem that is an ordinary word will fire." >&2
    fi

    _checked=""
    for stem in $_stems; do
        [ "${#stem}" -ge "$_min" ] || continue
        # Reserved and infrastructure names that are not clients.
        case "$stem" in
            example|localhost|invalid|test|local|internal|olympus|github|forgejo|tailscale) continue ;;
        esac
        if [ -n "$_dict" ] && grep -qixF "$stem" "$_dict" 2>/dev/null; then
            continue
        fi
        _checked="$_checked $stem"
    done

    if [ -n "$_checked" ]; then
        for pair in "$@"; do
            ls="${pair%%:*}"
            rs="${pair##*:}"
            [ -n "$ls" ] || continue
            [ "$ls" = "$zero" ] && continue
            # The SAME range the path check uses, so the two halves cannot
            # disagree about what this push introduces, and so a first push to a
            # new remote does not walk history twice.
            if [ "$rs" = "$zero" ]; then
                _known=$(git for-each-ref --format='%(refname)' "refs/remotes/$remote" 2>/dev/null \
                         | grep -v '/wip/' || true)
                if [ -n "$_known" ]; then
                    # shellcheck disable=SC2086
                    _added=$(git log --format= -p --diff-filter=d "$ls" --not $_known 2>/dev/null | grep '^+' || true)
                else
                    _added=$(git log --format= -p --diff-filter=d "$ls" 2>/dev/null | grep '^+' || true)
                fi
            else
                _added=$(git log --format= -p --diff-filter=d "${rs}..${ls}" 2>/dev/null | grep '^+' || true)
            fi
            for stem in $_checked; do
                case " $NAME_OFFENDING " in *" $stem "*) continue ;; esac
                if printf '%s' "$_added" | grep -qiF "$stem"; then
                    NAME_OFFENDING="$NAME_OFFENDING $stem"
                fi
            done
        done
    fi
fi

# REPORTED SEPARATELY, so a path hit and a content hit never mask each other.
# They are independent findings about the same push and either one refuses it.
if [ -n "$NAME_OFFENDING" ]; then
    url=$(git remote get-url "$remote" 2>/dev/null || echo "unknown")
    echo
    echo "${RED}${BOLD}REFUSED${RESET}: a recorded client name appears in a push to '${remote}'."
    echo
    echo "  remote '${remote}' -> ${url}"
    echo "  '${remote}' is not listed in PRIVATE_REMOTES, so it is treated as public."
    echo
    echo "${BOLD}Names found in the content this push introduces:${RESET}"
    for n in $NAME_OFFENDING; do echo "    $n"; done
    echo
    echo "  These were read from: $NAME_SOURCES"
    echo "  They are forbidden in public prose BECAUSE the project records them"
    echo "  as clients there. That is the point: nobody has to extend a list."
    echo
    echo "${BOLD}Fix one of these:${RESET}"
    echo "  - Anonymise the mention. The sentence usually survives it:"
    echo "        engagement-acme  ->  engagement-a***"
    echo "  - Pushing to the wrong remote? Push to one you declared private."
    echo "  - Not actually a client name? Narrow PRIVATE_NAME_SOURCES, or raise"
    echo "        PRIVATE_NAME_MIN_STEM (currently ${PRIVATE_NAME_MIN_STEM:-6})."
    echo
    echo "${YELLOW}Bypass (last resort, record the reason):${RESET}"
    echo "  SKIP_PRIVATE_REMOTE_GATE=1 git push ${remote} ..."
    echo
    exit 1
fi

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
