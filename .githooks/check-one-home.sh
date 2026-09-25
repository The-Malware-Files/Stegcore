#!/usr/bin/env bash
# Author:  Daniel Iwugo
# Comment: Christ is King
#
# check-one-home.sh — one home per fact, enforced instead of remembered.
#
# WHY
#
# ICM (Interpretable Context Methodology) names Pattern 5: every piece of
# information has exactly one home. The pattern is right and the repo cannot obey
# it literally, because some files genuinely live twice: the fleet installs hooks
# from `tools/claude-setup/hooks/` and git runs `.githooks/`. So the rule enforced
# here is the enforceable half. A second home must be DECLARED in
# `one-home.manifest`, and declared copies must be byte-identical.
#
# It is a gate rather than a convention because 2026-09-07 spent a day on what
# conventions do when nobody is looking: `install.sh` wrong in both copies in
# different ways, an installed unit newer than the repo's, `pre-commit` and
# `pre-push` carrying a per-project addition their canonical copies lacked, and
# four drift detectors nobody consulted. A rule you must remember is not a
# control ([[a-constraint-beats-a-gate]]).
#
# THREE CHECKS
#
#   1. Declared pairs must match. The canonical side is named first in the
#      manifest and is the one to edit.
#   2. A staged file whose content already exists at another tracked path is an
#      UNDECLARED second home. Either name the pair in the manifest, or delete
#      one. This is the check that catches the next one rather than the last one.
#   3. A declared TOPIC may be discussed away from its owner only if that passage
#      also routes to the owner. This is the restatement check; see below.
#
# WHY CHECK 3 EXISTS
#
# Checks 1 and 2 both compare content hashes, so between them they enforce one
# home per FILE. Pattern 5 says one home per FACT, and the gap between those two
# sentences was measured on 2026-09-08: `AGENTS.md` and `CLAUDE.md` state 9 of 10
# sampled rule topics BOTH, at 3% verbatim overlap (41 shared 8-word shingles out
# of 1,248). Not a copy. A restatement, in different words, of the same rule. A
# hash comparison cannot see it by construction, and it is the more dangerous of
# the two shapes: a copy that drifts is visibly two files disagreeing, whereas a
# restatement that drifts just looks like two documents, each internally fine.
#
# It had already drifted twice by the time the check was written. `AGENTS.md`
# routed rule 3 to a SISTER PROJECT'S `CLAUDE.md §2` as canonical rather than to
# this repo's; and on the toolchain pin the two documents disagreed with the
# COPY being right and the canonical side stale ("pin when v0.1 begins", written
# before v0.1 shipped and `rust-toolchain.toml` landed).
#
# HOW IT WORKS, and what it deliberately does not attempt
#
# It does not try to detect paraphrase. Judging whether two paragraphs mean the
# same thing is not something a shell gate can do honestly, and a gate that
# guesses at meaning produces findings nobody trusts. Instead the manifest
# DECLARES the topics that have one home, and the gate enforces the mechanical
# consequence: if a scoped document discusses a topic it does not own, the
# passage must route to the owner. A link is allowed; a restatement is not.
#
# So this is a ratchet rather than a proof. It catches exactly the topics named
# in the manifest and is blind to every topic nobody has named yet, which is
# stated here so the check is never mistaken for coverage. Each topic added is
# one more fact that cannot quietly grow a second home.
#
# WHAT IT CANNOT SEE, stated rather than implied: copies outside the repo. Those
# are split between two owners, and until 2026-09-13 this comment named only one
# of them while neither actually held the ground:
#
#   an installed systemd unit   `scripts/converge-machine.sh`
#   any other deployed file     `scripts/hooks/check-deployed-drift.sh`
#
# The second did not exist. converge-machine converges units and the installed
# binary, and never claimed the rest; this comment sent the reader to it anyway.
# The gap cost a measurement: the bench sweep on atlas ran four commits behind
# the repo, still carrying a RAM gate the repo had replaced, and a 19 GB model
# was deleted on the strength of what it reported. Naming a limit is not the same
# as covering it, and a handoff between two honest statements is where the ground
# goes unowned.
#
# Usage:  check-one-home.sh [--staged]
#   --staged   compare the STAGED content (hook use). Default: the working tree.
#
# Exit 0 clean, 1 on a finding, 2 when it could not run.

set -uo pipefail

STAGED=0
[ "${1:-}" = "--staged" ] && STAGED=1

root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$root" || exit 0

MANIFEST="$root/one-home.manifest"

# Where the fleet canonical lives, for the `fleet-pair` and `fleet-dir`
# directives. Looked up rather than assumed, and absent is a legitimate answer:
# a project cloned on a machine with no hephaestus checkout still has to be
# committable, so those directives degrade to a note there rather than to a
# refusal. Empty means "not found", which every use below tests for.
# Counts fleet directives skipped for want of a checkout. Declared here because
# `set -u` is on and it is first touched inside a loop branch that may never run.
fleet_unchecked=0

FLEET_ROOT=""
for _c in "${HEPHAESTUS_ROOT:-}" "$root/../hephaestus" "$HOME/the-factory/hephaestus"; do
    [ -n "$_c" ] || continue
    # VALIDATED, NOT MERELY SET. An HEPHAESTUS_ROOT pointing somewhere that is
    # not a hephaestus checkout used to count as found, and every fleet directive
    # then reported its canonical as missing, turning "there is no fleet here" into
    # a wall of findings that refuse the commit. That is precisely the outcome the
    # note path exists to avoid, so the marker file decides rather than the
    # variable being non-empty.
    if [ -f "$_c/tools/claude-setup/install-project.sh" ]; then
        FLEET_ROOT="$(cd "$_c" && pwd)"
        break
    fi
done
# A missing manifest is not "clean". Every other check in this repo that opened
# with a silent `exit 0` on a missing input eventually reported sound about a
# thing that was not there, which is what `hooks-live-check.sh` was written to
# stop. Say it and pass, so the absence is visible without blocking a commit in
# a repo that has not adopted the manifest.
if [ ! -f "$MANIFEST" ]; then
    echo "[one-home] no one-home.manifest at the repo root, so NOTHING is checked here."
    exit 0
fi

findings=()
notes=()

# Content hash of a path, from the index when --staged and from disk otherwise.
# Using git's hash rather than sha256sum means the staged and working-tree paths
# compare the same way, and a file git does not have is reported as absent rather
# than as a mismatch against an empty string.
content_hash() {
    local p="$1" h=""
    if [ "$STAGED" = 1 ]; then
        # `git ls-files -s` reads the index, which is exactly what is about to be
        # committed, including a staged deletion (absent from the output).
        h=$(git ls-files -s -- "$p" 2>/dev/null | awk '{print $2}')
        [ -n "$h" ] && { printf '%s\n' "$h"; return 0; }
        # Not in the index. That is not the same as absent, and treating it as
        # absent was this gate's first bug: `.git/info/exclude` carries
        # `/.githooks/`, because the installed hooks are an install TARGET whose
        # canonical home is tools/claude-setup/hooks/. Nine of the twelve files
        # there are tracked only because they predate that line. So the copy that
        # actually runs on every commit is, for three of them, untracked, and a
        # gate that reads only the index would report the running hook as missing
        # while it is right there doing its job.
        :
    fi
    [ -f "$p" ] || return 0
    git hash-object -- "$p" 2>/dev/null
}

# Which side changed most recently, so a mismatch says where to look rather than
# only that it exists. Advisory: a file touched without a commit has no date here.
last_touch() { git log -1 --format=%cs -- "$1" 2>/dev/null || true; }

compare_pair() {
    local canon="$1" copy="$2" why="${3:-}"
    local a b
    a=$(content_hash "$canon"); b=$(content_hash "$copy")
    if [ -z "$a" ] && [ -z "$b" ]; then
        notes+=("declared pair is absent on both sides: $canon and $copy (stale manifest entry?)")
        return
    fi
    if [ -z "$a" ]; then
        findings+=("MISSING CANONICAL: $canon is gone but its copy $copy is still here. The copy is now the only home and nothing installs it.")
        return
    fi
    if [ -z "$b" ]; then
        findings+=("MISSING COPY: $copy is gone while $canon remains. Whatever ran from the copy is not running now.")
        return
    fi
    if [ "$a" != "$b" ]; then
        findings+=("DIVERGED: $copy differs from its canonical home $canon${why:+  ($why)}
      canonical last committed: $(last_touch "$canon")   copy: $(last_touch "$copy")
      diff: diff '$canon' '$copy'")
    fi
}

# The route must sit in the PARAGRAPH that states the fact. A section that
# discusses a rule and links the owner three paragraphs later is not routing; the
# reader has already read the restatement by then.
#
# This was a +/-12 line window, tunable by a `TOPIC_WINDOW` environment variable.
# Both are gone. The window was too coarse (one unrelated link licensed a long
# restatement anywhere near it) and the variable was an UNTRACED bypass on a gate
# that advertises exactly one, `SKIP_ONE_HOME=1`, "with a stated reason":
# `TOPIC_WINDOW=9999` disabled the check silently, with nothing in the output
# saying so. A gate with an undocumented off switch is a gate you cannot rely on
# having run.

# ── Directive 1 and 2: the declared pairs ────────────────────────────────────
DUP_OK=()
TOPIC_ID=(); TOPIC_OWNER=(); TOPIC_RE=(); TOPIC_SCOPE=()
# Globbing OFF for the whole parse. `set -- $line` needs word splitting (the
# manifest is whitespace separated) but must NOT expand patterns: with globbing
# on, a `dup-ok` line's pattern is expanded against the working directory and
# `$2` becomes the first matching FILENAME instead of the pattern. Both live
# `dup-ok` entries were inert because of this, one of them expanding to a
# directory name that can never match a file path, so the exemptions they
# declare have never applied and the pairs they cover survive only by accident
# of a second rule. Which filename won was also locale dependent.
set -f
while IFS= read -r line; do
    line="${line%%#*}"
    # Quoting is not supported by this parser, so a path containing whitespace
    # is silently torn in two and produces a nonsense finding about a file that
    # does not exist. Refuse it loudly instead of guessing.
    case "$line" in
        *\"*|*\'*)
            findings+=("manifest: quotes are not supported; paths must not contain spaces: $line")
            continue
            ;;
    esac
    # shellcheck disable=SC2086
    set -- $line
    [ $# -eq 0 ] && continue
    case "$1" in
        pair)
            [ $# -ge 3 ] || { findings+=("manifest: 'pair' needs two paths: $line"); continue; }
            compare_pair "$2" "$3"
            ;;
        dir)
            [ $# -ge 3 ] || { findings+=("manifest: 'dir' needs two directories: $line"); continue; }
            cdir="${2%/}"; pdir="${3%/}"
            if [ ! -d "$cdir" ] && [ ! -d "$pdir" ]; then
                notes+=("declared directory pair is absent on both sides: $cdir and $pdir")
                continue
            fi
            # Only files present in BOTH are compared. A file the canonical
            # directory has and the copy does not is usually a fleet artefact this
            # project does not install; a file only the copy has is usually a
            # project-specific gate. Both are worth seeing and neither is a defect.
            # Enumerated from DISK rather than from the index, because the copy
            # side is frequently an install target that git does not track (see
            # content_hash). Listing it with `git ls-files` reported three live,
            # running hooks as absent.
            while IFS= read -r f; do
                base="${f#"$cdir"/}"
                if [ -e "$pdir/$base" ]; then
                    compare_pair "$cdir/$base" "$pdir/$base"
                else
                    notes+=("only in the canonical $cdir: $base (this project does not install it)")
                fi
            done < <(find "$cdir" -type f 2>/dev/null | sort)
            while IFS= read -r f; do
                base="${f#"$pdir"/}"
                [ -e "$cdir/$base" ] || notes+=("only in $pdir: $base (project-specific; a wholesale copy from $cdir would delete it)")
            done < <(find "$pdir" -type f 2>/dev/null | sort)
            ;;
        # ── Cross repository, because most copies are not in this repository ──
        #
        # `pair` and `dir` compare two paths inside ONE repository, which is the
        # shape hephaestus has and almost nothing else does. A consumer project
        # holds copies whose canonical lives in hephaestus, so before this there
        # was no directive that could name them, and the practical result was
        # that nineteen projects shipped no manifest at all and this gate
        # announced "no one-home.manifest at the repo root, so NOTHING is checked
        # here" on every single commit. A gate that says it is checking nothing,
        # every time, becomes scenery (peer session, 2026-09-25).
        #
        # A MISSING FLEET ROOT IS A NOTE, NOT A FINDING. A project cloned on a
        # machine that has no hephaestus checkout must still be committable, and
        # a gate that refuses those commits is one somebody disables for good.
        fleet-pair | fleet-dir)
            [ $# -ge 3 ] || { findings+=("manifest: '$1' needs a fleet path and a local path: $line"); continue; }
            if [ -z "${FLEET_ROOT:-}" ]; then
                fleet_unchecked=$((fleet_unchecked + 1))
                continue
            fi
            fcanon="$FLEET_ROOT/${2#/}"
            if [ ! -e "$fcanon" ]; then
                findings+=("manifest: the fleet canonical is missing: $fcanon")
                continue
            fi
            if [ "$1" = "fleet-pair" ]; then
                compare_pair "$fcanon" "$3" "the canonical is in the hephaestus checkout at $FLEET_ROOT"
            else
                cdir="${fcanon%/}"; pdir="${3%/}"
                if [ ! -d "$pdir" ]; then
                    notes+=("declared fleet directory is not installed here: $pdir")
                    continue
                fi
                # Only files present in BOTH, as with `dir`: a fleet file this
                # project does not install is not a defect, and a local addition
                # is usually a project-specific gate worth keeping.
                while IFS= read -r f; do
                    base="${f#"$cdir"/}"
                    if [ -e "$pdir/$base" ]; then
                        compare_pair "$cdir/$base" "$pdir/$base" "the canonical is in the hephaestus checkout"
                    fi
                done < <(find "$cdir" -type f 2>/dev/null | sort)
                while IFS= read -r f; do
                    base="${f#"$pdir"/}"
                    [ -e "$cdir/$base" ] || notes+=("only in $pdir: $base (project specific; a wholesale copy from the fleet would delete it)")
                done < <(find "$pdir" -type f 2>/dev/null | sort)
            fi
            ;;
        dup-ok)
            [ $# -ge 2 ] || continue
            DUP_OK+=("$2")
            ;;
        topic-scope)
            [ $# -ge 2 ] || { findings+=("manifest: 'topic-scope' needs a path: $line"); continue; }
            TOPIC_SCOPE+=("$2")
            ;;
        topic)
            [ $# -ge 4 ] || { findings+=("manifest: 'topic' needs an id, an owner and a pattern: $line"); continue; }
            # The pattern is the whole rest of the line, taken from the line
            # itself rather than from the split words, so runs of spaces and
            # regex metacharacters survive intact. A pattern cannot contain '#'
            # (comment stripping runs first); no topic has needed one.
            TOPIC_ID+=("$2")
            TOPIC_OWNER+=("$3")
            TOPIC_RE+=("$(printf '%s' "$line" | sed -E 's/^[[:space:]]*topic[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+//; s/[[:space:]]+$//')")
            ;;
        *)
            findings+=("manifest: unknown directive '$1' in: $line")
            ;;
    esac
done < "$MANIFEST"
set +f   # globbing back on; the parse is done

# ── Check 2: an undeclared second home ───────────────────────────────────────
#
# Only over the files being committed, because the question is whether THIS change
# creates a second home. Running it over the whole tree on every commit would
# re-report the ones already accepted, and a gate that cries every time is a gate
# that gets bypassed every time.
if [ "$STAGED" = 1 ]; then
    changed=$(git diff --cached --name-only --diff-filter=d)
else
    changed=$(git diff --name-only --diff-filter=d; git ls-files --others --exclude-standard)
fi

# `fleet-pair` and `fleet-dir` count as declarations too, and leaving them out
# was a real bug: a path declared against a canonical in ANOTHER repository was
# still reported by the undeclared-second-home check below, which then told the
# reader to declare a pair they had already declared. Only the LOCAL side of a
# fleet directive is a path in this repository, so only $3 is taken from those.
declared_paths=$(
    { grep -E '^\s*(pair|dir)\s' "$MANIFEST" 2>/dev/null | awk '{print $2"\n"$3}'
      grep -E '^\s*fleet-pair\s' "$MANIFEST" 2>/dev/null | awk '{print $3}'
      # A fleet-dir names a DIRECTORY whose canonical is in another repository,
      # so the files inside it are declared without being listed. Expanded here
      # rather than special-cased below, because the duplicate check tests
      # whether BOTH sides are declared and a directory name never matches a
      # file path. Without this, a hook covered by fleet-dir was reported as an
      # undeclared second home and the advice was to declare what was declared.
      while IFS= read -r _fd; do
          _fd="${_fd%%#*}"
          set -f; set -- $_fd; set +f
          [ "${1:-}" = "fleet-dir" ] && [ -d "${3%/}" ] && find "${3%/}" -type f 2>/dev/null
      done <"$MANIFEST"
    } | sed '/^$/d'
)

# ── Check 2b: a near-duplicate (fuzzy) second home ───────────────────────────
#
# WHY THIS EXISTS
#
# Check 2 above finds a second home only when it is byte-identical to the
# first, which a restatement defeats by construction: reword one phrase,
# reformat one number, drop one word, and the hash matches nothing. Measured on
# a fixture on 2026-09-22: two files differing only by "500 GB" versus "500GB"
# passed this gate at exit 0, which is exactly the drift Pattern 5 (one home per
# fact) exists to catch. Check 3 already catches this for topics an operator
# has named in the manifest; this pass catches it for everything else, at the
# cost of being a heuristic rather than a proof.
#
# WHAT "SMALL EDIT DISTANCE" MEANS HERE
#
# True Levenshtein distance over whole files, computed pairwise against every
# tracked path, does not finish in commit time on a repo this size. The proxy
# used instead: normalise (lowercase, whitespace collapsed to one token per
# line) then count how many tokens `diff` calls added or removed between the
# two streams. `diff` is LCS based and fast; the count it produces is not the
# minimal edit distance but it is monotone with how different the documents
# are, which is the property this check needs. A one word substitution shows up
# as roughly two or three changed tokens (the word removed, its replacement
# added); a genuinely different document shows up as most of its tokens changed.
#
# BOUNDING THE COST, three ways, because comparing every changed file against
# every tracked file is the check this gate deliberately did NOT write for
# Check 2 either:
#
#   1. Extension allowlist. Only file types where a "restated fact" is a
#      plausible shape (docs, scripts, config) are scanned at all.
#   2. A byte size cap and a same-side size ratio. A restatement of one fact is
#      short, and two files of wildly different size are not the same fact
#      reworded.
#   3. A token floor. Below a handful of tokens, "close in edit distance" stops
#      meaning anything: two near-empty files are trivially close to everything
#      near-empty, which was Check 2's own reason for excluding empty files.
#
# WHAT THIS DELIBERATELY DOES NOT ATTEMPT: paraphrase that changes vocabulary
# wholesale, restatement in a file type outside the allowlist, or a fact spread
# across a file larger than the size cap. Those stay uncaught by this pass the
# same way Check 2's header already says byte copies outside the repo stay
# uncaught by that one; a heuristic that is honest about its edge beats one
# that is silently believed to be complete.
#
# The same exemptions as Check 2 apply: dup-ok globs, a declared pair (either
# order), and a declared dir pair covering both sides.
NEARDUP_MIN_TOKENS=8
NEARDUP_MAX_BYTES=20000
NEARDUP_SIZE_RATIO=30

declare -A NEARDUP_BYTES_CACHE
declare -A NEARDUP_REPORTED

neardup_eligible_ext() {
    case "$1" in
        *.md|*.txt|*.sh|*.toml|*.rs|*.py|*.json|*.yml|*.yaml|*.mjs|*.js|*.ts|*.service|*.timer) return 0 ;;
        *) return 1 ;;
    esac
}

# Byte size of a path. Read from NEARDUP_BYTES_CACHE, which
# neardup_prime_bytes populates in one bulk pass. The first version of this
# check forked `wc -c` or `git cat-file -s` once PER CANDIDATE PER CHANGED
# FILE, which on this repo's ~1,400 eligible-extension files took over 40
# seconds for a two file commit; that cost is why the size lookup is a bulk
# precompute rather than a per-file fork.
neardup_bytes() {
    printf '%s' "${NEARDUP_BYTES_CACHE[$1]:-0}"
}

# Bulk size lookup for every extension-eligible candidate, once, before the
# per changed file scan starts. Staged mode resolves through a single
# `git cat-file --batch-check` rather than one process per file; working tree
# mode resolves through a single `wc -c` invocation over the whole candidate
# list. Either way this is O(1) process forks in the candidate count, not
# O(n).
neardup_prime_bytes() {
    local elig=() f
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        neardup_eligible_ext "$f" && elig+=("$f")
    done <<< "$all_paths"
    [ ${#elig[@]} -gt 0 ] || return 0

    if [ "$STAGED" = 1 ]; then
        local meta path hash
        local -A h2s
        local hashes=()
        local metas=()
        while IFS=$'\t' read -r meta path; do
            [ -n "$path" ] || continue
            hash="${meta#* }"; hash="${hash% *}"
            metas+=("$hash|$path")
            hashes+=("$hash")
        done < <(git ls-files -s -- "${elig[@]}" 2>/dev/null)
        if [ ${#hashes[@]} -gt 0 ]; then
            local hh ss
            while IFS=' ' read -r hh ss; do
                [ -n "$hh" ] || continue
                h2s["$hh"]="$ss"
            done < <(printf '%s\n' "${hashes[@]}" | sort -u | git cat-file --batch-check='%(objectname) %(objectsize)' 2>/dev/null)
        fi
        local entry
        for entry in "${metas[@]}"; do
            hash="${entry%%|*}"; path="${entry#*|}"
            NEARDUP_BYTES_CACHE["$path"]="${h2s[$hash]:-0}"
        done
    else
        local line sz rest
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            # `wc -c` right-aligns the size with LEADING spaces, so trimming
            # with `${line%% *}` matched the whole line as one "suffix" and
            # produced an empty size for every file. `read` splits on
            # whitespace and drops the padding on its own.
            read -r sz rest <<< "$line"
            [ "$rest" = "total" ] && continue
            NEARDUP_BYTES_CACHE["$rest"]="$sz"
        done < <(wc -c -- "${elig[@]}" 2>/dev/null)
    fi
}

# Lowercased, whitespace collapsed to one token per line. Reads from the index
# when --staged, matching content_hash's own split between staged and disk.
neardup_tokens() {
    local p="$1"
    if [ "$STAGED" = 1 ]; then
        git show ":$p" 2>/dev/null
    else
        [ -f "$p" ] && cat "$p" 2>/dev/null
    fi | tr '[:upper:]' '[:lower:]' | tr -s '[:space:]' '\n' | sed '/^$/d'
}

# Count of tokens `diff` calls added or removed between two normalised
# streams: the "small edit distance" proxy, explained above.
neardup_distance() {
    diff <(neardup_tokens "$1") <(neardup_tokens "$2") 2>/dev/null | grep -c '^[<>]'
}

# declared_paths as an array, and the declared `dir` pairs pulled out of the
# manifest once, so the per-candidate exemption checks below are bash
# membership tests and a handful of array entries rather than a `grep` fork
# and a full manifest re-read for every candidate that reaches them.
mapfile -t NEARDUP_DECLARED_ARR <<< "$declared_paths"
NEARDUP_DIR_C=(); NEARDUP_DIR_D=()
while IFS= read -r nd_line; do
    nd_line="${nd_line%%#*}"
    set -f; set -- $nd_line; set +f
    [ "${1:-}" = "dir" ] || continue
    NEARDUP_DIR_C+=("${2%/}"); NEARDUP_DIR_D+=("${3%/}")
done < "$MANIFEST"

neardup_declared() {
    local x="$1" e
    for e in "${NEARDUP_DECLARED_ARR[@]}"; do
        [ "$e" = "$x" ] && return 0
    done
    return 1
}

# Scan one changed file against the rest of the tree for a near, but not
# exact, twin. Only reached when Check 2 above found no byte-identical one.
neardup_scan() {
    local p="$1"
    neardup_eligible_ext "$p" || return 0
    # Every lookup below reads NEARDUP_BYTES_CACHE and the exemption arrays
    # directly rather than through a function call captured with `$(...)`.
    # Command substitution forks a subshell, and the first working version of
    # this loop called one for the extension and one for the byte size of
    # EVERY same-extension candidate: on this repo's ~700 markdown files that
    # was ~1,400 forks per changed file, which is what turned a sub-second
    # gate into a 22 second one. None of these lookups need a subshell.
    local pbytes="${NEARDUP_BYTES_CACHE[$p]:-0}"
    [ "$pbytes" -gt 0 ] && [ "$pbytes" -le "$NEARDUP_MAX_BYTES" ] || return 0
    local pext=""
    case "$p" in *.*) pext="${p##*.}" ;; esac
    # Token count is read once and lazily: most changed files never reach a
    # candidate that survives the extension and size filters, and computing it
    # up front forked for every changed file regardless of whether it was ever
    # used.
    local ptok=""

    local t
    while IFS= read -r t; do
        [ -n "$t" ] || continue
        [ "$t" = "$p" ] && continue
        # Same extension only: a `case` test against p's own extension, which
        # discards the overwhelming majority of candidates before anything
        # forks.
        case "$t" in
            *."$pext") ;;
            *) continue ;;
        esac

        skip=0
        for g in ${DUP_OK[@]+"${DUP_OK[@]}"}; do
            # shellcheck disable=SC2254
            case "$t" in $g) skip=1; break ;; esac
        done
        [ "$skip" = 1 ] && continue
        # Already declared as a pair, in either order.
        if neardup_declared "$p" && neardup_declared "$t"; then
            continue
        fi
        # A declared `dir` pair covers its files without naming each one.
        covered=0
        for di in "${!NEARDUP_DIR_C[@]}"; do
            c="${NEARDUP_DIR_C[$di]}"; d="${NEARDUP_DIR_D[$di]}"
            case "$p" in "$c"/*|"$d"/*) case "$t" in "$c"/*|"$d"/*) covered=1 ;; esac ;; esac
        done
        [ "$covered" = 1 ] && continue

        local tbytes="${NEARDUP_BYTES_CACHE[$t]:-0}"
        [ "$tbytes" -gt 0 ] || continue
        local hi="$pbytes" lo="$tbytes"
        if [ "$tbytes" -gt "$pbytes" ]; then hi="$tbytes"; lo="$pbytes"; fi
        # Percentage difference against the larger side.
        (( (hi - lo) * 100 / hi > NEARDUP_SIZE_RATIO )) && continue

        if [ -z "$ptok" ]; then
            ptok=$(neardup_tokens "$p" | wc -l | tr -d '[:space:]')
            [ "$ptok" -ge "$NEARDUP_MIN_TOKENS" ] || return 0
        fi
        local ttok; ttok=$(neardup_tokens "$t" | wc -l | tr -d '[:space:]')
        [ "$ttok" -ge "$NEARDUP_MIN_TOKENS" ] || continue

        # Report each near-duplicate pair once regardless of which side of it
        # was the "changed" file that found it first.
        local key
        if [[ "$p" < "$t" ]]; then key="$p"$'\x1e'"$t"; else key="$t"$'\x1e'"$p"; fi
        [ -n "${NEARDUP_REPORTED[$key]+x}" ] && continue

        local dist; dist=$(neardup_distance "$p" "$t")
        [ "$dist" -gt 0 ] || continue
        local threshold=$(( ptok / 10 ))
        [ "$threshold" -lt 4 ] && threshold=4
        if [ "$dist" -le "$threshold" ]; then
            NEARDUP_REPORTED[$key]=1
            findings+=("NEAR-DUPLICATE: $p restates $t with only $dist token(s) changed after
      normalising case and whitespace. That is not the same as identical, and
      it is exactly what a byte comparison cannot see. Either route one to the
      other, delete the copy, or if this is a real second home: declare it in
      one-home.manifest so the drift is enforced from now on:
          pair $t $p
      If the near duplication is upstream's and not ours to fix: dup-ok $p")
        fi
    done <<< "$all_paths"
}

if [ -n "$changed" ]; then
    # One pass over the index gives every tracked path's content hash.
    index=$(git ls-files -s 2>/dev/null | awk '{print $2" "$4}')
    # Every path that could hold a near-duplicate: the whole index plus, in
    # working-tree mode, whatever is new and untracked. Built once rather than
    # per changed file, because the fuzzy pass is the expensive one here and
    # nothing in it should be repeated more than the number of changed files.
    if [ "$STAGED" = 1 ]; then
        all_paths=$(git ls-files 2>/dev/null)
    else
        all_paths=$(git ls-files 2>/dev/null; git ls-files --others --exclude-standard 2>/dev/null)
    fi
    neardup_prime_bytes

    while IFS= read -r p; do
        [ -n "$p" ] || continue
        # An empty file is not a fact with two homes.
        h=$(content_hash "$p"); [ -n "$h" ] || continue
        [ "$h" = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391" ] && continue

        skip=0
        for g in ${DUP_OK[@]+"${DUP_OK[@]}"}; do
            # shellcheck disable=SC2254
            case "$p" in $g) skip=1; break ;; esac
        done
        [ "$skip" = 1 ] && continue

        twins=$(printf '%s\n' "$index" | awk -v h="$h" -v self="$p" '$1==h && $2!=self {print $2}')

        if [ -z "$twins" ]; then
            # No byte-identical twin. That is not the same as no restatement: a
            # fact reworded with a synonym, a reformatted number, or a
            # rewrapped sentence hashes nothing like its original and walks
            # straight past the check above.
            neardup_scan "$p"
            continue
        fi

        while IFS= read -r t; do
            [ -n "$t" ] || continue
            for g in ${DUP_OK[@]+"${DUP_OK[@]}"}; do
                # shellcheck disable=SC2254
                case "$t" in $g) continue 2 ;; esac
            done
            # Already declared as a pair, in either order.
            if printf '%s\n' "$declared_paths" | grep -qxF "$p" && printf '%s\n' "$declared_paths" | grep -qxF "$t"; then
                continue
            fi
            # A declared `dir` pair covers its files without naming each one.
            covered=0
            while IFS= read -r line; do
                line="${line%%#*}"; set -- $line
                [ "${1:-}" = "dir" ] || continue
                c="${2%/}"; d="${3%/}"
                case "$p" in "$c"/*|"$d"/*) case "$t" in "$c"/*|"$d"/*) covered=1 ;; esac ;; esac
            done < "$MANIFEST"
            [ "$covered" = 1 ] && continue

            findings+=("UNDECLARED SECOND HOME: $p is byte-identical to $t.
      One of them is now a copy that will drift. Either delete one, or declare
      the pair in one-home.manifest so this gate keeps them identical:
          pair $t $p
      If the duplication is upstream's and not ours to fix: dup-ok $p")
        done <<< "$twins"
    done <<< "$changed"
fi

# ── Check 3: a declared topic restated away from its home ────────────────────
#
# Runs over the whole declared scope rather than only over changed files, unlike
# check 2. The scope is a handful of named documents, so the cost is trivial, and
# a restatement that predates the topic being declared is exactly the thing worth
# finding. Check 2 is limited to the diff because it would otherwise re-report
# every duplicate the repo has already accepted; there is no such backlog here.
if [ ${#TOPIC_ID[@]} -gt 0 ]; then
    if [ ${#TOPIC_SCOPE[@]} -eq 0 ]; then
        findings+=("manifest: topics are declared but no 'topic-scope' names a document to check them against, so the restatement check would silently pass on everything.")
    fi
    for ti in "${!TOPIC_ID[@]}"; do
        tid="${TOPIC_ID[$ti]}"; towner="${TOPIC_OWNER[$ti]}"; tre="${TOPIC_RE[$ti]}"
        if [ ! -f "$towner" ]; then
            findings+=("topic '$tid' names an owner that does not exist: $towner")
            continue
        fi
        # The owner must actually cover the topic. Otherwise a topic can be
        # declared, the owner rewritten to drop it, and the gate goes on
        # policing a home that is empty: the same blind-pattern failure the
        # claims gate exists to report.
        if ! grep -qEi -- "$tre" "$towner" 2>/dev/null; then
            findings+=("topic '$tid' has an owner that no longer discusses it: $towner does not match /$tre/.
      Either the owner moved the fact (repoint the topic) or the fact lost its
      home entirely, which is what this gate exists to prevent.")
            continue
        fi
        # Measure the pattern before trusting a single finding it produces.
        #
        # The first topic list written for this gate declared code-style with a
        # pattern containing '#'. Comment stripping runs before the directive is
        # parsed, so the pattern arrived as a bare '^' and matched EVERY LINE of
        # every scoped document: seventy findings, all of them noise, from a rule
        # that was never actually tested. A pattern that matches most of a file
        # is not recognising a topic, it is recognising text, and the findings it
        # produces would train a reader to skip this gate's output.
        owner_lines=$(wc -l < "$towner" 2>/dev/null || echo 0)
        owner_hits=$(grep -cEi -- "$tre" "$towner" 2>/dev/null || echo 0)
        # The ratio only means anything once there are enough lines to take a
        # ratio of. Without the floor, a short owner where the topic is stated
        # once in four lines reads as 25% and gets refused, which fails the
        # honest case: a small document whose whole job is that one fact.
        if [ "$owner_lines" -ge 20 ] && [ $(( owner_hits * 4 )) -gt "$owner_lines" ]; then
            findings+=("topic '$tid' has a pattern that matches $owner_hits of $owner_lines lines in $towner, so it is matching prose rather than a topic: /$tre/
      Narrow it to a phrase the topic actually owns. Note that '#' cannot appear
      in a pattern; the manifest strips comments first and what survives may
      still be a valid regex that matches everything.")
            continue
        fi
        for sp in "${TOPIC_SCOPE[@]}"; do
            [ "$sp" = "$towner" ] && continue
            [ -f "$sp" ] || { notes+=("topic-scope path is absent: $sp"); continue; }
            # A route is a markdown LINK to the owner: `](<owner>` , optionally
            # with an anchor. Requiring a link rather than a mention is not
            # pedantry about syntax, it is the only form that names a file
            # unambiguously and that `walk-test.py` can later prove still lands
            # somewhere.
            #
            # The looser rule was tried first and was worse than useless here. It
            # accepted any appearance of the owner's BASENAME in the window, and
            # AGENTS.md happened to carry the phrase "the operator's Dokima
            # CLAUDE.md" inside the very block that restates ten of these rules.
            # A pointer at a SISTER PROJECT'S file satisfied the check, so the
            # gate passed the single worst restatement in the repo and reported
            # three findings where there were thirteen. A route to the wrong
            # repository is not a route; it is a reader sent somewhere the fact
            # is not.
            # PARAGRAPH scope, not a line window, and matching on the
            # paragraph's text with its line breaks collapsed.
            #
            # Three ways the previous rule was defeated, all measured against
            # fixtures on 2026-09-09:
            #
            #   1. It grepped a +/-12 line window for ANY link to the owner, so a
            #      single unrelated link licensed a 25 line restatement anywhere
            #      near it. `AGENTS.md` already carries 16 links to `CLAUDE.md`,
            #      which put most of that file inside a permissive window.
            #   2. Matching was line based, so wrapping a phrase across a newline
            #      defeated it. An ordinary markdown re-wrap disarmed the gate by
            #      accident, which made it non-deterministic under reflowing.
            #   3. The link had to be spelled exactly as the manifest spells the
            #      owner, so a CORRECT relative route from a subdirectory,
            #      `](../CLAUDE.md)`, was refused. That put this gate in direct
            #      contradiction with `walk-test.py`, which would refuse the
            #      absolute form as a broken link.
            #
            # A paragraph is the right unit because it is the unit a reader
            # reads: if this passage states the fact, THIS passage must route.
            while IFS=$'\t' read -r lno para; do
                [ -n "$lno" ] || continue
                # Does this paragraph route to the owner? Every link target in it
                # is resolved relative to the scoped file's own directory, so the
                # absolute and relative spellings both count and neither has to
                # be guessed at.
                routed=0
                for target in $(printf '%s' "$para" | grep -oE -- '\]\([^)]+\)' | sed -E 's/^\]\(//; s/\)$//; s/#.*$//'); do
                    case "$target" in
                        http*|"") continue ;;
                    esac
                    resolved=$(realpath -m --relative-to="$root" -- "$(dirname "$sp")/$target" 2>/dev/null)
                    [ "$resolved" = "$towner" ] && { routed=1; break; }
                    # An absolute-from-root spelling, which is how the manifest
                    # writes it and how a top-level document links.
                    resolved=$(realpath -m --relative-to="$root" -- "$root/$target" 2>/dev/null)
                    [ "$resolved" = "$towner" ] && { routed=1; break; }
                done
                if [ "$routed" -eq 0 ]; then
                    findings+=("RESTATEMENT: $sp:$lno discusses '$tid', which lives in $towner, without routing there.
      One home per FACT, not per file. This passage is a second home: when the
      rule changes, this copy is the one nobody remembers to update.
      Fix it by replacing the restatement with a pointer, e.g. \"see $towner\".
      If this passage genuinely IS the owner now, move the topic's owner in
      one-home.manifest instead of adding a link.")
                fi
            done < <(awk -v re="$tre" '
                # Paragraphs assembled by hand rather than with RS="", because
                # RS="" gives no way to recover the paragraph is starting LINE
                # and a finding without a line number is a finding nobody can
                # act on.
                #
                # Both sides are lowercased to reproduce the old `grep -Ei`.
                # That is safe for the manifest is patterns, which are prose
                # phrases, and would NOT be safe for a pattern carrying a
                # character class like [A-Z]; the breadth guard above already
                # refuses patterns that behave like prose, and a class-bearing
                # topic would need this revisited.
                function flush(   lower) {
                    if (buf != "") {
                        lower = tolower(buf)
                        if (lower ~ tolower(re)) printf "%d\t%s\n", startline, buf
                    }
                    buf = ""
                }
                /^[[:space:]]*$/ { flush(); next }
                {
                    if (buf == "") { startline = NR; buf = $0 }
                    else { buf = buf " " $0 }
                }
                END { flush() }
            ' "$sp" 2>/dev/null || true)
        done
    done
fi

# SAID OUT LOUD, EVERY TIME, and not behind the verbose flag. An ordinary note
# is a detail; this one is the gate reporting that it checked nothing, and a
# check whose silence is indistinguishable from a pass is the failure this whole
# file is about. It does not refuse, because a project cloned somewhere without
# hephaestus still has to be committable.
if [ "${fleet_unchecked:-0}" -gt 0 ]; then
    printf '[one-home] %s fleet directive(s) NOT CHECKED: no hephaestus checkout found.\n' \
        "$fleet_unchecked" >&2
    printf '[one-home] Set HEPHAESTUS_ROOT to one, or accept that these copies are unguarded here.\n' >&2
fi

if [ ${#notes[@]} -gt 0 ] && [ "${ONE_HOME_VERBOSE:-0}" = "1" ]; then
    printf '[one-home] %s\n' "${notes[@]}"
fi

if [ ${#findings[@]} -gt 0 ]; then
    echo "[one-home] the same fact lives in two places and they disagree:"
    printf '  - %s\n' "${findings[@]}"
    echo
    echo "  Fix the canonical side, then copy it across. Do not fix only the copy;"
    echo "  the next fleet install would overwrite it and the finding would return."
    echo "  Last resort, with a stated reason: SKIP_ONE_HOME=1 git commit ..."
    exit 1
fi
exit 0
