#!/usr/bin/env bash
# Author:  Daniel Iwugo
# Comment: Christ is King
# source-header-gate.sh — the operator's signature on his own source, and a
# ratchet that makes coverage climb instead of stalling at sixty percent.
#
# ── WHAT IT ENFORCES ────────────────────────────────────────────────────────
#
# Two lines near the top of a source file, in that file's comment syntax:
#
#     // Author:  Daniel Iwugo
#     // Comment: Christ is King
#
# Both values come from `.baseline-hook-config`, never from this script. The
# gate enforces "the configured lines are present", so the alias can differ per
# project (it already does) and changing the words later is a config edit rather
# than a rewrite of every file. This script does not know or care what the words
# say.
#
# ── WHOSE COMMITS ───────────────────────────────────────────────────────────
#
# The operator's only, matched on committer email. This is not politeness, it is
# the one thing that keeps a personal signature from becoming a requirement
# imposed on somebody else: a contributor's patch is never asked to carry
# another person's name or statement. On a solo repo the distinction costs
# nothing; the day a repo takes its first outside patch, it is the difference
# between a signature and a mandate.
#
# ── WHY A RATCHET AND NOT A SWEEP ───────────────────────────────────────────
#
# Enforcing on touched files alone always stalls: coverage climbs to roughly the
# fraction of the tree anybody actually opens and stops, because the rest is
# files nobody has a reason to edit. Enforcing on the whole tree at once rewrites
# thousands of files in one commit, which buries real changes and ruins
# `git blame` on every line of the repository.
#
# So three mechanisms, which together climb without ever blocking unrelated work:
#
#   FLOOR     coverage is recorded in `.source-header-floor` and may never go
#             DOWN. It is rewritten upward automatically whenever it rises. This
#             cannot force progress; it makes regression impossible.
#   RADIUS    touching any file in a directory requires that whole directory to
#             be covered. Coverage then arrives in coherent units, and this is
#             the mechanism that kills the long tail, which is where these
#             efforts normally die: four stragglers per crate, carried forever.
#   QUOTA     a commit that touches source must also cover N cold files from
#             anywhere. Small tax, and the only mechanism that reaches
#             directories nobody is working in.
#
# The one deliberately NOT implemented is a time-based ramp (floor rises 2% a
# week whatever happens). It is the strongest-looking ratchet and the one that
# blocks real work during a busy month, which is how a gate earns a bypass and
# then gets deleted.
#
# ── WHERE THE COVERAGE NUMBER GOES ──────────────────────────────────────────
#
# To `~/.hephaestus/source-header-coverage.json`, for hephaestus to read. NOT to
# the operator's morning brief (operator, 2026-09-22): it is machine-facing
# progress on a task nobody needs to supervise, and a brief that carries
# non-critical lines teaches him to skim the critical ones.
#
# Usage:  source-header-gate.sh --staged
# Bypass: SKIP_SOURCE_HEADER=1, which is recorded in the transcript like any other.

set -u

[ "${SKIP_SOURCE_HEADER:-0}" = "1" ] && exit 0

ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
cd "$ROOT" || exit 0

CFG="$ROOT/.baseline-hook-config"
[ -f "$CFG" ] || exit 0

# Read one key out of the config without executing the file. The baseline hooks
# parse rather than source for the same reason, and a gate that sources its own
# config is a gate whose config can turn it off by running code.
cfg() {
    local key="$1" default="${2:-}" line
    line=$(grep -E "^[[:space:]]*${key}=" "$CFG" 2>/dev/null | tail -n 1) || true
    [ -n "$line" ] || { printf '%s' "$default"; return; }
    line="${line#*=}"
    line="${line%\"}"; line="${line#\"}"
    line="${line%\'}"; line="${line#\'}"
    printf '%s' "$line"
}

[ "$(cfg SOURCE_HEADER_ENABLED 0)" = "1" ] || exit 0

AUTHOR=$(cfg SOURCE_HEADER_AUTHOR "")
COMMENT=$(cfg SOURCE_HEADER_COMMENT "")
EMAILS=$(cfg SOURCE_HEADER_EMAILS "")
EXEMPT=$(cfg SOURCE_HEADER_EXEMPT_PATHS "")
QUOTA=$(cfg SOURCE_HEADER_QUOTA 2)
FLOOR_FILE="$ROOT/$(cfg SOURCE_HEADER_FLOOR_FILE .source-header-floor)"

if [ -z "$AUTHOR" ] || [ -z "$COMMENT" ]; then
    echo "[source-header] SOURCE_HEADER_ENABLED=1 but AUTHOR or COMMENT is unset." >&2
    echo "  A gate with nothing to enforce is worse than no gate: set both in" >&2
    echo "  .baseline-hook-config, or set SOURCE_HEADER_ENABLED=0." >&2
    exit 1
fi

# ── Whose commit is this ────────────────────────────────────────────────────
me=$(git config user.email 2>/dev/null || true)
if [ -n "$EMAILS" ]; then
    matched=0
    for e in $EMAILS; do [ "$me" = "$e" ] && matched=1; done
    [ "$matched" = "1" ] || exit 0
fi

# ── Which files are in scope ────────────────────────────────────────────────
#
# Extensions only, and a generated or vendored file is never in scope. Those two
# exclusions are not tidiness. A generated file loses the header every time its
# generator runs, so the gate would fail on a file nobody touched, which is the
# shape that gets gates bypassed. A vendored file carrying the operator's name
# is a false attribution claim, and on the AGPL sister projects it is a licence
# problem rather than a style one.
in_scope() {
    local f="$1"
    case "$f" in
        */vendor/*|vendor/*|*/node_modules/*|*/target/*|*/dist/*|*/.venv/*) return 1 ;;
        *.generated.*|*_pb2.py|*.pb.go|docs/plan/*) return 1 ;;
        # Throwaway and machine-made trees, exempt by default rather than by
        # per-project configuration (operator, 2026-09-23). A signature is a
        # statement of authorship, and it does not belong on something written
        # to be deleted or on something a generator will overwrite. Most of
        # these are untracked anyway, so this is belt as well as braces: the
        # one that is NOT is `fixtures/`, which is tracked across this fleet and
        # is test data rather than authored source.
        tmp/*|*/tmp/*|temp/*|*/temp/*) return 1 ;;
        scratch/*|*/scratch/*|scratchpad/*|*/scratchpad/*) return 1 ;;
        sandbox/*|*/sandbox/*|fixtures/*|*/fixtures/*|fixture/*|*/fixture/*) return 1 ;;
        third_party/*|*/third_party/*|*/build/*|*/.cache/*) return 1 ;;
    esac
    if [ -n "$EXEMPT" ]; then
        for pat in $EXEMPT; do
            # shellcheck disable=SC2254
            case "$f" in $pat) return 1 ;; esac
        done
    fi
    case "$f" in
        *.rs|*.py|*.sh|*.ts|*.tsx|*.js|*.jsx|*.mjs|*.cjs|*.go|*.kt|*.java|*.c|*.h|*.cpp|*.hpp) return 0 ;;
        # Added 2026-09-23 after counting what the fleet actually holds. `.mjs`
        # alone was 338 tracked files and was silently out of scope, which is
        # the quiet half of a coverage figure: the percentage looked fine
        # because the denominator was wrong.
        *.ps1|*.rb|*.sql) return 0 ;;
        *) return 1 ;;
    esac
}

# The comment prefix for a file's language. A gate that writes `//` into a
# Python file has mangled it, so this map is load-bearing rather than cosmetic.
prefix_for() {
    case "$1" in
        *.py|*.sh|*.ps1|*.rb) printf '#' ;;
        # `printf --` consumes the `--` as an option terminator and emits
        # NOTHING, so this returned an empty prefix and every .sql file was
        # signed with a bare " Author: ..." line that is not valid SQL. The
        # `--` before the format is what makes the argument literal.
        *.sql) printf -- '--' ;;
        *) printf '//' ;;
    esac
}

has_header() {
    local f="$1" p
    [ -f "$f" ] || return 0   # deleted; nothing to carry a header
    p=$(prefix_for "$f")
    # `grep -qF --` because the SQL prefix IS `--`, which grep otherwise
    # reads as an option. This is the same trap as printf, one layer down:
    # any tool handed a pattern that starts with a dash needs telling.
    head -n 12 "$f" 2>/dev/null | grep -qF -- "$p Author:  $AUTHOR" &&
        head -n 12 "$f" 2>/dev/null | grep -qF -- "$p Comment: $COMMENT"
}

# A HEADER ABOVE A SHEBANG IS A BROKEN FILE, not a signed one.
#
# Found while testing this gate, 2026-09-22, by signing the gate itself: the
# obvious way to add a header is to prepend it, and prepending above `#!` stops
# the kernel seeing the interpreter line. The script then fails with exit 126,
# "Permission denied", which names neither the cause nor the file.
#
# The gate that asks for the header is the right place to refuse the broken
# arrangement, because it is the only thing that knows both facts. `#!` is only
# meaningful on line 1, so the test is exact rather than heuristic.
shebang_displaced() {
    local f="$1"
    [ -f "$f" ] || return 1
    head -n 1 "$f" 2>/dev/null | grep -q '^#!' && return 1
    # `#![` is a RUST INNER ATTRIBUTE, not a shebang, and a comment above one is
    # perfectly legal Rust. The first version matched any `^#!` and so refused
    # every `.rs` file beginning `#![allow(...)]`, which is most test files on
    # this fleet. It reported a broken file that compiled and passed its tests,
    # which is the expensive kind of false positive: it sends you looking for a
    # fault in the file rather than in the check.
    head -n 12 "$f" 2>/dev/null | grep -q '^#![^[]'
}

# Every in-scope file tracked by git, for the coverage figure.
all_tracked() { git ls-files -z | tr '\0' '\n'; }

staged=$(git diff --cached --name-only --diff-filter=ACMR)

missing=""
touched_dirs=""
displaced=""
for f in $staged; do
    in_scope "$f" || continue
    touched_dirs="$touched_dirs $(dirname "$f")"
    shebang_displaced "$f" && displaced="$displaced $f"
    has_header "$f" || missing="$missing $f"
done

# Checked before anything else, because this file is broken right now and every
# other finding is noise beside that.
if [ -n "$displaced" ]; then
    echo "[source-header] the header was put ABOVE the shebang, which breaks the file:" >&2
    for f in $displaced; do echo "    $f" >&2; done
    echo >&2
    echo "  A '#!' line only works as line 1. Above it, the interpreter is never" >&2
    echo "  read and the script fails with 'Permission denied' (exit 126)." >&2
    echo "  Move the two lines BELOW the shebang." >&2
    exit 1
fi

# Nothing in scope in this commit: no radius, no quota, nothing to say.
if [ -z "$touched_dirs" ]; then exit 0; fi

# ── RADIUS: a touched directory must be whole ───────────────────────────────
radius_missing=""
for d in $(printf '%s\n' $touched_dirs | sort -u); do
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        in_scope "$f" || continue
        [ "$(dirname "$f")" = "$d" ] || continue
        has_header "$f" || radius_missing="$radius_missing $f"
    done <<EOF
$(all_tracked)
EOF
done

# ── Coverage and the floor ──────────────────────────────────────────────────
total=0; covered=0
while IFS= read -r f; do
    [ -n "$f" ] || continue
    in_scope "$f" || continue
    total=$((total + 1))
    has_header "$f" && covered=$((covered + 1))
done <<EOF
$(all_tracked)
EOF

pct=0
[ "$total" -gt 0 ] && pct=$(( covered * 10000 / total ))   # basis points
floor=0
[ -f "$FLOOR_FILE" ] && floor=$(tr -cd '0-9' < "$FLOOR_FILE" 2>/dev/null || echo 0)
[ -n "$floor" ] || floor=0

# Machine-facing progress. Not the operator's brief, by his decision.
state_dir="${HOME}/.hephaestus"
if [ -d "$state_dir" ] || mkdir -p "$state_dir" 2>/dev/null; then
    printf '{"repo":"%s","covered":%d,"total":%d,"basis_points":%d,"floor":%d}\n' \
        "$(basename "$ROOT")" "$covered" "$total" "$pct" "$floor" \
        > "$state_dir/source-header-coverage-$(basename "$ROOT").json" 2>/dev/null || true
fi

fail=0

if [ -n "$radius_missing" ]; then
    echo "[source-header] a directory you touched is not fully signed." >&2
    echo "  Coverage arrives per directory rather than per line, so the long tail" >&2
    echo "  of four stragglers per crate cannot be carried forever." >&2
    echo >&2
    for f in $radius_missing; do echo "    $f" >&2; done
    fail=1
fi

if [ "$pct" -lt "$floor" ]; then
    echo "[source-header] coverage went DOWN: $((pct / 100)).$((pct % 100))% is below the" >&2
    echo "  recorded floor of $((floor / 100)).$((floor % 100))%. The floor only moves up." >&2
    fail=1
fi

# ── QUOTA: the only mechanism that reaches files nobody is working in ───────
if [ "$fail" = "0" ] && [ "$QUOTA" -gt 0 ] && [ "$covered" -lt "$total" ]; then
    newly=0
    for f in $staged; do
        in_scope "$f" || continue
        # A file that gained the header in this commit and was not otherwise
        # being modified for its own sake still counts: the point is that cold
        # files get covered, not that the commit is pure.
        if has_header "$f" && ! git show "HEAD:$f" 2>/dev/null | head -n 12 | grep -qF "Comment: $COMMENT"; then
            newly=$((newly + 1))
        fi
    done
    if [ "$newly" -lt "$QUOTA" ]; then
        echo "[source-header] this commit signs $newly cold file(s); the quota is $QUOTA." >&2
        echo "  $((total - covered)) of $total files are still unsigned." >&2
        echo "  Pick any $((QUOTA - newly)) and add the two lines. Candidates:" >&2
        shown=0
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            in_scope "$f" || continue
            has_header "$f" && continue
            echo "    $f" >&2
            shown=$((shown + 1))
            [ "$shown" -ge 5 ] && break
        done <<EOF
$(all_tracked)
EOF
        fail=1
    fi
fi

if [ -n "$missing" ] && [ "$fail" = "0" ]; then
    echo "[source-header] staged file(s) missing the signature:" >&2
    for f in $missing; do echo "    $f" >&2; done
    fail=1
fi

if [ "$fail" = "1" ]; then
    p='//'
    echo >&2
    echo "  Add near the top of each file, in that file's comment syntax, and" >&2
    echo "  BELOW the shebang where there is one:" >&2
    echo >&2
    echo "    $p Author:  $AUTHOR" >&2
    echo "    $p Comment: $COMMENT" >&2
    echo >&2
    echo "  Exempt a path: SOURCE_HEADER_EXEMPT_PATHS in .baseline-hook-config." >&2
    echo "  Last resort, and recorded: SKIP_SOURCE_HEADER=1 git commit ..." >&2
    exit 1
fi

# Coverage rose: move the floor up and carry it in this commit, so the new floor
# and the work that earned it land together.
if [ "$pct" -gt "$floor" ]; then
    printf '%d\n' "$pct" > "$FLOOR_FILE"
    git add "$FLOOR_FILE" 2>/dev/null || true
    echo "[source-header] coverage $((pct / 100)).$((pct % 100))% ($covered/$total), floor raised."
fi

exit 0
