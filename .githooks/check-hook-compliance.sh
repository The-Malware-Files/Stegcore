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
# Two shapes it is meant to catch, both observed:
#
#   - A wholesale hook copy silently deleting a guard one project had added
#     inline to its managed hook. Nothing says so; the gate is just gone.
#   - A remote name that is right nearly everywhere and wrong in one place,
#     because `origin` is the private hub in most repos and the public one in
#     others. The same literal string means opposite things two directories
#     apart.
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

# tools/claude-setup/hooks/ is the CANONICAL source the fleet installs from, so
# an edit there reaches 13 repos. It was not watched, meaning the one place where
# a change has fleet-wide blast radius was the one place this check ignored.
WATCHED='^(\.githooks/|tools/claude-setup/hooks/|\.baseline-hook-config$|\.baseline-hook-allow$|CLAUDE\.md$|AGENTS\.md$)'

# grep -oP needs PCRE, which is absent on busybox and on macOS's system grep.
# Both checks that do real work used it, and a grep that cannot run returns
# nothing, which reads as "found no problems". Detect it once and say so, rather
# than reporting a clean pass built on a tool that never ran.
if echo x | grep -qoP 'x' 2>/dev/null; then HAVE_PCRE=1; else HAVE_PCRE=0; fi

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
#
# The interpreter is taken from the shebang, not assumed. Gate fragments are no
# longer all shell: claims-gate.py is Python, and running `bash -n` on it
# reported a syntax error in a file that is perfectly valid. A checker that
# reports a correct file as broken teaches people to bypass it, which is the
# same end state as having no checker.
for f in $changed; do
    case "$f" in .githooks/*) ;; *) continue ;; esac
    [ -f "$f" ] || continue

    case "$(head -1 "$f" 2>/dev/null)" in
        *python*) checker="python3 -m py_compile" ;;
        *bash*|*sh)  checker="bash -n" ;;
        *)
            # No usable shebang. Fall back on the extension, and say plainly
            # when neither tells us anything rather than guessing at bash.
            case "$f" in
                *.py) checker="python3 -m py_compile" ;;
                *.sh) checker="bash -n" ;;
                *)    note "$f has no shebang and no known extension; not syntax checked"; continue ;;
            esac
            ;;
    esac

    # A checker that is not installed must not read as a pass.
    if ! command -v "${checker%% *}" >/dev/null 2>&1; then
        note "$f not syntax checked: ${checker%% *} is not installed here"
        continue
    fi

    if $checker "$f" 2>/dev/null; then
        pass "$f parses"
    else
        fail "$f has a syntax error:"
        $checker "$f" 2>&1 | sed 's/^/      /'
    fi
done
# py_compile leaves bytecode beside the source; the hook must not dirty the tree.
rm -rf .githooks/__pycache__ 2>/dev/null || true

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
# A remote name copied from another project silently names nothing, and a
# deny-first gate that allow-lists a non-existent remote blocks every push
# instead of allowing the intended one.
if [ -f .baseline-hook-config ]; then
    # HAVE_PCRE is consulted here too. It was detected at the top of this file
    # specifically so a missing -P could not read as "found no problems", and
    # then this line used -P unconditionally anyway: on a grep without PCRE,
    # `declared` came back empty, the block below was skipped, and the check
    # that this file's own comment calls "the single edit that defeats the whole
    # push gate" produced no output and no finding.
    if [ "$HAVE_PCRE" = 1 ]; then
        declared=$(grep -oP "^PRIVATE_REMOTES=['\"]?\K[^'\"]*" .baseline-hook-config 2>/dev/null | head -1 || true)
    else
        declared=$(sed -nE "s/^PRIVATE_REMOTES=['\"]?([^'\"]*).*/\1/p" .baseline-hook-config 2>/dev/null | head -1 || true)
    fi
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
        # The single edit that defeats the whole push gate is adding a PUBLIC
        # remote to PRIVATE_REMOTES: one word, and private material flows
        # straight out with the gate reporting success. Nothing caught it,
        # because the check above only asks whether the NAME resolves, not what
        # it points at. Classify by URL, which is the thing that is actually
        # true, rather than by the nickname, which is just a local label.
        for r in $declared; do
            url=$(git remote get-url "$r" 2>/dev/null || true)
            case "$url" in
                *github.com*|*gitlab.com*|*bitbucket.org*|*codeberg.org*|*sr.ht*)
                    fail "PRIVATE_REMOTES declares '$r' private, but it points at a public host:"
                    note "$url"
                    note "private material would be pushed there with the gate reporting success"
                    note "if this really is a private repo on that host, say so in the commit"
                    ;;
            esac
        done

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
    # The old pattern was anchored on the literal `$repo_root/.githooks/`, which
    # is only how pre-push spells it. pre-commit uses `$_os_root` and `$_hc_root`
    # for its two fragment call sites, so this check matched ZERO of them and
    # both new pre-commit gates could lose their exec bit in silence. Match any
    # variable, and fall back to a plain grep where PCRE is unavailable.
    #
    # A THIRD spelling exists since 2026-08-11 and neither pattern above can see
    # it. pre-push now resolves fragments through a helper, `gate_frag <name>`,
    # so that they are found wherever the hook itself was installed (a
    # third-party clone puts them in the git directory, where `git clean -xfd`
    # cannot delete them). That form carries no `.githooks/` at all, so this
    # check went from matching four fragments in pre-push to matching zero,
    # including the private-material gate.
    #
    # The check whose entire purpose is catching "this gate would silently never
    # fire" was itself silently never firing, introduced by the commit that
    # fixed the same class one layer down. Fragment names now also allow .py,
    # because claims-gate.py is one.
    if [ "$HAVE_PCRE" = 1 ]; then
        frags=$( { grep -oP '\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/\.githooks/\K[a-z0-9-]+\.(sh|py)' "$f";
                   grep -oP 'gate_frag[[:space:]]+\K[a-z0-9-]+\.(sh|py)' "$f"; } 2>/dev/null | sort -u)
    else
        frags=$( { grep -oE '/\.githooks/[a-z0-9-]+\.(sh|py)' "$f" | sed 's|.*/||';
                   grep -oE 'gate_frag[[:space:]]+[a-z0-9-]+\.(sh|py)' "$f" | sed 's|.*[[:space:]]||'; } 2>/dev/null | sort -u)
    fi
    while IFS= read -r frag; do
        [ -n "$frag" ] || continue
        if [ -x ".githooks/$frag" ]; then
            pass "$f calls $frag, which is present and executable"
        else
            fail "$f calls .githooks/$frag, which is missing or not executable"
            note "the gate would silently never fire"
        fi
    done <<EOF
$frags
EOF
done

echo
if [ "$findings" -eq 0 ]; then
    echo "${GREEN}${BOLD}hook-compliance: no findings${RESET}"
    exit 0
fi
echo "${RED}${BOLD}hook-compliance: $findings finding(s)${RESET}"
# The old line said "say why in the commit message". This runs as a PRE-COMMIT
# hook: the message does not exist yet and nothing here ever read one, so the
# route it advertised was impossible and the blanket bypass was the only way
# past a finding that could not be argued away. Two sessions hit that
# independently on 2026-09-21. Operator decision: name the real route.
echo "Fix them. If a finding is WRONG for this repo, the only route past it is the"
echo "bypass below, and the reason belongs in the commit message so review can see"
echo "it. This hook runs before the message exists, so it cannot read one."
echo "Bypass (last resort, record the reason): SKIP_HOOK_COMPLIANCE=1 git commit ..."
exit 1
