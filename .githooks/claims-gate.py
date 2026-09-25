#!/usr/bin/env python3
# Author:  Daniel Iwugo
# Comment: Christ is King
"""claims-gate.py — do this repo's documents still agree with the tree, and with each other?

WHAT THIS CATCHES, AND WHAT IT DOES NOT.

On 2026-08-10 a single session found eight documents asserting something that
had stopped being true. Three of the eight were written by the session itself.
The eight split cleanly into two kinds, and only one kind is mechanisable:

  Gateable, and what this gate is for
    - a count in a document against a count in the tree (an ADR log with 77
      entries and an index that stops at 76)
    - two documents asserting one fact and disagreeing (a north-star doc whose
      section 7 called a project primary four weeks after section 3 paused it)
    - a number in a config against the machine it describes (a job runner
      declaring 6 GB usable on a 20 GB box)
    - a string that must no longer appear anywhere (a retired hostname)

  NOT gateable, and deliberately out of scope
    - a health check that passed because a different service owned the port
    - free VRAM read off an idle card rather than from inside a CUDA context
    - "the re-run is free" when half of it needs a GPU

The second list is reasoning and measurement-method error. A gate claiming to
catch it would itself be a document asserting something untrue, which is the
failure this file exists to attack. Four of eight is the honest figure.

THE DESIGN, AND WHY IT IS NOT THE OBVIOUS ONE.

The obvious shape is a checklist: "CLAUDE.md should say 77". That puts the
expected value in a THIRD hand-maintained place, so the checklist drifts
alongside the documents and the gate rots into decoration. This repo's
scripts/hooks/check-doc-drift.py has exactly that shape, and it works only
because its expectations are computed rather than written down.

So the unit here is not an expectation. It is a MEASUREMENT plus the set of
documents that assert it:

    measure once, from the tree
    every document that states that fact must match the measurement
    and therefore each other

Nothing declares the answer. Adding the 78th ADR changes the measurement, and
every document asserting the old total fails at once, naming the new value.

An assertion whose pattern matches NOTHING is a failure of kind "blind", not a
pass. A check that cannot run has not passed (principles doc, and the same
convention check-doc-drift.py uses). This matters more than it sounds: the most
common way a gate like this dies is that someone rewords the sentence it reads,
the regex stops matching, and the gate reports success forever.

NO SHELL. Measurements are a fixed verb set, never a command from the
declaration file. This file is read from the repository being pushed, and hooks
now live in third-party clones too; a declaration file that could execute would
be a code-execution surface handed to whoever wrote the repo. Regexes and file
reads are the whole capability, and inputs are size-capped so a pathological
pattern cannot run away with the push.

EXIT CODES, matching the rest of the toolchain:
  0  every claim agrees (or the repo declares none)
  1  drift: a document disagrees with the tree or with another document
  2  the check could not run (missing file, pattern gone blind, bad TOML).
     NOT success.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

# Inputs are capped so a repo-supplied regex cannot spend the push. 8 MB is far
# past any prose file in the fleet; the largest here is under 400 KB.
MAX_BYTES = 8 * 1024 * 1024
MAX_PATHS = 5000

CLAIMS_FILE = ".baseline-claims.toml"

problems: list[str] = []
blind: list[str] = []


def repo_root() -> Path:
    """The worktree root, found without shelling out to git."""
    here = Path.cwd().resolve()
    for cand in (here, *here.parents):
        if (cand / ".git").exists():
            return cand
    return here


ROOT = repo_root()


def safe_path(raw: str, where: str) -> Path | None:
    """Resolve a declared path, refusing anything that escapes the worktree.

    The declaration file is repository content. Absolute paths and `..` are
    refused rather than normalised, so a claim cannot quietly read /etc or a
    sibling checkout and report on it as though it were this repo.
    """
    if raw.startswith("/") or ".." in Path(raw).parts:
        problems.append(f"{where}: path {raw!r} leaves the repository; refused")
        return None
    return (ROOT / raw).resolve()


def read_text(p: Path, where: str) -> str | None:
    try:
        if p.stat().st_size > MAX_BYTES:
            blind.append(f"{where}: {p.relative_to(ROOT)} is larger than the {MAX_BYTES // 1024 // 1024} MB cap")
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        blind.append(f"{where}: {raw_rel(p)} does not exist")
        return None
    except OSError as exc:
        blind.append(f"{where}: {raw_rel(p)} could not be read ({exc.strerror})")
        return None


def raw_rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def compile_pattern(pat: str, where: str) -> re.Pattern[str] | None:
    # An empty pattern compiles happily and matches every line, which would make
    # a count claim silently report the file's line count as its answer.
    if not pat:
        problems.append(f"{where}: needs a non-empty `pattern`")
        return None
    try:
        return re.compile(pat, re.M)
    except re.error as exc:
        problems.append(f"{where}: pattern {pat!r} is not a valid regex ({exc})")
        return None


# ── Measurement verbs ───────────────────────────────────────────────────────
# Each returns a string (the measured value) or None, having recorded why not.


def measure_count_matches(spec: dict, where: str) -> str | None:
    """How many lines in a file, or across a glob, match a pattern."""
    pat = compile_pattern(spec.get("pattern", ""), where)
    if pat is None:
        return None
    targets = resolve_targets(spec, where)
    if targets is None:
        return None
    exclude = spec.get("exclude")
    exc = compile_pattern(exclude, where) if exclude else None
    if exclude and exc is None:
        return None
    total = 0
    for t in targets:
        text = read_text(t, where)
        if text is None:
            return None
        for line in text.splitlines():
            if pat.search(line) and not (exc and exc.search(line)):
                total += 1
    return str(total)


def measure_count_paths(spec: dict, where: str) -> str | None:
    """How many paths match a glob, optionally only those holding a child file.

    `require_child` is what makes "how many crates" mean directories that are
    actually crates, rather than every stray directory under crates/.
    """
    glob = spec.get("glob")
    if not glob:
        problems.append(f"{where}: count_paths needs a `glob`")
        return None
    if glob.startswith("/") or ".." in Path(glob).parts:
        problems.append(f"{where}: glob {glob!r} leaves the repository; refused")
        return None
    child = spec.get("require_child")
    hits = 0
    for i, p in enumerate(sorted(ROOT.glob(glob))):
        if i >= MAX_PATHS:
            blind.append(f"{where}: glob {glob!r} matched more than {MAX_PATHS} paths")
            return None
        if child and not (p / child).exists():
            continue
        hits += 1
    return str(hits)


def measure_capture(spec: dict, where: str) -> str | None:
    """The first capture group of the first match in a file.

    This is the verb that ties a config number to the document describing it,
    and one document's statement of a fact to another's.
    """
    targets = resolve_targets(spec, where)
    if targets is None:
        return None
    if len(targets) != 1:
        problems.append(f"{where}: capture needs exactly one file, got {len(targets)}")
        return None
    pat = compile_pattern(spec.get("pattern", ""), where)
    if pat is None:
        return None
    text = read_text(targets[0], where)
    if text is None:
        return None
    m = pat.search(text)
    if not m:
        blind.append(
            f"{where}: pattern {spec['pattern']!r} matched nothing in "
            f"{raw_rel(targets[0])}; the wording changed and the measurement went blind"
        )
        return None
    if not m.groups():
        problems.append(f"{where}: capture pattern needs a capture group")
        return None
    return m.group(1).strip()


def resolve_targets(spec: dict, where: str) -> list[Path] | None:
    """A claim names either one `file` or a `glob` of them."""
    if "file" in spec:
        p = safe_path(spec["file"], where)
        return None if p is None else [p]
    if "glob" in spec:
        glob = spec["glob"]
        if glob.startswith("/") or ".." in Path(glob).parts:
            problems.append(f"{where}: glob {glob!r} leaves the repository; refused")
            return None
        hits = sorted(ROOT.glob(glob))[:MAX_PATHS]
        if not hits:
            blind.append(f"{where}: glob {glob!r} matched no files")
            return None
        return hits
    problems.append(f"{where}: needs a `file` or a `glob`")
    return None


MEASURES = {
    "count_matches": measure_count_matches,
    "count_paths": measure_count_paths,
    "capture": measure_capture,
}


# ── The two claim shapes ────────────────────────────────────────────────────


def check_agreement(claim: dict, idx: int) -> None:
    """One measurement; every document asserting it must match."""
    cid = claim.get("id", f"claim[{idx}]")
    what = claim.get("what", "")
    spec = claim.get("measure")
    if not isinstance(spec, dict):
        problems.append(f"{cid}: needs a [claim.measure] table")
        return
    kind = spec.get("kind")
    fn = MEASURES.get(kind)
    if fn is None:
        problems.append(
            f"{cid}: unknown measure kind {kind!r}; known kinds are "
            + ", ".join(sorted(MEASURES))
        )
        return

    measured = fn(spec, cid)
    if measured is None:
        return

    asserts = claim.get("asserted_in") or []
    if not asserts:
        problems.append(f"{cid}: measures {measured!r} but no document asserts it")
        return

    for a in asserts:
        p = safe_path(a.get("file", ""), cid)
        if p is None:
            continue
        text = read_text(p, cid)
        if text is None:
            continue
        pat = compile_pattern(a.get("pattern", ""), cid)
        if pat is None:
            continue
        found = pat.findall(text)
        if not found:
            # The single most important branch in this file. A pattern that
            # matches nothing is how a gate dies quietly.
            blind.append(
                f"{cid}: {raw_rel(p)} no longer matches {a['pattern']!r}; "
                f"the wording changed and this assertion went unchecked"
            )
            continue
        for got in found:
            got_s = (got if isinstance(got, str) else got[0]).strip()
            if got_s != measured:
                problems.append(
                    f"{cid}: {raw_rel(p)} says {got_s!r} but the tree measures "
                    f"{measured!r}"
                    + (f" ({what})" if what else "")
                )


def check_absent(claim: dict, idx: int) -> None:
    """A string that must no longer appear: a retired name, a dead hostname."""
    cid = claim.get("id", f"absent[{idx}]")
    pat = compile_pattern(claim.get("pattern", ""), cid)
    if pat is None:
        return
    targets = resolve_targets(claim, cid)
    if targets is None:
        return
    why = claim.get("what", "")
    for t in targets:
        text = read_text(t, cid)
        if text is None:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if pat.search(line):
                problems.append(
                    f"{cid}: {raw_rel(t)}:{n} still contains {claim['pattern']!r}"
                    + (f" ({why})" if why else "")
                )


def main() -> None:
    path = ROOT / CLAIMS_FILE
    if not path.exists():
        # A repo that has declared no claims is not in violation of anything.
        # This is what makes the gate safe to ship everywhere at once.
        sys.exit(0)

    try:
        with path.open("rb") as fh:
            doc = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        print(f"? claims: {CLAIMS_FILE} is not valid TOML ({exc})", file=sys.stderr)
        print("  (a check that cannot run has not passed)", file=sys.stderr)
        sys.exit(2)
    except OSError as exc:
        print(f"? claims: {CLAIMS_FILE} unreadable ({exc.strerror})", file=sys.stderr)
        sys.exit(2)

    claims = doc.get("claim") or []
    absents = doc.get("absent") or []
    if not claims and not absents:
        print(f"✓ claims: {CLAIMS_FILE} declares none")
        sys.exit(0)

    for i, c in enumerate(claims):
        check_agreement(c, i)
    for i, a in enumerate(absents):
        check_absent(a, i)

    if problems:
        print("✗ claims: a document no longer describes the tree", file=sys.stderr)
        for p in problems:
            print(f"    {p}", file=sys.stderr)
        for b in blind:
            print(f"    (blind) {b}", file=sys.stderr)
        sys.exit(1)

    if blind:
        print("? claims: a check went blind and therefore did not pass", file=sys.stderr)
        for b in blind:
            print(f"    {b}", file=sys.stderr)
        print(
            "  Fix the pattern or the document it reads. A regex that matches\n"
            "  nothing reports success forever.",
            file=sys.stderr,
        )
        sys.exit(2)

    n = len(claims) + len(absents)
    print(f"✓ claims: {n} claim(s) hold; documents agree with the tree and each other")
    sys.exit(0)


if __name__ == "__main__":
    main()
