# Engineering Baseline — Project-Agnostic Operating Rules

**This is the shared engineering constitution. It is project-agnostic: no
product names, no infrastructure identifiers, no repository paths. Every
project layers its own specifics on top of this file; nothing here is
allowed to depend on a particular project.**

How to read this: a project's own `CLAUDE.md` should open with
`> Inherits the engineering baseline at claude-baseline/CLAUDE.md` and then
contain only what is genuinely specific to that project (its domain rules,
its architecture, its release cadence). If a rule is true for every
project, it belongs here, not there.

These rules are non-negotiable unless explicitly overridden in writing in
the working session.

---

## 1. Product standard

Everything that ships is commercial-grade software, not a hobby project.
Hold all work to the highest known standards: thorough testing, clean
architecture, comprehensive documentation, security-conscious code,
professional UX. Every change is production-ready.

When fixing an issue, prefer the thorough solution over the quick
workaround. If the reliable approach is more complex, do that first rather
than applying a band-aid that becomes technical debt.

---

## 2. Robustness mandate

**Every layer must be designed to be extremely robust against real-world
unpredictability and edge cases, and must handle errors exceptionally
well.** "Every layer" is literal: each module, each script, each CI
workflow, each external surface.

### 2.1 Concrete expectations

- **Fail loud, never silent.** No caught error is swallowed. Discarding an
  error result without handling it is forbidden. Every error surfaces a
  human-readable reason and a diagnostic path. Log the full error context
  chain, not just the final layer. No panicking unwrap/expect/assert in
  non-test code unless a prior invariant check proves it cannot fire.
- **Pre-flight everything.** Disk space, network reachability, dependency
  presence, credentials, capacity, version compatibility — checked before
  a long job starts, not halfway through.
- **Timeouts on every wait.** No blocking read, lock acquisition,
  subprocess, or network call waits forever. Use deadline-bounded lock
  acquisition on any hot path.
- **Idempotent by default.** Any operation that can be re-run after an
  interruption must be safe to re-run. Partial-state files are written via
  atomic rename-on-close or cleaned up on the next run. Never leave
  `.part`, `.tmp`, or half-written files behind.
- **State markers on phased pipelines.** Every phase writes a completion
  marker; the next run resumes from the last completed phase unless a
  `--force` flag says otherwise.
- **Validate inputs at boundaries.** Path strings, hashes, JSON payloads,
  filenames — validated at the surface. Path traversal, invalid encodings,
  malformed input, zero-byte files, over-long paths, symlink traversal,
  TOCTOU races — all handled at the boundary. Trust internal code; only
  validate where untrusted data enters.
- **Resource caps on every parser.** Recursion depth, decompressed size,
  regex backtracking, per-item memory — all bounded with hard, documented
  limits.
- **Concurrency discipline.** Every shared lock has a deadline. Every
  worker thread has a panic/crash hook that logs to a known path. Every
  channel is bounded. Backpressure sleeps the producer; it never drops
  work.
- **Graceful degradation.** When a sub-system fails, the rest of the
  pipeline degrades cleanly with a visible warning rather than crashing or
  producing silently-wrong results.
- **Signal handling and cleanup.** Ctrl+C, SIGTERM, OOM kill, preemption —
  always leave the dataset recoverable and temp directories wiped.
- **Reproducibility.** Two runs on the same input produce byte-identical
  output. Iteration order of unordered collections must not leak into
  results (sort at the serialization boundary). Capture wall-clock
  timestamps once per operation and reuse them.
- **Observability.** Every long-running loop emits a heartbeat every 30 to
  60 seconds. Every failure writes a diagnostic path the user can paste
  into a bug report. Every pipeline stage logs entry, exit, and duration.

**When in doubt, prefer the robust approach even if it is slower to write.
Every shortcut here is a future outage.**

---

## 3. Planning and feature-design discipline

Whenever you draft a plan, a spec, a milestone, a task list, an API
surface, a schema, a CLI flag, an IPC contract, or any design artifact,
think through these eight dimensions **before** the artifact is considered
done. Skipping any one is the root cause of outages.

1. **Loopholes.** Enumerate explicitly: what could go wrong in the real
   world? Adversarial input? A concurrent-access race? Partial failure?
   Every plan has a numbered "loophole hunt" section pairing each loophole
   with an explicit fix or an accepted-risk argument.
2. **Robustness and graceful degradation.** Describe how the system stays
   useful when a sub-component fails. (See §2.)
3. **Quality bar.** Target best-of-class: correct first, then fast
   (measured baselines), efficient (memory/CPU/IO budgets), stable
   (non-flaky tests, reproducible output), versatile (works across
   environments and inputs), modular (trait or interface boundaries,
   single responsibility, swappable backends), testable (every non-trivial
   function has a test).
4. **Scale-conscious design.** Evaluate every decision against one order
   of magnitude beyond today's scale. (See §12.)
5. **Cross-layer implications.** A change in one layer is checked against
   that layer's consumers. Schema changes ship with migration adapters.
   API changes ship with version bumps. Every layer-crossing interaction
   is an explicit contract with a defined error shape.
6. **Observability.** Heartbeats, diagnostic paths, per-stage timing.
7. **Data preservation by default.** Answer explicitly: "what happens to
   the data?" Dropping data is a load-bearing decision requiring written
   rationale. The default is keep everything, annotate what changed.
8. **Integration-first design.** Every new module, binary, or feature is
   designed as an integration into the existing system, not a standalone
   add-on. It fits existing contracts, reuses canonical modules, honours
   locked conventions, ships in the language already used at that layer.
   If a genuinely better alternative would work better as an independent
   piece, stop and surface the choice before proceeding.

If you cannot fill in a dimension, the plan is not done — surface the gap
and ask for direction.

---

## 4. Two-phase review framework

**Every release ships only after a pre-tag gate review. Every work cycle
closes with a lightweight retrospective. Each serves one purpose; they do
not overlap.**

Four review axes: **integrity, general quality, security posture, extreme
robustness** — applied in the pre-tag gate.

1. **Release gate review** — before every tag/merge. A full sweep across
   the cumulative delta since the last tag, written up with a sign-off
   line. The tag does not land without it. A green CI run is necessary but
   not sufficient; the gate sign-off is the actual gate.
2. **Retrospective** — at the close of each work cycle. Short (30 to 45
   minutes). NOT a re-run of the four axes. Captures: what shipped, what
   slipped, what surprised, what to fold into the next gate so the same
   surprise does not escape twice. Retrospective findings never block a
   release; they shape the next gate.

**Finding-handling.** Every finding surfaced in a gate is fixed in the
same cycle. Deferral is the exception: a finding may defer only if its fix
needs physical hardware, external coordination, or a full infrastructure
build. Every deferred finding carries a written reason and a concrete
next step.

**Self-evolving gate.** Every finding adds an automated check so the same
finding class cannot escape silently next time. The gate gets stronger
every cycle.

A fifth axis is worth running: **recipient review** — for any work handed
to an external party (a PR to another maintainer, a public release), ask
"what would a critical reviewer flag, even something small?" This catches
documentation drift, copy-paste traps, and tone issues the four axes miss.

---

## 5. Supply chain and dependency discipline

The dependency graph is attack surface. Treat it like one. The current
threat pattern: an attacker compromises one package, harvests credentials
from everyone who installs it, and uses those to compromise the next — a
cascade. The defense is **blast-radius reduction**: assume any dependency
may turn hostile, and make sure that when one does, it reaches nothing
valuable.

- **Lockfiles are committed, always.** `Cargo.lock`, `package-lock.json`,
  `pnpm-lock.yaml`, `uv.lock` — all version-controlled, for libraries as
  well as binaries.
- **Version cooldown.** Do not adopt a dependency version younger than the
  cooldown window (default: 7 days; longer for critical paths). Most
  compromised versions are caught within days. See `supply-chain/` for
  the `.npmrc` and Renovate configuration that automate this.
- **Pin everything that is not lockfile-managed.** Editor extensions
  pinned to exact versions. CI actions pinned by commit hash, never by
  tag. Container base images pinned by digest, never by tag.
- **Disable auto-update** on editors and editor extensions. Update
  deliberately, after the cooldown window, having read what changed.
- **Minimize the surface.** Every dependency and every editor extension is
  attack surface and runs with your privileges. Audit and prune
  regularly. Prefer the standard library and a small, well-known
  dependency set over many small convenience packages.
- **Isolate untrusted builds.** Do not run a build, install, or test of
  untrusted third-party code as the same user that holds your keys and
  credentials. Use a container, a VM, or a dedicated user. For build
  scripts and macros, prefer a sandbox.
- **Vet dependencies.** Use the ecosystem's audit tooling (advisory-db
  checks, dependency review). Know that audit tools catch *known* issues,
  not zero-days — cooldown and isolation cover the rest.
- **A new dependency is a decision.** Adding one is reviewed like any
  other design choice: who maintains it, how big is it, what does it pull
  in transitively, could three lines of our own code replace it.
- **AI coding tools are now targeted.** Configuration and credential files
  for AI development tools are an explicit exfiltration target. Keep their
  config free of plaintext secrets; keep their credentials out of synced
  repositories.

A weekly automated dependency audit is defined in
`agents/weekly-dependency-audit.md`. It proposes; a human reviews and
approves. Nothing auto-merges.

---

## 6. Scope discipline

- **Do not touch code outside the scope of the task.** Do not reformat,
  restructure, or refactor anything unrelated.
- **Pre-existing warnings on untouched code are left alone.** Warnings on
  newly-added or modified code are fixed before the work is done.
- **If something looks broken outside scope**, record it in the project's
  deferred-work tracker and move on.
- **Do not add features, abstractions, or indirection beyond what the task
  requires.** A bug fix does not need surrounding cleanup. Three similar
  lines beat a premature abstraction.
- **Do not add error handling for scenarios that cannot happen.** Trust
  internal code and framework guarantees. Validate only at system
  boundaries.
- **Default to no comments.** Add one only when the *why* is non-obvious:
  a hidden constraint, a subtle invariant, a workaround for a specific
  bug, behavior that would surprise a reader. Do not explain *what* the
  code does — names do that. Do not reference the current task in
  comments.
- **Even in auto-accept mode, pause and ask** when something is unclear,
  when a design decision has multiple valid paths, or when a mistake would
  be expensive. A 30-second question saves 30 minutes of rework.

---

## 7. Test coverage

- **At least 90% branch coverage on changed files.** Every new function
  covered. Every error path covered.
- **Never disable a test without a documented reason** in the test file.
  Never delete or comment out an existing test without documenting why.
- **The test pyramid is real:** unit, integration, end-to-end, adversarial,
  chaos, benchmarks. For load-bearing components, all layers apply.
- **Tests verify correctness, not feature presence.** A passing suite does
  not mean the feature works as the user expects; manual verification of
  user-facing behavior is required before claiming complete.
- **No flaky tests.** A test that passes 90% of the time is not green.
  Find the race or ordering bug; do not add retry loops.

---

## 8. Commit hygiene

- **One commit per atomic change.** Not end-of-milestone mega-commits.
- **Commit messages describe the *why*,** not the *what*.
- **No co-author trailers and no AI-attribution boilerplate.** No
  "Generated with", no tool attribution, no robot emoji. The author is the
  author; tools are tools.
- **No `--no-verify` and no skipping signing** unless explicitly requested
  in the session. If a hook fails, fix the underlying issue and make a new
  commit. Do not amend pushed commits.
- **Commit messages are public-safe:** no internal planning markers, no
  private paths, no infrastructure identifiers, no secrets.
- **No hyphens in user-facing strings** (UI copy, CLI output, reports,
  documentation prose, PR descriptions). Rewrite with commas, semicolons,
  parentheses, or restructure the sentence. Hyphens in identifiers, flags,
  file paths, and commit subjects are fine.
- **Push only when asked.** If on the default branch, branch first. Never
  force-push a shared branch.

---

## 9. Code style

- Follow the language's standard formatter and linter. Fix all warnings on
  changed code before finishing.
- Prefer error propagation over panics in all non-test code.
- No debug prints or scratch logging left in production paths.
- Comments explain *why*, not *what* (see §6).
- Error messages shown to users are plain language, not raw error strings.

---

## 10. Verification discipline

When asked to verify, simulate, or test that something works:

1. **Run real checks.** Write test scripts, read the actual library
   source, grep for actual behavior. Do not theorize about what should
   happen and present it as verification.
2. **If live testing is impossible** (needs hardware or network access not
   available), say so explicitly and describe what was verified statically
   versus what still needs manual testing.
3. **If thorough testing will take significant time,** say so before
   starting and let the user decide whether to invest it.
4. **Never present a theoretical walkthrough as an actual test.**

---

## 11. Explanation register

When explaining anything — a concept, a trade-off, why one tool was chosen
over another, what a piece of code does — default to the register of a
sharp 17-year-old: smart and curious, but without a CS degree.

1. **Lead with the picture, not the jargon.** Open with what the thing
   does in plain language. The technical name comes second.
2. **Use analogies to physical things.**
3. **Diagrams are first-class.** A six-line ASCII picture beats 30 lines
   of prose. Use tables for trade-offs.
4. **Define every acronym the first time** it appears.
5. **Trade-offs as tables:** what you get / what you give up / who it
   hurts when it fails.
6. **Numbers carry units and context,** not bare figures.
7. **Never end a section without a "so what".** One sentence on why the
   reader should care.
8. **No condescension.** Do not dumb it down; do not assume prior
   knowledge the reader does not have.

Applies to chat replies, plan sections, commit bodies, comments longer
than two lines, and PR descriptions.

---

## 12. Scale-conscious design

Evaluate every architectural decision, data structure, and pipeline
against **one to two orders of magnitude beyond today's scale**, even when
today's dataset is small. This does not mean over-engineering today's
code; it means:

1. **No in-memory collection that grows unboundedly with input size.**
   Stream or partition instead. A trait or interface boundary alone is not
   enough if the chosen implementation still accumulates everything.
2. **Trait/interface boundaries between logic and storage.** Parsers,
   scoring, and detection never touch storage directly. Storage backends
   are swappable.
3. **Content-addressed paths for file storage** (`hash[0:2]/hash[2:4]/
   hash`) so the layout works identically on local disk or object storage.
4. **Design batch work as partition, distribute, merge, reconcile.** The
   reconcile step resolves conflicts that pure merge gets wrong at scale.
5. **Prefer streaming over accumulation.** Process one item at a time
   where possible.
6. **Lay the trait, the convention, and the path structure now** even if
   today's implementation behind them is trivial. A trait boundary is
   nearly free; a rewrite is enormous.

---

## 13. Secrets and data handling

- **Credentials never appear in logs, commits, error messages, or shared
  output.** A pre-commit hook scans for them (see `hooks/`).
- **Secrets never live in a synced repository in plaintext.** Use an
  encrypted-at-rest mechanism so the repository only ever holds
  ciphertext, or keep them out of version control entirely.
- **Private keys are per-machine or hardware-backed where practical.** A
  single private key shared across machines means one compromise is total
  compromise.
- **No untrusted data on a trusted machine without isolation** (see §5).
- **Validate at the boundary, trust internally** (see §2.1).

---

## Adopting this baseline

1. Copy or symlink `claude-baseline/` into the new project, or reference it
   from the project's own `CLAUDE.md`.
2. Install the hooks: run `hooks/install.sh` from inside the project repo.
3. Add the supply-chain configuration: copy the relevant file from
   `supply-chain/` for the project's package manager.
4. The project's own `CLAUDE.md` inherits this file by reference and adds
   only project-specific rules.
5. Register the weekly dependency audit (`agents/weekly-dependency-audit.md`)
   as a scheduled task.

When a baseline rule changes, change it here. Project files never fork a
baseline rule; they either inherit it or explicitly override it in writing
with a recorded reason.

---

# Stegcore — Project-Specific Addendum

The text above is the project-agnostic engineering baseline, copied from
`~/the-factory/crazy-random-ideas/claude-baseline/CLAUDE.md` on
2026-05-23 as Stegcore's starting point. From here, this file grows
Stegcore-specific rules without modifying the baseline; the two are
independent.

## A1. Product summary

Stegcore is a cross-platform desktop and CLI steganography toolkit:
embed encrypted messages inside images and audio, extract them with a
passphrase, analyse files for hidden content, and benchmark covers for
suitability. Rust workspace (`crates/engine`, `crates/core`,
`crates/cli`, `src-tauri`) + React/TypeScript frontend. AGPL-3.0-or-later.

## A2. Dual-use discipline

Steganography is dual-use. The `AUP.md` at the repo root documents the
gating principles; the in-product version lives in
`frontend/src/components/Installer.tsx` (`StepAUP`). When the canonical
text changes, propagate the change to the in-product copy on the next
release cut.

## A3. Sovereign rules (Stegcore-specific overlays on the baseline)

- **No future-version references in user-facing artefacts.** README,
  AUP, GitHub release notes, marketing copy do not name versions that
  have not shipped. The one exception is `private/plans/roadmap.md`,
  which is gitignored and is the roadmap's job. See
  `~/.claude/projects/-home-mercury-the-factory-Stegcore/memory/feedback_no_future_version_refs.md`.
- **Aletheia parity is the floor, not the ceiling.** Where Stegcore
  reimplements a classical detector that Aletheia also has, the numerical
  output must match Aletheia's to floating-point precision on a
  documented test corpus. Stegcore is allowed to be faster; it is not
  allowed to be a different answer.
- **Calibrated thresholds, never guessed.** Detector thresholds are set
  by `private/calibration/calibrate.py` against a real dataset at a
  documented FPR ceiling. Default at the time of writing: τ=2% per
  detector on Cassavia + BOSSbase 1.01, giving ~4% combined ensemble
  FPR on natural-image covers.
- **Tiered fingerprint architecture.** Structural tool fingerprints
  carry an explicit tier — `Exact` (decisive, short-circuits the
  ensemble) or `Heuristic` (corroborating, floors the verdict at
  `Suspicious`). New fingerprints declare a tier; tier choice is
  empirically justified by FPR on a clean corpus.
- **The fingerprint validation harness is part of the release gate.**
  `tests/fingerprint/harness.py` must pass `--smoke` on every release;
  `--full` runs locally before tagging.

## A4. Release discipline

- Bump version in **six** locations: the three workspace crate
  `Cargo.toml`s (engine, core, cli), `src-tauri/Cargo.toml`,
  `src-tauri/tauri.conf.json`, `frontend/package.json`. The release
  binary's `--version` is the canonical check.
- CHANGELOG entries describe **only what this release shipped**. No
  "next release will…" lines, no forward-looking promises.
- Tag from `main` after a clean CI signal across all three OS runners +
  the Tauri Dev Build matrix.

## A5. Memory location

Per-session project memory lives at
`~/.claude/projects/-home-mercury-the-factory-Stegcore/memory/`. A
mirrored backup lives at
`~/the-factory/crazy-random-ideas/claude-config/projects/-home-mercury-the-factory-Stegcore/memory/`;
refresh it after substantive memory changes so the backup stays useful
on a fresh machine.

## A6. CI invariants

- `cargo fmt --check` on all three OS runners (introducing rustfmt
  drift breaks all three at once, as v4.0.1 push 47a1552 demonstrated).
- `cargo clippy -- -D warnings` on engine + core + cli.
- `cargo test --workspace` green.
- Licence header check on every changed file.
- Tauri Dev Build matrix on Linux + macOS + Windows for every push to
  `dev` or `main`.

GitHub Actions minutes are not infinite — the local `tests/fingerprint/harness.py
--smoke` run is the first line of defence; CI is the second.
