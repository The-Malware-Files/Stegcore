# Contributing to Stegcore

Stegcore is open to contributions. Bug reports, patches, documentation
fixes, security disclosures and feature ideas are all welcome.

## How to contribute

- **Bug reports.** Open an issue with a clear reproduction, the version
  you are on, and your platform.
- **Security disclosures.** See [SECURITY.md](SECURITY.md) for the
  responsible disclosure process. Please do not open public issues for
  security bugs.
- **Feature requests and ideas.** Open an issue labelled `discussion`.
  Maintainers will reply with whether it fits the roadmap and, if so,
  what shape a useful PR would take.
- **Pull requests.** See the PR guidelines below.
- **Commercial-licence enquiries.** See [COMMERCIAL.md](COMMERCIAL.md)
  for the dual-licence terms. Email `ops@themalwarefiles.com` to start.

## Pull-request guidelines

1. **Open or comment on an issue first** if the change is non-trivial.
   This avoids duplicate work and gives you a quick read on whether the
   change fits the roadmap.
2. **One commit per atomic change** with a clear commit message that
   explains the *why*, not just the *what*. No co-author trailers, no
   AI-attribution boilerplate, no force-pushes to shared branches.
3. **Run the preflight locally** before opening a PR (see below).
4. **Keep diffs focused.** A bug fix does not need a surrounding
   refactor; a refactor PR should not also change behaviour. Match the
   style of the surrounding code.
5. **Tests for new behaviour.** New functions get tests; new error
   paths get tests. CI enforces a ≥90% line-coverage gate.
6. **British English** in user-facing strings, comments and PR
   descriptions; identifiers follow the surrounding library.
7. **No future-version references** in user-facing artefacts. The
   roadmap is the only place that names not-yet-released versions.
8. **Documentation updates** ride with the code change they describe.

## Local CI preflight

Run the local equivalent of what CI runs before opening a PR:

```bash
cargo fmt --all --check
cargo clippy -p stegcore-engine -p stegcore-core -p stegcore-cli \
  --all-targets -- -D warnings
cargo test --workspace
cargo deny --workspace --all-features check licenses bans sources
(cd frontend && npm run e2e)
```

A `scripts/preflight.sh` runner wraps these (and optionally replays
the full Linux CI matrix locally via
[nektos/act](https://github.com/nektos/act)). Run it as
`./scripts/preflight.sh` (cheap subset, ~30s) or
`./scripts/preflight.sh --full` (~5 min, replays the Linux CI matrix).

## What is out of scope

- Pull requests that disable, remove, or weaken the AUP, supply-chain
  policy, or any safety gate without a written discussion.
- Telemetry, network calls, account systems, or cloud dependencies of
  any kind. Stegcore is offline by design.
- Cosmetic-only PRs that touch a lot of files without behaviour change.
  Style and formatting are enforced by the toolchain; please rely on
  that rather than opening a dedicated reformat PR.

## Licence

Stegcore is **dual-licensed**: AGPL-3.0-or-later by default
([LICENSE](LICENSE)) and a commercial licence for organisations that
cannot meet the AGPL source-release obligation
([COMMERCIAL.md](COMMERCIAL.md)).

Contributions are accepted under the AGPL-3.0-or-later licence of
the project. By submitting a contribution you confirm you have the
right to license your contribution to The Malware Files under those
terms, and that we may relicense the combined work (including your
contribution) under the dual-licence arrangement described in
COMMERCIAL.md. This is the same pattern used by Qt, MySQL, and other
dual-licensed projects.

If you would prefer to keep a contribution outside the dual-licence
arrangement, mention it in the PR body and we will discuss before
merging.

Contact: `ops@themalwarefiles.com`
