# Contributing to Stegcore

Thanks for your interest. At the moment Stegcore is a solo project and **external contributions are not being accepted**. This keeps the codebase small, the review quality high, and the release cadence tight during the early milestones.

## What is welcome

- **Bug reports.** Open an issue with a clear reproduction, the version you are on, and your platform.
- **Security disclosures.** See [SECURITY.md](SECURITY.md) for the responsible disclosure process. Please do not open public issues for security bugs.
- **Feature requests and ideas.** Open an issue labelled "discussion". These feed the roadmap in `private/plans/roadmap.md` even when the answer is not yet.
- **Commercial-licence enquiries.** See [COMMERCIAL.md](COMMERCIAL.md) for the dual-licence terms; email `ops@themalwarefiles.com` to start.

## What is not accepted right now

- Pull requests for code, documentation, or translation changes.
- Drive-by patches.
- Refactor proposals.

When external contributions do open, guidance will be published here and announced in the release notes. Until then, any PR will be closed with a pointer to this file.

## Local CI preflight (when contributions open)

Stegcore's gates are explicit and reproducible. Before opening any PR
(once that path is open), run the local equivalents of what CI runs:

```bash
cargo fmt --all --check
cargo clippy -p stegcore-engine -p stegcore-core -p stegcore-cli \
  --all-targets -- -D warnings
cargo test --workspace
cargo deny --workspace --all-features check licenses bans sources
(cd frontend && npm run e2e)
```

A `scripts/preflight.sh` runner that wraps these (and optionally
replays the full Linux CI matrix locally via [nektos/act](https://github.com/nektos/act))
is planned for the next sprint; track the
`project_local_ci_preflight` memory note for status.

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
