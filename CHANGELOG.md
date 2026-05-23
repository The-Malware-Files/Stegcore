# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

_No changes yet._

---

## [4.0.1]; 2026-05-30

Steganalysis suite at Aletheia parity. Tiered fingerprint architecture.
Acceptable Use Policy. Project documentation tightened.

### Engine
- **Aletheia detector ports**: Sample Pair Analysis and RS reimplemented
  against Aletheia's reference; agreement to floating-point precision on
  the Cassavia 2022 test set (16 significant digits, IEEE 754 last-bit
  round-off only).
- **Weighted Stego (WS) detector** added; Aletheia parity on the third
  classical detector.
- **Tiered fingerprint architecture**: structural tool fingerprints now
  carry a confidence tier:
  - `Exact` (decisive, short-circuits the ensemble to "Likely Stego")
  - `Heuristic` (corroborating, floors the verdict at "Suspicious")
- **LSBSteg fingerprint**: reads the 64-bit big-endian payload-length
  header from the row-major BGR LSB stream. 100% TPR on real LSBSteg
  output (Heuristic tier; ~0.2% false-positive rate on grayscale natural
  imagery).
- **Dead fingerprint cleanup**: removed `check_steghide` (offset-0
  magic check that never fired against real Steghide output) and
  `check_openstego_png` (whole-file substring scan that never fired
  against real OpenStego output). Both verified empirically.
- **Phase 3.5 calibration**: thresholds refit on Cassavia + BOSSbase
  1.01 at a 2% per-detector false-positive ceiling (~4% combined on
  natural-image covers; documented as the empirical detection-gain
  ceiling for a purely classical pipeline).
- **Q-37 weight rebalance**: equal 1/3 weights for SPA / RS / WS;
  chi² and entropy dropped from the verdict OR-logic (kept as
  visible signals, no longer gating).
- **AnalysisReport.tool_fingerprint_tier**: new field (`"exact"` /
  `"heuristic"` / `null`). Additive, backward-compatible for CLI JSON
  and CSV consumers.

### GUI
- **Tier-aware fingerprint badge** in the analysis card and the
  detail panel:
  - Red pill for `exact` matches (decisive)
  - Amber pill for `heuristic` matches (corroborating)
  - Neutral pill for legacy reports without a tier
- Tooltip carries the full label; pill shows just the tool name so
  cards stay readable.

### Documentation
- **`AUP.md`** at the repo root; canonical Acceptable Use Policy,
  expands the in-product Installer text into a versioned document
  covering audience, prohibited uses, dual-use gating principles,
  reporting channel and dual-use framing.
- **README**: steganalysis-suite callout rewritten for the parity
  milestone; the "known issue" warning from v4.0.0 is retired.
- **Fingerprint validation harness** at `tests/fingerprint/harness.py`
 ; procedural noise covers, TPR / FPR / cross-tool specificity
  asserts for LSBSteg + Steghide + OpenStego. Run with `--smoke` for
  CI or `--full` for the local sweep.

### Adversarial gate
A pre-tag adversarial sweep across seven surfaces, all landed before
the release tag.

- **Fuzz harnesses**: four cargo-fuzz targets cover analyse on PNG /
  BMP / WAV and extract on PNG. The sweep found a JPEG out-of-bounds
  panic in DQT, DRI and APP/COM segment parsing; bounds checks added
  to each, mirroring the existing SOF0/SOF1 pattern. A
  `catch_unwind` safety net wraps the engine boundary so a future
  unexpected panic surfaces as a clean error rather than aborting
  the host process.
- **Property tests**: round-trip identity, dimension preservation
  and never-panic-on-random-bytes verified with proptest.
- **CLI integration suite**: 45 tests covering version / help /
  standalone / round-trip / error paths / pathological inputs /
  info-score-diff / quiet-json.
- **Lossy-pipeline survival**: ImageMagick PNG→PNG preserved,
  PNG→JPEG destroyed cleanly, resize destroyed, Pillow re-save
  preserved, metadata-strip preserved. Behavioural contract: silent
  corruption is never an outcome.
- **Crash injection**: SIGKILL at five delay windows during embed.
  Atomic-rename-on-close discipline holds across all of them; the
  source file is never mutated mid-extract.
- **Concurrent + caps**: 100 parallel analyses, 4 parallel
  embed-and-extracts, capacity boundary, malformed-dimensions
  zero-OOM, zero-payload reject.
- **Content-sniffing dispatcher**: analyse / embed / extract now
  route by magic-byte sniff (PNG `89 50 4E 47`, BMP `BM`, JPEG
  `FF D8 FF`, RIFF/WAVE), with extension as a fallback. A PNG named
  `.jpg`, a BMP named `.png`, a WAV named `.png` all dispatch
  correctly; garbage falls back to extension. Closes a real
  user-facing rough edge.
- **Supply-chain CI**: cargo-deny wired in alongside cargo-audit
  (licence allow-list, sources policy, wildcard ban with workspace
  exemption). Dependabot configured weekly with ecosystem-grouped
  PRs (cargo + npm + actions) and a cooldown discipline.
- **Adversarial-stego corpus**: generator for LSB-matching (±1
  modulation) samples that defeat the classical SPA/RS/WS pipeline
  by design. Used to document where classical detection ends.
- **GUI E2E**: Playwright suite vs the Vite dev server (smoke /
  navigation / monkey-clicker / wizard back-button) on the Linux
  runner; an optional WDIO 8 + tauri-driver job covers the actual
  Tauri-runtime IPC boundary. Caught and fixed a real first-run
  promise-chain bug that left the app blank in browser-only mode.

### CI / build
- Clippy strict (`-D warnings`) clean across engine + core + cli.
- 160+ workspace unit tests passing plus the adversarial-gate
  integration + property + E2E suites.
- Release binary build verified on Linux x86_64; reports
  `stegcore 4.0.1`.
- Coverage published to Codecov; ≥90% line-coverage gate enforced
  on every main push.

---

## [4.0.0]; 2026-04-20

First real release. Build in public.

### Structure
- Engine consolidated into the Stegcore monorepo as `crates/engine/`; no more submodule
- Single AGPL-3.0-or-later licence across the workspace
- Copyright now The Malware Files; contact `ops@themalwarefiles.com`

### Engine
- Per-detector 0% FPR calibration on the Cassavia 2022 LSBSteg test set
- Fingerprint-led verdict: a confirmed structural signature drives the ensemble
- OR-logic ensemble: any calibrated detector firing raises the verdict to at least Suspicious
- Removed the imprecise "sequential LSB" statistical heuristic that misattributed output to Steghide/OpenStego

### Known limitation
- The classical Sample Pair Analysis and RS detectors carry almost no signal on the LSBSteg test set at 0% FPR. Detection of OpenStego and Steghide via structural fingerprints is reliable; detection of other tools via classical analysis is not. Both algorithms will be reimplemented against the reference specifications, and Weighted Stego will be added, in v4.0.1. See README for the full head-to-head with Aletheia.

### Other
- Bug fixes and improvements

---

## [4.0.0-beta.1]; 2026-03-23

Complete rewrite. Rust + Tauri v2 replaces the Python + PyInstaller codebase.

### Engine
- Full Rust engine with three AEAD ciphers + Argon2id
- Direct Rust crate dependency (replaced C FFI boundary)
- Parallel batch analysis with rayon
- Magic byte validation (PNG, BMP, JPEG, WAV, WebP, FLAC)
- File size limits with clear error messages
- Fixed: `extract_with_keyfile` now auto-detects embedding mode
  (was hardcoded to sequential, breaking adaptive-mode key file extraction)
- Fixed: Adaptive mode variance calculation now uses upper 7 bits (LSB-immune),
  preventing embed/extract slot mismatch on large images
- Fixed: WAV sample read errors now propagate instead of being silently dropped
- Fixed: JPEG restart marker decode/encode (sequence counter + raw byte skip)
- Fixed: Two-pass extraction reads only header + metadata + ciphertext (not full image)
- Fixed: Passphrase seed XOR-fold preserves entropy beyond 32 bytes
- Fixed: Chi-squared distribution formula corrected
- Release profile: LTO + codegen-units=1
- 87 engine unit tests, 81.7% line coverage

### GUI
- Tauri v2 desktop app (~10 MB native binary)
- React + TypeScript frontend with step-by-step wizards
- First-run setup wizard (AUP, licence, preferences)
- Animated steganalysis dashboard with five chart types:
  - Chi-Squared lateral slide (block-based, per-channel p-values)
  - RS Analysis untangle (per-channel, 4-curve divergence)
  - Sample Pair Analysis arc sweep gauge (DWW quadratic, with confidence)
  - LSB Entropy corner ripple heatmap (per-channel autocorrelation, 10×10 grid)
  - Audio oscilloscope trace (WAV/FLAC waveform with LSB highlighting)
- Progressive two-phase analysis (fast preliminary + background full)
- Before/after pixel diff on embed success
- Copy dashboard to clipboard as image
- PDF/HTML/JSON/CSV export from cached reports
- Keyboard shortcuts (E/X/A/L/R/?)
- Interface size scaling (small/default/large/xl)
- Dark and light themes with live switching
- Reduce-motion support
- Clipboard auto-clear after configurable timeout
- Skeleton loaders for lazy-loaded routes
- Success sound (optional, via Web Audio API)
- Format recommendations on cover file selection
- Smart output naming (auto-generated from input)
- Error recovery suggestions
- Stable footer (no layout shift between routes)

### CLI
- Subcommands: embed, extract, analyse, score, diff, info, ciphers, wizard, doctor, benchmark, verse, completions
- Shell completions (Bash, Zsh, Fish)
- Config file (~/.config/stegcore/config.toml)
- `stegcore doctor`; system health check
- `stegcore benchmark`; real cipher throughput test
- `stegcore diff`; pixel comparison between files
- `stegcore verse`; daily Bible verse
- Pipe support (stdin payloads, `--raw` stdout for binary)
- `--quiet` mode (exit code only)
- `--json` on all commands
- `--watch` mode (directory monitoring)
- Coloured help output with clap styles
- Progress ETA on batch operations
- Elapsed time on all spinners
- Box-drawing summary cards
- Smart output naming (auto-generated when `-o` omitted)

### Security
- Content Security Policy enabled in Tauri
- Passphrase env var warnings in help text
- Path canonicalisation in IPC commands
- Config directory created with 0o700 permissions
- TOCTOU fixes (direct file opens, no pre-checks)
- Oracle-resistant error messages
- CLI passphrase zeroisation after use (Zeroizing<Vec<u8>>)
- Key files written with 0o600 permissions (Unix)
- Deniable metadata no longer reveals deniable mode (deniable field always false)
- Deniable partition half randomised (adversary cannot infer which is real)
- Deniable key files only written when --export-key is explicitly set
- Empty decoy passphrase rejected with clear error
- tauri-plugin-fs scoped to minimal required permissions
- Passphrase cleared from Zustand stores after successful embed/extract
- Decompression bomb capped at 256 MB
- JPEG extract allocation capped to coefficient capacity

### Polish
- Backdrop blur on settings panel overlay
- Spring physics on all interactive buttons (cubic-bezier bounce)
- Dashboard chart cards lift on hover
- Drop zone hover lift with shadow
- Contextual tooltips on cipher/mode selectors
- Box-drawn summary cards in CLI output (Unicode borders)
- Summary card after CLI embed (cover, output, cipher, mode)
- Inline examples in `--help` for embed, extract, analyse
- Bible verse footer auto-scrolls on 5s idle, snaps back on interaction
- Before/after pixel diff shown on embed success

### Distribution
- One-liner install script (Linux/macOS)
- Homebrew formula
- Winget manifest
- Kali Linux packaging
- SourceForge release notes
- Comprehensive integration test suite (357 tests across 35+ categories)

---

## [2.0.12]; 2026-03-12

- Passphrase memory hardening (zeroed after use)
- Full pytest suite (64 tests, 93.73% coverage)
- CI test job on every push

Bug fixes and improvements.

---

## [2.0.11]; 2026-03

- Asset path resolution fix for pip installs
- Lazy imports in GUI (eliminates 3-5s startup delay)
- CONTRIBUTING.md and CI licence check

Bug fixes and improvements.

---

## [2.0.10]; 2026-03

- Unified binary (CLI + GUI from single entrypoint)
- `--onedir` distribution (no per-launch extraction overhead)
- Lazy core imports in CLI (near-instant startup)
- Comparison table in README

Bug fixes and improvements.

---

## [2.0.6]; 2026-02

- JPEG support restored without `jpegio` (pixel-domain LSB, output as PNG)

---

## [2.0.0]; 2026-02

Complete rewrite of v1.

- Three AEAD ciphers (Ascon-128, ChaCha20-Poly1305, AES-256-GCM)
- Argon2id key derivation
- Adaptive LSB steganography with spread spectrum
- Deniable dual-payload mode
- Cover image scoring
- Desktop GUI (dark + light themes)
- CLI with wizard and power modes
- PNG, BMP, JPEG, WAV format support

---

## [1.0.0]; 2023

Initial release. Basic LSB, single cipher (AES-256), CLI only.
