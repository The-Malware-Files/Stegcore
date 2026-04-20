# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

_No changes yet._

---

## [4.0.0] — 2026-04-20

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

## [4.0.0-beta.1] — 2026-03-23

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
- `stegcore doctor` — system health check
- `stegcore benchmark` — real cipher throughput test
- `stegcore diff` — pixel comparison between files
- `stegcore verse` — daily Bible verse
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

## [2.0.12] — 2026-03-12

- Passphrase memory hardening (zeroed after use)
- Full pytest suite (64 tests, 93.73% coverage)
- CI test job on every push

Bug fixes and improvements.

---

## [2.0.11] — 2026-03

- Asset path resolution fix for pip installs
- Lazy imports in GUI (eliminates 3-5s startup delay)
- CONTRIBUTING.md and CI licence check

Bug fixes and improvements.

---

## [2.0.10] — 2026-03

- Unified binary (CLI + GUI from single entrypoint)
- `--onedir` distribution (no per-launch extraction overhead)
- Lazy core imports in CLI (near-instant startup)
- Comparison table in README

Bug fixes and improvements.

---

## [2.0.6] — 2026-02

- JPEG support restored without `jpegio` (pixel-domain LSB, output as PNG)

---

## [2.0.0] — 2026-02

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

## [1.0.0] — 2023

Initial release. Basic LSB, single cipher (AES-256), CLI only.
