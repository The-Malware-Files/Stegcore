# Architecture

How Stegcore is built, and why it's built this way.

---

## The Big Picture

Stegcore is a Rust workspace with four crates and a React frontend, all
packaged as a Tauri v2 desktop application:

```
Cargo.toml              root workspace
├── crates/engine/      steganography engine — LSB, crypto, steganalysis
├── crates/core/        public library — error types, wrappers, utilities
├── crates/cli/         CLI binary — clap v4, subcommands, config
├── src-tauri/          Tauri v2 app shell — IPC commands, settings
└── frontend/           React + TypeScript + Vite — the GUI
```

The engine (`crates/engine`) contains the steganographic algorithms and
steganalysis suite. It's a normal workspace crate, consumed by
`crates/core` as a path dependency. No `unsafe` code at the crate
boundary, no FFI, no feature flags — a single clean Rust API.

---

## How Things Talk to Each Other

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Frontend   │     │  src-tauri   │     │  crates/core │
│   (React)    │────▶│  (IPC cmds)  │────▶│  (wrappers)  │──┐
│   Zustand    │◀────│  lib.rs      │◀────│  steg.rs     │  │
│   Canvas     │     │              │     │  analysis.rs │  │
└──────────────┘     └──────────────┘     └──────────────┘  │
                                                             │
                     ┌──────────────┐     ┌─────────────────┐  │
                     │  crates/cli  │────▶│  crates/engine  │◀─┘
                     │  (clap v4)   │     │  steg.rs        │
                     │  main.rs     │     │  analysis.rs    │
                     └──────────────┘     │  crypto.rs      │
                                          └─────────────────┘
```

- **Frontend → src-tauri**: Tauri IPC (`invoke`). All calls are async.
  CPU-heavy operations use `spawn_blocking` so the GTK event loop never
  blocks.
- **src-tauri → crates/core**: Direct Rust function calls. The Tauri
  commands are thin wrappers.
- **crates/core → crates/engine**: Path dependency. Wrappers convert
  engine types to public types via JSON round-trip for serialisation
  stability.
- **crates/cli → crates/core**: Same wrappers, different frontend.

The CLI and GUI share the same core library. If it works in one, it works
in the other.

---

## Data Flow

### Embedding (hiding data)

```
User provides: passphrase + payload file + cover file + cipher + mode

1. Read payload bytes from file (or stdin with "-")
2. Generate random salt (16 bytes) and nonce (cipher-dependent)
3. Derive encryption key from passphrase + salt using Argon2id
4. Compress payload with Zstandard
5. Encrypt compressed bytes with chosen AEAD cipher
6. Prepend metadata header: [2-byte length][JSON metadata][ciphertext]
   Metadata includes: cipher, mode, nonce (base64), salt (base64)
7. Score cover file for suitability (entropy, texture, capacity)
8. Embed the combined bytes into cover file LSBs:
   - Image (PNG/BMP/WebP): scatter bits across pixel channels
   - JPEG: modify DCT coefficients (JSteg technique)
   - WAV: modify audio sample LSBs
9. Write output file
10. Optionally export key file (JSON with cipher, nonce, salt)
```

### Extraction (recovering data)

```
User provides: stego file + passphrase (+ optional key file)

1. Detect file format from magic bytes + extension
2. Calculate slot positions from passphrase (or key file)
3. Try sequential mode first → if that fails, try adaptive mode
   (the extractor auto-detects which mode was used)
4. Read LSBs from the calculated positions
5. Parse metadata header (first 2 bytes = length, then JSON)
6. Re-derive encryption key from passphrase + stored salt
7. Decrypt with the cipher and nonce from metadata
8. Decompress with Zstandard
9. Write recovered payload to output file
```

### Analysis (detecting hidden content)

```
User provides: one or more files to scan

1. Detect format, load pixel/sample data
2. Run detectors in parallel (rayon):
   - Chi-Squared (block-based): tests LSB pair distribution uniformity
   - Sample Pair Analysis (DWW quadratic): measures adjacent pixel correlation
   - RS Analysis (per-channel): Regular/Singular group asymmetry detection
   - LSB Entropy (per-channel autocorrelation): measures randomness of least significant bits
   - Tool Fingerprinting: checks for Steghide/OutGuess/OpenStego/generic LSB
3. For images: compute 10×10 block entropy grid (heatmap data)
   For audio: downsample waveform + flag suspicious regions
4. Ensemble scoring → overall verdict (Clean / Suspicious / Likely Stego)
5. Return AnalysisReport with per-test scores and distribution data
```

---

## Crate Responsibilities

### `crates/core` — Public Library

The bridge between the engine and the outside world.

- **errors.rs** — `StegError` enum. Every error variant has a
  `suggestion()` method that returns a helpful hint (e.g. "Try a larger
  cover file" for `InsufficientCapacity`). Error messages for wrong
  passphrase and no-payload-found are intentionally identical (oracle
  resistance).
- **steg.rs** — Safe wrappers for `embed_adaptive`, `embed_sequential`,
  `embed_deniable`, `extract`, `extract_with_keyfile`, `assess`, and
  `read_meta`. KeyFile conversion between public and engine types uses
  JSON round-trip for serialisation stability.
- **analysis.rs** — `analyse()` wraps the engine's steganalysis suite.
  `analyse_batch()` uses rayon for parallel processing. Also contains
  report generation: HTML, CSV, JSON export.
- **keyfile.rs** — `KeyFile` struct with JSON serialisation. Read/write
  functions for `.json` key files.
- **utils.rs** — Format detection (magic bytes: PNG `\x89PNG`, JPEG
  `\xFF\xD8\xFF`, BMP `BM`, WAV `RIFF`, WebP `RIFF...WEBP`, FLAC
  `fLaC`). File validation (size limits, extension matching). Temp file
  creation with 0o600 permissions.
- **verses.rs** — 30 NLT Bible verses, time-based rotation.

### `crates/cli` — CLI Binary

Everything terminal-facing.

- **main.rs** — Clap v4 argument parsing with coloured help output
  (`clap_styles`). Dispatches to subcommands. Bible verse printing
  (disabled in quiet/JSON mode). SIGINT handler.
- **commands/** — One file per subcommand:
  - `embed.rs` — Stdin pipe support (`-`), smart output naming, summary
    card on success, export key file.
  - `extract.rs` — `--stdout` for text, `--raw` for binary piping.
  - `analyse.rs` — Batch via glob, progress bar with ETA, watch mode
    (directory monitoring with `notify`), box-drawn result cards,
    HTML/CSV/JSON report generation.
  - `score.rs` — Cover file suitability scoring.
  - `info.rs` — Read embedded metadata (requires passphrase).
  - `diff.rs` — Pixel-level comparison between two images.
  - `ciphers.rs` — List available ciphers.
  - `wizard.rs` — Interactive guided mode for beginners.
- **output.rs** — Coloured terminal output (crossterm), RAII spinner
  with elapsed time, exit code mapping, `print_summary` box-drawing,
  JSON output helper.
- **prompt.rs** — Secure passphrase input (rpassword), confirmation
  loop.
- **config.rs** — TOML config file at `~/.config/stegcore/config.toml`.
  Supports: default cipher, mode, output folder, export key, verbose,
  verses.

### `src-tauri` — Desktop App Shell

Thin IPC layer between the frontend and the core library.

- **lib.rs** — All Tauri `#[command]` functions. Every CPU-heavy
  operation uses `tauri::async_runtime::spawn_blocking()` to prevent
  blocking the GTK main thread. Includes:
  - `score_cover`, `embed`, `extract`, `analyse_file`,
    `analyse_file_progressive`, `analyse_batch_files`
  - `pixel_diff` — compares original vs stego at pixel level
  - `get_settings`, `set_settings` — JSON persistence in app config dir
  - `is_first_run`, `complete_setup` — first-run wizard state
  - `get_verse`, `get_supported_formats`, `file_size`
  - Progressive analysis emits `analysis_complete` Tauri events so the
    frontend can update without polling.
  - Settings stored at `~/.config/stegcore/settings.json` with 0o700
    directory permissions.

### `frontend` — React GUI

The user-facing interface.

- **Routes**: Home (4-card landing), Embed (4-step wizard), Extract
  (3-step wizard), Analyse (file picker + results + dashboard), Learn
  (placeholder for future guides).
- **State management**: Zustand stores — `embedStore` (payload, cover,
  options, result), `extractStore` (stego, passphrase, result),
  `settingsStore` (theme, cipher defaults, security prefs).
- **Steganalysis dashboard**: Canvas-based animated charts (not SVG).
  Each chart manages its own `requestAnimationFrame` loop with a frame
  counter. Charts re-render on container resize via `ResizeObserver`.
  - Chi-Squared (block-based): lateral slide (horizontal bars per RGB channel)
  - RS Analysis (per-channel): untangle (4 curves diverging from midline)
  - Sample Pair (DWW quadratic): arc sweep gauge (circular dial with bounce)
  - LSB Entropy (per-channel autocorrelation): corner ripple heatmap (10×10 grid, wave reveal)
  - Audio: oscilloscope trace (waveform bars with region highlighting)
- **Design system**: CSS custom properties (`--sc-*` for brand,
  `--ui-*` for semantic). Dark/light themes via `data-theme` attribute.
  Interface size scaling via CSS `zoom`. System font stack.
- **IPC layer** (`lib/ipc.ts`): Typed wrappers around Tauri `invoke`.
  `safeInvoke` provides mock fallbacks for browser-only dev mode but
  propagates all backend errors in production.
- **Toast system**: Auto-dismiss with countdown bar (4s default, 30s
  for reload notifications). Exit animation mirrors entry.

---

## Key Design Decisions

1. **Single monorepo** — All code is in one repository under
   AGPL-3.0-or-later. The engine lives at `crates/engine/` as a
   workspace crate; `crates/core/` consumes it as a normal Rust path
   dependency. No FFI, no `unsafe` at the crate boundary.

2. **Self-contained payload** — All metadata (cipher, nonce, salt, mode)
   is embedded inside the stego file's LSBs alongside the ciphertext.
   No key file is required for extraction. The key file is an optional
   export for backup or out-of-band sharing.

3. **Async Tauri commands** — Every IPC command that touches the engine
   uses `spawn_blocking()`. Without this, the GTK main thread blocks
   during analysis/embedding, the webview can't render, and on WSL2 the
   display connection times out ("Broken pipe").

4. **Progressive analysis** — Fast preliminary results from 10% pixel
   sampling, full accuracy runs in background. The Tauri event system
   notifies the frontend when the full report is ready, and the user
   sees a "Hit R to reload" toast.

5. **Mode auto-detection** — The extractor tries sequential slot
   calculation first. If parsing fails (wrong metadata header), it
   retries with adaptive slot calculation. This means the user never
   has to remember which mode was used — the correct one is found
   automatically.

6. **Canvas charts, not SVG** — The steganalysis dashboard uses HTML5
   Canvas for frame-precise animation control. Each chart has its own
   `requestAnimationFrame` loop. Canvas re-renders on resize via
   `ResizeObserver` with DPR-aware scaling (capped at 2x).

7. **Completely offline** — No network calls, no telemetry, no CDN
   fonts, no update checks. Fonts are system stack. All assets bundled.

8. **Oracle resistance** — `DecryptionFailed` and `NoPayloadFound`
   return identical error messages. An attacker can't distinguish
   between "this file has hidden content with a wrong passphrase" and
   "this file has no hidden content at all".

---

## Build

```bash
# Development (GUI + hot reload)
cd frontend && npm install && cd ..
cargo tauri dev

# CLI only (fast, no frontend needed)
cargo build --features engine -p stegcore-cli

# Release binary (optimised: LTO + single codegen unit)
cargo build --release --features engine

# Without engine (public build, stubs only)
cargo build --release --no-default-features

# Run tests
cargo test --workspace --features engine

# Type check frontend
cd frontend && npx tsc --noEmit

# Clippy + format
cargo clippy --workspace --features engine -- -D warnings
cargo fmt --all --check
```

---

## File Map

```
.
├── Cargo.toml                        workspace definition
├── Cargo.lock                        pinned dependency versions
├── README.md                         user-facing documentation
├── USAGE.md                          CLI reference
├── ARCHITECTURE.md                   this file
├── CONTRIBUTING.md                   developer guide
├── CHANGELOG.md                      version history
├── SECURITY.md                       threat model + responsible use
├── LICENSE                           AGPL-3.0
├── icon.svg                          brand icon (layered stack)
├── install.sh                        universal installer (Linux/macOS)
│
├── crates/
│   ├── core/
│   │   ├── Cargo.toml                optional engine dependency
│   │   ├── build.rs                  feature flag → cfg(engine)
│   │   └── src/
│   │       ├── lib.rs                re-exports
│   │       ├── steg.rs               embed/extract/assess wrappers
│   │       ├── analysis.rs           steganalysis + report generation
│   │       ├── keyfile.rs            key file serialisation
│   │       ├── errors.rs             StegError enum + suggestions
│   │       ├── utils.rs              format detection, file validation
│   │       └── verses.rs             Bible verse rotation
│   │
│   └── cli/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs               arg parsing, dispatch, doctor, benchmark
│           ├── commands/             one file per subcommand
│           ├── output.rs             coloured output, spinner, summary cards
│           ├── prompt.rs             secure passphrase input
│           └── config.rs             TOML config file
│
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json               window config, CSP, permissions
│   └── src/
│       └── lib.rs                    IPC commands, settings, first-run
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   └── src/
│       ├── main.tsx                  React entry, theme init
│       ├── App.tsx                   layout, routing, footer, splash
│       ├── App.css                   design tokens, animations
│       ├── routes/                   page components
│       ├── components/               reusable UI + steganalysis charts
│       └── lib/                      stores, IPC, toast, sound, theme
│
├── dist/                             packaging (Homebrew, winget, Kali)
└── docs/                             additional documentation
```
