# Contributing to Stegcore

Stegcore is built for journalists, activists, and anyone who needs privacy
that works without a security degree. If you're contributing, keep that
person in mind. Every feature should be understandable by a first-time
user. Every error message should tell them what to do next. Every default
should be the safe choice.

---

## Dev environment

**Prerequisites:** Rust 1.77+, Node.js 20+ (24 recommended), npm.

```bash
git clone https://github.com/elementmerc/Stegcore.git
cd Stegcore

# Install frontend dependencies
cd frontend && npm install && cd ..

# Run in development mode (GUI + hot reload)
cargo tauri dev

# Or build release binaries
cargo build --release
```

**Linux dependencies:**
```bash
sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libglib2.0-dev
```

**Node.js version (this machine):**
```bash
export NVM_DIR="$HOME/.nvm" && source "$NVM_DIR/nvm.sh" && nvm use 24
```

---

## Project structure

```
Cargo.toml              — workspace root
crates/core/            — public library (errors, wrappers, keyfile, utils, verses)
crates/cli/             — CLI binary (clap v4, completions, config)
src-tauri/              — Tauri v2 app shell + IPC commands
frontend/               — React + TypeScript + Vite + Tailwind
  src/components/       — reusable UI (DropZone, ScoreCard, EntropyBar, etc.)
  src/components/steganalysis/ — analysis dashboard charts (canvas-based)
  src/routes/           — page components (Home, Embed, Extract, Analyse, Learn)
  src/lib/              — stores (Zustand), IPC wrappers, theme, sound, toast
libstegcore/            — private engine (not in this repo)
scripts/                — private test scripts (not in public repo)
dist/                   — packaging (Homebrew, winget, Kali, SourceForge)
```

---

## Code style

**Rust:**
- `cargo fmt --all` before every commit
- `cargo clippy --workspace -- -D warnings` must pass
- British English in all user-facing strings and comments

**TypeScript:**
- `npx tsc --noEmit` from `frontend/` must pass
- Inline styles using `--ui-*` / `--sc-*` CSS variables
- CSS hover classes (not inline JS style mutations)
- `React.memo()` for heavy sub-components
- All canvas chart animations use `requestAnimationFrame` loops, not CSS

---

## Architecture rules

- **No modals.** Toasts only for notifications.
- **Two repos:** `stegcore` (public, AGPL) + `libstegcore` (private).
  Do not suggest merging them.
- **All Tauri commands** must be `async` with `spawn_blocking` for
  CPU-heavy work to prevent UI freezes.
- **UX impact awareness:** Every code change must be evaluated for
  its impact on the user interface and workflow. Backend changes can
  affect response times, error messages, and data shapes.
- **Completely offline.** No network calls, no telemetry, no external
  font loading. Everything must be bundled.
- **Privacy-first.** Config dir created with 0o700. Passphrases cleared
  from memory after use. No logging of sensitive data.

---

## Testing

```bash
# Run all Rust tests
cargo test --workspace

# With engine (if libstegcore is available)
cargo test --workspace --features engine

# TypeScript type check
cd frontend && npx tsc --noEmit

# Format check
cargo fmt --all --check

# System health check
cargo run -p stegcore-cli -- doctor
```

---

## Licence

Stegcore is licensed under AGPL-3.0-or-later. Contributions are accepted
under the same licence.

Contact: ops@themalwarefiles.com

---

## Pull requests

- One logical change per PR
- Include a description of what changed and why
- Consider UX impact — present pros and cons of significant changes
- Ensure all checks pass (`clippy`, `fmt`, `tsc`)
- Test in both dark and light themes
- Respect the `prefers-reduced-motion` setting
