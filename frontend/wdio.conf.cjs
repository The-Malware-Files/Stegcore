// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// WebdriverIO configuration for the Tauri-bound side of Track D.
//
// What this exercises that the Vite Playwright suite does not:
//
//   - The actual built Tauri binary loading WebKitGTK (Linux), so all
//     IPC paths (invoke, plugin-fs, plugin-dialog) are real.
//   - First-run detection through the Tauri-side `is_first_run` command.
//   - Bundle / plugin permission boundaries.
//
// Constraints (these are upstream, not ours; see project_v4_release_
// sprint_2.md for the survey):
//
//   - Linux only. tauri-driver does not support macOS yet (open
//     feature request).
//   - WebdriverIO 8 only. WDIO 9 fails because tauri-driver 2.0.6
//     does not strip BiDi capabilities when forwarding to
//     WebKitWebDriver. Open upstream bug.
//   - Optional in CI — does not block release. Findings here open
//     tech-debt entries; the Vite-Playwright suite is the gate.
//
// Why .cjs and not .ts: the frontend package.json declares
// `"type": "module"`, so WDIO's ts-node loader transpiles to CommonJS
// and the surrounding ESM scope rejects `module.exports` (T-31).
// CommonJS dodges the loader fight; specs are plain .js for the same
// reason. The config is small and not type-heavy.
//
// Run locally (from the repo root):
//   cargo build --bin stegcore-gui          # outputs target/debug/stegcore-gui
//   tauri-driver --port 4444 &              # start the driver
//   cd frontend && npx wdio run wdio.conf.cjs
//
// On CI the `gui-e2e-tauri` job does this orchestration; see
// .github/workflows/ci.yml.

const fs = require('node:fs')
const path = require('node:path')

// Resolve the built binary. Stegcore is a Cargo workspace, so
// `cargo build --bin stegcore-gui` (and `tauri build --debug` when run
// from a workspace member) outputs to the workspace `target/debug/`
// directory, not `src-tauri/target/debug/`. The binary name is
// `stegcore-gui` per src-tauri/Cargo.toml.
//
// CARGO_TARGET_DIR override is honoured if set (some CI configs set
// it to share caches). Fallback order:
//   1. $CARGO_TARGET_DIR/debug/<bin>
//   2. <repo-root>/target/debug/<bin>
//   3. <repo-root>/src-tauri/target/debug/<bin>  (legacy single-crate)
const BIN_NAME = process.platform === 'win32' ? 'stegcore-gui.exe' : 'stegcore-gui'
const REPO_ROOT = path.resolve(__dirname, '..')

const candidates = [
  process.env.CARGO_TARGET_DIR
    ? path.join(process.env.CARGO_TARGET_DIR, 'debug', BIN_NAME)
    : null,
  path.join(REPO_ROOT, 'target', 'debug', BIN_NAME),
  path.join(REPO_ROOT, 'src-tauri', 'target', 'debug', BIN_NAME),
].filter(Boolean)

const TAURI_BIN = candidates.find((p) => fs.existsSync(p)) ?? candidates[1]

exports.config = {
  runner: 'local',
  framework: 'mocha',
  specs: ['./e2e-tauri/**/*.spec.js'],
  // tauri-driver listens on 4444 by default.
  hostname: '127.0.0.1',
  port: 4444,
  capabilities: [
    {
      // The webview, not chromium: WebKitGTK on Linux, WebView2 on
      // Windows. tauri-driver translates these to the platform driver.
      browserName: 'wry',
      // Required by tauri-driver — points at the built application.
      'tauri:options': {
        application: TAURI_BIN,
      },
    },
  ],
  logLevel: 'warn',
  bail: 0,
  // Tauri startup is slow on first launch — 30s leaves headroom.
  waitforTimeout: 30_000,
  connectionRetryTimeout: 60_000,
  connectionRetryCount: 2,
  mochaOpts: {
    ui: 'bdd',
    timeout: 60_000,
  },
  reporters: ['spec'],
}
