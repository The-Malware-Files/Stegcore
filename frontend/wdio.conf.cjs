// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
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
// Run locally:
//   cd frontend
//   npx tauri build --debug          # build the binary once
//   npx tauri-driver --port 4444 &   # start the driver
//   npx wdio run wdio.conf.cjs
//
// On CI the `gui-e2e-tauri` job does this orchestration; see
// .github/workflows/ci.yml.

const path = require('node:path')

// Resolve the built binary. tauri build --debug places it at
// src-tauri/target/debug/<binary-name>. The binary name is
// stegcore-gui per src-tauri/Cargo.toml.
const TAURI_BIN = path.resolve(
  __dirname,
  '..',
  'src-tauri',
  'target',
  'debug',
  process.platform === 'win32' ? 'stegcore-gui.exe' : 'stegcore-gui',
)

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
