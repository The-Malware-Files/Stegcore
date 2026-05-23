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
// Run locally:
//   cd frontend
//   npx tauri build --debug          # build the binary once
//   npx tauri-driver --port 4444 &   # start the driver
//   npx wdio run wdio.conf.ts
//
// On CI the `tauri-e2e` job does this orchestration; see
// .github/workflows/ci.yml.

import type { Options } from '@wdio/types'
import path from 'node:path'

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

export const config: Options.Testrunner = {
  runner: 'local',
  framework: 'mocha',
  specs: ['./e2e-tauri/**/*.spec.ts'],
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
      } as unknown as object,
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
  // Per-test setup: we don't reset Tauri state between specs because
  // re-launching the binary is expensive. Tests should be order-
  // independent and clean up their own side effects.
  autoCompileOpts: {
    autoCompile: true,
    tsNodeOpts: {
      project: './tsconfig.app.json',
      transpileOnly: true,
    },
  },
}
