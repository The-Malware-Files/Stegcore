// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Playwright configuration for Track D of the v4.0.1 adversarial gate.
//
// We target the Vite dev server, not the full Tauri runtime. Reason:
// tauri-driver v2.0.6 + WebdriverIO 9 is upstream-broken (BiDi capability
// forwarding) and has no macOS support. The Vite dev path covers the
// React state machine, the wizard back-button discipline, the route
// transitions and the error boundary — which is where GUI bugs actually
// live. The Tauri IPC boundary is exercised by Rust integration tests
// instead.
//
// Tests run on Linux only in CI; macOS + Windows runners stay focused on
// the cross-platform Rust matrix. Locally a developer can re-run the
// suite with `npm run e2e`.

import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // One retry on CI to swallow occasional dev-server cold-start flakes.
  // Locally we want any flake to surface so we can fix it.
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',

  use: {
    baseURL: 'http://127.0.0.1:5173',
    trace: 'on-first-retry',
    // The app reads localStorage/IndexedDB heavily for settings; reset
    // between tests so one suite's state never leaks into another.
    storageState: { cookies: [], origins: [] },
  },

  // Bring up the Vite dev server. Reuse on local runs so iteration is
  // fast; force a fresh start on CI so the server state is deterministic.
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 5173',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
})
