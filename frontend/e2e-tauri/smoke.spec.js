// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Tauri-bound smoke test — Track D adversarial gate, IPC side.
//
// The Vite-Playwright suite exercises the React state machine without
// the Tauri IPC bridge. This suite covers the boundary that the other
// can't: the actual Tauri binary launches, the webview loads, the
// `is_first_run` command resolves, and the user can click through the
// installer (or skip to Home, depending on the saved state).

import { browser, $, expect } from '@wdio/globals'

describe('Tauri runtime — smoke', () => {
  it('window is open and accessible', async () => {
    // Wait for the WebView to be alive. waitUntil keeps polling until
    // the title settles to something non-empty (Tauri sets it via
    // tauri.conf.json before the SPA mounts).
    await browser.waitUntil(
      async () => (await browser.getTitle()).length > 0,
      { timeout: 30_000, timeoutMsg: 'Tauri window never reported a title' },
    )
    const title = await browser.getTitle()
    expect(title.length).toBeGreaterThan(0)
  })

  it('reaches the home cards (after dismissing any installer)', async () => {
    // First-run vs returning user: try the home cards first; if not
    // found, the installer is up — click Continue three times then
    // re-check. The Continue button is `inst-btn-primary`.
    const findHome = () => $('button=Embed')
    const hasHome = await findHome().isExisting()

    if (!hasHome) {
      for (let i = 0; i < 3; i++) {
        const cont = await $('.inst-btn-primary')
        if (!(await cont.isExisting())) break
        await cont.click()
        await browser.pause(300)
      }
    }

    const home = await findHome()
    await home.waitForExist({ timeout: 10_000 })
    await expect(home).toBeDisplayed()
  })
})
