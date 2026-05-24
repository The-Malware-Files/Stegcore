// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Adversarial monkey-clicker — Track D of the adversarial gate. Random
// click N visible interactive elements per route. The page must not:
//
//   - render the error boundary ("Something went wrong")
//   - log uncaught page errors
//   - leave the document in a state where Home cards are unreachable
//
// The point isn't pretty assertions; it's that a drunk user mashing
// the UI doesn't blank-screen the app. Findings here become regression
// tests in their own files.

import { test, expect } from '@playwright/test'

const ROUTES = ['/', '/embed', '/extract', '/analyse', '/learn'] as const
const CLICKS_PER_ROUTE = 25
const SEED = 0xC0FFEE

// Deterministic PRNG so the same monkey-test produces the same sequence
// across runs — flakes can be reproduced from the log alone.
class Lcg {
  constructor(private state: number) {}
  next(): number {
    this.state = (Math.imul(this.state, 1664525) + 1013904223) | 0
    return (this.state >>> 0) / 0x100000000
  }
  pick<T>(arr: T[]): T {
    return arr[Math.floor(this.next() * arr.length)]
  }
}

// Tauri-bridge errors raised when an Tauri-bound click handler runs in
// the Vite-only browser (no window.__TAURI_INTERNALS__). These are
// expected here and out of scope for the GUI-chaos check; the Tauri
// integration job (when added) exercises that path properly.
const TAURI_IPC_NOISE = /transformCallback|__TAURI_INTERNALS__|__TAURI_INVOKE_KEY__|window\.__TAURI/

for (const route of ROUTES) {
  test(`drunk-user monkey on ${route}`, async ({ page }) => {
    const rng = new Lcg(SEED)
    const pageErrors: string[] = []
    page.on('pageerror', err => {
      if (TAURI_IPC_NOISE.test(err.message)) return
      pageErrors.push(err.message)
    })

    await page.goto(route)
    // Allow lazy-loaded route to settle.
    await page.waitForLoadState('networkidle', { timeout: 10_000 })

    for (let i = 0; i < CLICKS_PER_ROUTE; i++) {
      // Collect currently-visible clickable elements every iteration so
      // we react to whatever the previous click revealed.
      const clickables = await page
        .locator('button:visible, a:visible, [role="button"]:visible')
        .all()

      if (clickables.length === 0) break

      const target = rng.pick(clickables)
      // Don't navigate out of the dev server — skip links to external
      // origins (rare, but Learn might add some).
      const href = await target.getAttribute('href').catch(() => null)
      if (href && /^https?:/i.test(href)) continue

      // The click can fail (element detached, modal closed, etc.). That
      // is fine; the point is the app survives, not that every click
      // lands. We do require no uncaught error to be raised.
      await target.click({ timeout: 1500, trial: false }).catch(() => undefined)

      // Crash signal check after each click — fail fast.
      const crashed = await page.getByText('Something went wrong').count()
      if (crashed > 0) {
        throw new Error(`error boundary fired on ${route} after click ${i}`)
      }
    }

    expect(pageErrors, `uncaught page errors on ${route}:\n${pageErrors.join('\n')}`)
      .toEqual([])
  })
}
