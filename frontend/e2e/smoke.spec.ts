// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Smoke test — the first thing CI checks. If the home route doesn't
// render, nothing else is worth running.

import { test, expect } from '@playwright/test'

// Each home card is a <button> whose accessible name is its heading
// text ("Embed", "Extract", …). Role-based selectors stay robust to
// title-vs-text refactoring; we wait the splash out (≈3.5s) by using
// a generous toBeVisible timeout rather than racing the animation.
const card = (page: import('@playwright/test').Page, name: string) =>
  page.getByRole('button', { name: new RegExp(`^${name}\\b`) })

test.describe('home route', () => {
  test('renders the four primary actions', async ({ page }) => {
    await page.goto('/')
    await expect(card(page, 'Embed')).toBeVisible({ timeout: 15_000 })
    await expect(card(page, 'Extract')).toBeVisible()
    await expect(card(page, 'Analyse')).toBeVisible()
    await expect(card(page, 'Learn')).toBeVisible()
  })

  test('no console errors on cold load', async ({ page }) => {
    const errors: string[] = []
    page.on('console', msg => {
      if (msg.type() === 'error') errors.push(msg.text())
    })
    page.on('pageerror', err => errors.push(`pageerror: ${err.message}`))
    await page.goto('/')
    await card(page, 'Embed').waitFor({ state: 'visible', timeout: 15_000 })
    // The error boundary text is the canonical "render crashed" signal.
    await expect(page.getByText('Something went wrong')).toHaveCount(0)
    // Allow benign React dev-mode warnings; flag only red errors.
    const fatal = errors.filter(e =>
      !/DevTools|favicon|sourcemap|HMR/i.test(e)
    )
    expect(fatal, `unexpected console errors:\n${fatal.join('\n')}`).toEqual([])
  })
})
