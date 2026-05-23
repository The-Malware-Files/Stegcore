// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Each landing-page card navigates to the matching route. Browser-back
// returns to Home with no state corruption. Catches React-Router config
// regressions and lazy-loaded route load failures.

import { test, expect } from '@playwright/test'

const ROUTES = [
  { name: 'Embed',   path: '/embed'   },
  { name: 'Extract', path: '/extract' },
  { name: 'Analyse', path: '/analyse' },
  { name: 'Learn',   path: '/learn'   },
] as const

for (const { name, path } of ROUTES) {
  test(`navigates to ${name} and back`, async ({ page }) => {
    await page.goto('/')
    const target = page.getByRole('button', { name: new RegExp(`^${name}\\b`) })
    await target.waitFor({ state: 'visible', timeout: 15_000 })
    await target.click()
    await expect(page).toHaveURL(new RegExp(`${path}$`))

    // The error boundary is the page-level crash signal.
    await expect(page.getByText('Something went wrong')).toHaveCount(0)

    // Back to home — page must still be alive and show the cards again.
    await page.goBack()
    await expect(page).toHaveURL(/\/$/)
    await expect(page.getByRole('button', { name: /^Embed\b/ })).toBeVisible()
  })
}
