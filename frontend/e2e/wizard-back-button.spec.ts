// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Wizard back-button discipline. The engineering baseline's robustness
// mandate demands graceful state on every navigation. If the back
// button drops the user into a blank page or eats their already-entered
// data, that's a bug worth catching here rather than in user reports.

import { test, expect } from '@playwright/test'

test.describe('embed wizard', () => {
  test('back from /embed returns to home', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('button', { name: /^Embed\b/ }).click()
    await expect(page).toHaveURL(/embed$/)

    // The wizard layout always provides a left-side back action. Use
    // the browser back as the canonical user gesture — keyboard /
    // mouse-button-4 both end up here.
    await page.goBack()
    await expect(page).toHaveURL(/\/$/)
    await expect(page.getByRole('button', { name: /^Embed\b/ })).toBeVisible()
  })
})

test.describe('extract wizard', () => {
  test('back from /extract returns to home', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('button', { name: /^Extract\b/ }).click()
    await expect(page).toHaveURL(/extract$/)
    await page.goBack()
    await expect(page).toHaveURL(/\/$/)
    await expect(page.getByRole('button', { name: /^Extract\b/ })).toBeVisible()
  })
})

test.describe('analyse wizard', () => {
  test('back from /analyse returns to home', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('button', { name: /^Analyse\b/ }).click()
    await expect(page).toHaveURL(/analyse$/)
    await page.goBack()
    await expect(page).toHaveURL(/\/$/)
    await expect(page.getByRole('button', { name: /^Analyse\b/ })).toBeVisible()
  })
})
