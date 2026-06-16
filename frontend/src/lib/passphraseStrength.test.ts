// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { describe, it, expect } from 'vitest'
import { zxcvbnPercent, scoreWithZxcvbn } from './passphraseStrength'

describe('zxcvbnPercent', () => {
  it('maps the 0-4 score band onto the 0-100 scale', () => {
    expect(zxcvbnPercent(0)).toBe(8)
    expect(zxcvbnPercent(1)).toBe(30)
    expect(zxcvbnPercent(2)).toBe(55)
    expect(zxcvbnPercent(3)).toBe(80)
    expect(zxcvbnPercent(4)).toBe(100)
  })

  it('clamps out-of-range scores', () => {
    expect(zxcvbnPercent(-2)).toBe(8)
    expect(zxcvbnPercent(9)).toBe(100)
  })
})

// These drive the real zxcvbn-ts library (pure JS, loads fine under jsdom), so
// they validate the actual lazy-load + scoring integration rather than a mock.
describe('scoreWithZxcvbn', () => {
  it('returns 0 for an empty value without loading the library', async () => {
    await expect(scoreWithZxcvbn('')).resolves.toBe(0)
  })

  it('rates a known-bad password in the lowest band', async () => {
    // "password" is in zxcvbn's dictionary, so score 0 -> 8.
    await expect(scoreWithZxcvbn('password')).resolves.toBe(8)
  })

  it('rates a long random-ish passphrase in a high band', async () => {
    const strong = await scoreWithZxcvbn('7xQ!vue-9Lph_zRm24Kd')
    expect(strong).toBeGreaterThanOrEqual(80)
  })

  it('always resolves within the 0-100 range', async () => {
    const v = await scoreWithZxcvbn('moderate-pass-2026')
    expect(v).toBeGreaterThanOrEqual(0)
    expect(v).toBeLessThanOrEqual(100)
  })
})
