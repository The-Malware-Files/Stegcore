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
import {
  scorePassphrase,
  passphraseTier,
  filledSegments,
  tierFromScore,
  segmentsFromScore,
  SEGMENTS,
} from './passphrase'

describe('scorePassphrase', () => {
  it('returns 0 for empty input', () => {
    expect(scorePassphrase('')).toBe(0)
  })

  it('never decreases as a single character class is extended', () => {
    // The v4.0.2 fix: penalties are score caps, not subtractions, so adding
    // characters can never drop the score (which previously read as broken).
    let prev = -1
    for (let n = 1; n <= 16; n++) {
      const score = scorePassphrase('a'.repeat(n))
      expect(score).toBeGreaterThanOrEqual(prev)
      prev = score
    }
  })

  it('caps a single character class at 30', () => {
    // 16 lowercase letters: lots of length + unique bonus, but one class.
    expect(scorePassphrase('abcdefghijklmnop')).toBe(30)
  })

  it('caps a common password at 10, case-insensitively', () => {
    expect(scorePassphrase('password')).toBe(10)
    expect(scorePassphrase('Password')).toBe(10)
  })

  it('caps a mostly-repeated string at 30', () => {
    expect(scorePassphrase('aaaaaaaaaaaaaaaa')).toBeLessThanOrEqual(30)
  })

  it('rates a long mixed-class passphrase as strong', () => {
    expect(scorePassphrase('Tr0ub4dour&3xpl0it!2026')).toBeGreaterThanOrEqual(60)
  })

  it('stays within the 0..100 range', () => {
    const s = scorePassphrase('Tr0ub4dour&3xpl0it!2026-with-much-more-entropy-XYZ')
    expect(s).toBeGreaterThanOrEqual(0)
    expect(s).toBeLessThanOrEqual(100)
  })
})

describe('passphraseTier', () => {
  it('is Weak for empty and common input', () => {
    expect(passphraseTier('')).toBe('Weak')
    expect(passphraseTier('password')).toBe('Weak')
  })

  it('is Fair in the middle band', () => {
    // Single long class is capped at exactly 30, which is the Fair floor.
    expect(passphraseTier('abcdefghijklmnop')).toBe('Fair')
  })

  it('is Strong for a long mixed-class passphrase', () => {
    expect(passphraseTier('Tr0ub4dour&3xpl0it!2026')).toBe('Strong')
  })
})

describe('filledSegments', () => {
  it('is 0 only for empty input', () => {
    expect(filledSegments('')).toBe(0)
  })

  it('is at least 1 for any non-empty input (never blank)', () => {
    for (const s of ['a', 'aa', 'aaaa', 'aabbcc', 'password', '1', '!']) {
      expect(filledSegments(s)).toBeGreaterThanOrEqual(1)
    }
  })

  it('is non-decreasing as a class is extended and never exceeds SEGMENTS', () => {
    let prev = 0
    for (let n = 1; n <= 16; n++) {
      const f = filledSegments('a'.repeat(n))
      expect(f).toBeGreaterThanOrEqual(prev)
      expect(f).toBeLessThanOrEqual(SEGMENTS)
      prev = f
    }
  })

  it('fills all segments for a maximal passphrase', () => {
    expect(filledSegments('Tr0ub4dour&3xpl0it!2026')).toBe(SEGMENTS)
  })
})

describe('tierFromScore', () => {
  it('maps the three bands by score', () => {
    expect(tierFromScore(0)).toBe('Weak')
    expect(tierFromScore(29)).toBe('Weak')
    expect(tierFromScore(30)).toBe('Fair')
    expect(tierFromScore(59)).toBe('Fair')
    expect(tierFromScore(60)).toBe('Strong')
    expect(tierFromScore(100)).toBe('Strong')
  })
})

describe('segmentsFromScore', () => {
  it('floors at 1 for any non-zero score and scales to SEGMENTS', () => {
    expect(segmentsFromScore(0)).toBe(1) // floored, the caller guards empty input
    expect(segmentsFromScore(5)).toBe(1)
    expect(segmentsFromScore(50)).toBe(5)
    expect(segmentsFromScore(100)).toBe(SEGMENTS)
  })
})
