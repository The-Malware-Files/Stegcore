// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// Passphrase strength scoring, kept out of the component file so it can be
// unit-tested directly and shared without tripping fast-refresh.

// ── Common password blacklist (top patterns) ──────────────────────────────

const COMMON = new Set([
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  '1234567890', 'qwerty', 'abc123', 'letmein', 'admin', 'welcome',
  'monkey', 'master', 'dragon', 'login', 'princess', 'football',
  'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman', 'access',
  'hello', 'charlie', 'donald', '654321', 'passw0rd', 'qwerty123',
])

export const SEGMENTS = 10

// Weakness is expressed as score *caps*, never as subtractions. A flat
// subtraction can make the score (and the visible bar) drop as the user types
// more characters, which reads as broken. Caps keep the score monotonic: as a
// passphrase grows it rises toward, then sits at, the relevant ceiling.
export function scorePassphrase(s: string): number {
  if (!s.length) return 0

  // Positive contributions only (each non-decreasing as the passphrase grows).
  let score = 0

  // Length is the strongest factor.
  if (s.length >= 8)  score += 15
  if (s.length >= 12) score += 15
  if (s.length >= 16) score += 15
  if (s.length >= 20) score += 10
  if (s.length >= 28) score += 10

  // Character class diversity.
  const hasLower  = /[a-z]/.test(s)
  const hasUpper  = /[A-Z]/.test(s)
  const hasDigit  = /\d/.test(s)
  const hasSymbol = /[^a-zA-Z0-9]/.test(s)
  const classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length
  score += classes * 8

  // Bonus for unique characters relative to length.
  const unique = new Set(s).size
  if (unique >= 10) score += 5
  if (unique >= 15) score += 5

  // Weakness caps (applied as ceilings, not subtractions).
  if (classes <= 1) score = Math.min(score, 30)

  let repeats = 0
  for (let i = 1; i < s.length; i++) {
    if (s[i] === s[i - 1]) repeats++
  }
  if (repeats > s.length * 0.4) score = Math.min(score, 30)

  // Common passwords are always weak, but still render a (red) segment.
  if (COMMON.has(s.toLowerCase())) score = Math.min(score, 10)

  return Math.max(0, Math.min(100, score))
}

export type PassphraseTier = 'Weak' | 'Fair' | 'Strong'

export function passphraseTier(value: string): PassphraseTier {
  const pct = scorePassphrase(value)
  return pct < 30 ? 'Weak' : pct < 60 ? 'Fair' : 'Strong'
}

/** Number of coloured segments to render for a passphrase (0 only when empty). */
export function filledSegments(value: string): number {
  if (!value) return 0
  const pct = scorePassphrase(value)
  // Floor at 1 so a non-empty passphrase always shows at least one segment;
  // otherwise a low-but-nonzero score rounds to 0 and the bar looks blank.
  return Math.max(1, Math.round((pct / 100) * SEGMENTS))
}
