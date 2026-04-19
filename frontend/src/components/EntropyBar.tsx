// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { memo, useMemo } from 'react'

interface EntropyBarProps {
  value: string
  className?: string
}

// ── Common password blacklist (top patterns) ──────────────────────────────

const COMMON = new Set([
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  '1234567890', 'qwerty', 'abc123', 'letmein', 'admin', 'welcome',
  'monkey', 'master', 'dragon', 'login', 'princess', 'football',
  'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman', 'access',
  'hello', 'charlie', 'donald', '654321', 'passw0rd', 'qwerty123',
])

// ── Passphrase strength scoring ───────────────────────────────────────────

function scorePassphrase(s: string): number {
  if (!s.length) return 0

  // Instant fail: common passwords
  if (COMMON.has(s.toLowerCase())) return 5

  let score = 0

  // Length is the strongest factor
  if (s.length >= 8)  score += 15
  if (s.length >= 12) score += 15
  if (s.length >= 16) score += 15
  if (s.length >= 20) score += 10
  if (s.length >= 28) score += 10

  // Character class diversity
  const hasLower   = /[a-z]/.test(s)
  const hasUpper   = /[A-Z]/.test(s)
  const hasDigit   = /\d/.test(s)
  const hasSymbol  = /[^a-zA-Z0-9]/.test(s)
  const classes = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length
  score += classes * 8

  // Penalise all-same-case or all-digits
  if (s.length > 4 && classes <= 1) score -= 15

  // Penalise sequential/repeated characters
  let repeats = 0
  for (let i = 1; i < s.length; i++) {
    if (s[i] === s[i - 1]) repeats++
  }
  if (repeats > s.length * 0.4) score -= 15

  // Bonus for unique characters relative to length
  const unique = new Set(s).size
  if (unique >= 10) score += 5
  if (unique >= 15) score += 5

  return Math.max(0, Math.min(100, score))
}

// ── Component ─────────────────────────────────────────────────────────────

const SEGMENTS = 10

export const EntropyBar = memo(function EntropyBar({ value, className = '' }: EntropyBarProps) {
  const { filled, tier, barColor } = useMemo(() => {
    const pct = scorePassphrase(value)
    const t = pct < 30 ? 'Weak' : pct < 60 ? 'Fair' : 'Strong'
    const f = Math.round((pct / 100) * SEGMENTS)
    const c =
      t === 'Strong' ? 'var(--ui-success)' :
      t === 'Fair'   ? 'var(--ui-warn)' :
                       'var(--ui-danger)'
    return { filled: f, tier: t, barColor: c }
  }, [value])

  if (!value) return null

  return (
    <div className={className}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
        <span style={{ fontSize: 11, color: 'var(--ui-text2)' }}>Passphrase strength</span>
        <span style={{ fontSize: 11, color: barColor, fontWeight: 600 }}>{tier}</span>
      </div>
      <div style={{ display: 'flex', gap: 3 }}>
        {Array.from({ length: SEGMENTS }, (_, i) => (
          <div
            key={i}
            style={{
              flex: 1,
              height: 4,
              borderRadius: 2,
              background: i < filled ? barColor : 'var(--ui-border2)',
              transition: 'background var(--sc-t-base)',
            }}
          />
        ))}
      </div>
    </div>
  )
})
