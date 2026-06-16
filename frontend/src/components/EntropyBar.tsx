// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { memo, useState, useEffect } from 'react'
import { SEGMENTS, scorePassphrase, tierFromScore, segmentsFromScore } from '../lib/passphrase'
import { scoreWithZxcvbn } from '../lib/passphraseStrength'

interface EntropyBarProps {
  value: string
  className?: string
}

export const EntropyBar = memo(function EntropyBar({ value, className = '' }: EntropyBarProps) {
  // The heuristic renders synchronously as the instant fallback; the zxcvbn
  // refinement arrives asynchronously and is keyed to the value it scored, so a
  // stale result from a previous keystroke is never shown.
  const heuristic = scorePassphrase(value)
  const [refined, setRefined] = useState<{ value: string; pct: number } | null>(null)

  useEffect(() => {
    let cancelled = false
    scoreWithZxcvbn(value)
      .then((pct) => {
        if (!cancelled) setRefined({ value, pct })
      })
      .catch(() => {
        /* keep the heuristic score */
      })
    return () => {
      cancelled = true
    }
  }, [value])

  if (!value) return null

  const pct = refined && refined.value === value ? refined.pct : heuristic
  const tier = tierFromScore(pct)
  const filled = segmentsFromScore(pct)
  const barColor =
    tier === 'Strong' ? 'var(--ui-success)' :
    tier === 'Fair'   ? 'var(--ui-warn)' :
                        'var(--ui-danger)'

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
