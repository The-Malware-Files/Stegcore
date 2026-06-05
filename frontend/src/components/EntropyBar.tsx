// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { memo, useMemo } from 'react'
import { SEGMENTS, passphraseTier, filledSegments } from '../lib/passphrase'

interface EntropyBarProps {
  value: string
  className?: string
}

export const EntropyBar = memo(function EntropyBar({ value, className = '' }: EntropyBarProps) {
  const { filled, tier, barColor } = useMemo(() => {
    const t = passphraseTier(value)
    const f = filledSegments(value)
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
