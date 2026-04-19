// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { memo } from 'react'
import { Star } from 'lucide-react'

interface ScoreCardProps {
  score: number | null
  loading?: boolean
  className?: string
}

type ScoreTier = { label: string; color: string; showStar: boolean }

function tier(score: number): ScoreTier {
  if (score >= 0.75) return { label: 'Excellent', color: 'var(--ui-success)',  showStar: true }
  if (score >= 0.50) return { label: 'Good',      color: 'var(--ui-accent)',   showStar: false }
  if (score >= 0.25) return { label: 'Fair',       color: 'var(--ui-warn)',    showStar: false }
  return               { label: 'Poor',       color: 'var(--ui-danger)',   showStar: false }
}

export const ScoreCard = memo(function ScoreCard({ score, loading = false, className = '' }: ScoreCardProps) {
  if (loading) {
    return (
      <div
        className={className}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 12px',
          borderRadius: 20,
          background: 'var(--ui-border)',
          height: 28,
          width: 100,
          animation: 'pulse 1.2s ease-in-out infinite',
        }}
      />
    )
  }

  if (score === null) return null

  const { label, color, showStar } = tier(score)
  const pct = Math.round(score * 100)

  return (
    <div
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 12px',
        borderRadius: 20,
        background: `color-mix(in srgb, ${color} 18%, var(--ui-surface))`,
        border: `1px solid color-mix(in srgb, ${color} 40%, transparent)`,
        color,
        fontSize: 13,
        fontWeight: 500,
      }}
    >
      {showStar && <Star size={13} fill="currentColor" strokeWidth={0} />}
      <span>{label}</span>
      <span style={{ opacity: 0.75 }}>{pct}%</span>
    </div>
  )
})
