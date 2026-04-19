// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

interface StepTrackProps {
  steps: string[]
  current: number // 1-based
  className?: string
}

export function StepTrack({ steps, current, className = '' }: StepTrackProps) {
  return (
    <div className={`flex items-center gap-0 ${className}`} role="list" aria-label="Progress">
      {steps.map((label, i) => {
        const num = i + 1
        const isActive = num === current
        const isDone = num < current

        const dotColor = isDone
          ? 'var(--ui-success)'
          : isActive
            ? 'var(--ui-accent)'
            : 'var(--ui-border2)'

        const labelColor = isDone
          ? 'var(--ui-success)'
          : isActive
            ? 'var(--ui-text)'
            : 'var(--ui-text2)'

        const lineColor = isDone ? 'var(--ui-success)' : 'var(--ui-border)'

        return (
          <div key={num} className="flex items-center" role="listitem">
            {/* Dot + label */}
            <div className="flex flex-col items-center gap-1">
              <div
                style={{
                  width: isActive ? 10 : 7,
                  height: isActive ? 10 : 7,
                  borderRadius: '50%',
                  backgroundColor: dotColor,
                  transition: 'all var(--sc-t-base)',
                  flexShrink: 0,
                }}
                aria-current={isActive ? 'step' : undefined}
              />
              <span
                style={{
                  fontSize: 10,
                  letterSpacing: '0.04em',
                  color: labelColor,
                  transition: 'color var(--sc-t-base)',
                  whiteSpace: 'nowrap',
                }}
              >
                {label}
              </span>
            </div>

            {/* Connector line */}
            {i < steps.length - 1 && (
              <div
                style={{
                  width: 36,
                  height: 1,
                  marginBottom: 14,
                  backgroundColor: lineColor,
                  transition: 'background-color var(--sc-t-base)',
                  flexShrink: 0,
                }}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
