// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import type { LucideIcon } from 'lucide-react'

interface IconButtonProps {
  icon: LucideIcon
  label: string
  onClick: () => void
  variant?: 'ghost' | 'filled'
  size?: 'sm' | 'md' | 'lg'
  disabled?: boolean
  active?: boolean
  className?: string
}

const SIZE_MAP = { sm: 16, md: 20, lg: 24 } as const
const PAD_MAP  = { sm: 6,  md: 8,  lg: 10 } as const

export function IconButton({
  icon: Icon,
  label,
  onClick,
  variant = 'ghost',
  size = 'md',
  disabled = false,
  active = false,
  className = '',
}: IconButtonProps) {
  const iconSize = SIZE_MAP[size]
  const padding  = PAD_MAP[size]

  const filled = variant === 'filled'

  return (
    <button
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding,
        borderRadius: 'var(--sc-radius-btn)',
        border: 'none',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.4 : 1,
        background: filled
          ? 'var(--ui-accent)'
          : active
            ? 'color-mix(in srgb, var(--ui-accent) 15%, transparent)'
            : 'transparent',
        color: filled ? '#ffffff' : active ? 'var(--ui-accent)' : 'var(--ui-muted)',
        transition: 'background var(--sc-t-fast), color var(--sc-t-fast)',
      }}
      onMouseEnter={(e) => {
        if (disabled) return
        const el = e.currentTarget as HTMLButtonElement
        el.style.background = filled
          ? 'color-mix(in srgb, var(--ui-accent) 90%, white 10%)'
          : 'color-mix(in srgb, var(--ui-accent) 12%, transparent)'
        el.style.color = filled ? '#ffffff' : 'var(--ui-text)'
      }}
      onMouseLeave={(e) => {
        const el = e.currentTarget as HTMLButtonElement
        el.style.background = filled
          ? 'var(--ui-accent)'
          : active
            ? 'color-mix(in srgb, var(--ui-accent) 15%, transparent)'
            : 'transparent'
        el.style.color = filled ? '#ffffff' : active ? 'var(--ui-accent)' : 'var(--ui-muted)'
      }}
      className={className}
    >
      <Icon size={iconSize} strokeWidth={1.8} />
    </button>
  )
}
