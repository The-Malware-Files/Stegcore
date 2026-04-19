// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

interface ToggleProps {
  checked: boolean
  onChange: (v: boolean) => void
  label?: string
  description?: string
  disabled?: boolean
  className?: string
}

export function Toggle({ checked, onChange, label, description, disabled = false, className = '' }: ToggleProps) {
  const id = label ? `toggle-${label.replace(/\s+/g, '-').toLowerCase()}` : undefined

  return (
    <div className={`flex items-start gap-3 ${className}`}>
      <button
        id={id}
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        onClick={() => !disabled && onChange(!checked)}
        style={{
          flexShrink: 0,
          width: 36,
          height: 20,
          borderRadius: 10,
          border: 'none',
          cursor: disabled ? 'not-allowed' : 'pointer',
          opacity: disabled ? 0.45 : 1,
          background: checked ? 'var(--ui-accent)' : 'var(--ui-border)',
          position: 'relative',
          transition: 'background var(--sc-t-fast)',
          padding: 0,
        }}
      >
        <span
          style={{
            position: 'absolute',
            top: 2,
            left: checked ? 18 : 2,
            width: 16,
            height: 16,
            borderRadius: '50%',
            background: '#ffffff',
            transition: 'left var(--sc-t-fast)',
            boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
          }}
        />
      </button>

      {(label || description) && (
        <div style={{ userSelect: 'none' }}>
          {label && (
            <label
              htmlFor={id}
              style={{
                display: 'block',
                fontSize: 14,
                fontWeight: 500,
                color: 'var(--ui-text)',
                cursor: disabled ? 'default' : 'pointer',
                lineHeight: 1.4,
              }}
            >
              {label}
            </label>
          )}
          {description && (
            <p style={{ fontSize: 12, color: 'var(--ui-text2)', marginTop: 2, lineHeight: 1.5 }}>
              {description}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
