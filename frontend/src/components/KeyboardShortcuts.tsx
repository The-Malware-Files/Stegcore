// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useEffect } from 'react'
import { X } from 'lucide-react'

interface KeyboardShortcutsProps {
  open: boolean
  onClose: () => void
}

const SHORTCUTS: [string, string][] = [
  ['E', 'Embed'],
  ['X', 'Extract'],
  ['A', 'Analyse'],
  ['L', 'Learn'],
  ['R', 'Reload full analysis'],
  ['?', 'Show shortcuts'],
  ['Esc', 'Close / Go back'],
]

export function KeyboardShortcuts({ open, onClose }: KeyboardShortcutsProps) {
  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === '?') {
        e.preventDefault()
        onClose()
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 8000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0,0,0,0.4)',
        backdropFilter: 'blur(4px)',
        animation: 'kbd-fade-in 0.15s ease-out',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: 'var(--ui-surface)',
          border: '1px solid var(--ui-border)',
          borderRadius: 12,
          padding: '24px 28px',
          minWidth: 280,
          maxWidth: 360,
          boxShadow: '0 8px 32px rgba(0,0,0,0.2)',
          animation: 'kbd-scale-in 0.2s ease-out',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: 'var(--ui-text)', margin: 0 }}>
            Keyboard shortcuts
          </h3>
          <button
            onClick={onClose}
            aria-label="Close"
            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--ui-text2)', padding: 0, display: 'flex' }}
          >
            <X size={16} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {SHORTCUTS.map(([key, desc]) => (
            <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 13, color: 'var(--ui-text2)' }}>{desc}</span>
              <kbd style={{
                fontSize: 11,
                fontFamily: "'Space Mono', monospace",
                fontWeight: 600,
                padding: '3px 8px',
                borderRadius: 5,
                border: '1px solid var(--ui-border)',
                background: 'var(--ui-bg)',
                color: 'var(--ui-text)',
                letterSpacing: '0.05em',
                minWidth: 28,
                textAlign: 'center',
              }}>
                {key}
              </kbd>
            </div>
          ))}
        </div>
      </div>

      <style>{`
        @keyframes kbd-fade-in {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
        @keyframes kbd-scale-in {
          from { opacity: 0; transform: scale(0.95); }
          to   { opacity: 1; transform: scale(1); }
        }
      `}</style>
    </div>
  )
}
