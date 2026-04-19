// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { BookOpen } from 'lucide-react'
import { useFooter } from '../App'

export default function Learn() {
  useFooter({
    backLabel: 'Home',
    backAction: () => { window.history.back() },
  })

  return (
    <div style={{ padding: '48px 40px 32px', flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <span style={{
          display: 'block',
          fontSize: 11,
          fontFamily: "'Space Mono', monospace",
          color: 'var(--ui-text2)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase' as const,
          marginBottom: 8,
        }}>
          Guide
        </span>
        <h2 style={{ fontSize: 28, fontWeight: 600, color: 'var(--ui-text)', letterSpacing: '-0.02em', marginBottom: 6 }}>
          Learn Stegcore
        </h2>
        <p style={{ fontSize: 13, color: 'var(--ui-text2)', lineHeight: 1.6 }}>
          Understand steganography, encryption, and how to protect your data.
        </p>
      </div>

      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '3rem 2rem',
        borderRadius: 'var(--sc-radius-card)',
        border: '1px solid var(--ui-border)',
        background: 'var(--ui-surface)',
        textAlign: 'center',
      }}>
        <BookOpen size={40} strokeWidth={1.2} style={{ color: 'var(--ui-text2)', marginBottom: 16 }} />
        <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--ui-text)', marginBottom: 8 }}>
          Coming soon
        </h3>
        <p style={{ fontSize: 13, color: 'var(--ui-text2)', maxWidth: 360, lineHeight: 1.65 }}>
          Interactive guides covering threat models, choosing the right cipher,
          when to use deniable mode, and understanding steganalysis results.
        </p>
      </div>
    </div>
  )
}
