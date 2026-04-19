// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Lock, Unlock, ScanSearch, BookOpen, type LucideIcon } from 'lucide-react'
import { useDragStore } from '../lib/stores/dragStore'
import { useEmbedStore } from '../lib/stores/embedStore'
import { useExtractStore } from '../lib/stores/extractStore'

const EMBED_EXTS = ['.png', '.bmp', '.jpg', '.jpeg', '.webp', '.wav']
const EXTRACT_EXTS = [...EMBED_EXTS, '.flac']

function extOf(name: string): string {
  return '.' + (name.split('.').pop() ?? '').toLowerCase()
}

// ── Column card ───────────────────────────────────────────────────────────

interface ColumnProps {
  Icon: LucideIcon
  title: string
  description: string
  shortcut: string
  // icon bg tint colour — solid dark with accent mix
  iconBg: string
  iconColor: string
  iconBorder: string
  onClick: () => void
  isLast?: boolean
}

function Column({ Icon, title, description, shortcut, iconBg, iconColor, iconBorder, onClick, isLast }: ColumnProps) {
  return (
    <button
      className="sc-home-col"
      onClick={onClick}
      style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 0,
        padding: '2rem',
        background: 'transparent',
        border: 'none',
        borderRight: isLast ? 'none' : '1px solid var(--ui-border)',
        cursor: 'pointer',
        textAlign: 'center',
        minHeight: '100%',
      }}
    >
      {/* Icon box */}
      <div
        className="sc-home-icon"
        style={{
          width: 64,
          height: 64,
          borderRadius: 16,
          background: iconBg,
          border: `1px solid ${iconBorder}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: 20,
          color: iconColor,
          transition: 'transform .18s ease',
        }}
      >
        <Icon size={26} strokeWidth={1.8} />
      </div>

      {/* Title */}
      <h2 style={{
        fontSize: 15,
        fontWeight: 600,
        color: 'var(--ui-text)',
        marginBottom: 8,
        letterSpacing: '-0.01em',
      }}>
        {title}
      </h2>

      {/* Description */}
      <p style={{
        fontSize: 12,
        color: 'var(--ui-text2)',
        lineHeight: 1.65,
        maxWidth: 180,
        marginBottom: 18,
      }}>
        {description}
      </p>

      {/* Keyboard shortcut badge */}
      <span style={{
        display: 'inline-block',
        fontSize: 10,
        fontWeight: 700,
        fontFamily: "'Space Mono', monospace",
        padding: '2px 8px',
        borderRadius: 5,
        border: '1px solid var(--ui-border)',
        color: 'var(--ui-text2)',
        letterSpacing: '0.1em',
        background: 'transparent',
      }}>
        {shortcut}
      </span>
    </button>
  )
}

// ── Home page ─────────────────────────────────────────────────────────────

export default function Home() {
  const navigate = useNavigate()
  const { setDragging, reset: resetDrag } = useDragStore()
  const { setCoverFile, reset: resetEmbed } = useEmbedStore()
  const { reset: resetExtract } = useExtractStore()

  // Clean slate — clear any state from previous operations
  useEffect(() => {
    resetEmbed()
    resetExtract()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.target as HTMLElement).tagName === 'INPUT' || (e.target as HTMLElement).tagName === 'TEXTAREA') return
      if (e.key === 'e' || e.key === 'E') navigate('/embed')
      if (e.key === 'x' || e.key === 'X') navigate('/extract')
      if (e.key === 'a' || e.key === 'A') navigate('/analyse')
      if (e.key === 'l' || e.key === 'L') navigate('/learn')
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [navigate])

  const handleDragOver = (e: React.DragEvent) => { e.preventDefault(); setDragging(true) }
  const handleDragLeave = () => setDragging(false)
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    resetDrag()
    const files = Array.from(e.dataTransfer.files)
    if (!files.length) return
    const ext = extOf(files[0].name)
    if (EMBED_EXTS.includes(ext)) {
      setCoverFile(files[0], URL.createObjectURL(files[0]))
      navigate('/embed')
    } else if (EXTRACT_EXTS.includes(ext)) {
      navigate('/extract')
    } else {
      navigate('/analyse')
    }
  }

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      style={{ display: 'flex', height: '100%', width: '100%' }}
    >
      <Column
        Icon={Lock}
        title="Embed"
        description="Hide encrypted data inside an image or audio file."
        shortcut="E"
        iconBg="color-mix(in srgb, #2a7fff 12%, #04080f)"
        iconColor="#4da6ff"
        iconBorder="color-mix(in srgb, #2a7fff 25%, transparent)"
        onClick={() => navigate('/embed')}
      />
      <Column
        Icon={Unlock}
        title="Extract"
        description="Recover a hidden message using your passphrase."
        shortcut="X"
        iconBg="color-mix(in srgb, #22c55e 12%, #04080f)"
        iconColor="#4ade80"
        iconBorder="color-mix(in srgb, #22c55e 25%, transparent)"
        onClick={() => navigate('/extract')}
      />
      <Column
        Icon={ScanSearch}
        title="Analyse"
        description="Detect hidden content with the built-in analysis suite."
        shortcut="A"
        iconBg="color-mix(in srgb, #f59e0b 12%, #04080f)"
        iconColor="#fbbf24"
        iconBorder="color-mix(in srgb, #f59e0b 25%, transparent)"
        onClick={() => navigate('/analyse')}
      />
      <Column
        Icon={BookOpen}
        title="Learn"
        description="Understand steganography, threat models, and how Stegcore works."
        shortcut="L"
        iconBg="color-mix(in srgb, #a855f7 12%, #04080f)"
        iconColor="#c084fc"
        iconBorder="color-mix(in srgb, #a855f7 25%, transparent)"
        onClick={() => navigate('/learn')}
        isLast
      />
    </div>
  )
}
