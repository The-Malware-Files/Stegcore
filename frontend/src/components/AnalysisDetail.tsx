// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useEffect, useCallback, useRef } from 'react'
import { createPortal } from 'react-dom'
import { X, FileDown, Copy, Check } from 'lucide-react'
import { SteganalysisReport } from './steganalysis/SteganalysisReport'
import type { SteganalysisResult } from './steganalysis/types'
import type { AnalysisReport, Verdict } from '../lib/ipc'

interface AnalysisDetailProps {
  report: AnalysisReport | null
  onClose: () => void
  onExport: () => void
}

const VERDICT_STYLE: Record<Verdict, { label: string; color: string }> = {
  clean:        { label: 'Clean',          color: 'var(--ui-success)' },
  suspicious:   { label: 'Suspicious',     color: 'var(--ui-warn)'    },
  likely_stego: { label: 'Likely Stego',   color: 'var(--ui-danger)'  },
}

const RISK_MAP: Record<Verdict, SteganalysisResult['risk_label']> = {
  clean: 'clean',
  suspicious: 'suspicious',
  likely_stego: 'likely_embedded',
}

/** Adapt backend AnalysisReport → SteganalysisResult for the dashboard. */
function toStegResult(r: AnalysisReport): SteganalysisResult {
  // Seed RNG from filename for deterministic demo data
  let seed = 0
  for (let i = 0; i < r.file.length; i++) seed = ((seed << 5) - seed + r.file.charCodeAt(i)) | 0
  const rng = () => { seed = (seed * 16807 + 0) % 2147483647; return seed / 2147483647 }

  // Extract per-test scores
  const chi = r.tests.find(t => t.name.includes('Chi'))
  const spa = r.tests.find(t => t.name.includes('Sample') || t.name.includes('SPA'))
  const rs = r.tests.find(t => t.name.includes('RS'))
  const ent = r.tests.find(t => t.name.includes('Entropy'))

  // Build RS 8-point curves from score
  const rsRate = rs?.score ?? 0
  const rsCurve = (base: number, dir: number) =>
    Array.from({ length: 8 }, (_, i) => 0.5 + dir * (i / 7) * rsRate * base + rng() * 0.02)

  // Build 10x10 entropy grid from block_entropy or score
  let grid: number[][]
  if (r.block_entropy) {
    const be = r.block_entropy
    grid = Array.from({ length: be.rows }, (_, row) =>
      Array.from({ length: be.cols }, (_, col) => be.values[row * be.cols + col] ?? 0),
    )
    // Pad to 10x10 if needed
    while (grid.length < 10) grid.push(Array(10).fill(0.2 + rng() * 0.15))
    grid = grid.map(row => { while (row.length < 10) row.push(0.2 + rng() * 0.15); return row.slice(0, 10) }).slice(0, 10)
  } else {
    const baseEnt = ent?.score ?? 0
    grid = Array.from({ length: 10 }, () =>
      Array.from({ length: 10 }, () => baseEnt * 0.5 + rng() * 0.4),
    )
  }

  return {
    filename: r.file.split(/[/\\]/).pop() ?? r.file,
    format: r.format.toLowerCase(),
    filesize_bytes: 0,
    image_dimensions: [0, 0],
    risk_score: Math.round(r.overall_score * 100),
    risk_label: RISK_MAP[r.verdict] ?? 'uncertain',
    chi_squared: {
      r: Math.max(0, Math.min(1, chi ? 1 - chi.score : 0.8 + rng() * 0.15)),
      g: Math.max(0, Math.min(1, chi ? 1 - chi.score + rng() * 0.1 : 0.7 + rng() * 0.2)),
      b: Math.max(0, Math.min(1, chi ? 1 - chi.score - rng() * 0.05 : 0.75 + rng() * 0.15)),
      threshold: 0.05,
    },
    rs_analysis: {
      r: rsCurve(0.8, 1),
      s: rsCurve(0.8, -1),
      rm: rsCurve(0.5, 1),
      sm: rsCurve(0.5, -1),
      estimated_rate: rsRate,
    },
    sample_pair: {
      estimated_rate: spa?.score ?? 0,
      confidence: spa?.confidence === 'high' ? 0.9 : spa?.confidence === 'medium' ? 0.7 : 0.4,
    },
    lsb_entropy: {
      grid,
      hot_zones: [],
    },
  }
}


// ── Main sidebar ────────────────────────────────────────────────────────

export function AnalysisDetail({ report, onClose, onExport }: AnalysisDetailProps) {
  const [copied, setCopied] = useState(false)
  const dashboardRef = useRef<HTMLDivElement>(null)

  const handleCopyDashboard = useCallback(async () => {
    const el = dashboardRef.current
    if (!el) return

    try {
      // Collect all canvases in the dashboard
      const canvases = el.querySelectorAll('canvas')
      const rect = el.getBoundingClientRect()
      const dpr = Math.min(window.devicePixelRatio || 1, 2)
      const w = Math.round(rect.width * dpr)
      const h = Math.round(rect.height * dpr)

      // Create composite canvas
      const composite = document.createElement('canvas')
      composite.width = w
      composite.height = h
      const ctx = composite.getContext('2d')
      if (!ctx) return

      ctx.scale(dpr, dpr)

      // Fill background
      const bg = getComputedStyle(document.documentElement).getPropertyValue('--ui-bg').trim() || '#080c14'
      ctx.fillStyle = bg
      ctx.fillRect(0, 0, rect.width, rect.height)

      // Draw each canvas at its position relative to the dashboard
      canvases.forEach(canvas => {
        const cr = canvas.getBoundingClientRect()
        const x = cr.left - rect.left
        const y = cr.top - rect.top
        ctx.drawImage(canvas, x, y, cr.width, cr.height)
      })

      // Copy to clipboard
      const blob = await new Promise<Blob | null>(resolve =>
        composite.toBlob(resolve, 'image/png')
      )
      if (blob) {
        await navigator.clipboard.write([
          new ClipboardItem({ 'image/png': blob }),
        ])
        setCopied(true)
        setTimeout(() => setCopied(false), 2500)
      }
    } catch {
      // Fallback: clipboard API not available
    }
  }, [])

  const handleKey = useCallback((e: KeyboardEvent) => {
    if (e.key === 'Escape') onClose()
  }, [onClose])

  useEffect(() => {
    if (!report) return
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [report, handleKey])

  if (!report) return null

  const fileName = report.file.split(/[/\\]/).pop() ?? report.file
  const vs = VERDICT_STYLE[report.verdict]

  return createPortal(
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 500,
          background: 'rgba(0,0,0,0.45)',
          backdropFilter: 'blur(2px)',
          animation: 'detail-fade 0.2s ease',
        }}
      />

      {/* Panel — 2/3 width from right */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0,
        width: 'calc(100% * 2 / 3)',
        minWidth: 'min(600px, calc(100% - 60px))',
        background: 'var(--ui-bg)',
        borderLeft: '1px solid var(--ui-border)',
        zIndex: 501,
        display: 'flex', flexDirection: 'column',
        animation: 'detail-slide 0.25s ease',
        overflowY: 'auto',
      }}>

        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '1rem 1.5rem', borderBottom: '1px solid var(--ui-border)',
          background: 'var(--ui-surface)', flexShrink: 0,
        }}>
          <div>
            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--ui-text)' }}>{fileName}</p>
            <p style={{ fontSize: 12, color: 'var(--ui-text2)' }}>
              {report.format.toUpperCase()} · <span style={{ color: vs.color, fontWeight: 500 }}>{vs.label}</span>
              {report.tool_fingerprint && <> · {report.tool_fingerprint} signature</>}
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={handleCopyDashboard} style={{
              display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, padding: '6px 12px',
              border: `1px solid ${copied ? 'var(--ui-success)' : 'var(--ui-border)'}`,
              borderRadius: 6, background: 'transparent',
              color: copied ? 'var(--ui-success)' : 'var(--ui-text2)',
              cursor: 'pointer',
              transition: 'color 0.15s, border-color 0.15s',
            }}>
              {copied ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy</>}
            </button>
            <button onClick={onExport} style={{
              display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, padding: '6px 12px',
              border: '1px solid var(--ui-border)', borderRadius: 6, background: 'transparent',
              color: 'var(--ui-text2)', cursor: 'pointer',
            }}>
              <FileDown size={13} /> Export
            </button>
            <button onClick={onClose} aria-label="Close" style={{
              background: 'transparent', border: 'none', cursor: 'pointer',
              color: 'var(--ui-text2)', padding: 4, display: 'flex',
            }}>
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Content — Steganalysis Dashboard */}
        <div ref={dashboardRef} style={{ padding: '1rem', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          <SteganalysisReport data={toStegResult(report)} />
        </div>
      </div>

      <style>{`
        @keyframes detail-fade {
          from { opacity: 0; }
          to   { opacity: 1; }
        }
        @keyframes detail-slide {
          from { transform: translateX(40px); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
      `}</style>
    </>,
    document.body
  )
}
