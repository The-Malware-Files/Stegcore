// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useCallback, useEffect, useRef } from 'react'
import { ScanSearch } from 'lucide-react'
import { useFooter } from '../App'
import { analyseFileProgressive, pickFiles } from '../lib/ipc'
import { toast } from '../lib/toast'
import { useSettingsStore } from '../lib/stores/settingsStore'
import { AnalysisDetail } from '../components/AnalysisDetail'
import type { AnalysisReport, Verdict } from '../lib/ipc'

// ── Verdict helpers ───────────────────────────────────────────────────────

const VERDICT_STYLE: Record<Verdict, { label: string; color: string }> = {
  clean:        { label: '✓ Clean',          color: 'var(--ui-success)' },
  suspicious:   { label: '⚠ Suspicious',     color: 'var(--ui-warn)'    },
  likely_stego: { label: '✗ Likely Stego',   color: 'var(--ui-danger)'  },
}

// ── Score bar — animated fill ─────────────────────────────────────────────

function ScoreBar({ score, delay = 0 }: { score: number; delay?: number }) {
  const [width, setWidth] = useState(0)
  const pct = Math.round(score * 100)
  const color = score < 0.25 ? 'var(--ui-success)' : score < 0.55 ? 'var(--ui-warn)' : 'var(--ui-danger)'

  useEffect(() => {
    const t = setTimeout(() => setWidth(pct), delay)
    return () => clearTimeout(t)
  }, [pct, delay])

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
      <div style={{ flex: 1, height: 3, borderRadius: 2, background: 'var(--ui-border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${width}%`, borderRadius: 2, background: color, transition: 'width 0.5s ease' }} />
      </div>
      <span style={{ fontSize: 11, color, width: 45, textAlign: 'right', fontFamily: "'Space Mono', monospace" }}>
        {pct}/100
      </span>
    </div>
  )
}

// ── Client-side HTML report generation (no IPC round-trip) ───────────────

function scoreHex(s: number): string {
  return s < 0.25 ? '#22c55e' : s < 0.55 ? '#f59e0b' : '#ef4444'
}

/** Escape HTML special characters to prevent XSS in exported reports. */
function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function generateHtmlReport(reports: AnalysisReport[]): string {
  const rows = reports.map(r => {
    const vClass = r.verdict === 'clean' ? 'verdict-clean' : r.verdict === 'suspicious' ? 'verdict-suspicious' : 'verdict-stego'
    const vLabel = r.verdict === 'clean' ? '✓ Clean' : r.verdict === 'suspicious' ? '⚠ Suspicious' : '✗ Likely Stego'
    const fp = r.tool_fingerprint ? `<p style="font-size:0.8rem;color:#4a5568">Signature: ${esc(r.tool_fingerprint)}</p>` : ''
    const tests = r.tests.map(t => {
      const pct = Math.round(t.score * 100)
      return `<tr><td>${esc(t.name)}</td><td><div style="background:#1a2535;border-radius:4px;height:6px;width:140px;overflow:hidden"><div style="height:100%;width:${pct}%;background:${scoreHex(t.score)};border-radius:4px"></div></div> <span style="font-size:0.75rem;color:#4a5568">${pct}%</span></td><td style="color:${t.confidence === 'high' ? '#ef4444' : t.confidence === 'medium' ? '#f59e0b' : '#4a5568'}">${esc(t.confidence)}</td><td style="color:#4a5568">${esc(t.detail)}</td></tr>`
    }).join('')
    const fileName = esc(r.file.split(/[/\\]/).pop() ?? r.file)
    return `<div style="background:#0d1520;border:1px solid #1a2535;border-radius:12px;padding:1.5rem;margin-bottom:1.5rem"><div style="font-size:1rem;font-weight:600;margin-bottom:0.25rem">${fileName}</div><div style="font-size:0.8rem;color:#4a5568;margin-bottom:1rem">Format: ${esc(r.format)} | Overall: ${(r.overall_score * 100).toFixed(0)}%</div><div class="${vClass}" style="display:inline-flex;padding:0.3rem 0.8rem;border-radius:6px;font-size:0.85rem;font-weight:600;margin-bottom:1rem">${vLabel}</div>${fp}<table style="width:100%;border-collapse:collapse;font-size:0.85rem"><tr><th style="text-align:left;color:#4a5568;padding:0.4rem 0.5rem;border-bottom:1px solid #1a2535">Detector</th><th>Score</th><th>Confidence</th><th>Detail</th></tr>${tests}</table></div>`
  }).join('')

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Stegcore Analysis Report</title><style>body{font-family:-apple-system,sans-serif;background:#070d14;color:#e8eaf0;margin:0;padding:2rem}h1{font-size:1.5rem;font-weight:500;letter-spacing:0.1em;margin-bottom:2rem}th{text-align:left}.verdict-clean{background:rgba(34,197,94,0.15);color:#22c55e}.verdict-suspicious{background:rgba(245,158,11,0.15);color:#f59e0b}.verdict-stego{background:rgba(239,68,68,0.15);color:#ef4444}td{padding:0.5rem;border-bottom:1px solid #1a253544;vertical-align:middle}</style></head><body><h1>STEGCORE — Analysis Report</h1>${rows}</body></html>`
}

// ── Analyse route ─────────────────────────────────────────────────────────

export default function Analyze() {
  const [paths, setPaths] = useState<string[]>([])
  const [reports, setReports] = useState<AnalysisReport[]>([])
  const [errors, setErrors] = useState<string[]>([])
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState({ current: 0, total: 0, file: '' })
  const [selectedReport, setSelectedReport] = useState<AnalysisReport | null>(null)
  const [preliminary, setPreliminary] = useState(false)
  const [fullReports, setFullReports] = useState<Map<string, AnalysisReport>>(new Map())
  const { settings } = useSettingsStore()

  useFooter({
    backLabel: 'Home',
    backAction: () => { window.history.back() },
  })

  const [analysedPaths, setAnalysedPaths] = useState<Set<string>>(new Set())
  const expectedCountRef = useRef(0)
  const toastFiredRef = useRef(false)

  // Listen for full analysis completion from Tauri backend
  useEffect(() => {
    let unlistenOk: (() => void) | undefined
    let unlistenErr: (() => void) | undefined
    import('@tauri-apps/api/event').then(({ listen }) => {
      listen<string>('analysis_complete', (event) => {
        try {
          const report: AnalysisReport = JSON.parse(event.payload)
          setFullReports(prev => {
            const next = new Map(prev)
            next.set(report.file, report)
            return next
          })
        } catch { /* ignore parse errors */ }
      }).then(fn => { unlistenOk = fn })

      // Also listen for errors so the "Full analysis running" label clears
      listen<string>('analysis_complete_error', () => {
        // Mark as done even if failed — stops the "running" spinner
        toastFiredRef.current = true
      }).then(fn => { unlistenErr = fn })
    }).catch(() => { /* browser dev mode */ })
    return () => { unlistenOk?.(); unlistenErr?.() }
  }, [])

  // Auto-swap preliminary results with full results when they arrive
  useEffect(() => {
    if (fullReports.size === 0) return
    if (fullReports.size >= expectedCountRef.current && expectedCountRef.current > 0) {
      // All full reports arrived — auto-swap
      setReports(prev => prev.map(r => fullReports.get(r.file) ?? r))
      setPreliminary(false)
      if (!toastFiredRef.current) {
        toastFiredRef.current = true
        toast.success('Full analysis loaded')
      }
    }
  }, [fullReports])

  // R key also swaps manually (for partial arrivals)
  useEffect(() => {
    if (fullReports.size === 0) return
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA') return
      if (e.key === 'r' || e.key === 'R') {
        setReports(prev => prev.map(r => fullReports.get(r.file) ?? r))
        setPreliminary(false)
        toast.success('Full analysis loaded')
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [fullReports])

  // Open native file dialog → returns full filesystem paths
  const handlePick = useCallback(async () => {
    const picked = await pickFiles({
      title: 'Select files to analyse',
      multiple: true,
      filters: [{ name: 'Supported', extensions: ['png', 'bmp', 'jpg', 'jpeg', 'webp', 'wav', 'flac'] }],
    })
    if (picked.length > 0) {
      setPaths(prev => {
        const existing = new Set(prev)
        // Skip files already in the list OR already analysed
        const newPaths = picked.filter(p => !existing.has(p) && !analysedPaths.has(p))
        if (newPaths.length === 0 && picked.length > 0) {
          toast.info('All selected files have already been analysed')
        }
        return [...prev, ...newPaths]
      })
    }
  }, [analysedPaths])

  const runAnalysis = useCallback(async (filePaths: string[]) => {
    if (!filePaths.length) return
    setRunning(true)
    setProgress({ current: 0, total: filePaths.length, file: '' })

    // Yield to let React paint the progress indicator before heavy IPC work
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))

    const ok: AnalysisReport[] = []
    const errs: string[] = []

    for (let i = 0; i < filePaths.length; i++) {
      const fp = filePaths[i]
      const fileName = fp.split(/[/\\]/).pop() ?? fp

      // Show which file is being analysed (bar stays at previous completed count)
      setProgress(p => ({ ...p, file: fileName }))
      await new Promise(r => requestAnimationFrame(r))

      try {
        const report = await analyseFileProgressive(fp)
        ok.push(report)
      } catch (e) {
        const msg = `${fileName}: ${e instanceof Error ? e.message : 'Analysis failed'}`
        errs.push(msg)
      }

      // Bar advances AFTER this file completes
      setProgress({ current: i + 1, total: filePaths.length, file: fileName })
      await new Promise(r => requestAnimationFrame(r))
    }

    // Hold at 100% briefly so the user sees it fill before results appear
    await new Promise(r => setTimeout(r, 600))

    setReports(prev => [...prev, ...ok])
    setErrors(prev => [...prev, ...errs])
    setAnalysedPaths(prev => {
      const next = new Set(prev)
      filePaths.forEach(p => next.add(p))
      return next
    })
    if (ok.length > 0) {
      toast.success(`Preliminary analysis complete — ${ok.length} file${ok.length > 1 ? 's' : ''}`)
      setPreliminary(true)
      setFullReports(new Map())
      expectedCountRef.current = ok.length
      toastFiredRef.current = false
    }
    if (errs.length > 0) toast.error(`${errs.length} file${errs.length > 1 ? 's' : ''} failed`)
    setRunning(false)
  }, [])

  // Export from cached reports — no re-analysis needed
  const handleExport = useCallback(async () => {
    if (!reports.length) return
    const format = settings.defaultReportFormat

    let content: string
    let mimeType: string
    let ext: string

    if (format === 'json') {
      content = JSON.stringify(reports, null, 2)
      mimeType = 'application/json'
      ext = 'json'
    } else if (format === 'csv') {
      const rows = ['File,Format,Verdict,Overall Score,Test,Score,Confidence,Detail']
      for (const r of reports) {
        for (const t of r.tests) {
          const csvEsc = (s: string) => s.replace(/"/g, '""')
          rows.push(`"${csvEsc(r.file)}","${csvEsc(r.format)}","${csvEsc(r.verdict)}",${r.overall_score},"${csvEsc(t.name)}",${t.score},"${csvEsc(t.confidence)}","${csvEsc(t.detail)}"`)

        }
      }
      content = rows.join('\n')
      mimeType = 'text/csv'
      ext = 'csv'
    } else {
      // HTML (also used as base for PDF)
      content = generateHtmlReport(reports)
      mimeType = 'text/html'
      ext = 'html'
    }

    if (format === 'pdf') {
      const iframe = document.createElement('iframe')
      iframe.style.cssText = 'position:fixed;left:-9999px;width:800px;height:600px'
      document.body.appendChild(iframe)
      const doc = iframe.contentDocument ?? iframe.contentWindow?.document
      if (doc) {
        doc.open()
        doc.write(content)
        doc.close()
        setTimeout(() => {
          iframe.contentWindow?.print()
          setTimeout(() => document.body.removeChild(iframe), 1000)
        }, 300)
      }
      return
    }

    // Use Tauri native save dialog (blob downloads don't work in webview)
    try {
      const { save } = await import('@tauri-apps/plugin-dialog')
      const { writeTextFile } = await import('@tauri-apps/plugin-fs')
      const path = await save({
        title: 'Save report',
        defaultPath: `stegcore-report.${ext}`,
        filters: [{ name: `${ext.toUpperCase()} files`, extensions: [ext] }],
      })
      if (path) {
        await writeTextFile(path, content)
      }
    } catch {
      // Fallback for dev/browser mode
      const blob = new Blob([content], { type: mimeType })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `stegcore-report.${ext}`
      a.click()
      URL.revokeObjectURL(url)
    }
  }, [reports, settings.defaultReportFormat])

  return (
    <div style={{ padding: '48px 40px 32px', flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      {/* Header */}
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
          Steganalysis
        </span>
        <h2 style={{ fontSize: 28, fontWeight: 600, color: 'var(--ui-text)', letterSpacing: '-0.02em', marginBottom: 6 }}>
          Detect hidden data
        </h2>
        <p style={{ fontSize: 13, color: 'var(--ui-text2)', lineHeight: 1.6 }}>
          Single file or batch drop
        </p>
      </div>

      {/* Drop zone — native file picker on click */}
      <div
        className="sc-analyse-drop"
        onClick={running ? undefined : handlePick}
        style={{
          borderRadius: 'var(--sc-radius-card)',
          padding: '2.5rem 1.5rem',
          textAlign: 'center',
          cursor: running ? 'default' : 'pointer',
          opacity: running ? 0.6 : 1,
          userSelect: 'none',
        }}
      >
        <ScanSearch size={32} strokeWidth={1.5} style={{ color: 'var(--ui-warn)', margin: '0 auto 0.5rem', display: 'block' }} />
        <p style={{ color: 'var(--ui-text)', fontSize: 14, fontWeight: 500 }}>
          {running ? 'Analysing…' : 'Drop file(s) or click to scan'}
        </p>
        {paths.length > 0 && (
          <p style={{ color: 'var(--ui-text2)', fontSize: 12, marginTop: 4 }}>
            {paths.length} file{paths.length > 1 ? 's' : ''} selected
          </p>
        )}
      </div>

      {/* Running — determinate progress bar + per-file status */}
      {running && (
        <div style={{ marginTop: '1.25rem' }}>
          <div style={{ height: 4, borderRadius: 2, background: 'var(--ui-border)', overflow: 'hidden', marginBottom: 12 }}>
            <div style={{
              height: '100%',
              width: `${progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0}%`,
              borderRadius: 2,
              background: 'var(--ui-warn)',
              transition: 'width 0.3s ease',
            }} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ animation: 'spin 0.8s linear infinite' }}>
              <circle cx="8" cy="8" r="6" stroke="var(--ui-warn)" strokeWidth="2" strokeOpacity="0.3" />
              <path d="M8 2A6 6 0 0 1 14 8" stroke="var(--ui-warn)" strokeWidth="2" strokeLinecap="round" />
            </svg>
            <span style={{ fontSize: 13, color: 'var(--ui-text2)' }}>
              Analysing {progress.current}/{progress.total}
              {progress.file && <> — <span style={{ fontFamily: "'Space Mono', monospace", fontSize: 12 }}>{progress.file}</span></>}
            </span>
          </div>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {/* Analyse button (shown when files selected but not yet analysed) */}
      {paths.filter(p => !analysedPaths.has(p)).length > 0 && !running && (
        <button
          className="sc-btn-primary"
          onClick={() => runAnalysis(paths.filter(p => !analysedPaths.has(p)))}
          style={{
            width: '100%',
            marginTop: '1rem',
            padding: '11px',
            background: 'var(--ui-accent)',
            border: 'none',
            borderRadius: 'var(--sc-radius-btn)',
            color: '#ffffff',
            fontSize: 14,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          Analyse {paths.filter(p => !analysedPaths.has(p)).length} new file{paths.filter(p => !analysedPaths.has(p)).length > 1 ? 's' : ''}
        </button>
      )}

      {/* Results — clickable cards open detail sidebar */}
      {reports.length > 0 && reports.map((report, ri) => (
        <div
          key={ri}
          className="sc-result-card"
          onClick={() => setSelectedReport(report)}
          style={{
            marginTop: ri === 0 ? 20 : 14,
            cursor: 'pointer',
            borderRadius: 10,
            padding: '12px 14px',
          }}
        >
          {/* File name */}
          <p style={{ fontSize: 12, fontFamily: "'Space Mono', monospace", color: 'var(--ui-accent)', marginBottom: 8 }}>
            {report.file.split(/[/\\]/).pop() ?? report.file}
          </p>

          {/* Score bars — staggered animation */}
          {report.tests.map((t, i) => (
            <div key={t.name} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 9 }}>
              <span style={{ fontSize: 11, color: 'var(--ui-text2)', width: 160, flexShrink: 0, fontFamily: "'Space Mono', monospace" }}>
                {t.name}
              </span>
              <ScoreBar score={t.score} delay={(ri * report.tests.length + i) * 120 + 100} />
            </div>
          ))}

          {/* Verdict row */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            borderTop: '1px solid var(--ui-border)', paddingTop: 10, marginTop: 4,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 500, color: VERDICT_STYLE[report.verdict].color }}>
                {VERDICT_STYLE[report.verdict].label}
              </span>
              <span style={{ fontSize: 11, color: 'var(--ui-text2)' }}>
                {report.tool_fingerprint
                  ? `${report.tool_fingerprint} detected`
                  : `Score: ${Math.round(report.overall_score * 100)}%`}
              </span>
            </div>
            {preliminary && (
              <span style={{ fontSize: 10, color: 'var(--ui-warn)', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--ui-warn)', animation: 'pulse 1.2s ease-in-out infinite' }} />
                Preliminary · Full analysis running…
              </span>
            )}
            <span style={{ fontSize: 11, color: 'var(--ui-text2)' }}>
              Click for details →
            </span>
          </div>
        </div>
      ))}

      {/* Detail sidebar */}
      <AnalysisDetail
        report={selectedReport}
        onClose={() => setSelectedReport(null)}
        onExport={handleExport}
      />

      {/* Errors */}
      {errors.map((e, i) => (
        <div key={i} style={{
          padding: '10px 14px', borderRadius: 8, marginTop: 8,
          background: 'color-mix(in srgb, var(--ui-danger) 10%, var(--ui-surface))',
          border: '1px solid color-mix(in srgb, var(--ui-danger) 25%, transparent)',
          fontSize: 13, color: 'var(--ui-danger)',
        }}>
          {e}
        </div>
      ))}
    </div>
  )
}
