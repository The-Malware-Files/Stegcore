// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useRef, useEffect } from 'react'
import { RotateCcw } from 'lucide-react'
import { THEME, easeOut, scoreColor } from './analysisTheme'
import { ChiSquaredChart } from './ChiSquaredChart'
import { RSAnalysisChart } from './RSAnalysisChart'
import { SPAGauge } from './SPAGauge'
import { LSBHeatmap } from './LSBHeatmap'
import { OscilloscopeTrace } from './OscilloscopeTrace'
import type { AudioAnalysisData } from './OscilloscopeTrace'
import type { SteganalysisResult } from './types'

interface Props {
  data: SteganalysisResult
}

const RISK_LABELS: Record<string, string> = {
  clean: 'CLEAN',
  uncertain: 'UNCERTAIN',
  suspicious: 'SUSPICIOUS',
  likely_embedded: 'LIKELY EMBEDDED',
}

function RiskHeader({ data, scoreFrame }: { data: SteganalysisResult; scoreFrame: number }) {
  const p = easeOut(Math.min(1, scoreFrame / 90))
  const displayScore = Math.round(data.risk_score * p)
  const color = scoreColor(data.risk_score)
  const barWidth = data.risk_score * p
  const label = RISK_LABELS[data.risk_label] ?? 'UNKNOWN'
  const [w, h] = data.image_dimensions
  const sizeMB = (data.filesize_bytes / (1024 * 1024)).toFixed(1)

  return (
    <div style={{
      padding: '16px 20px 14px',
      background: THEME.surface,
      border: `1px solid ${THEME.border}`,
      borderRadius: 10,
      marginBottom: 16,
    }}>
      {/* Top row: score + badge */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 14, marginBottom: 10 }}>
        <span style={{
          fontSize: 48, fontWeight: 700, color,
          fontFamily: "'Syne', 'Space Grotesk', sans-serif",
          lineHeight: 1,
        }}>
          {displayScore}
        </span>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          padding: '4px 12px', borderRadius: 20,
          background: `${color}22`, color,
          fontSize: 11, fontWeight: 600, fontFamily: "'Space Mono', monospace",
          letterSpacing: '0.05em',
        }}>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: color }} />
          {label}
        </span>
      </div>

      {/* Progress bar */}
      <div style={{
        height: 4, borderRadius: 2, overflow: 'hidden',
        background: 'rgba(255,255,255,0.07)', marginBottom: 8,
      }}>
        <div style={{
          height: '100%', borderRadius: 2,
          width: `${barWidth}%`,
          background: `linear-gradient(90deg, ${THEME.green}, ${THEME.blue}, ${THEME.red})`,
          transition: 'width 0.05s linear',
        }} />
      </div>

      {/* Meta */}
      <div style={{ fontSize: 11, color: THEME.textMuted, fontFamily: "'Space Mono', monospace" }}>
        {data.filename}
        {data.filesize_bytes > 0 && <> · {sizeMB} MB</>}
        {w > 0 && h > 0 && <> · {w}×{h}</>}
      </div>
    </div>
  )
}

function ChartCard({ title, children, onReplay, badge }: {
  title: string
  children: React.ReactNode
  onReplay: () => void
  badge?: { text: string; color: string }
}) {
  return (
    <div className="sc-chart-card" style={{
      background: THEME.surface,
      border: `1px solid ${THEME.border}`,
      borderRadius: 10,
      padding: '12px 14px',
      position: 'relative',
      overflow: 'hidden',
      display: 'flex',
      flexDirection: 'column',
      minHeight: 220,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{
          fontSize: 12, fontWeight: 700, letterSpacing: '0.08em',
          textTransform: 'uppercase', color: THEME.textMuted,
          fontFamily: "'Space Mono', monospace",
        }}>
          {title}
        </span>
        <button
          onClick={onReplay}
          title="Replay animation"
          style={{
            background: 'transparent', border: 'none', cursor: 'pointer',
            color: THEME.textMuted, padding: 2, display: 'flex',
            borderRadius: 4, transition: 'color 0.15s',
          }}
          onMouseEnter={e => { e.currentTarget.style.color = THEME.textPrimary }}
          onMouseLeave={e => { e.currentTarget.style.color = THEME.textMuted }}
        >
          <RotateCcw size={12} />
        </button>
      </div>
      <div style={{ flex: 1, minHeight: 0, overflow: 'hidden' }}>
        {children}
      </div>
      {badge && (
        <div style={{ marginTop: 8, flexShrink: 0 }}>
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 5,
            padding: '4px 10px', borderRadius: 12,
            background: `${badge.color}18`, color: badge.color,
            fontSize: 10, fontWeight: 600, fontFamily: "'Space Mono', monospace",
            letterSpacing: '0.04em', textTransform: 'uppercase',
            whiteSpace: 'nowrap', maxWidth: '100%',
          }}>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: badge.color, flexShrink: 0 }} />
            {badge.text}
          </span>
        </div>
      )}
    </div>
  )
}

function chiVerdict(chi: { r: number; g: number; b: number; threshold: number }): { text: string; color: string } {
  const suspicious = [chi.r, chi.g, chi.b].filter(p => p < chi.threshold)
  if (suspicious.length === 0) return { text: 'Clean — all channels natural', color: '#3dd6a3' }
  const channels = ['R', 'G', 'B'].filter((_, i) => [chi.r, chi.g, chi.b][i] < chi.threshold)
  return { text: `Suspicious — ${channels.join(', ')} channel${channels.length > 1 ? 's' : ''}`, color: '#ff5c5c' }
}

function rsVerdict(rate: number): { text: string; color: string } {
  if (rate < 0.15) return { text: `Est. rate ${Math.round(rate * 100)}% — clean`, color: '#3dd6a3' }
  if (rate < 0.45) return { text: `Est. rate ${Math.round(rate * 100)}% — uncertain`, color: '#f5c842' }
  return { text: `Est. rate ${Math.round(rate * 100)}% — likely embedded`, color: '#ff5c5c' }
}

function spaVerdict(rate: number, conf: number): { text: string; color: string } {
  if (rate < 0.2) return { text: `${Math.round(rate * 100)}% embedded · ${Math.round(conf * 100)}% conf`, color: '#3dd6a3' }
  if (rate < 0.5) return { text: `${Math.round(rate * 100)}% embedded · ${Math.round(conf * 100)}% conf`, color: '#f5c842' }
  return { text: `${Math.round(rate * 100)}% embedded · ${Math.round(conf * 100)}% conf`, color: '#ff5c5c' }
}

function lsbVerdict(grid: number[][], isAudio: boolean): { text: string; color: string } {
  const flat = grid.flat()
  const hot = flat.filter(v => v > 0.65).length
  if (isAudio) {
    // Audio: single pill — clean (green) or anomalous (red)
    if (hot === 0) return { text: 'No anomalous blocks detected', color: '#3dd6a3' }
    return { text: `${hot} region${hot > 1 ? 's' : ''} — likely embedded`, color: '#ff5c5c' }
  }
  if (hot === 0) return { text: 'No anomalous blocks detected', color: '#3dd6a3' }
  if (hot <= 3) return { text: `${hot} hot zone${hot > 1 ? 's' : ''} — uncertain`, color: '#f5c842' }
  return { text: `${hot} hot zones — likely embedded`, color: '#ff5c5c' }
}

export function SteganalysisReport({ data }: Props) {
  const [chiReplay, setChiReplay] = useState(false)
  const [rsReplay, setRsReplay] = useState(false)
  const [spaReplay, setSpaReplay] = useState(false)
  const [lsbReplay, setLsbReplay] = useState(false)
  const [scoreFrame, setScoreFrame] = useState(0)
  const [dashWidth, setDashWidth] = useState(800)
  const dashRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!dashRef.current) return
    const obs = new ResizeObserver(entries => {
      for (const e of entries) setDashWidth(e.contentRect.width)
    })
    obs.observe(dashRef.current)
    return () => obs.disconnect()
  }, [])

  const isAudio = data.format === 'wav' || data.format === 'flac'

  const toAudioData = (d: SteganalysisResult): AudioAnalysisData => {
    // Convert LSB entropy grid to waveform samples
    const flat = d.lsb_entropy.grid.flat()
    const waveform = flat.map((v, i) => Math.sin(i * 0.3) * (0.3 + v * 0.6) * (v > 0.65 ? 1.2 : 1))
    const suspiciousRegions: [number, number][] = []
    let inRegion = false
    let regionStart = 0
    flat.forEach((v, i) => {
      if (v > 0.65 && !inRegion) { inRegion = true; regionStart = i }
      if ((v <= 0.65 || i === flat.length - 1) && inRegion) { inRegion = false; suspiciousRegions.push([regionStart, i]) }
    })
    return {
      waveform_samples: waveform,
      suspicious_regions: suspiciousRegions,
      lsb_anomaly_score: d.risk_score,
      verdict: d.risk_label,
      duration_seconds: flat.length / 44.1, // approximate
    }
  }

  // Score counter animation
  useState(() => {
    let f = 0
    const tick = () => {
      f++
      setScoreFrame(f)
      if (f < 100) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  })

  return (
    <div ref={dashRef} style={{ padding: '0 2px', display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Risk header */}
      <RiskHeader data={data} scoreFrame={scoreFrame} />

      {/* Charts grid: 2×2 on wide (≥480px), vertical scroll on narrow */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: dashWidth < 480 ? '1fr' : 'repeat(2, 1fr)',
        gridTemplateRows: dashWidth < 480 ? 'auto' : '1fr 1fr',
        gap: 12,
        flex: 1,
        minHeight: 0,
        overflowY: dashWidth < 480 ? 'auto' : undefined,
      }}>
        <ChartCard title="Chi-Squared" onReplay={() => setChiReplay(true)} badge={chiVerdict(data.chi_squared)}>
          <ChiSquaredChart data={data} replay={chiReplay} onReplayDone={() => setChiReplay(false)} />
        </ChartCard>
        <ChartCard title="RS Analysis" onReplay={() => setRsReplay(true)} badge={rsVerdict(data.rs_analysis.estimated_rate)}>
          <RSAnalysisChart data={data} replay={rsReplay} onReplayDone={() => setRsReplay(false)} />
        </ChartCard>
        <ChartCard title="Sample Pair" onReplay={() => setSpaReplay(true)} badge={spaVerdict(data.sample_pair.estimated_rate, data.sample_pair.confidence)}>
          <SPAGauge data={data} replay={spaReplay} onReplayDone={() => setSpaReplay(false)} />
        </ChartCard>
        <ChartCard title={isAudio ? 'Audio LSB' : 'LSB Entropy'} onReplay={() => setLsbReplay(true)} badge={lsbVerdict(data.lsb_entropy.grid, isAudio)}>
          {isAudio ? (
            <OscilloscopeTrace
              data={toAudioData(data)}
              replay={lsbReplay}
              onReplayDone={() => setLsbReplay(false)}
            />
          ) : (
            <LSBHeatmap data={data} replay={lsbReplay} onReplayDone={() => setLsbReplay(false)} />
          )}
        </ChartCard>
      </div>
    </div>
  )
}
