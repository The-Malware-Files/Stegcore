// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useRef, useEffect, useState, useCallback } from 'react'
import { getTheme, easeOut } from './analysisTheme'
import { useAnimationFrame, useContainerSize } from './useAnimationFrame'
import type { SteganalysisResult } from './types'

interface Props {
  data: SteganalysisResult
  replay: boolean
  onReplayDone: () => void
}

const PAD = { left: 28, right: 50, top: 22, bottom: 36 }
const DPR = Math.min(typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1, 2)

export function ChiSquaredChart({ data, replay, onReplayDone }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [containerRef, size] = useContainerSize()
  const [frame, resetFrame] = useAnimationFrame(100)
  const [hover, setHover] = useState<number | null>(null)

  useEffect(() => {
    if (replay) { resetFrame(); onReplayDone() }
  }, [replay, resetFrame, onReplayDone])

  // Draw
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const { w, h } = size
    canvas.width = w * DPR
    canvas.height = h * DPR
    ctx.scale(DPR, DPR)
    ctx.clearRect(0, 0, w, h)
    const th = getTheme()

    const cw = w - PAD.left - PAD.right
    const ch = h - PAD.top - PAD.bottom
    const t = frame

    const channels: [string, number, string][] = [
      ['R', data.chi_squared.r, th.channelR],
      ['G', data.chi_squared.g, th.channelG],
      ['B', data.chi_squared.b, th.channelB],
    ]
    const barH = ch / 3 - 8
    const delays = [0, 12, 24]
    const textAlpha = easeOut(Math.max(0, (t - 50) / 30)) // numbers fade in last

    // Grid lines
    ctx.strokeStyle = th.gridLine
    ctx.lineWidth = 0.5
    for (let i = 0; i <= 5; i++) {
      const x = PAD.left + (i / 5) * cw
      ctx.beginPath(); ctx.moveTo(x, PAD.top); ctx.lineTo(x, PAD.top + ch); ctx.stroke()
    }

    // X axis labels (fade in)
    ctx.font = '10px "Space Mono", monospace'
    ctx.fillStyle = th.textMuted
    ctx.textAlign = 'center'
    ctx.globalAlpha = textAlpha
    for (let i = 0; i <= 5; i++) {
      const x = PAD.left + (i / 5) * cw
      ctx.fillText((i * 0.2).toFixed(1), x, h - PAD.bottom + 14)
    }
    ctx.globalAlpha = 1

    // Axis spines
    ctx.strokeStyle = th.axisLine
    ctx.lineWidth = 0.5
    ctx.beginPath(); ctx.moveTo(PAD.left, PAD.top); ctx.lineTo(PAD.left, PAD.top + ch); ctx.stroke()
    ctx.beginPath(); ctx.moveTo(PAD.left, PAD.top + ch); ctx.lineTo(PAD.left + cw, PAD.top + ch); ctx.stroke()

    // Bars
    channels.forEach(([label, pval, color], i) => {
      const y = PAD.top + i * (ch / 3) + 4
      const progress = easeOut(Math.max(0, (t - delays[i]) / 35))
      const barWidth = pval * cw * progress

      // Ghost track
      ctx.fillStyle = color.replace(')', ',0.1)').replace('rgb', 'rgba')
      if (color.startsWith('#')) {
        ctx.globalAlpha = 0.1
        ctx.fillStyle = color
      }
      ctx.fillRect(PAD.left, y, cw, barH)
      ctx.globalAlpha = 1

      // Filled bar
      ctx.fillStyle = color
      ctx.globalAlpha = hover === i ? 1.0 : 0.9
      ctx.fillRect(PAD.left, y, barWidth, barH)
      ctx.globalAlpha = 1

      // Channel label (fade in with text)
      ctx.font = '9px "Space Mono", monospace'
      ctx.fillStyle = color
      ctx.textAlign = 'right'
      ctx.globalAlpha = textAlpha
      ctx.fillText(label, PAD.left - 8, y + barH / 2 + 3)
      ctx.globalAlpha = 1

      // p-value text (fade in after bars + text delay)
      if (progress > 0.15) {
        ctx.font = '10px "Space Mono", monospace'
        ctx.fillStyle = th.textPrimary
        ctx.textAlign = 'left'
        ctx.globalAlpha = textAlpha * Math.min(1, (progress - 0.15) / 0.3)
        ctx.fillText(pval.toFixed(3), PAD.left + barWidth + 6, y + barH / 2 + 3)
        ctx.globalAlpha = 1
      }
    })

    // Threshold line (frames 90-112)
    const thresholdAlpha = easeOut(Math.max(0, (t - 60) / 15))
    if (thresholdAlpha > 0) {
      const thresholdX = PAD.left + data.chi_squared.threshold * cw
      ctx.globalAlpha = thresholdAlpha
      ctx.strokeStyle = 'rgba(255,70,70,0.8)'
      ctx.lineWidth = 1
      ctx.setLineDash([4, 5])
      ctx.beginPath(); ctx.moveTo(thresholdX, PAD.top); ctx.lineTo(thresholdX, PAD.top + ch); ctx.stroke()
      ctx.setLineDash([])

      ctx.font = '10px "Space Mono", monospace'
      ctx.fillStyle = 'rgba(255,90,90,0.9)'
      ctx.textAlign = 'center'
      ctx.fillText('p=0.05', thresholdX, PAD.top - 7)
      ctx.globalAlpha = 1
    }
  }, [frame, data, hover, size])

  const handleMove = useCallback((e: React.MouseEvent) => {
    const canvas = canvasRef.current
    if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    const y = e.clientY - rect.top
    const ch = size.h - PAD.top - PAD.bottom
    const relY = y - PAD.top
    if (relY < 0 || relY > ch) { setHover(null); return }
    setHover(Math.min(2, Math.floor(relY / (ch / 3))))
  }, [size])

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%', minHeight: 140, height: '100%' }}>
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', display: 'block' }}
        onMouseMove={handleMove}
        onMouseLeave={() => setHover(null)}
      />
    </div>
  )
}
