// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useRef, useEffect, useState, useCallback } from 'react'
import { getTheme, easeInOut, lerp } from './analysisTheme'
import { useAnimationFrame, useContainerSize } from './useAnimationFrame'
import type { SteganalysisResult } from './types'

interface Props {
  data: SteganalysisResult
  replay: boolean
  onReplayDone: () => void
}

const PAD = { left: 46, right: 12, top: 18, bottom: 36 }
const DPR = Math.min(typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1, 2)

function smoothCurve(ctx: CanvasRenderingContext2D, pts: { x: number; y: number }[]) {
  if (pts.length < 2) return
  ctx.moveTo(pts[0].x, pts[0].y)
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[Math.max(0, i - 1)]
    const p1 = pts[i]
    const p2 = pts[i + 1]
    const p3 = pts[Math.min(pts.length - 1, i + 2)]
    const cp1x = p1.x + (p2.x - p0.x) / 6
    const cp1y = p1.y + (p2.y - p0.y) / 6
    const cp2x = p2.x - (p3.x - p1.x) / 6
    const cp2y = p2.y - (p3.y - p1.y) / 6
    ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, p2.x, p2.y)
  }
}

export function RSAnalysisChart({ data, replay, onReplayDone }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [containerRef, size] = useContainerSize()
  const [frame, resetFrame] = useAnimationFrame(100)
  const [hoverX, setHoverX] = useState<number | null>(null)

  useEffect(() => { if (replay) { resetFrame(); onReplayDone() } }, [replay, resetFrame, onReplayDone])

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
    const p = easeInOut(Math.min(1, t / 65))

    // Compute y-axis range from actual data (extend beyond 0–1 if needed)
    const rs = data.rs_analysis
    const allVals = [...rs.r, ...rs.s, ...rs.rm, ...rs.sm]
    const yMin = Math.min(0, ...allVals) - 0.05
    const yMax = Math.max(1, ...allVals) + 0.05
    const yRange = yMax - yMin

    const xScale = (i: number, total: number) => PAD.left + (i / (total - 1)) * cw
    const yScale = (v: number) => PAD.top + ch - ((v - yMin) / yRange) * ch

    // Grid — draw ticks at nice intervals
    ctx.strokeStyle = th.gridLine
    ctx.lineWidth = 0.5
    const yTicks = [0, 0.2, 0.4, 0.6, 0.8, 1.0].filter(v => v >= yMin && v <= yMax)
    for (const tick of yTicks) {
      const y = yScale(tick)
      ctx.beginPath(); ctx.moveTo(PAD.left, y); ctx.lineTo(PAD.left + cw, y); ctx.stroke()
    }
    for (let i = 0; i <= 4; i++) {
      const x = PAD.left + (i / 4) * cw
      ctx.beginPath(); ctx.moveTo(x, PAD.top); ctx.lineTo(x, PAD.top + ch); ctx.stroke()
    }

    // Axis labels (fade in last)
    const textAlpha = easeInOut(Math.max(0, (t - 50) / 30))
    ctx.font = '10px "Space Mono", monospace'
    ctx.fillStyle = th.textMuted
    ctx.globalAlpha = textAlpha
    ctx.textAlign = 'right'
    for (const tick of yTicks) ctx.fillText(tick.toFixed(1), PAD.left - 4, yScale(tick) + 3)
    ctx.textAlign = 'center'
    for (let i = 0; i <= 4; i++) ctx.fillText(`${i * 25}%`, PAD.left + (i / 4) * cw, h - PAD.bottom + 14)
    ctx.globalAlpha = 1

    // Spines
    ctx.strokeStyle = th.axisLine
    ctx.beginPath(); ctx.moveTo(PAD.left, PAD.top); ctx.lineTo(PAD.left, PAD.top + ch); ctx.stroke()
    ctx.beginPath(); ctx.moveTo(PAD.left, PAD.top + ch); ctx.lineTo(PAD.left + cw, PAD.top + ch); ctx.stroke()

    // Curves
    const curves: [number[], string, number[], boolean][] = [
      [rs.r, th.rsCurveR, [], false],
      [rs.s, th.rsCurveS, [], false],
      [rs.rm, th.rsCurveRM, [5, 5], true],
      [rs.sm, th.rsCurveSM, [5, 5], true],
    ]

    ctx.globalAlpha = 0.25 + p * 0.75

    for (const [vals, color, dash, isDashed] of curves) {
      const n = vals.length
      const pts = vals.map((v, i) => ({
        x: xScale(i, n),
        y: yScale(lerp(0.5, v, p)),
      }))

      ctx.strokeStyle = color
      ctx.lineWidth = isDashed ? 1.2 : 2
      ctx.setLineDash(dash)
      ctx.beginPath()
      smoothCurve(ctx, pts)
      ctx.stroke()
      ctx.setLineDash([])
    }

    ctx.globalAlpha = 1

    // Hover crosshair
    if (hoverX !== null) {
      const x = hoverX
      ctx.strokeStyle = th.textMuted
      ctx.lineWidth = 0.5
      ctx.setLineDash([3, 3])
      ctx.beginPath(); ctx.moveTo(x, PAD.top); ctx.lineTo(x, PAD.top + ch); ctx.stroke()
      ctx.setLineDash([])
    }
  }, [frame, data, hoverX, size])

  const handleMove = useCallback((e: React.MouseEvent) => {
    const canvas = canvasRef.current
    if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    const x = (e.clientX - rect.left) / rect.width * size.w
    if (x >= PAD.left && x <= size.w - PAD.right) setHoverX(x)
    else setHoverX(null)
  }, [size])

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%', minHeight: 140, height: '100%' }}>
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', display: 'block' }}
        onMouseMove={handleMove}
        onMouseLeave={() => setHoverX(null)}
      />
    </div>
  )
}
