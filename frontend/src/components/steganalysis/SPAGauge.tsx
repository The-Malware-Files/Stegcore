// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useRef, useEffect } from 'react'
import { getTheme, easeOut, clamp } from './analysisTheme'
import { useAnimationFrame, useContainerSize } from './useAnimationFrame'
import type { SteganalysisResult } from './types'

interface Props {
  data: SteganalysisResult
  replay: boolean
  onReplayDone: () => void
}

const DPR = Math.min(typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1, 2)
const START_ANGLE = Math.PI * 0.75
const ARC_SPAN = Math.PI * 1.5

export function SPAGauge({ data, replay, onReplayDone }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [containerRef, containerSize] = useContainerSize()
  const [frame, resetFrame] = useAnimationFrame(100)
  const size = Math.min(containerSize.w, containerSize.h)

  useEffect(() => { if (replay) { resetFrame(); onReplayDone() } }, [replay, resetFrame, onReplayDone])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const s = size
    canvas.width = s * DPR
    canvas.height = s * DPR
    ctx.scale(DPR, DPR)
    ctx.clearRect(0, 0, s, s)
    const th = getTheme()

    const cx = s / 2, cy = s * 0.48
    const r = Math.min(s * 0.38, s * 0.38)
    const t = frame
    const { estimated_rate, confidence } = data.sample_pair

    // Animation progress
    let p = easeOut(Math.min(1, t / 55))
    let currentValue = estimated_rate * p
    const currentConf = confidence * p

    // Bounce (frames 55-80)
    if (t > 55 && t < 80) {
      const bounceT = t - 55
      const bounce = Math.sin(bounceT * 0.3) * 0.03 * Math.max(0, 1 - bounceT / 25)
      currentValue = clamp(estimated_rate + bounce, 0, 1)
      p = 1
    } else if (t >= 80) {
      currentValue = estimated_rate
      p = 1
    }

    // 1. Tick marks
    for (let i = 0; i <= 10; i++) {
      const frac = i / 10
      const angle = START_ANGLE + ARC_SPAN * frac
      const isMajor = i % 2.5 === 0 || i === 0 || i === 10
      const len = isMajor ? 10 : 6
      const x1 = cx + Math.cos(angle) * r
      const y1 = cy + Math.sin(angle) * r
      const x2 = cx + Math.cos(angle) * (r + 2)
      const y2 = cy + Math.sin(angle) * (r + 2)
      const x3 = cx + Math.cos(angle) * (r - len)
      const y3 = cy + Math.sin(angle) * (r - len)
      ctx.strokeStyle = isMajor ? th.textMuted : th.gridLine
      ctx.lineWidth = isMajor ? 1 : 0.5
      ctx.beginPath(); ctx.moveTo(x2, y2); ctx.lineTo(x3, y3); ctx.stroke()
      void x1; void y1
    }

    const textAlpha = easeOut(Math.max(0, (t - 50) / 30))

    // 2. "0" and "1" labels
    ctx.font = '10px "Space Mono", monospace'
    ctx.fillStyle = th.textMuted
    ctx.textAlign = 'center'
    ctx.globalAlpha = textAlpha
    const lbl0Angle = START_ANGLE
    const lbl1Angle = START_ANGLE + ARC_SPAN
    ctx.fillText('0', cx + Math.cos(lbl0Angle) * (r - 16), cy + Math.sin(lbl0Angle) * (r - 16) + 3)
    ctx.fillText('1', cx + Math.cos(lbl1Angle) * (r - 16), cy + Math.sin(lbl1Angle) * (r - 16) + 3)
    ctx.globalAlpha = 1

    // 3. Background track
    ctx.strokeStyle = th.gridLine
    ctx.lineWidth = 10
    ctx.lineCap = 'round'
    ctx.beginPath()
    ctx.arc(cx, cy, r, START_ANGLE, START_ANGLE + ARC_SPAN)
    ctx.stroke()

    // 4. Confidence band
    ctx.strokeStyle = 'rgba(77,159,255,0.15)'
    ctx.lineWidth = 10
    ctx.beginPath()
    ctx.arc(cx, cy, r, START_ANGLE, START_ANGLE + ARC_SPAN * currentConf)
    ctx.stroke()

    // 5. Value arc with gradient
    const grad = ctx.createLinearGradient(
      cx + Math.cos(START_ANGLE) * r, cy + Math.sin(START_ANGLE) * r,
      cx + Math.cos(START_ANGLE + ARC_SPAN) * r, cy + Math.sin(START_ANGLE + ARC_SPAN) * r,
    )
    grad.addColorStop(0, th.green)
    grad.addColorStop(0.55, th.blue)
    grad.addColorStop(1, th.red)
    ctx.strokeStyle = grad
    ctx.lineWidth = 10
    ctx.lineCap = 'round'
    ctx.beginPath()
    ctx.arc(cx, cy, r, START_ANGLE, START_ANGLE + ARC_SPAN * currentValue)
    ctx.stroke()

    // 5b. Confidence interval band (±5% shaded region around value)
    if (p > 0.3) {
      const ciWidth = 0.05 // ±5%
      const ciLow = clamp(currentValue - ciWidth, 0, 1)
      const ciHigh = clamp(currentValue + ciWidth, 0, 1)
      const ciStartAngle = START_ANGLE + ARC_SPAN * ciLow
      const ciEndAngle = START_ANGLE + ARC_SPAN * ciHigh
      ctx.strokeStyle = 'rgba(77,159,255,0.12)'
      ctx.lineWidth = 18
      ctx.lineCap = 'butt'
      ctx.beginPath()
      ctx.arc(cx, cy, r, ciStartAngle, ciEndAngle)
      ctx.stroke()
      ctx.lineCap = 'round'
    }

    // 6. Needle
    const needleAngle = START_ANGLE + ARC_SPAN * currentValue
    const nx1 = cx + Math.cos(needleAngle) * (r - 13)
    const ny1 = cy + Math.sin(needleAngle) * (r - 13)
    const nx2 = cx + Math.cos(needleAngle) * (r + 4)
    const ny2 = cy + Math.sin(needleAngle) * (r + 4)
    ctx.save()
    ctx.shadowColor = th.textMuted
    ctx.shadowBlur = 8
    ctx.strokeStyle = th.textPrimary
    ctx.lineWidth = 2
    ctx.beginPath(); ctx.moveTo(nx1, ny1); ctx.lineTo(nx2, ny2); ctx.stroke()
    ctx.restore()

    // 7. Centre readout (fade in last)
    ctx.globalAlpha = textAlpha
    ctx.font = '700 22px "Syne", "Space Grotesk", sans-serif'
    ctx.fillStyle = th.textPrimary
    ctx.textAlign = 'center'
    ctx.textBaseline = 'middle'
    ctx.fillText(`${Math.round(currentValue * 100)}%`, cx, cy - 4)
    ctx.font = '10px "Space Mono", monospace'
    ctx.fillStyle = th.textMuted
    ctx.fillText('EMBEDDED', cx, cy + 14)

    // 8. Confidence label — removed, pill handles this
    ctx.textBaseline = 'alphabetic'
    ctx.globalAlpha = 1
  }, [frame, data, size])

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%', minHeight: 160, height: '100%' }}>
      <canvas
        ref={canvasRef}
        style={{ width: size, height: size, display: 'block', margin: '0 auto' }}
      />
    </div>
  )
}
