// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useRef, useEffect } from 'react'
import { getTheme, easeOut } from './analysisTheme'
import { useAnimationFrame, useContainerSize } from './useAnimationFrame'

interface Props {
  /** Normalised LSB entropy values per block (0.0–1.0) */
  values: number[]
  replay: boolean
  onReplayDone: () => void
}

const PAD = { left: 10, right: 10, top: 8, bottom: 24 }
const DPR = Math.min(typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1, 2)

export function AudioWaveform({ values, replay, onReplayDone }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [containerRef, size] = useContainerSize()
  const [frame, resetFrame] = useAnimationFrame(100)

  useEffect(() => { if (replay) { resetFrame(); onReplayDone() } }, [replay, resetFrame, onReplayDone])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || values.length === 0) return
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
    const revealProgress = easeOut(Math.min(1, t / 70))
    const textAlpha = easeOut(Math.max(0, (t - 50) / 30))

    const n = values.length
    const barW = cw / n
    const midY = PAD.top + ch / 2

    // Centre line
    ctx.strokeStyle = th.gridLine
    ctx.lineWidth = 0.5
    ctx.beginPath()
    ctx.moveTo(PAD.left, midY)
    ctx.lineTo(PAD.left + cw, midY)
    ctx.stroke()

    // Waveform bars — each value drives the bar height (0.5 = flat, 1.0 = max)
    const revealedBars = Math.floor(n * revealProgress)
    for (let i = 0; i < revealedBars; i++) {
      const v = values[i]
      // Map entropy to bar height: 0.5 = natural (short), 1.0 = anomalous (tall)
      const amplitude = v * 0.9
      const barH = amplitude * (ch / 2)
      const x = PAD.left + i * barW

      // Colour: green (low entropy) → amber → red (high entropy)
      let color: string
      if (v < 0.4) color = th.green
      else if (v < 0.7) color = th.amber
      else color = th.red

      // Draw symmetric bars (up and down from centre)
      ctx.fillStyle = color
      ctx.globalAlpha = 0.7 + v * 0.3

      // Upper bar
      ctx.fillRect(x + 1, midY - barH, barW - 2, barH)
      // Lower bar (mirror)
      ctx.fillRect(x + 1, midY, barW - 2, barH)

      ctx.globalAlpha = 1
    }

    // Highlight hot zones with a subtle glow
    if (t > 60) {
      for (let i = 0; i < n; i++) {
        if (values[i] > 0.7) {
          const x = PAD.left + i * barW + barW / 2
          const pulseAlpha = 0.15 + 0.05 * Math.sin((t - 60) * 0.1 + i * 0.3)
          ctx.fillStyle = th.red
          ctx.globalAlpha = pulseAlpha
          ctx.beginPath()
          ctx.arc(x, midY, barW * 1.5, 0, Math.PI * 2)
          ctx.fill()
          ctx.globalAlpha = 1
        }
      }
    }

    // Labels
    ctx.globalAlpha = textAlpha
    ctx.font = '10px "Space Mono", monospace'
    ctx.fillStyle = th.textMuted
    ctx.textAlign = 'center'
    ctx.fillText('Audio sample blocks', PAD.left + cw / 2, h - 4)

    // Anomaly indicator labels
    ctx.textAlign = 'left'
    ctx.fillStyle = th.green
    ctx.fillText('Normal', PAD.left, h - 4)
    ctx.textAlign = 'right'
    ctx.fillStyle = th.red
    ctx.fillText('Anomalous', PAD.left + cw, h - 4)
    ctx.globalAlpha = 1
  }, [frame, values, size])

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%', minHeight: 160, height: '100%' }}>
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', display: 'block' }}
      />
    </div>
  )
}
