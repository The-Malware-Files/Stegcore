// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useRef, useEffect, useState, useCallback } from 'react'
import { easeOut, clamp, heatColor } from './analysisTheme'
import { useAnimationFrame, useContainerSize } from './useAnimationFrame'
import type { SteganalysisResult } from './types'

interface Props {
  data: SteganalysisResult
  replay: boolean
  onReplayDone: () => void
}

const PAD = { left: 26, right: 8, top: 10, bottom: 8 }
const DPR = Math.min(typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1, 2)

export function LSBHeatmap({ data, replay, onReplayDone }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [containerRef, size] = useContainerSize()
  const [frame, resetFrame] = useAnimationFrame(100)
  const [hoverCell, setHoverCell] = useState<[number, number] | null>(null)

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

    const grid = data.lsb_entropy.grid
    const G = grid.length
    if (G === 0) return
    const cols = grid[0].length

    const cw = w - PAD.left - PAD.right
    const ch = h - PAD.top - PAD.bottom
    const cellSize = Math.min(cw / cols, ch / G)
    const gridW = cellSize * cols
    const gridH = cellSize * G
    const offsetX = PAD.left + (cw - gridW) / 2
    const offsetY = PAD.top + (ch - gridH) / 2

    const t = frame
    const maxDist = Math.sqrt((G - 1) ** 2 + (cols - 1) ** 2)
    const waveFront = (t / 60) * maxDist * 1.6

    // Row/col labels (fade in last)
    const textAlpha = easeOut(clamp((t - 50) / 30, 0, 1))
    ctx.font = '10px "Space Mono", monospace'
    ctx.fillStyle = 'rgba(255,255,255,0.25)'
    ctx.globalAlpha = textAlpha
    ctx.textAlign = 'right'
    for (let r = 0; r < G; r++) {
      ctx.fillText(String(r), offsetX - 4, offsetY + r * cellSize + cellSize / 2 + 3)
    }
    ctx.textAlign = 'center'
    for (let c = 0; c < cols; c++) {
      ctx.fillText(String(c), offsetX + c * cellSize + cellSize / 2, offsetY - 3)
    }
    ctx.globalAlpha = 1

    // Cells
    for (let r = 0; r < G; r++) {
      for (let c = 0; c < cols; c++) {
        const v = grid[r][c]
        const dist = Math.sqrt(r * r + c * c)
        let alpha = easeOut(clamp((waveFront - dist) / 3.8, 0, 1))

        // Idle pulse for hot cells
        if (t > 60 && v > 0.65) {
          const pulse = 0.05 * Math.sin((t - 60) * 0.08 + r * 0.5 + c * 0.3)
          alpha = clamp(alpha + pulse, 0, 1)
        }

        const [cr, cg, cb] = heatColor(v)
        const fillAlpha = alpha * 0.9

        ctx.fillStyle = `rgba(${Math.round(cr)},${Math.round(cg)},${Math.round(cb)},${fillAlpha})`
        const x = offsetX + c * cellSize
        const y = offsetY + r * cellSize
        ctx.fillRect(x, y, cellSize - 1, cellSize - 1)

        // Hot cell inner stroke
        if (v > 0.7 && alpha > 0.5) {
          ctx.strokeStyle = `rgba(255,255,255,${alpha * 0.25})`
          ctx.lineWidth = 0.7
          ctx.strokeRect(x + 0.5, y + 0.5, cellSize - 2, cellSize - 2)
        }

        // Hover highlight
        if (hoverCell && hoverCell[0] === r && hoverCell[1] === c) {
          ctx.strokeStyle = 'rgba(255,255,255,0.5)'
          ctx.lineWidth = 1
          ctx.strokeRect(x, y, cellSize - 1, cellSize - 1)
        }
      }
    }
  }, [frame, data, hoverCell, size])

  const handleMove = useCallback((e: React.MouseEvent) => {
    const canvas = canvasRef.current
    if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    const mx = (e.clientX - rect.left) / rect.width * size.w
    const my = (e.clientY - rect.top) / rect.height * size.h

    const grid = data.lsb_entropy.grid
    const G = grid.length
    if (G === 0) return
    const cols = grid[0].length
    const cw = size.w - PAD.left - PAD.right
    const ch = size.h - PAD.top - PAD.bottom
    const cellSize = Math.min(cw / cols, ch / G)
    const gridW = cellSize * cols
    const gridH = cellSize * G
    const offsetX = PAD.left + (cw - gridW) / 2
    const offsetY = PAD.top + (ch - gridH) / 2

    const c = Math.floor((mx - offsetX) / cellSize)
    const r = Math.floor((my - offsetY) / cellSize)
    if (r >= 0 && r < G && c >= 0 && c < cols) setHoverCell([r, c])
    else setHoverCell(null)
  }, [data, size])

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%', minHeight: 160, height: '100%' }}>
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', display: 'block' }}
        onMouseMove={handleMove}
        onMouseLeave={() => setHoverCell(null)}
      />
    </div>
  )
}
