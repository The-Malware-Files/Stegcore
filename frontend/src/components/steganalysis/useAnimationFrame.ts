// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useEffect, useCallback, useRef } from 'react'

/**
 * Shared rAF hook with frame counter + reset.
 * Returns [frame, resetFrame].
 */
export function useAnimationFrame(maxFrames = 200): [number, () => void] {
  const [frame, setFrame] = useState(0)
  const rafRef = useRef<number>(0)
  const frameRef = useRef(0)

  const resetFrame = useCallback(() => {
    frameRef.current = 0
    setFrame(0)
    // Restart the rAF loop since it stopped at maxFrames
    cancelAnimationFrame(rafRef.current)
    const tick = () => {
      if (frameRef.current < maxFrames) {
        frameRef.current += 1
        setFrame(frameRef.current)
        rafRef.current = requestAnimationFrame(tick)
      }
    }
    rafRef.current = requestAnimationFrame(tick)
  }, [maxFrames])

  useEffect(() => {
    const tick = () => {
      if (frameRef.current < maxFrames) {
        frameRef.current += 1
        setFrame(frameRef.current)
        rafRef.current = requestAnimationFrame(tick)
      }
      // Stop requesting frames once maxFrames is reached — saves CPU/GPU
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [maxFrames])

  return [frame, resetFrame]
}

/**
 * Tracks container size via ResizeObserver.
 * Returns [ref, { w, h }] — attach ref to the container div.
 * Canvas components should use w/h to set canvas dimensions each frame.
 */
export function useContainerSize(): [React.RefObject<HTMLDivElement | null>, { w: number; h: number }] {
  const ref = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState({ w: 300, h: 160 })

  useEffect(() => {
    const el = ref.current
    if (!el) return

    const update = () => {
      const w = el.offsetWidth
      const h = el.offsetHeight
      if (w > 0 && h > 0) setSize({ w, h })
    }

    // Initial measure after layout settles
    const timer = setTimeout(update, 60)

    // Re-measure on resize
    const ro = new ResizeObserver(update)
    ro.observe(el)

    return () => {
      clearTimeout(timer)
      ro.disconnect()
    }
  }, [])

  return [ref, size]
}
