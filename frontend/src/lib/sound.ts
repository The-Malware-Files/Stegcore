// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

/**
 * Subtle success/error audio feedback using Web Audio API.
 * No external audio files needed — tones are synthesised.
 * Respects the user's reduce-motion setting (no sound when enabled).
 */

let ctx: AudioContext | null = null

function getCtx(): AudioContext | null {
  if (typeof window === 'undefined') return null
  if (!ctx) {
    try { ctx = new AudioContext() } catch { return null }
  }
  return ctx
}

/** Short ascending two-note chime — embed/extract success */
export function playSuccess() {
  const c = getCtx()
  if (!c) return
  const now = c.currentTime
  const gain = c.createGain()
  gain.connect(c.destination)
  gain.gain.setValueAtTime(0.08, now)
  gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3)

  const o1 = c.createOscillator()
  o1.type = 'sine'
  o1.frequency.setValueAtTime(880, now)
  o1.connect(gain)
  o1.start(now)
  o1.stop(now + 0.15)

  const o2 = c.createOscillator()
  o2.type = 'sine'
  o2.frequency.setValueAtTime(1320, now + 0.1)
  o2.connect(gain)
  o2.start(now + 0.1)
  o2.stop(now + 0.3)
}

/** Short descending two-note chime for error / failure feedback.
 *  Synthesised via Web Audio (no asset dep, no loading lag, plays even
 *  when the bundled audio file would have been blocked by autoplay
 *  policy). Mirrors playSuccess in shape so the two stay tonally
 *  consistent. */
export function playError() {
  const c = getCtx()
  if (!c) return
  const now = c.currentTime
  const gain = c.createGain()
  gain.connect(c.destination)
  gain.gain.setValueAtTime(0.07, now)
  gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35)

  const o1 = c.createOscillator()
  o1.type = 'sine'
  o1.frequency.setValueAtTime(440, now)
  o1.connect(gain)
  o1.start(now)
  o1.stop(now + 0.18)

  const o2 = c.createOscillator()
  o2.type = 'sine'
  o2.frequency.setValueAtTime(330, now + 0.12)
  o2.connect(gain)
  o2.start(now + 0.12)
  o2.stop(now + 0.35)
}
