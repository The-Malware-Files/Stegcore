// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useEffect, useRef, useState } from 'react'

interface SplashProps {
  onComplete: () => void
}

export default function SplashDark({ onComplete }: SplashProps) {
  const topBarRef = useRef<SVGRectElement>(null)
  const midLeftRef = useRef<SVGRectElement>(null)
  const midRightRef = useRef<SVGRectElement>(null)
  const bottomBarRef = useRef<SVGRectElement>(null)
  const pulseRef = useRef<SVGCircleElement>(null)
  const stegRef = useRef<HTMLSpanElement>(null)
  const coreRef = useRef<HTMLSpanElement>(null)
  const taglineRef = useRef<HTMLParagraphElement>(null)

  const [visible, setVisible] = useState(true)

  useEffect(() => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    if (reduced) {
      // Show final state immediately
      const els = [topBarRef, midLeftRef, midRightRef, bottomBarRef]
      els.forEach(r => { if (r.current) r.current.style.opacity = '1' })
      if (pulseRef.current) pulseRef.current.style.opacity = '0'
      if (stegRef.current) { stegRef.current.style.opacity = '1'; stegRef.current.style.transform = 'translateX(0)' }
      if (coreRef.current) { coreRef.current.style.opacity = '1'; coreRef.current.style.transform = 'translateX(0)' }
      if (taglineRef.current) taglineRef.current.style.opacity = '1'
      const t = setTimeout(onComplete, 800)
      return () => clearTimeout(t)
    }

    // Sequence the animation
    const timers: ReturnType<typeof setTimeout>[] = []

    // t=0: top bar from left, bottom bar from right
    const t1 = setTimeout(() => {
      if (topBarRef.current) {
        topBarRef.current.style.transition = 'transform 440ms cubic-bezier(0.22,1,0.36,1), opacity 200ms ease'
        topBarRef.current.style.transform = 'translateX(0)'
        topBarRef.current.style.opacity = '1'
      }
      if (bottomBarRef.current) {
        bottomBarRef.current.style.transition = 'transform 440ms cubic-bezier(0.22,1,0.36,1), opacity 200ms ease'
        bottomBarRef.current.style.transform = 'translateX(0)'
        bottomBarRef.current.style.opacity = '1'
      }
    }, 0)
    timers.push(t1)

    // t=120: mid bars from their sides
    const t2 = setTimeout(() => {
      if (midLeftRef.current) {
        midLeftRef.current.style.transition = 'transform 400ms cubic-bezier(0.22,1,0.36,1), opacity 200ms ease'
        midLeftRef.current.style.transform = 'translateX(0)'
        midLeftRef.current.style.opacity = '1'
      }
      if (midRightRef.current) {
        midRightRef.current.style.transition = 'transform 400ms cubic-bezier(0.22,1,0.36,1), opacity 200ms ease'
        midRightRef.current.style.transform = 'translateX(0)'
        midRightRef.current.style.opacity = '1'
      }
    }, 120)
    timers.push(t2)

    // t=300: radial pulse
    const t3 = setTimeout(() => {
      if (pulseRef.current) {
        pulseRef.current.style.transition = 'r 800ms ease-out, opacity 800ms ease-out'
        pulseRef.current.style.opacity = '0'
        pulseRef.current.setAttribute('r', '80')
      }
    }, 300)
    timers.push(t3)

    // t=520: STEG from left, CORE from right
    const t4 = setTimeout(() => {
      if (stegRef.current) {
        stegRef.current.style.transition = 'transform 380ms cubic-bezier(0.22,1,0.36,1), opacity 200ms ease'
        stegRef.current.style.transform = 'translateX(0)'
        stegRef.current.style.opacity = '1'
      }
      if (coreRef.current) {
        coreRef.current.style.transition = 'transform 380ms cubic-bezier(0.22,1,0.36,1), opacity 200ms ease'
        coreRef.current.style.transform = 'translateX(0)'
        coreRef.current.style.opacity = '1'
      }
    }, 520)
    timers.push(t4)

    // t=820: tagline fade in
    const t5 = setTimeout(() => {
      if (taglineRef.current) {
        taglineRef.current.style.transition = 'opacity 380ms ease'
        taglineRef.current.style.opacity = '1'
      }
    }, 820)
    timers.push(t5)

    // t=820+380+300=1500: call onComplete
    const t6 = setTimeout(() => {
      setVisible(false)
      onComplete()
    }, 1500)
    timers.push(t6)

    return () => timers.forEach(clearTimeout)
  }, [onComplete])

  if (!visible) return null

  return (
    <>
      <style>{`
        .sc-splash-bar { opacity: 0; }
        .sc-splash-word { opacity: 0; }
        .sc-splash-tagline { opacity: 0; }
        .sc-pulse { opacity: 0.25; }
      `}</style>
      <div style={{
        position: 'fixed',
        inset: 0,
        zIndex: 9999,
        background: '#04080f',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '28px',
        overflow: 'hidden',
      }}>
        {/* Icon */}
        <svg
          width="96"
          height="96"
          viewBox="0 0 64 64"
          style={{ overflow: 'visible' }}
        >
          {/* Radial pulse — emits from centre on collision */}
          <circle
            ref={pulseRef}
            className="sc-pulse"
            cx="32"
            cy="34"
            r="4"
            fill="none"
            stroke="#2a7fff"
            strokeWidth="1.5"
          />
          <rect
            ref={topBarRef}
            className="sc-splash-bar"
            x="8" y="10" width="48" height="12" rx="2.5"
            fill="#4da6ff"
            style={{ transform: 'translateX(-80px)' }}
          />
          <rect
            ref={midLeftRef}
            className="sc-splash-bar"
            x="8" y="28" width="21" height="12" rx="2.5"
            fill="#2a7fff"
            style={{ transform: 'translateX(-60px)' }}
          />
          <rect
            ref={midRightRef}
            className="sc-splash-bar"
            x="35" y="28" width="21" height="12" rx="2.5"
            fill="#2a7fff"
            style={{ transform: 'translateX(60px)' }}
          />
          <rect
            ref={bottomBarRef}
            className="sc-splash-bar"
            x="8" y="46" width="48" height="12" rx="2.5"
            fill="#1252cc"
            style={{ transform: 'translateX(80px)' }}
          />
        </svg>

        {/* Wordmark */}
        <div style={{
          display: 'flex',
          overflow: 'hidden',
          letterSpacing: '0.2em',
          fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Ubuntu, sans-serif',
          fontWeight: 500,
          fontSize: '28px',
          color: '#c8d8f2',
          textTransform: 'uppercase',
        }}>
          <span
            ref={stegRef}
            className="sc-splash-word"
            style={{ display: 'inline-block', transform: 'translateX(-60px)' }}
          >
            STEG
          </span>
          <span
            ref={coreRef}
            className="sc-splash-word"
            style={{ display: 'inline-block', transform: 'translateX(60px)' }}
          >
            CORE
          </span>
        </div>

        {/* Tagline */}
        <p
          ref={taglineRef}
          className="sc-splash-tagline"
          style={{
            margin: 0,
            fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Ubuntu, sans-serif',
            fontSize: '11px',
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
            color: '#2a7fff',
          }}
        >
          HIDE · ENCRYPT · DENY
        </p>
      </div>
    </>
  )
}
