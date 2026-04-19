// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useEffect, useRef, useState } from 'react'
import { playSuccess, playError } from '../lib/sound'

interface ProcessingScreenProps {
  phase: string
  status: 'processing' | 'success' | 'error'
  errorMessage?: string
  onRetry?: () => void
  onComplete?: () => void
}

/** 64px animated spinner — scaled-up version of the button SpinnerIcon. */
function LargeSpinner({ fading }: { fading: boolean }) {
  return (
    <svg
      width={64}
      height={64}
      viewBox="0 0 64 64"
      style={{
        display: 'block',
        transition: 'opacity 200ms ease-out, transform 200ms ease-out',
        opacity: fading ? 0 : 1,
        transform: fading ? 'scale(0.8)' : 'scale(1)',
      }}
    >
      {/* Track circle */}
      <circle
        cx="32" cy="32" r="26"
        fill="none"
        stroke="var(--ui-accent)"
        strokeWidth="3"
        strokeOpacity="0.15"
      />
      {/* Active arc */}
      <circle
        cx="32" cy="32" r="26"
        fill="none"
        stroke="var(--ui-accent)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray="40 124"
        style={{ animation: 'spin 1s linear infinite', transformOrigin: 'center' }}
      />
    </svg>
  )
}

/** 64px animated checkmark — spring chime effect. */
function LargeCheck() {
  return (
    <svg
      width={64}
      height={64}
      viewBox="0 0 52 52"
      style={{
        display: 'block',
        animation: 'sc-icon-spring 400ms cubic-bezier(0.34, 1.56, 0.64, 1) forwards',
      }}
    >
      <circle
        cx="26" cy="26" r="24"
        fill="none"
        stroke="var(--ui-success)"
        strokeWidth="2"
        strokeDasharray="151"
        strokeDashoffset="151"
        style={{ animation: 'sc-check-circle 0.4s ease-out 0.1s forwards' }}
      />
      <path
        d="M14 27l7 7 16-16"
        fill="none"
        stroke="var(--ui-success)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeDasharray="40"
        strokeDashoffset="40"
        style={{ animation: 'sc-check-tick 0.3s ease-out 0.45s forwards' }}
      />
    </svg>
  )
}

/** 64px animated X mark — matches SuccessCheck pattern. */
function LargeError() {
  return (
    <svg
      width={64}
      height={64}
      viewBox="0 0 52 52"
      style={{
        display: 'block',
        animation: 'sc-icon-spring 400ms cubic-bezier(0.34, 1.56, 0.64, 1) forwards',
      }}
    >
      <circle
        cx="26" cy="26" r="24"
        fill="none"
        stroke="var(--ui-danger)"
        strokeWidth="2"
        strokeDasharray="151"
        strokeDashoffset="151"
        style={{ animation: 'sc-check-circle 0.4s ease-out 0.1s forwards' }}
      />
      <path
        d="M17 17l18 18"
        fill="none"
        stroke="var(--ui-danger)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray="26"
        strokeDashoffset="26"
        style={{ animation: 'sc-check-tick 0.25s ease-out 0.4s forwards' }}
      />
      <path
        d="M35 17l-18 18"
        fill="none"
        stroke="var(--ui-danger)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeDasharray="26"
        strokeDashoffset="26"
        style={{ animation: 'sc-check-tick 0.25s ease-out 0.5s forwards' }}
      />
    </svg>
  )
}

/**
 * Full-screen processing overlay for embed/extract operations.
 * Covers the content area with an opaque background and shows
 * a large spinner → checkmark/X transition.
 */
export function ProcessingScreen({
  phase,
  status,
  errorMessage,
  onRetry,
  onComplete,
}: ProcessingScreenProps) {
  const [dismissing, setDismissing] = useState(false)
  const prevStatus = useRef(status)

  // Play sound when status transitions to success or error
  useEffect(() => {
    if (prevStatus.current === 'processing' && status === 'success') {
      playSuccess()
    } else if (prevStatus.current === 'processing' && status === 'error') {
      playError()
    }
    prevStatus.current = status
  }, [status])

  // Auto-dismiss after success animation
  useEffect(() => {
    if (status !== 'success' || !onComplete) return
    const t1 = setTimeout(() => setDismissing(true), 600)
    const t2 = setTimeout(() => onComplete(), 800)
    return () => { clearTimeout(t1); clearTimeout(t2) }
  }, [status, onComplete])

  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        zIndex: 10,
        background: 'var(--ui-bg)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 24,
        animation: 'sc-processing-enter 200ms ease-out',
        opacity: dismissing ? 0 : 1,
        transition: 'opacity 200ms ease-out',
      }}
    >
      {/* Icon area — fixed size container for spinner/check/error swap */}
      <div style={{ width: 64, height: 64, position: 'relative' }}>
        {status === 'processing' && <LargeSpinner fading={false} />}
        {status === 'success' && <LargeCheck />}
        {status === 'error' && <LargeError />}
      </div>

      {/* Status text — crossfades on change */}
      <div style={{ height: 24, overflow: 'hidden', textAlign: 'center' }}>
        {status === 'processing' && (
          <span
            key={phase}
            style={{
              display: 'block',
              fontSize: 13,
              color: 'var(--ui-text2)',
              fontFamily: "'Space Mono', monospace",
              letterSpacing: '0.04em',
              animation: 'sc-phase-in 250ms ease-out',
            }}
          >
            {phase}
          </span>
        )}
        {status === 'success' && (
          <span
            style={{
              display: 'block',
              fontSize: 13,
              color: 'var(--ui-success)',
              fontWeight: 500,
              animation: 'sc-phase-in 200ms ease-out 200ms both',
            }}
          >
            Done
          </span>
        )}
        {status === 'error' && (
          <span
            style={{
              display: 'block',
              fontSize: 13,
              color: 'var(--ui-danger)',
              animation: 'sc-phase-in 200ms ease-out',
              maxWidth: 320,
            }}
          >
            {errorMessage || 'Something went wrong'}
          </span>
        )}
      </div>

      {/* Retry button — error state only */}
      {status === 'error' && onRetry && (
        <button
          onClick={onRetry}
          style={{
            fontSize: 13,
            color: 'var(--ui-accent)',
            background: 'transparent',
            border: '1px solid var(--ui-border)',
            borderRadius: 'var(--sc-radius-btn)',
            padding: '8px 20px',
            cursor: 'pointer',
            animation: 'sc-phase-in 200ms ease-out 300ms both',
          }}
        >
          Try Again
        </button>
      )}
    </div>
  )
}
