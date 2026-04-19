// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useEffect, useCallback, useRef } from 'react'
import { X, CheckCircle2, AlertTriangle, AlertCircle, Info } from 'lucide-react'
import { toast, type Toast, type ToastType } from '../lib/toast'

const ICON: Record<ToastType, typeof CheckCircle2> = {
  success: CheckCircle2,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
}

const ACCENT: Record<ToastType, string> = {
  success: 'var(--ui-success)',
  error: 'var(--ui-danger)',
  warning: 'var(--ui-warn)',
  info: 'var(--ui-accent)',
}

function ToastCard({ t }: { t: Toast }) {
  const Icon = ICON[t.type]
  const accent = ACCENT[t.type]
  const [exiting, setExiting] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const startRef = useRef(Date.now())
  const rafRef = useRef(0)

  const duration = t.duration || 0
  const showBar = !t.persistent && duration > 0

  const handleDismiss = useCallback(() => {
    setExiting(true)
    setTimeout(() => toast.remove(t.id), 250)
  }, [t.id])

  // Countdown bar animation
  useEffect(() => {
    if (!showBar) return
    startRef.current = Date.now()

    const tick = () => {
      const now = Date.now()
      const e = now - startRef.current
      setElapsed(e)
      if (e >= duration) {
        setExiting(true)
        setTimeout(() => toast.remove(t.id), 250)
        return
      }
      rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [showBar, duration, t.id])

  const progress = showBar ? Math.max(0, 1 - elapsed / duration) : 0

  return (
    <div
      role={t.type === 'error' ? 'alert' : undefined}
      style={{
        display: 'flex',
        flexDirection: 'column',
        borderRadius: 8,
        background: 'var(--ui-surface)',
        border: '1px solid var(--ui-border)',
        borderLeft: `3px solid ${accent}`,
        boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
        maxWidth: 340,
        overflow: 'hidden',
        animation: exiting ? 'toast-out 0.25s ease-in forwards' : 'toast-in 0.25s ease-out',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 14px' }}>
        <Icon size={16} style={{ color: accent, flexShrink: 0, marginTop: 1 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ fontSize: 13, color: 'var(--ui-text)', fontWeight: 500, lineHeight: 1.4 }}>
            {t.message}
          </p>
          {t.detail && (
            <p style={{ fontSize: 11, color: 'var(--ui-text2)', marginTop: 3, lineHeight: 1.4, wordBreak: 'break-word' }}>
              {t.detail}
            </p>
          )}
        </div>
        <button
          onClick={handleDismiss}
          aria-label="Dismiss"
          style={{
            background: 'transparent',
            border: 'none',
            cursor: 'pointer',
            color: 'var(--ui-text2)',
            padding: 0,
            display: 'flex',
            flexShrink: 0,
          }}
        >
          <X size={14} />
        </button>
      </div>
      {/* Countdown bar */}
      {showBar && (
        <div style={{
          height: 2,
          background: 'rgba(255,255,255,0.08)',
          overflow: 'hidden',
        }}>
          <div style={{
            height: '100%',
            width: `${progress * 100}%`,
            background: 'rgba(255,255,255,0.35)',
            transition: 'none',
          }} />
        </div>
      )}
    </div>
  )
}

export function ToastContainer() {
  const [toasts, setToasts] = useState<Toast[]>([])

  useEffect(() => {
    return toast.subscribe(setToasts)
  }, [])

  if (!toasts.length) return null

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label="Notifications"
      style={{
        position: 'fixed',
        top: 68,
        right: 16,
        zIndex: 9000,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        pointerEvents: 'auto',
      }}
    >
      {toasts.map((t) => (
        <ToastCard key={t.id} t={t} />
      ))}
      <style>{`
        @keyframes toast-in {
          from { opacity: 0; transform: translateX(20px); }
          to   { opacity: 1; transform: translateX(0); }
        }
        @keyframes toast-out {
          from { opacity: 1; transform: translateX(0); }
          to   { opacity: 0; transform: translateX(20px); }
        }
      `}</style>
    </div>
  )
}
