// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface Toast {
  id: string
  type: ToastType
  message: string
  /** Technical detail shown when "Show technical error details" is on */
  detail?: string
  /** If true, stays until the user dismisses it */
  persistent: boolean
  duration: number // ms (0 = persistent)
}

type Listener = (toasts: Toast[]) => void

const MAX_VISIBLE = 3
let toasts: Toast[] = []
const listeners = new Set<Listener>()

function notify() {
  const copy = [...toasts]
  listeners.forEach((l) => l(copy))
}

function add(t: Omit<Toast, 'id'>): string {
  const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2)}`
  const entry: Toast = { ...t, id }

  // If at max capacity, remove the oldest non-persistent toast
  if (toasts.length >= MAX_VISIBLE) {
    const oldest = toasts.find((x) => !x.persistent)
    if (oldest) toasts = toasts.filter((x) => x.id !== oldest.id)
  }

  toasts = [...toasts, entry]
  notify()

  // Auto-dismiss is handled by the ToastCard component's countdown bar.
  // The store no longer uses setTimeout — the component manages its own lifecycle.

  return id
}

export const toast = {
  success(message: string, duration = 4000): string {
    return add({ type: 'success', message, persistent: false, duration })
  },

  error(message: string, detail?: string): string {
    // Errors auto-dismiss after 8 seconds (longer than success)
    return add({ type: 'error', message, detail, persistent: false, duration: 8000 })
  },

  warning(message: string, duration = 5000): string {
    return add({ type: 'warning', message, persistent: false, duration })
  },

  info(message: string, duration = 4000): string {
    return add({ type: 'info', message, persistent: false, duration })
  },

  /** Persistent toast — stays until dismissed or removed by ID. No countdown bar. */
  persistent(message: string, type: ToastType = 'info'): string {
    return add({ type, message, persistent: true, duration: 0 })
  },

  /** Long-duration toast (e.g. "Hit R to reload") — 30s with countdown. */
  long(message: string, type: ToastType = 'info', duration = 30000): string {
    return add({ type, message, persistent: false, duration })
  },

  remove(id: string): void {
    toasts = toasts.filter((t) => t.id !== id)
    notify()
  },

  subscribe(listener: Listener): () => void {
    listeners.add(listener)
    listener([...toasts])
    return () => listeners.delete(listener)
  },
}
