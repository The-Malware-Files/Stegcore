// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

export type Theme = 'dark' | 'light' | 'system'

const STORAGE_KEY = 'stegcore-theme'

function systemPreference(): 'dark' | 'light' {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

/** Return the theme that is actually applied (resolves 'system'). */
export function effectiveTheme(): 'dark' | 'light' {
  const stored = (localStorage.getItem(STORAGE_KEY) ?? 'system') as Theme
  if (stored === 'system') return systemPreference()
  return stored
}

/** Apply the given theme to the document root. */
function apply(theme: 'dark' | 'light') {
  document.documentElement.setAttribute('data-theme', theme)
}

/** Call once at startup (before first render) to restore persisted theme. */
export function initTheme(): void {
  apply(effectiveTheme())

  // Keep in sync if OS preference changes while 'system' is set
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const stored = (localStorage.getItem(STORAGE_KEY) ?? 'system') as Theme
    if (stored === 'system') apply(systemPreference())
  })
}

export function setTheme(theme: Theme): void {
  localStorage.setItem(STORAGE_KEY, theme)
  apply(effectiveTheme())
}

export function toggleTheme(): void {
  const current = effectiveTheme()
  setTheme(current === 'dark' ? 'light' : 'dark')
}

/** Apply 'reduce-motion' attribute based on settings. */
export function setReduceMotion(enabled: boolean): void {
  document.documentElement.setAttribute('data-reduce-motion', String(enabled))
}
