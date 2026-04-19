// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Theme-aware colours for the steganalysis dashboard.
// Resolves from CSS custom properties so it works in both dark and light mode.

function css(varName: string, fallback: string): string {
  if (typeof document === 'undefined') return fallback
  return getComputedStyle(document.documentElement).getPropertyValue(varName).trim() || fallback
}

/** Call this at render time to get current theme colours. */
export function getTheme() {
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light'
  return {
    bg:           css('--ui-bg', isDark ? '#080c14' : '#f0f4fa'),
    surface:      isDark ? 'rgba(255,255,255,0.028)' : 'rgba(0,0,0,0.03)',
    border:       isDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.08)',
    borderHover:  isDark ? 'rgba(255,255,255,0.18)' : 'rgba(0,0,0,0.2)',
    textPrimary:  css('--sc-text-primary', isDark ? '#e8edf5' : '#0d1520'),
    textMuted:    isDark ? 'rgba(255,255,255,0.25)' : 'rgba(0,0,0,0.35)',
    textFaint:    isDark ? '#3a4558' : '#94a3b8',

    // These accent colours work on both backgrounds
    red:    '#ff5c5c',
    green:  '#3dd6a3',
    blue:   '#4d9fff',
    amber:  '#f5c842',

    channelR: '#ff5c5c',
    channelG: '#3dd6a3',
    channelB: '#4d9fff',

    rsCurveR:  '#4d9fff',
    rsCurveS:  '#ff7c5c',
    rsCurveRM: isDark ? 'rgba(77,159,255,0.55)' : 'rgba(29,78,216,0.45)',
    rsCurveSM: isDark ? 'rgba(255,124,92,0.55)' : 'rgba(220,38,38,0.45)',

    gridLine:   isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
    axisLine:   isDark ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.15)',
  }
}

// Static fallback for non-canvas uses (React inline styles)
export const THEME = {
  surface:      'var(--ui-surface)',
  border:       'var(--ui-border)',
  borderHover:  'var(--ui-border2)',
  textPrimary:  'var(--ui-text)',
  textMuted:    'var(--ui-text2)',

  red:    '#ff5c5c',
  green:  '#3dd6a3',
  blue:   '#4d9fff',
  amber:  '#f5c842',
}

export const easeOut = (t: number) => 1 - Math.pow(1 - Math.min(1, Math.max(0, t)), 3)
export const easeInOut = (t: number) => {
  t = Math.min(1, Math.max(0, t))
  return t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2
}
export const lerp = (a: number, b: number, t: number) => a + (b - a) * t
export const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

export function scoreColor(score: number): string {
  // Aligned with verdict thresholds: Clean (<25), Suspicious (25–55), Likely Stego (>55)
  if (score < 25) return THEME.green
  if (score <= 55) return THEME.amber
  return THEME.red
}

export function heatColor(v: number): [number, number, number] {
  if (v < 0.33) {
    const t = v / 0.33
    return [lerp(40, 245, t), lerp(190, 200, t), lerp(120, 66, t)]
  } else if (v < 0.66) {
    const t = (v - 0.33) / 0.33
    return [lerp(245, 255, t), lerp(200, 80, t), lerp(66, 55, t)]
  } else {
    const t = (v - 0.66) / 0.34
    return [lerp(255, 220, t), lerp(80, 30, t), lerp(55, 70, t)]
  }
}
