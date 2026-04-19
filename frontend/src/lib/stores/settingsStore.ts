// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { create } from 'zustand'
import type { Cipher, EmbedMode } from '../ipc'

export type FontSize = 'small' | 'default' | 'large' | 'xl'

export const FONT_SIZE_PX: Record<FontSize, number> = {
  small: 13,
  default: 14,
  large: 15,
  xl: 16,
}

export interface Settings {
  theme: 'dark' | 'light' | 'system'
  fontSize: FontSize
  reduceMotion: boolean
  defaultCipher: Cipher
  defaultMode: EmbedMode
  defaultOutputFolder: string
  autoExportKey: boolean
  autoScoreOnDrop: boolean
  passphraseMinLen: number
  clearClipboardSecs: number
  sessionTimeoutMins: number
  showTechnicalErrors: boolean
  bibleVerses: boolean
  defaultReportFormat: 'pdf' | 'html' | 'json' | 'csv'
  reportOutputFolder: string
}

const DEFAULTS: Settings = {
  theme: 'system',
  fontSize: 'default',
  reduceMotion: false,
  defaultCipher: 'chacha20-poly1305',
  defaultMode: 'adaptive',
  defaultOutputFolder: '',
  autoExportKey: false,
  autoScoreOnDrop: true,
  passphraseMinLen: 12,
  clearClipboardSecs: 30,
  sessionTimeoutMins: 0,
  showTechnicalErrors: false,
  bibleVerses: false,
  defaultReportFormat: 'pdf',
  reportOutputFolder: '',
}

interface SettingsStore {
  settings: Settings
  loaded: boolean
  load: () => Promise<void>
  update: (partial: Partial<Settings>) => void
}

export const useSettingsStore = create<SettingsStore>((set, get) => ({
  settings: { ...DEFAULTS },
  loaded: false,

  load: async () => {
    try {
      const { getSettings } = await import('../ipc')
      const remote = await getSettings()
      set({ settings: { ...DEFAULTS, ...remote }, loaded: true })
    } catch {
      // backend unavailable in dev — use defaults
      set({ loaded: true })
    }
  },

  update: (partial) => {
    const next = { ...get().settings, ...partial }
    set({ settings: next })

    // Apply side-effects immediately when relevant settings change
    if (partial.theme !== undefined) {
      import('../theme').then(({ setTheme }) => setTheme(partial.theme!))
    }
    if (partial.reduceMotion !== undefined) {
      import('../theme').then(({ setReduceMotion }) => setReduceMotion(partial.reduceMotion!))
    }
    if (partial.fontSize !== undefined) {
      document.documentElement.setAttribute('data-font-size', partial.fontSize)
    }

    // Fire-and-forget — errors are swallowed; UI shouldn't block on this
    import('../ipc').then(({ setSettings }) => setSettings(partial)).catch(() => undefined)
  },
}))
