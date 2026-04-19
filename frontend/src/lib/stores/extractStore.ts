// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { create } from 'zustand'

export type ExtractStep = 1 | 2 | 3

interface ExtractStore {
  step: ExtractStep
  stegoFile: File | null
  stegoPath: string | null  // real filesystem path
  stegoPreviewUrl: string | null
  keyFile: File | null
  keyFilePath: string | null  // real filesystem path
  keyFileMetadata: Record<string, unknown> | null
  passphrase: string
  result: Uint8Array | null
  resultText: string | null
  error: string | null
  extracting: boolean

  setStep: (s: ExtractStep) => void
  setStegoFile: (f: File | null, previewUrl: string | null, path?: string | null) => void
  setKeyFile: (f: File | null, metadata: Record<string, unknown> | null, path?: string | null) => void
  setPassphrase: (p: string) => void
  setResult: (bytes: Uint8Array) => void
  setError: (e: string | null) => void
  setExtracting: (v: boolean) => void
  reset: () => void
}

const INITIAL = {
  step: 1 as ExtractStep,
  stegoFile: null as File | null,
  stegoPath: null as string | null,
  stegoPreviewUrl: null as string | null,
  keyFile: null as File | null,
  keyFilePath: null as string | null,
  keyFileMetadata: null as Record<string, unknown> | null,
  passphrase: '',
  result: null as Uint8Array | null,
  resultText: null as string | null,
  error: null as string | null,
  extracting: false,
}

export const useExtractStore = create<ExtractStore>((set) => ({
  ...INITIAL,

  setStep: (step) => set({ step }),
  setStegoFile: (stegoFile, stegoPreviewUrl, stegoPath) => set({ stegoFile, stegoPreviewUrl, stegoPath: stegoPath ?? null }),
  setKeyFile: (keyFile, keyFileMetadata, keyFilePath) => set({ keyFile, keyFileMetadata, keyFilePath: keyFilePath ?? null }),
  setPassphrase: (passphrase) => set({ passphrase }),

  setResult: (result) => {
    let resultText: string | null = null
    try {
      resultText = new TextDecoder('utf-8', { fatal: true }).decode(result)
    } catch {
      resultText = null
    }
    set({ result, resultText, error: null, passphrase: '' })
  },

  setError: (error) => set({ error, extracting: false }),
  setExtracting: (extracting) => set({ extracting }),

  reset: () => set({ ...INITIAL }),
}))
