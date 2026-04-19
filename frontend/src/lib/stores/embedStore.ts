// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { create } from 'zustand'
import type { Cipher, EmbedMode, EmbedResult } from '../ipc'

export type EmbedStep = 1 | 2 | 3 | 4

interface EmbedStore {
  step: EmbedStep
  payloadFile: File | null
  payloadPath: string | null
  payloadSizeBytes: number
  coverFile: File | null
  coverPath: string | null
  coverSizeBytes: number
  coverPreviewUrl: string | null
  coverScore: number | null
  coverScoring: boolean
  cipher: Cipher
  mode: EmbedMode
  deniable: boolean
  decoyFile: File | null
  decoyPath: string | null
  passphrase: string
  decoyPassphrase: string
  exportKey: boolean
  outputPath: string | null
  result: EmbedResult | null
  error: string | null
  embedding: boolean

  setStep: (s: EmbedStep) => void
  setPayloadFile: (f: File | null, path?: string | null) => void
  setCoverFile: (f: File | null, previewUrl: string | null, path?: string | null) => void
  setCoverScore: (score: number | null, scoring?: boolean) => void
  setOptions: (opts: Partial<Pick<EmbedStore, 'cipher' | 'mode' | 'deniable' | 'decoyFile' | 'decoyPath' | 'passphrase' | 'decoyPassphrase' | 'exportKey'>>) => void
  setResult: (r: EmbedResult) => void
  setError: (e: string | null) => void
  setEmbedding: (v: boolean) => void
  reset: () => void
}

const INITIAL = {
  step: 1 as EmbedStep,
  payloadFile: null as File | null,
  payloadPath: null as string | null,
  payloadSizeBytes: 0,
  coverFile: null as File | null,
  coverPath: null as string | null,
  coverSizeBytes: 0,
  coverPreviewUrl: null as string | null,
  coverScore: null as number | null,
  coverScoring: false,
  cipher: 'chacha20-poly1305' as Cipher,
  mode: 'adaptive' as EmbedMode,
  deniable: false,
  decoyFile: null as File | null,
  decoyPath: null as string | null,
  passphrase: '',
  decoyPassphrase: '',
  exportKey: false,
  outputPath: null as string | null,
  result: null as EmbedResult | null,
  error: null as string | null,
  embedding: false,
}

export const useEmbedStore = create<EmbedStore>((set) => ({
  ...INITIAL,

  setStep: (step) => set({ step }),
  setPayloadFile: (payloadFile, payloadPath) => set({ payloadFile, payloadPath: payloadPath ?? null, payloadSizeBytes: payloadFile?.size ?? 0 }),
  setCoverFile: (coverFile, coverPreviewUrl, coverPath) => set({ coverFile, coverPreviewUrl, coverPath: coverPath ?? null, coverScore: null, coverSizeBytes: coverFile?.size ?? 0 }),
  setCoverScore: (coverScore, coverScoring = false) => set({ coverScore, coverScoring }),
  setOptions: (opts) => set(opts),
  setResult: (result) => set({ result, error: null, passphrase: '', decoyPassphrase: '' }),
  setError: (error) => set({ error, embedding: false }),
  setEmbedding: (embedding) => set({ embedding }),

  reset: () => set({ ...INITIAL }),
}))
