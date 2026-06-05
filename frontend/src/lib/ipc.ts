// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// ── Native file picker — returns full filesystem paths ──────────────────

export interface FilePickerOptions {
  title?: string
  multiple?: boolean
  filters?: Array<{ name: string; extensions: string[] }>
}

/** Open a native file dialog via Tauri plugin-dialog. Returns full paths.
 *  Falls back to empty array in browser dev mode. */
export async function pickFiles(opts: FilePickerOptions = {}): Promise<string[]> {
  try {
    const { open } = await import('@tauri-apps/plugin-dialog')
    const result = await open({
      title: opts.title,
      multiple: opts.multiple ?? false,
      filters: opts.filters,
    })
    if (!result) return []
    return Array.isArray(result) ? result : [result]
  } catch (e) {
    // Only return mocks when Tauri is genuinely unavailable (browser dev mode).
    // Real errors (permissions, plugin misconfiguration) must propagate.
    const msg = e instanceof Error ? e.message : String(e)
    const isTauriMissing = msg.includes('__TAURI_INTERNALS__') || msg.includes('not a function') || msg.includes('Cannot find module')
    if (isTauriMissing) {
      return opts.multiple ? ['/mock/file1.png', '/mock/file2.png'] : ['/mock/file.png']
    }
    return []
  }
}

// ── Safe invoke — degrades to mock when Tauri is unavailable (browser dev) ──

async function safeInvoke<T>(cmd: string, args?: unknown, mock?: T): Promise<T> {
  try {
    const { invoke } = await import('@tauri-apps/api/core')
    return await invoke<T>(cmd, args as Record<string, unknown>)
  } catch (e) {
    // Only use mock when Tauri is genuinely unavailable (browser dev mode).
    // Backend errors (wrong passphrase, file not found, etc.) must propagate.
    const msg = e instanceof Error ? e.message : String(e)
    const isTauriMissing = msg.includes('__TAURI_INTERNALS__') || msg.includes('not a function') || msg.includes('Cannot find module')
    if (isTauriMissing && mock !== undefined) return mock
    throw e
  }
}

export type Cipher = 'ascon-128' | 'chacha20-poly1305' | 'aes-256-gcm'
export type EmbedMode = 'adaptive' | 'sequential'

export interface EmbedOptions {
  cover: string
  payload: string
  passphrase: string
  cipher: Cipher
  mode: EmbedMode
  deniable: boolean
  decoyPayload?: string
  decoyPassphrase?: string
  exportKey: boolean
  output: string
}

export interface EmbedResult {
  outputPath: string
  keyFilePath?: string
}

export interface ExtractOptions {
  stego: string
  passphrase: string
  keyFile?: string
}

export type TestConfidence = 'low' | 'medium' | 'high'
export type Verdict = 'clean' | 'suspicious' | 'likely_stego'

export interface DistBin {
  label: string
  expected: number
  observed: number
}

export interface TestResult {
  name: string
  score: number
  confidence: TestConfidence
  detail: string
  distribution?: DistBin[]
}

export interface BlockEntropy {
  cols: number
  rows: number
  values: number[]
}

/** Confidence tier of a structural tool fingerprint.
 *
 *  - `"exact"` is decisive: a tool-specific magic / structural invariant
 *    matched (LSBSteg's 64-bit big-endian length header, Steghide's magic in
 *    the decrypted stream once T-26 lands, etc.). The engine short-circuits
 *    the ensemble and emits `Verdict::Stego` on an exact hit.
 *  - `"heuristic"` is corroborating only: the pattern is suggestive (e.g.
 *    LSBSteg's plausible length on a small image) but could occur naturally
 *    at low rates. The engine floors the verdict at `Suspicious`, not at
 *    `Stego`. Heuristic fingerprints lift a Clean verdict to Suspicious; they
 *    never demote a Stego verdict.
 *
 *  Frontends key off this value for the tier badge — colour, label and
 *  tooltip — without re-parsing `tool_fingerprint`.
 */
export type FingerprintTier = 'exact' | 'heuristic'

export interface AnalysisReport {
  file: string
  format: string
  tests: TestResult[]
  verdict: Verdict
  overall_score: number
  tool_fingerprint: string | null
  /** Tier of the matched fingerprint. `null` whenever `tool_fingerprint` is null. */
  tool_fingerprint_tier?: FingerprintTier | null
  block_entropy?: BlockEntropy
}

// ── Typed invoke() wrappers ──────────────────────────────────────────────

// ── Mock responses for dev mode ─────────────────────────────────────────

const MOCK_DIST: DistBin[] = Array.from({ length: 16 }, (_, i) => ({
  label: String(i * 16),
  expected: 40 + Math.random() * 20,
  observed: 38 + Math.random() * 24,
}))

const MOCK_REPORT: AnalysisReport = {
  file: '/mock/image.png',
  format: 'PNG',
  tests: [
    { name: 'Chi-Squared', score: 0.12, confidence: 'high', detail: 'LSB histogram within expected range', distribution: MOCK_DIST },
    { name: 'Sample Pair Analysis', score: 0.08, confidence: 'medium', detail: 'No fill ratio anomaly detected', distribution: MOCK_DIST.map(b => ({ ...b, expected: b.expected * 0.8, observed: b.observed * 0.82 })) },
    { name: 'RS Analysis', score: 0.11, confidence: 'high', detail: 'R/S ratio ≈ 1.0 — no asymmetry', distribution: [{ label: 'Regular', expected: 48, observed: 47 }, { label: 'Singular', expected: 48, observed: 49 }, { label: 'Unusable', expected: 4, observed: 4 }] },
    { name: 'LSB Entropy', score: 0.09, confidence: 'medium', detail: 'Entropy consistent with natural image noise' },
  ],
  verdict: 'clean',
  overall_score: 0.10,
  tool_fingerprint: null,
  tool_fingerprint_tier: null,
  block_entropy: { cols: 8, rows: 6, values: Array.from({ length: 48 }, () => 0.3 + Math.random() * 0.4) },
}

// ── Typed invoke() wrappers ──────────────────────────────────────────────

/** Returns the list of supported file extensions. */
export function getSupportedFormats(): Promise<string[]> {
  return safeInvoke<string[]>('get_supported_formats', undefined, ['png', 'bmp', 'jpg', 'jpeg', 'wav', 'webp', 'flac'])
}

/** Score a cover file for embedding suitability (0.0–1.0). */
export function scoreCover(path: string): Promise<number> {
  return safeInvoke<number>('score_cover', { path }, 0.72)
}

/** Embed a payload into a cover file. */
export function embed(opts: EmbedOptions): Promise<EmbedResult> {
  // Tauri v2 auto-converts camelCase → snake_case for Rust params
  return safeInvoke<EmbedResult>('embed', {
    cover: opts.cover,
    payload: opts.payload,
    passphrase: opts.passphrase,
    cipher: opts.cipher,
    mode: opts.mode,
    deniable: opts.deniable,
    decoyPayload: opts.decoyPayload ?? null,
    decoyPassphrase: opts.decoyPassphrase ?? null,
    exportKey: opts.exportKey,
    output: opts.output,
  }, { outputPath: '/mock/output.png' })
}

/** Extract hidden payload from a stego file. Returns raw bytes. */
export async function extract(opts: ExtractOptions): Promise<Uint8Array> {
  const result = await safeInvoke<number[] | Uint8Array>('extract', {
    stego: opts.stego,
    passphrase: opts.passphrase,
    keyFile: opts.keyFile ?? null,
  }, Array.from(new TextEncoder().encode('Hello from Stegcore (mock)')))
  // Tauri serialises Vec<u8> as a JSON array of numbers — convert to Uint8Array
  if (result instanceof Uint8Array) return result
  return new Uint8Array(result)
}

/** Analyse a single file for hidden content. */
export function analyseFile(path: string): Promise<AnalysisReport> {
  return safeInvoke<AnalysisReport>('analyse_file', { path }, { ...MOCK_REPORT, file: path })
}

/** Progressive analysis: returns fast preliminary results, full analysis runs in background.
 *  Listen for 'analysis_complete' Tauri event for the full report. */
export function analyseFileProgressive(path: string): Promise<AnalysisReport> {
  return safeInvoke<AnalysisReport>('analyse_file_progressive', { path }, { ...MOCK_REPORT, file: path })
}

/** Analyse multiple files. */
export function analyseBatchFiles(paths: string[]): Promise<Array<AnalysisReport | string>> {
  return safeInvoke<Array<AnalysisReport | string>>(
    'analyse_batch_files',
    { paths },
    paths.map((p) => ({ ...MOCK_REPORT, file: p })),
  )
}

/** Export an HTML report for the given file paths. Returns HTML string. */
export function exportHtmlReport(paths: string[]): Promise<string> {
  return safeInvoke<string>('export_html_report', { paths }, '<html><body><p>Mock report</p></body></html>')
}

// ── Settings ─────────────────────────────────────────────────────────────

export interface Settings {
  theme?: 'dark' | 'light' | 'system'
  fontSize?: 'small' | 'default' | 'large' | 'xl'
  reduceMotion?: boolean
  defaultCipher?: Cipher
  defaultMode?: EmbedMode
  defaultOutputFolder?: string
  autoExportKey?: boolean
  autoScoreOnDrop?: boolean
  showTechnicalErrors?: boolean
  bibleVerses?: boolean
  defaultReportFormat?: 'pdf' | 'html' | 'json' | 'csv'
  reportOutputFolder?: string
}

/** Load persisted settings from the Tauri app config dir. */
export function getSettings(): Promise<Settings> {
  return safeInvoke<Settings>('get_settings', undefined, {})
}

/** Persist a partial settings update. */
export function setSettings(partial: Partial<Settings>): Promise<void> {
  return safeInvoke<void>('set_settings', { settings: partial }, undefined)
}

/** Mark first-run setup as complete. */
export function completeSetup(theme: string, defaultCipher: string): Promise<void> {
  return safeInvoke<void>('complete_setup', { theme, defaultCipher }, undefined)
}

/**
 * Reveal a path in the OS file manager. Accepts a file or a directory; the
 * backend opens the parent folder when given a file. The mock is a no-op so
 * browser dev mode stays quiet; under Tauri, backend errors propagate.
 */
export function openFolder(path: string): Promise<void> {
  return safeInvoke<void>('open_folder', { path }, undefined)
}

// ── Aliases for sprint naming consistency ────────────────────────────────

export interface VerseData {
  text: string
  reference: string
}

export function getVerse(): Promise<VerseData> {
  return safeInvoke<VerseData>('get_verse', undefined, {
    text: 'For God so loved the world that he gave his one and only Son, that whoever believes in him shall not perish but have eternal life.',
    reference: 'John 3:16',
  })
}

export interface PixelDiffResult {
  totalPixels: number
  changedPixels: number
  percentChanged: number
  maxDelta: number
  lsbOnly: boolean
}

export function pixelDiff(original: string, stego: string): Promise<PixelDiffResult> {
  return safeInvoke<PixelDiffResult>('pixel_diff', { original, stego }, {
    totalPixels: 1920 * 1080, changedPixels: 12450, percentChanged: 0.6, maxDelta: 1, lsbOnly: true,
  })
}

export function getFileSize(path: string): Promise<number> {
  return safeInvoke<number>('file_size', { path }, 0)
}

export const analyseBatch = analyseBatchFiles

export function exportReport(paths: string[], format: string = 'html'): Promise<string> {
  if (format === 'csv') return safeInvoke<string>('export_csv_report', { paths }, 'File,Format,Verdict\nmock.png,PNG,Clean')
  if (format === 'json') return safeInvoke<string>('export_json_report', { paths }, '[]')
  return exportHtmlReport(paths)
}
