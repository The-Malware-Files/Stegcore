// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Unlock, Key, KeyRound, Eye, EyeOff, FileDown } from 'lucide-react'
import { ProcessingScreen } from '../components/ProcessingScreen'
import { useExtractStore } from '../lib/stores/extractStore'
import { useFooter } from '../App'
import { extract as ipcExtract, pickFiles } from '../lib/ipc'

const EXTRACT_STEPS = ['Stego file', 'Key file', 'Extract']

// Detect legacy Python key file (absence of "engine": "rust-v1")
function isLegacyKeyFile(meta: Record<string, unknown>): boolean {
  return meta['engine'] !== 'rust-v1'
}

function StepShell({ title, subtitle, step, totalSteps, children }: {
  title: string
  subtitle?: string
  step?: number
  totalSteps?: number
  children: React.ReactNode
}) {
  const pad = (n: number) => String(n).padStart(2, '0')
  return (
    <div style={{ padding: '48px 40px 32px', flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        {step != null && totalSteps != null && <span style={{
          display: 'block',
          fontSize: 11,
          fontFamily: "'Space Mono', monospace",
          color: 'var(--ui-text2)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase' as const,
          marginBottom: 8,
        }}>
          {pad(step)} / {pad(totalSteps)}
        </span>}
        <h2 style={{ fontSize: 28, fontWeight: 600, color: 'var(--ui-text)', letterSpacing: '-0.02em', marginBottom: subtitle ? 6 : 0 }}>
          {title}
        </h2>
        {subtitle && <p style={{ fontSize: 13, color: 'var(--ui-text2)', lineHeight: 1.6 }}>{subtitle}</p>}
      </div>
      {children}
    </div>
  )
}

// ── Step 1: Stego file ────────────────────────────────────────────────────

function Step1() {
  const { stegoFile, stegoPath, setStegoFile, setStep } = useExtractStore()
  const navigate = useNavigate()

  const handlePick = useCallback(async () => {
    const paths = await pickFiles({
      title: 'Select stego file',
      multiple: false,
      filters: [{ name: 'Stego files', extensions: ['png', 'bmp', 'jpg', 'jpeg', 'webp', 'wav', 'flac'] }],
    })
    if (paths.length > 0) {
      const name = paths[0].split(/[/\\]/).pop() ?? paths[0]
      const f = new File([], name)
      setStegoFile(f, null, paths[0])
    }
  }, [setStegoFile])

  useFooter({
    backLabel: 'Cancel',
    backAction: () => navigate('/'),
    continueLabel: 'Key file',
    continueAction: () => setStep(2),
    continueDisabled: !stegoFile,
    steps: EXTRACT_STEPS,
    currentStep: 1,
  })

  return (
    <StepShell title="Stego file" subtitle="Choose the file containing the hidden message." step={1} totalSteps={3}>
      <div
        onClick={handlePick}
        className="sc-analyse-drop"
        style={{
          borderRadius: 'var(--sc-radius-card)',
          padding: '2.5rem 1.5rem',
          textAlign: 'center',
          cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        {stegoFile ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--ui-text)' }}>{stegoFile.name}</span>
            {stegoPath && (
              <span style={{ fontSize: 10, color: 'var(--ui-text2)', fontFamily: "'Space Mono', monospace", wordBreak: 'break-all' }}>
                {stegoPath}
              </span>
            )}
            <button
              onClick={(e) => { e.stopPropagation(); setStegoFile(null, null) }}
              style={{ fontSize: 11, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer', marginTop: 4 }}
            >
              Remove
            </button>
          </div>
        ) : (
          <>
            <Unlock size={32} strokeWidth={1.5} style={{ color: 'var(--ui-accent)', margin: '0 auto 0.5rem', display: 'block' }} />
            <p style={{ color: 'var(--ui-text)', fontSize: 14, fontWeight: 500 }}>Click to select stego file</p>
            <p style={{ color: 'var(--ui-text2)', fontSize: 12, marginTop: 4 }}>PNG, BMP, JPEG, WebP, WAV, FLAC</p>
          </>
        )}
      </div>
    </StepShell>
  )
}

// ── Step 2: Key file (optional) ───────────────────────────────────────────

function Step2() {
  const { keyFile, keyFilePath, keyFileMetadata, setKeyFile, setStep } = useExtractStore()

  const handlePick = useCallback(async () => {
    const paths = await pickFiles({
      title: 'Select key file (optional)',
      multiple: false,
      filters: [{ name: 'Key files', extensions: ['json'] }],
    })
    if (paths.length > 0) {
      const name = paths[0].split(/[/\\]/).pop() ?? paths[0]
      const f = new File([], name)
      // Set key file with path — metadata preview not needed for extraction
      setKeyFile(f, null, paths[0])
    }
  }, [setKeyFile])

  const isLegacy = keyFileMetadata ? isLegacyKeyFile(keyFileMetadata) : false

  useFooter({
    backLabel: 'Stego file',
    backAction: () => setStep(1),
    continueLabel: 'Extract',
    continueAction: () => setStep(3),
    steps: EXTRACT_STEPS,
    currentStep: 2,
  })

  return (
    <StepShell title="Key file" subtitle="Key files are optional — you can extract with just your passphrase." step={2} totalSteps={3}>

      {/* Default "not needed" state */}
      {!keyFile && (
        <div style={{ padding: '1.25rem', borderRadius: 10, background: 'var(--ui-surface)', border: '1px solid var(--ui-border)', textAlign: 'center', marginBottom: '1rem' }}>
          <Key size={24} strokeWidth={1.5} style={{ color: 'var(--ui-text2)', margin: '0 auto 8px', display: 'block' }} />
          <p style={{ fontSize: 14, color: 'var(--ui-text)', fontWeight: 500 }}>No key file needed</p>
          <p style={{ fontSize: 13, color: 'var(--ui-text2)', marginTop: 4 }}>Just use your passphrase on the next step.</p>
        </div>
      )}

      {/* Key file picker */}
      <div
        onClick={handlePick}
        className="sc-analyse-drop"
        style={{
          borderRadius: 'var(--sc-radius-card)',
          padding: '1.5rem',
          textAlign: 'center',
          cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        {keyFile ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
            <KeyRound size={20} strokeWidth={1.5} style={{ color: 'var(--ui-success)' }} />
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--ui-text)' }}>{keyFile.name}</span>
            {keyFilePath && (
              <span style={{ fontSize: 10, color: 'var(--ui-text2)', fontFamily: "'Space Mono', monospace", wordBreak: 'break-all' }}>
                {keyFilePath}
              </span>
            )}
            <button
              onClick={(e) => { e.stopPropagation(); setKeyFile(null, null) }}
              style={{ fontSize: 11, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer', marginTop: 4 }}
            >
              Remove
            </button>
          </div>
        ) : (
          <>
            <Key size={24} strokeWidth={1.5} style={{ color: 'var(--ui-text2)', margin: '0 auto 0.5rem', display: 'block' }} />
            <p style={{ color: 'var(--ui-text2)', fontSize: 13 }}>Click to select a key file (optional)</p>
          </>
        )}
      </div>

      {/* Legacy warning */}
      {isLegacy && (
        <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--ui-warn) 12%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-warn) 30%, transparent)' }}>
          <p style={{ fontSize: 12, color: 'var(--ui-warn)', fontWeight: 500 }}>Legacy key file</p>
          <p style={{ fontSize: 12, color: 'var(--ui-text2)', marginTop: 2 }}>This key file was created by an older version of Stegcore and may not be compatible.</p>
        </div>
      )}

      {/* Metadata preview */}
      {keyFile && keyFileMetadata && !isLegacy && (
        <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--ui-accent) 6%, var(--ui-surface))', border: '1px solid var(--ui-border)' }}>
          <p style={{ fontSize: 11, color: 'var(--ui-text2)', marginBottom: 6, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Key file metadata</p>
          {['cipher', 'mode', 'deniable'].map((k) => (
            keyFileMetadata[k] !== undefined && (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, padding: '2px 0' }}>
                <span style={{ color: 'var(--ui-text2)' }}>{k}</span>
                <span style={{ color: 'var(--ui-text)', fontFamily: "'Space Mono', monospace" }}>{String(keyFileMetadata[k])}</span>
              </div>
            )
          ))}
        </div>
      )}
    </StepShell>
  )
}

// ── Step 3: Passphrase + Extract ──────────────────────────────────────────

function Step3() {
  const { stegoFile, stegoPath, keyFile, keyFilePath, passphrase, result, resultText, error, extracting, setPassphrase, setResult, setError, setExtracting, setStep } = useExtractStore()
  const navigate = useNavigate()
  const [showPass, setShowPass] = useState(false)
  const [showProcessing, setShowProcessing] = useState(false)
  const [processingStatus, setProcessingStatus] = useState<'processing' | 'success' | 'error'>('processing')
  const [pendingError, setPendingError] = useState<string | null>(null)
  const pendingResultRef = useRef<Uint8Array | null>(null)

  const [doneReady, setDoneReady] = useState(false)
  useEffect(() => {
    if (result) {
      const t = setTimeout(() => setDoneReady(true), 500)
      return () => clearTimeout(t)
    }
    setDoneReady(false)
  }, [result])

  useFooter({
    backLabel: 'Key file',
    backAction: extracting ? null : () => setStep(2),
    continueLabel: result ? 'Done' : undefined,
    continueAction: result && doneReady ? () => navigate('/') : null,
    continueDisabled: result ? !doneReady : undefined,
    steps: EXTRACT_STEPS,
    currentStep: 3,
  })

  const [extractPhase, setExtractPhase] = useState('')

  const handleExtract = useCallback(async () => {
    if (!stegoFile || showProcessing) return
    setShowProcessing(true)
    setExtracting(true)
    setProcessingStatus('processing')
    setExtractPhase('Preparing…')
    setError(null)

    // Force React to paint the spinner before the IPC call
    await new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)))

    try {
      setExtractPhase('Deriving key…')
      const bytes = await ipcExtract({
        stego: stegoPath ?? stegoFile.name,
        passphrase,
        keyFile: keyFilePath ?? keyFile?.name,
      })
      setExtractPhase('Decrypting…')
      pendingResultRef.current = bytes
      setProcessingStatus('success')
    } catch (e) {
      const detail = e instanceof Error ? e.message : undefined
      setPendingError(detail ?? 'Wrong passphrase or corrupted file.')
      setProcessingStatus('error')
    }
  }, [stegoFile, stegoPath, passphrase, keyFile, keyFilePath, setExtracting, setError, setResult])

  const handleSave = useCallback(async () => {
    if (!result) return
    try {
      const { save } = await import('@tauri-apps/plugin-dialog')
      const { writeFile } = await import('@tauri-apps/plugin-fs')
      const path = await save({
        title: 'Save extracted file',
        defaultPath: 'extracted',
      })
      if (path) {
        await writeFile(path, new Uint8Array(result))
      }
    } catch {
      // Fallback for dev/browser mode
      const blob = new Blob([new Uint8Array(result)])
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'extracted'
      a.click()
      URL.revokeObjectURL(url)
    }
  }, [result])

  const handleProcessingComplete = useCallback(() => {
    const bytes = pendingResultRef.current
    if (bytes) {
      setResult(bytes)
      pendingResultRef.current = null
    }
    setShowProcessing(false)
    setExtracting(false)
    setProcessingStatus('processing')
  }, [setResult, setExtracting])

  const handleProcessingRetry = useCallback(() => {
    setShowProcessing(false)
    setExtracting(false)
    setProcessingStatus('processing')
    setPendingError(null)
  }, [setExtracting])

  return (
    <div style={{ position: 'relative', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {showProcessing && (
        <ProcessingScreen
          phase={extractPhase}
          status={processingStatus}
          errorMessage={pendingError ?? undefined}
          onComplete={handleProcessingComplete}
          onRetry={handleProcessingRetry}
        />
      )}
    <StepShell title="Extract" subtitle="Enter your passphrase to reveal the hidden message." step={result ? undefined : 3} totalSteps={result ? undefined : 3}>

      {!result && (
        <>
          {/* Passphrase field */}
          <label style={{ fontSize: 12, color: 'var(--ui-text2)', display: 'block', marginBottom: 6, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.07em' }}>
            Passphrase
          </label>
          <div style={{ position: 'relative', marginBottom: 8 }}>
            <div style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--ui-text2)', pointerEvents: 'none' }}>
              <KeyRound size={15} />
            </div>
            <input
              type={showPass ? 'text' : 'password'}
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter' && !extracting) handleExtract() }}
              placeholder="Enter passphrase…"
              style={{
                width: '100%',
                background: 'var(--ui-surface)',
                border: '1px solid var(--ui-border)',
                borderRadius: 'var(--sc-radius-input)',
                color: 'var(--ui-text)',
                fontSize: 14,
                padding: '9px 40px',
                outline: 'none',
              }}
              onFocus={(e) => { e.currentTarget.style.borderColor = 'var(--ui-accent)' }}
              onBlur={(e) => { e.currentTarget.style.borderColor = 'var(--ui-border)' }}
            />
            <button
              onClick={() => setShowPass(v => !v)}
              aria-label={showPass ? 'Hide passphrase' : 'Show passphrase'}
              style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--ui-text2)', display: 'flex', alignItems: 'center' }}
            >
              {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
          {/* Extract button */}
          <button
            onClick={handleExtract}
            disabled={extracting || passphrase.length === 0}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 8,
              width: '100%',
              marginTop: '1.25rem',
              padding: '12px',
              background: 'var(--ui-accent)',
              border: 'none',
              borderRadius: 'var(--sc-radius-btn)',
              color: '#ffffff',
              fontSize: 15,
              fontWeight: 600,
              cursor: extracting || passphrase.length === 0 ? 'default' : 'pointer',
              opacity: extracting || passphrase.length === 0 ? 0.5 : 1,
              transition: 'opacity var(--sc-t-fast)',
            }}
          >
            {extracting ? <><SpinnerIcon /> {extractPhase || 'Extracting…'}</> : <><Unlock size={16} /> Extract</>}
          </button>
          {extracting && (
            <>
              <div style={{ marginTop: 10, height: 3, borderRadius: 2, background: 'var(--ui-border)', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: '40%',
                  borderRadius: 2,
                  background: 'var(--ui-accent)',
                  animation: 'slide-indeterminate 1.2s linear infinite',
                }} />
              </div>
              <p style={{ fontSize: 11, color: 'var(--ui-text2)', textAlign: 'center', marginTop: 6 }}>
                {extractPhase}
              </p>
            </>
          )}
        </>
      )}

      {/* Error — oracle-resistant message */}
      {error && (
        <div style={{ marginTop: '1rem', padding: '1rem', borderRadius: 10, background: 'color-mix(in srgb, var(--ui-danger) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-danger) 30%, transparent)' }}>
          <p style={{ fontSize: 13, color: 'var(--ui-danger)' }}>{error}</p>
          <button
            onClick={() => setError(null)}
            style={{ marginTop: 8, fontSize: 13, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}
          >
            Try again
          </button>
        </div>
      )}

      {/* Success */}
      {result && (
        <div style={{ padding: '1.25rem', borderRadius: 10, background: 'color-mix(in srgb, var(--ui-success) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-success) 30%, transparent)' }}>
          <p style={{ fontSize: 15, fontWeight: 600, color: 'var(--ui-success)', marginBottom: 10 }}>Extracted successfully</p>
          {resultText !== null ? (
            <pre style={{
              fontFamily: "'Space Mono', monospace",
              fontSize: 12,
              color: 'var(--ui-text)',
              background: 'var(--ui-surface)',
              border: '1px solid var(--ui-border)',
              borderRadius: 6,
              padding: 12,
              maxHeight: 180,
              overflowY: 'auto',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              marginBottom: 12,
            }}>
              {resultText.length > 1024 ? resultText.slice(0, 1024) + '…' : resultText}
            </pre>
          ) : (
            <p style={{ fontSize: 12, color: 'var(--ui-text2)', marginBottom: 12 }}>
              {result.byteLength.toLocaleString()} bytes (binary content)
            </p>
          )}
          <button
            onClick={handleSave}
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--ui-text)', background: 'var(--ui-surface)', border: '1px solid var(--ui-border)', borderRadius: 6, padding: '7px 14px', cursor: 'pointer' }}
          >
            <FileDown size={14} /> Save file
          </button>
        </div>
      )}
    </StepShell>
    </div>
  )
}

function SpinnerIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ animation: 'spin 0.8s linear infinite' }}>
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="2" strokeOpacity="0.3" />
      <path d="M8 2A6 6 0 0 1 14 8" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </svg>
  )
}

export default function Extract() {
  const { step } = useExtractStore()
  return (
    <div style={{ minHeight: '100%' }}>
      <div key={step} className="sc-enter">
        {step === 1 && <Step1 />}
        {step === 2 && <Step2 />}
        {step === 3 && <Step3 />}
      </div>
    </div>
  )
}
