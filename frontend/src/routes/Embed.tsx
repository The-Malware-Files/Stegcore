// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useEffect, useCallback, useRef, memo } from 'react'
import { useNavigate } from 'react-router-dom'
import { KeyRound, Eye, EyeOff, FolderOpen, Copy, Lock } from 'lucide-react'
// DropZone replaced by native file pickers for full filesystem paths
import { ScoreCard } from '../components/ScoreCard'
import { EntropyBar } from '../components/EntropyBar'
import { Toggle } from '../components/Toggle'
import { ProcessingScreen } from '../components/ProcessingScreen'
import { useEmbedStore } from '../lib/stores/embedStore'
import { useSettingsStore } from '../lib/stores/settingsStore'
import { useFooter } from '../App'
import { scoreCover, embed as ipcEmbed, pickFiles, getFileSize, pixelDiff, type PixelDiffResult } from '../lib/ipc'
import { convertFileSrc } from '@tauri-apps/api/core'
// Sound is now handled by ProcessingScreen
import type { Cipher, EmbedMode } from '../lib/ipc'

const EMBED_STEPS = ['Message', 'Cover', 'Options', 'Embed']

const CIPHER_INFO: Record<Cipher, { label: string; desc: string }> = {
  'ascon-128':         { label: 'Ascon-128',          desc: 'Lightweight cipher. Excellent for constrained environments.' },
  'aes-256-gcm':       { label: 'AES-256-GCM',       desc: 'Industry standard. Hardware-accelerated on most CPUs.' },
  'chacha20-poly1305': { label: 'ChaCha20-Poly1305', desc: 'Fast, secure. Recommended for most uses.' },
}

// ── Step wrappers ─────────────────────────────────────────────────────────

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
          {pad(step!)} / {pad(totalSteps!)}
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

// ── Step 1: Message file ──────────────────────────────────────────────────

function Step1() {
  const { payloadFile, payloadPath, payloadSizeBytes, setPayloadFile } = useEmbedStore()
  const navigate = useNavigate()

  // Native file picker for real filesystem paths
  const handlePick = useCallback(async () => {
    const paths = await pickFiles({
      title: 'Select message file',
      multiple: false,
      filters: [{ name: 'All files', extensions: ['*'] }],
    })
    if (paths.length > 0) {
      const name = paths[0].split(/[/\\]/).pop() ?? paths[0]
      const f = new File([], name)
      setPayloadFile(f, paths[0])
      // Fetch real file size from backend
      getFileSize(paths[0]).then(size => {
        useEmbedStore.setState({ payloadSizeBytes: size })
      }).catch(() => {})
    }
  }, [setPayloadFile])

  useFooter({
    backLabel: 'Cancel',
    backAction: () => navigate('/'),
    continueLabel: 'Choose Cover',
    continueAction: () => useEmbedStore.getState().setStep(2),
    continueDisabled: !payloadFile,
    steps: EMBED_STEPS,
    currentStep: 1,
  })

  return (
    <StepShell title="What do you want to hide?" subtitle="Select any file — text, binary, document." step={1} totalSteps={4}>
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
        {payloadFile ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--ui-text)' }}>{payloadFile.name}</span>
            {payloadPath && (
              <span style={{ fontSize: 10, color: 'var(--ui-text2)', fontFamily: "'Space Mono', monospace", wordBreak: 'break-all' }}>
                {payloadPath}
              </span>
            )}
            {payloadSizeBytes > 0 && (
              <span style={{ fontSize: 11, color: 'var(--ui-text2)' }}>
                {payloadSizeBytes > 1024 * 1024
                  ? `${(payloadSizeBytes / (1024 * 1024)).toFixed(1)} MB`
                  : `${(payloadSizeBytes / 1024).toFixed(1)} KB`}
              </span>
            )}
            <button
              onClick={(e) => { e.stopPropagation(); setPayloadFile(null) }}
              style={{ fontSize: 11, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer', marginTop: 4 }}
            >
              Remove
            </button>
          </div>
        ) : (
          <>
            <KeyRound size={32} strokeWidth={1.5} style={{ color: 'var(--ui-accent)', margin: '0 auto 0.5rem', display: 'block' }} />
            <p style={{ color: 'var(--ui-text)', fontSize: 14, fontWeight: 500 }}>Click to select message file</p>
            <p style={{ color: 'var(--ui-text2)', fontSize: 12, marginTop: 4 }}>Or drag and drop</p>
          </>
        )}
      </div>
    </StepShell>
  )
}

// ── Step 2: Cover file ────────────────────────────────────────────────────

function Step2() {
  const { coverFile, coverPath, coverSizeBytes, coverPreviewUrl, coverScore, coverScoring, setCoverFile, setCoverScore, setStep } = useEmbedStore()
  const { settings } = useSettingsStore()

  // Native file picker for real filesystem path
  const handlePick = useCallback(async () => {
    const paths = await pickFiles({
      title: 'Select cover file',
      multiple: false,
      filters: [{ name: 'Cover files', extensions: ['png', 'bmp', 'jpg', 'jpeg', 'webp', 'wav'] }],
    })
    if (paths.length > 0) {
      const name = paths[0].split(/[/\\]/).pop() ?? paths[0]
      const f = new File([], name)
      setCoverFile(f, null, paths[0])
      // Fetch real file size
      getFileSize(paths[0]).then(size => {
        useEmbedStore.setState({ coverSizeBytes: size })
      }).catch(() => {})
      if (settings.autoScoreOnDrop) {
        setCoverScore(null, true)
        try {
          const score = await scoreCover(paths[0])
          setCoverScore(score)
        } catch {
          setCoverScore(0, false)
        }
      }
    }
  }, [settings.autoScoreOnDrop, setCoverFile, setCoverScore])

  const handleManualScore = useCallback(async () => {
    const path = coverPath
    if (!path) return
    setCoverScore(null, true)
    try {
      const score = await scoreCover(path)
      setCoverScore(score)
    } catch {
      setCoverScore(0, false)
    }
  }, [coverPath, setCoverScore])

  useFooter({
    backLabel: 'Message',
    backAction: () => setStep(1),
    continueLabel: 'Options',
    continueAction: () => setStep(3),
    continueDisabled: !coverFile,
    steps: EMBED_STEPS,
    currentStep: 2,
  })

  return (
    <StepShell
      title="Cover file"
      subtitle="Choose the image or audio file that will carry your hidden message."
      step={2}
      totalSteps={4}
    >
      <div
        onClick={handlePick}
        className="sc-analyse-drop"
        style={{
          borderRadius: 'var(--sc-radius-card)',
          padding: '2rem 1.5rem',
          textAlign: 'center',
          cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        {coverFile ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
            {/* Thumbnail preview for image files */}
            {/\.(png|bmp|jpg|jpeg|webp)$/i.test(coverFile.name) && (coverPreviewUrl || coverPath) && (
              <img
                src={coverPreviewUrl ?? convertFileSrc(coverPath!)}
                alt="Cover preview"
                style={{ maxHeight: 100, maxWidth: '100%', borderRadius: 8, objectFit: 'contain', marginBottom: 4 }}
                onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
              />
            )}
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--ui-text)' }}>{coverFile.name}</span>
            {coverPath && (
              <span className="sc-path" style={{ wordBreak: 'break-all' }}>
                {coverPath}
              </span>
            )}
            {coverSizeBytes > 0 && (
              <span style={{ fontSize: 11, color: 'var(--ui-text2)' }}>
                {coverSizeBytes > 1024 * 1024
                  ? `${(coverSizeBytes / (1024 * 1024)).toFixed(1)} MB`
                  : `${(coverSizeBytes / 1024).toFixed(1)} KB`}
              </span>
            )}
            <button
              onClick={(e) => { e.stopPropagation(); setCoverFile(null, null); setCoverScore(null) }}
              style={{ fontSize: 11, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer', marginTop: 4 }}
            >
              Remove
            </button>
          </div>
        ) : (
          <>
            <Lock size={32} strokeWidth={1.5} style={{ color: 'var(--ui-accent)', margin: '0 auto 0.5rem', display: 'block' }} />
            <p style={{ color: 'var(--ui-text)', fontSize: 14, fontWeight: 500 }}>Click to select cover file</p>
            <p style={{ color: 'var(--ui-text2)', fontSize: 12, marginTop: 4 }}>PNG, BMP, JPEG, WebP, WAV</p>
          </>
        )}
      </div>

      {/* Format recommendation */}
      {coverFile && (() => {
        const ext = coverFile.name.split('.').pop()?.toLowerCase() ?? ''
        if (ext === 'jpg' || ext === 'jpeg') return (
          <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--ui-accent) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-accent) 25%, transparent)' }}>
            <p style={{ fontSize: 12, color: 'var(--ui-text2)' }}>
              JPEG uses DCT coefficient embedding. For maximum capacity, PNG is recommended.
            </p>
          </div>
        )
        if (ext === 'bmp') return (
          <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--ui-success) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-success) 25%, transparent)' }}>
            <p style={{ fontSize: 12, color: 'var(--ui-text2)' }}>
              BMP is lossless — excellent for embedding. PNG offers similar quality with smaller file size.
            </p>
          </div>
        )
        if (ext === 'png') return (
          <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--ui-success) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-success) 25%, transparent)' }}>
            <p style={{ fontSize: 12, color: 'var(--ui-text2)' }}>
              PNG — best format for steganography. Lossless, high capacity.
            </p>
          </div>
        )
        if (ext === 'wav') return (
          <div style={{ marginTop: 12, padding: '10px 14px', borderRadius: 8, background: 'color-mix(in srgb, var(--ui-accent) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-accent) 25%, transparent)' }}>
            <p style={{ fontSize: 12, color: 'var(--ui-text2)' }}>
              WAV audio embedding. Will not survive conversion to MP3 or other lossy formats.
            </p>
          </div>
        )
        return null
      })()}

      {/* Score */}
      {coverFile && (
        <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 10 }}>
          {!settings.autoScoreOnDrop && coverScore === null && !coverScoring && (
            <button
              onClick={handleManualScore}
              style={{ fontSize: 13, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}
            >
              Score cover
            </button>
          )}
          <ScoreCard score={coverScore} loading={coverScoring} />
          {coverScore !== null && (coverSizeBytes || coverFile.size) > 0 && (
            <span style={{ fontSize: 12, color: 'var(--ui-text2)' }}>
              ~{Math.round(coverScore * ((coverSizeBytes || coverFile.size) / 1024) * 0.1)} KB capacity
            </span>
          )}
        </div>
      )}
    </StepShell>
  )
}

// ── Step 3: Options ───────────────────────────────────────────────────────

const CipherPill = memo(function CipherPill({ cipher, selected, onSelect }: { cipher: Cipher; selected: boolean; onSelect: () => void }) {
  const info = CIPHER_INFO[cipher]
  return (
    <button
      onClick={onSelect}
      title={info.desc}
      style={{
        background: selected ? 'var(--ui-accent)' : 'var(--ui-surface2)',
        border: `1px solid ${selected ? 'var(--ui-accent)' : 'var(--ui-border)'}`,
        borderRadius: 20,
        padding: '6px 14px',
        cursor: 'pointer',
        fontSize: 12,
        fontWeight: selected ? 600 : 400,
        color: selected ? '#ffffff' : 'var(--ui-text2)',
        transition: 'background var(--sc-t-fast), border-color var(--sc-t-fast), color var(--sc-t-fast)',
        whiteSpace: 'nowrap',
      }}
    >
      {info.label}
    </button>
  )
})

const CapacityBar = memo(function CapacityBar({ label, usedKB, capacityKB }: { label: string; usedKB: number; capacityKB: number }) {
  const pct = capacityKB > 0 ? Math.min(100, Math.round((usedKB / capacityKB) * 100)) : 100
  const color = pct < 70 ? 'var(--ui-success)' : pct < 90 ? 'var(--ui-warn)' : 'var(--ui-danger)'
  const fmtKB = (v: number) => v > 0 && v < 1 ? v.toFixed(1) : String(Math.round(v))
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 3 }}>
        <span style={{ color: 'var(--ui-text2)' }}>{label}</span>
        <span style={{ color, fontFamily: "'Space Mono', monospace" }}>
          {fmtKB(usedKB)} / {fmtKB(capacityKB)} KB{usedKB > capacityKB ? ' — too large' : ''}
        </span>
      </div>
      <div style={{ height: 3, borderRadius: 2, background: 'var(--ui-border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, borderRadius: 2, background: color, transition: 'width var(--sc-t-base)' }} />
      </div>
    </div>
  )
})

const CapacityIndicator = memo(function CapacityIndicator({ coverSizeKB, coverScore, payloadSizeKB, decoySizeKB, deniable, mode }: {
  coverSizeKB: number; coverScore: number; payloadSizeKB: number; decoySizeKB: number; deniable: boolean; mode: string
}) {
  // Sequential mode has ~30% more capacity than adaptive
  const modeMultiplier = mode === 'sequential' ? 1.3 : 1.0
  const totalCapacityKB = Math.round(coverScore * coverSizeKB * 0.1 * modeMultiplier)
  const halfCapacity = Math.floor(totalCapacityKB / 2)

  return (
    <div style={{
      padding: '10px 14px',
      background: 'var(--ui-surface)',
      border: '1px solid var(--ui-border)',
      borderRadius: 8,
      marginBottom: '1.25rem',
    }}>
      {deniable ? (
        <>
          <CapacityBar label="Real payload" usedKB={payloadSizeKB} capacityKB={halfCapacity} />
          <CapacityBar label="Decoy payload" usedKB={decoySizeKB} capacityKB={halfCapacity} />
          <p style={{ fontSize: 10, color: 'var(--ui-text2)', marginTop: 2 }}>
            Total: ~{totalCapacityKB} KB · Each half: ~{halfCapacity} KB
          </p>
        </>
      ) : (
        <CapacityBar label="Capacity" usedKB={payloadSizeKB} capacityKB={totalCapacityKB} />
      )}
    </div>
  )
})

function Step3() {
  const { cipher, mode, deniable, decoyFile, passphrase, decoyPassphrase, exportKey, coverScore, coverFile, coverSizeBytes, payloadFile, payloadSizeBytes, setOptions, setStep } = useEmbedStore()
  const { settings } = useSettingsStore()
  const [showPass, setShowPass] = useState(false)
  const [showDecoyPass, setShowDecoyPass] = useState(false)

  // Apply settings defaults once settings have loaded from disk
  const { loaded: settingsLoaded } = useSettingsStore()
  const appliedDefaults = useRef(false)
  useEffect(() => {
    if (settingsLoaded && !appliedDefaults.current) {
      appliedDefaults.current = true
      setOptions({ cipher: settings.defaultCipher, mode: settings.defaultMode })
    }
  }, [settingsLoaded, settings.defaultCipher, settings.defaultMode, setOptions])

  useFooter({
    backLabel: 'Cover',
    backAction: () => setStep(2),
    continueLabel: 'Review',
    continueAction: () => setStep(4),
    continueDisabled: passphrase.length < 1 || (deniable && decoyPassphrase.length < 1),
    steps: EMBED_STEPS,
    currentStep: 3,
  })

  return (
    <StepShell title="Encryption options" subtitle="Set your cipher, mode, and passphrase." step={3} totalSteps={4}>

      {/* Cipher */}
      <p style={{ fontSize: 11, color: 'var(--ui-text2)', marginBottom: 8, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.09em' }}>Cipher</p>
      <div style={{ display: 'flex', gap: 6, marginBottom: '1.5rem', flexWrap: 'wrap' }}>
        {(Object.keys(CIPHER_INFO) as Cipher[]).map((c) => (
          <CipherPill key={c} cipher={c} selected={cipher === c} onSelect={() => setOptions({ cipher: c })} />
        ))}
      </div>

      {/* Mode — side-by-side cards */}
      <p style={{ fontSize: 11, color: 'var(--ui-text2)', marginBottom: 8, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.09em' }}>Embedding mode</p>
      <div style={{ display: 'flex', gap: 8, marginBottom: '1.5rem' }}>
        {(['adaptive', 'sequential'] as EmbedMode[]).map((m) => {
          const isSelected = mode === m
          return (
            <button
              key={m}
              onClick={() => setOptions({ mode: m })}
              title={m === 'adaptive'
                ? 'Scatters payload bits across high-entropy regions. Harder to detect but uses more space per bit.'
                : 'Sequential LSB embedding. Fits more data but is easier to detect with steganalysis tools.'}
              style={{
                flex: 1,
                padding: '12px 14px',
                background: isSelected ? 'color-mix(in srgb, var(--ui-accent) 8%, var(--ui-surface2))' : 'var(--ui-surface2)',
                border: `1.5px solid ${isSelected ? 'var(--ui-accent)' : 'var(--ui-border)'}`,
                borderRadius: 10,
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'border-color var(--sc-t-fast), background var(--sc-t-fast)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: isSelected ? 'var(--ui-accent)' : 'var(--ui-text)' }}>
                  {m === 'adaptive' ? 'Adaptive' : 'Standard'}
                </span>
                {m === 'adaptive' && (
                  <span style={{ fontSize: 9, fontWeight: 500, fontFamily: "'Space Mono', monospace", color: 'var(--ui-success)', marginTop: 3 }}>
                    Recommended
                  </span>
                )}
              </div>
              <p style={{ fontSize: 11, color: 'var(--ui-text2)', lineHeight: 1.5 }}>
                {m === 'adaptive' ? 'Higher resistance to detection; lower capacity.' : 'More data fits; standard LSB embedding.'}
              </p>
            </button>
          )
        })}
      </div>

      {/* Deniable */}
      <div style={{ marginBottom: '1.25rem' }}>
        <Toggle
          checked={deniable}
          onChange={(v) => setOptions({ deniable: v })}
          label="Deniable mode"
          description="Hide two separate messages — one real, one decoy. Each passphrase reveals a different payload. Neither partition references the other."
        />
        {deniable && (
          <div style={{ marginTop: 12, padding: '14px', borderRadius: 10, background: 'color-mix(in srgb, var(--ui-accent) 5%, var(--ui-surface))', border: '1px solid var(--ui-border)' }}>
            <p style={{ fontSize: 12, color: 'var(--ui-text2)', marginBottom: 10 }}>Decoy message file</p>
            <div
              onClick={async () => {
                const paths = await pickFiles({
                  title: 'Select decoy file',
                  multiple: false,
                  filters: [{ name: 'All files', extensions: ['*'] }],
                })
                if (paths.length > 0) {
                  const name = paths[0].split(/[/\\]/).pop() ?? paths[0]
                  const f = new File([], name)
                  setOptions({ decoyFile: f })
                  useEmbedStore.setState({ decoyPath: paths[0] })
                }
              }}
              className="sc-analyse-drop"
              style={{ borderRadius: 8, padding: '1rem', textAlign: 'center', cursor: 'pointer', userSelect: 'none' }}
            >
              {decoyFile ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--ui-text)' }}>{decoyFile.name}</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); setOptions({ decoyFile: null }); useEmbedStore.setState({ decoyPath: null }) }}
                    style={{ fontSize: 11, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer' }}
                  >
                    Remove
                  </button>
                </div>
              ) : (
                <p style={{ color: 'var(--ui-text2)', fontSize: 12 }}>Click to select decoy file</p>
              )}
            </div>
            <div style={{ marginTop: 12 }}>
              <label style={{ fontSize: 12, color: 'var(--ui-text2)', display: 'block', marginBottom: 4 }}>Decoy passphrase</label>
              <PassField value={decoyPassphrase} show={showDecoyPass} onToggle={() => setShowDecoyPass(v => !v)} onChange={(v) => setOptions({ decoyPassphrase: v })} />
            </div>
          </div>
        )}
      </div>

      {/* Capacity estimate */}
      {coverScore !== null && coverFile && payloadFile && (
        <CapacityIndicator
          coverSizeKB={(coverSizeBytes || coverFile.size) / 1024}
          coverScore={coverScore}
          payloadSizeKB={(payloadSizeBytes || payloadFile.size) / 1024}
          decoySizeKB={deniable && decoyFile ? decoyFile.size / 1024 : 0}
          deniable={deniable}
          mode={mode}
        />
      )}

      {/* Passphrase */}
      <div style={{ marginBottom: '1rem' }}>
        <label style={{ fontSize: 12, color: 'var(--ui-text2)', display: 'block', marginBottom: 6, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.07em' }}>Passphrase</label>
        <PassField value={passphrase} show={showPass} onToggle={() => setShowPass(v => !v)} onChange={(v) => setOptions({ passphrase: v })} />
        <div style={{ marginTop: 8 }}><EntropyBar value={passphrase} /></div>
        {passphrase.length > 0 && passphrase.length < settings.passphraseMinLen && (
          <p style={{ fontSize: 11, color: 'var(--ui-warn)', marginTop: 4 }}>
            Consider using at least {settings.passphraseMinLen} characters.
          </p>
        )}
      </div>

      {/* Export key */}
      <Toggle
        checked={exportKey}
        onChange={(v) => setOptions({ exportKey: v })}
        label="Export key file"
        description="Save an optional .json key file alongside the output."
      />
    </StepShell>
  )
}

function PassField({ value, show, onToggle, onChange }: { value: string; show: boolean; onToggle: () => void; onChange: (v: string) => void }) {
  return (
    <div style={{ position: 'relative' }}>
      <div style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--ui-text2)', pointerEvents: 'none' }}>
        <KeyRound size={15} />
      </div>
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
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
        onClick={onToggle}
        aria-label={show ? 'Hide passphrase' : 'Show passphrase'}
        style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--ui-text2)', display: 'flex', alignItems: 'center' }}
      >
        {show ? <EyeOff size={15} /> : <Eye size={15} />}
      </button>
    </div>
  )
}

// ── Step 4: Embed ─────────────────────────────────────────────────────────

function Step4() {
  const { payloadFile, payloadPath, coverFile, coverPath, cipher, mode, deniable, decoyFile, decoyPath, passphrase, decoyPassphrase, exportKey, result, error, embedding, setResult, setError, setEmbedding, setStep } = useEmbedStore()
  const navigate = useNavigate()
  const [copied, setCopied] = useState(false)
  const [diff, setDiff] = useState<PixelDiffResult | null>(null)
  const [diffLoading, setDiffLoading] = useState(false)
  const [showProcessing, setShowProcessing] = useState(false)
  const [processingStatus, setProcessingStatus] = useState<'processing' | 'success' | 'error'>('processing')
  const [pendingError, setPendingError] = useState<string | null>(null)
  const pendingResultRef = useRef<{ outputPath: string } | null>(null)

  // Auto-run pixel diff when embed succeeds
  useEffect(() => {
    if (result && coverPath && result.outputPath) {
      setDiffLoading(true)
      pixelDiff(coverPath, result.outputPath)
        .then(setDiff)
        .catch(() => {})
        .finally(() => setDiffLoading(false))
    }
  }, [result, coverPath])

  useFooter(result ? {
    // Success: Home button on the RIGHT (continue position), primary style, nothing on left
    continueLabel: 'Home',
    continueAction: () => navigate('/'),
  } : {
    backLabel: 'Options',
    backAction: embedding ? null : () => setStep(3),
    steps: EMBED_STEPS,
    currentStep: 4,
  })

  const [embedPhase, setEmbedPhase] = useState('')

  const handleEmbed = useCallback(async () => {
    if (!payloadFile || !coverFile || showProcessing) return
    setShowProcessing(true)
    setEmbedding(true)
    setProcessingStatus('processing')
    setEmbedPhase('Preparing…')
    setError(null)

    // Force React to paint the spinner before the IPC call
    await new Promise(r => requestAnimationFrame(() => setTimeout(r, 0)))

    try {
      setEmbedPhase('Deriving key…')
      const coverArg = coverPath ?? coverFile.name
      const payloadArg = payloadPath ?? payloadFile.name
      const coverStem = coverArg.replace(/\.[^.]+$/, '')
      const coverExt = coverArg.split('.').pop() ?? 'png'
      const outputArg = `${coverStem}_stego.${coverExt}`

      setEmbedPhase('Embedding…')
      const res = await ipcEmbed({
        cover: coverArg,
        payload: payloadArg,
        passphrase,
        cipher,
        mode,
        deniable,
        decoyPayload: deniable ? (decoyPath ?? decoyFile?.name ?? undefined) : undefined,
        decoyPassphrase: deniable ? decoyPassphrase : undefined,
        exportKey,
        output: outputArg,
      })
      setProcessingStatus('success')
      // Delay setResult so ProcessingScreen can show the checkmark animation
      pendingResultRef.current = res
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Something went wrong. Please try again.'
      setPendingError(msg)
      setProcessingStatus('error')
    }
  }, [payloadFile, payloadPath, coverFile, coverPath, passphrase, cipher, mode, deniable, decoyFile, decoyPath, decoyPassphrase, exportKey, setEmbedding, setError, setResult])

  const { settings } = useSettingsStore()

  const handleCopy = useCallback(() => {
    if (!result?.outputPath) return
    navigator.clipboard.writeText(result.outputPath)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
    // Auto-clear clipboard after configured timeout
    if (settings.clearClipboardSecs > 0) {
      setTimeout(() => {
        navigator.clipboard.writeText('').catch(() => {})
      }, settings.clearClipboardSecs * 1000)
    }
  }, [result, settings.clearClipboardSecs])

  const handleProcessingComplete = useCallback(() => {
    const res = pendingResultRef.current
    if (res) {
      setResult(res)
      pendingResultRef.current = null
    }
    setShowProcessing(false)
    setEmbedding(false)
    setProcessingStatus('processing')
  }, [setResult, setEmbedding])

  const handleProcessingRetry = useCallback(() => {
    setShowProcessing(false)
    setEmbedding(false)
    setProcessingStatus('processing')
    setPendingError(null)
  }, [setEmbedding])

  return (
    <div style={{ position: 'relative', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {showProcessing && (
        <ProcessingScreen
          phase={embedPhase}
          status={processingStatus}
          errorMessage={pendingError ?? undefined}
          onComplete={handleProcessingComplete}
          onRetry={handleProcessingRetry}
        />
      )}
    <StepShell title="Review & Embed" subtitle="Check your selections and embed when ready." step={result ? undefined : 4} totalSteps={result ? undefined : 4}>

      {/* Summary */}
      {!result && (
        <div style={{ background: 'var(--ui-surface)', border: '1px solid var(--ui-border)', borderRadius: 10, padding: '1rem', marginBottom: '1.5rem' }}>
          <Row label="Message" value={payloadFile?.name ?? '—'} />
          <Row label="Cover"   value={coverFile?.name ?? '—'} />
          <Row label="Cipher"  value={CIPHER_INFO[cipher].label} />
          <Row label="Mode"    value={mode === 'adaptive' ? 'Adaptive (Secure)' : 'Standard (High Capacity)'} />
          <Row label="Deniable" value={deniable ? 'Yes' : 'No'} />
          <Row label="Export key file" value={exportKey ? 'Yes' : 'No'} />
        </div>
      )}

      {/* Embed button */}
      {!result && !error && (
        <button
          onClick={handleEmbed}
          disabled={embedding}
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            width: '100%',
            padding: '12px',
            background: 'var(--ui-accent)',
            border: 'none',
            borderRadius: 'var(--sc-radius-btn)',
            color: '#ffffff',
            fontSize: 15,
            fontWeight: 600,
            cursor: embedding ? 'wait' : 'pointer',
            opacity: embedding ? 0.75 : 1,
            transition: 'opacity var(--sc-t-fast)',
          }}
        >
          {embedding ? (
            <>
              <SpinnerIcon />
              {embedPhase || 'Embedding…'}
            </>
          ) : (
            <>
              <Lock size={16} />
              Embed
            </>
          )}
        </button>
      )}

      {/* Progress bar (indeterminate while embedding) */}
      {embedding && (
        <>
          <div style={{ marginTop: 12, height: 3, borderRadius: 2, background: 'var(--ui-border)', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: '40%',
              borderRadius: 2,
              background: 'var(--ui-accent)',
              animation: 'slide-indeterminate 1.2s linear infinite',
            }} />
          </div>
          <p style={{ fontSize: 11, color: 'var(--ui-text2)', textAlign: 'center', marginTop: 6 }}>
            {embedPhase}
          </p>
        </>
      )}

      {/* Error state */}
      {error && (
        <div style={{ padding: '1rem', borderRadius: 10, background: 'color-mix(in srgb, var(--ui-danger) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-danger) 30%, transparent)' }}>
          <p style={{ fontSize: 14, color: 'var(--ui-danger)', fontWeight: 500 }}>Embedding failed</p>
          <p style={{ fontSize: 13, color: 'var(--ui-text2)', marginTop: 4 }}>{error}</p>
          <button onClick={() => { setError(null) }} style={{ marginTop: 10, fontSize: 13, color: 'var(--ui-accent)', background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}>
            Try Again
          </button>
        </div>
      )}

      {/* Success state */}
      {result && (
        <div style={{ padding: '1.25rem', borderRadius: 10, background: 'color-mix(in srgb, var(--ui-success) 10%, var(--ui-surface))', border: '1px solid color-mix(in srgb, var(--ui-success) 30%, transparent)' }}>
          <p style={{ fontSize: 15, fontWeight: 600, color: 'var(--ui-success)', marginBottom: 8 }}>Embedded successfully</p>
          <p style={{ fontSize: 12, color: 'var(--ui-text2)', fontFamily: "'Space Mono', monospace", wordBreak: 'break-all', marginBottom: 12 }}>
            {result.outputPath}
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={async () => {
                try {
                  const { open } = await import('@tauri-apps/plugin-shell')
                  const dir = result.outputPath.replace(/[/\\][^/\\]*$/, '')
                  await open(dir)
                } catch { /* dev mode — no file manager */ }
              }}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: 'var(--ui-text)', background: 'var(--ui-surface)', border: '1px solid var(--ui-border)', borderRadius: 6, padding: '6px 12px', cursor: 'pointer' }}
            >
              <FolderOpen size={14} /> Open folder
            </button>
            <button
              onClick={handleCopy}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, color: copied ? 'var(--ui-success)' : 'var(--ui-text)', background: 'var(--ui-surface)', border: '1px solid var(--ui-border)', borderRadius: 6, padding: '6px 12px', cursor: 'pointer' }}
            >
              <Copy size={14} /> {copied ? 'Copied!' : 'Copy path'}
            </button>
          </div>

          {/* Pixel diff — auto-computed after embed */}
          {diffLoading && (
            <div className="sc-skeleton" style={{ height: 48, marginTop: 12 }} />
          )}
          {diff && (() => {
            const ext = (coverFile?.name ?? '').split('.').pop()?.toLowerCase() ?? ''
            const isJpeg = ext === 'jpg' || ext === 'jpeg'
            const isWav = ext === 'wav'
            const pct = diff.percentChanged.toFixed(2)

            // Format-aware friendly summary
            const summary = isJpeg
              ? `DCT coefficients modified — output is a valid JPEG, visually indistinguishable from the original.`
              : isWav
                ? `${diff.changedPixels.toLocaleString()} audio samples modified (LSB only) — sounds identical to the original.`
                : diff.lsbOnly
                  ? `${diff.changedPixels.toLocaleString()} pixels modified (LSB only) — visually identical to the original.`
                  : `${diff.changedPixels.toLocaleString()} pixels modified — visually indistinguishable from the original.`

            const colour = (isJpeg || diff.lsbOnly) ? 'var(--ui-success)' : 'var(--ui-success)'

            return (
              <PixelDiffCard
                summary={summary}
                colour={colour}
                pct={pct}
                diff={diff}
                isJpeg={isJpeg}
              />
            )
          })()}
        </div>
      )}

      <style>{`
        @keyframes slide-indeterminate {
          0%   { transform: translateX(-150%); }
          100% { transform: translateX(350%); }
        }
      `}</style>
    </StepShell>
    </div>
  )
}

function PixelDiffCard({ summary, colour, pct, diff, isJpeg }: {
  summary: string; colour: string; pct: string; diff: PixelDiffResult; isJpeg: boolean
}) {
  const [showDetail, setShowDetail] = useState(false)
  return (
    <div style={{
      marginTop: 12, padding: '10px 14px', borderRadius: 8,
      background: 'var(--ui-surface)', border: '1px solid var(--ui-border)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: showDetail ? 8 : 0 }}>
        <span style={{ fontSize: 12, color: colour, fontWeight: 500, flex: 1 }}>
          {summary}
        </span>
        <button
          onClick={() => setShowDetail(v => !v)}
          style={{
            fontSize: 11, color: 'var(--ui-text2)', background: 'transparent',
            border: 'none', cursor: 'pointer', padding: '2px 6px',
            textDecoration: 'underline', flexShrink: 0,
          }}
        >
          {showDetail ? 'Hide' : 'Details'}
        </button>
      </div>
      {showDetail && (
        <div style={{ fontSize: 11, color: 'var(--ui-text2)', display: 'flex', flexDirection: 'column', gap: 3, fontFamily: "'Space Mono', monospace" }}>
          <span>Pixels changed: {diff.changedPixels.toLocaleString()} / {diff.totalPixels.toLocaleString()} ({pct}%)</span>
          <span>Maximum delta per channel: {diff.maxDelta}</span>
          <span>Modification type: {isJpeg ? 'DCT coefficient (frequency domain)' : diff.lsbOnly ? 'LSB only (1-bit)' : `Up to ${diff.maxDelta}-bit`}</span>
        </div>
      )}
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid var(--ui-border)' }}>
      <span style={{ fontSize: 12, color: 'var(--ui-text2)' }}>{label}</span>
      <span style={{ fontSize: 12, color: 'var(--ui-text)', fontWeight: 500 }}>{value}</span>
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

// ── Embed route ───────────────────────────────────────────────────────────

export default function Embed() {
  const { step } = useEmbedStore()

  return (
    <div style={{ minHeight: '100%' }}>
      <div key={step} className="sc-enter">
        {step === 1 && <Step1 />}
        {step === 2 && <Step2 />}
        {step === 3 && <Step3 />}
        {step === 4 && <Step4 />}
      </div>
    </div>
  )
}
