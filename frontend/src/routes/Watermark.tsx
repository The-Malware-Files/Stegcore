// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { useState, useEffect, useCallback } from 'react'
import { FolderOpen, KeyRound, Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { Toggle } from '../components/Toggle'
import { useFooter } from '../lib/footerContext'
import { useSettingsStore } from '../lib/stores/settingsStore'
import {
  pickFiles,
  watermarkFile,
  readWatermark,
  watermarkHasConsent,
  grantWatermarkConsent,
  type Cipher,
} from '../lib/ipc'

const CARRIER_EXTS = ['png', 'bmp', 'webp', 'pdf', 'docx', 'pptx', 'xlsx']

const CIPHERS: Array<{ id: Cipher; label: string }> = [
  { id: 'chacha20-poly1305', label: 'ChaCha20-Poly1305' },
  { id: 'aes-256-gcm', label: 'AES-256-GCM' },
  { id: 'ascon-128', label: 'Ascon-128' },
]

function defaultOutput(path: string): string {
  const slash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  const dir = slash >= 0 ? path.slice(0, slash + 1) : ''
  const name = slash >= 0 ? path.slice(slash + 1) : path
  const dot = name.lastIndexOf('.')
  if (dot <= 0) return `${dir}${name}_marked`
  return `${dir}${name.slice(0, dot)}_marked${name.slice(dot)}`
}

// ── One-time consent dialog ──────────────────────────────────────────────

function ConsentDialog({ onAccept, onCancel }: { onAccept: () => void; onCancel: () => void }) {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Watermarking authorisation"
      style={{
        position: 'fixed', inset: 0, zIndex: 50,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: 'rgba(0,0,0,0.6)',
      }}
    >
      <div style={{
        maxWidth: 440, margin: 16, padding: 24, borderRadius: 14,
        background: 'var(--ui-surface)', border: '1px solid var(--ui-border)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
          <ShieldCheck size={22} style={{ color: 'var(--ui-accent)' }} />
          <h2 style={{ fontSize: 16, fontWeight: 600, margin: 0 }}>Authorisation required</h2>
        </div>
        <p style={{ fontSize: 13, color: 'var(--ui-text2)', lineHeight: 1.7, marginBottom: 16 }}>
          Watermarking marks a file as yours. Only watermark files you own, or files whose
          recipients have been told they carry a tracking watermark. By continuing you confirm
          you are authorised to watermark this file. This is recorded once on this machine and
          shared with the command line tool.
        </p>
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={btnStyle(false)}>Cancel</button>
          <button onClick={onAccept} style={btnStyle(true)}>I am authorised</button>
        </div>
      </div>
    </div>
  )
}

function btnStyle(primary: boolean): React.CSSProperties {
  return {
    padding: '8px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer',
    border: '1px solid var(--ui-border)',
    background: primary ? 'var(--ui-accent)' : 'transparent',
    color: primary ? '#04080f' : 'var(--ui-text)',
  }
}

// ── Watermark route ──────────────────────────────────────────────────────

export default function Watermark() {
  const [verifyMode, setVerifyMode] = useState(false)
  const [file, setFile] = useState('')
  const [mark, setMark] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [showPass, setShowPass] = useState(false)
  const defaultCipher = useSettingsStore((s) => s.settings.defaultCipher)
  const [cipher, setCipher] = useState<Cipher>(defaultCipher)
  const [cipherTouched, setCipherTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [recovered, setRecovered] = useState('')
  const [consentOpen, setConsentOpen] = useState(false)
  const [hasConsent, setHasConsent] = useState(false)

  useFooter({
    backLabel: 'Home',
    backAction: () => { window.history.back() },
  })

  useEffect(() => {
    watermarkHasConsent().then(setHasConsent).catch(() => setHasConsent(false))
  }, [])

  // Follow the default-cipher setting until the user picks one here. Seeding
  // via useState alone misses the async settings load, so re-sync on change.
  useEffect(() => {
    if (!cipherTouched) setCipher(defaultCipher)
  }, [defaultCipher, cipherTouched])

  const pick = useCallback(async () => {
    const files = await pickFiles({
      title: 'Choose a file to watermark',
      filters: [{ name: 'Watermarkable files', extensions: CARRIER_EXTS }],
    })
    if (files[0]) {
      setFile(files[0])
      setStatus(null)
      setRecovered('')
    }
  }, [])

  const doApply = useCallback(async () => {
    setBusy(true)
    setStatus(null)
    try {
      const written = await watermarkFile({
        cover: file,
        mark,
        passphrase,
        cipher,
        output: defaultOutput(file),
      })
      setStatus({ kind: 'ok', text: `Watermarked to ${written}` })
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setStatus({ kind: 'err', text: msg })
    } finally {
      setBusy(false)
    }
  }, [file, mark, passphrase, cipher])

  const onApplyClick = useCallback(async () => {
    if (!file || !mark || !passphrase) return
    if (!hasConsent) {
      setConsentOpen(true)
      return
    }
    void doApply()
  }, [file, mark, passphrase, hasConsent, doApply])

  const acceptConsent = useCallback(async () => {
    setConsentOpen(false)
    try {
      await grantWatermarkConsent()
      setHasConsent(true)
      void doApply()
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setStatus({ kind: 'err', text: `Could not record authorisation: ${msg}` })
    }
  }, [doApply])

  const doVerify = useCallback(async () => {
    if (!file || !passphrase) return
    setBusy(true)
    setStatus(null)
    setRecovered('')
    try {
      const text = await readWatermark(file, passphrase)
      setRecovered(text)
      setStatus({ kind: 'ok', text: 'Watermark found' })
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      setStatus({ kind: 'err', text: msg })
    } finally {
      setBusy(false)
    }
  }, [file, passphrase])

  const canSubmit = verifyMode ? !!(file && passphrase) : !!(file && mark && passphrase)

  return (
    <div style={{ maxWidth: 560, margin: '0 auto', padding: '2rem 1.5rem' }}>
      <div style={{ marginBottom: '1.5rem' }}>
        <span style={{
          display: 'block', fontSize: 11, fontFamily: "'Space Mono', monospace",
          color: 'var(--ui-text2)', letterSpacing: '0.12em',
          textTransform: 'uppercase', marginBottom: 8,
        }}>
          Provenance
        </span>
        <h2 style={{ fontSize: 28, fontWeight: 600, color: 'var(--ui-text)', letterSpacing: '-0.02em', marginBottom: 6 }}>
          Watermark
        </h2>
        <p style={{ fontSize: 13, color: 'var(--ui-text2)', lineHeight: 1.6 }}>
          Write an encrypted ownership mark into an image or document, or read one back to prove
          provenance. Carriers: PNG, BMP, WebP, PDF, DOCX, PPTX, XLSX.
        </p>
      </div>

      <div style={{ marginBottom: 18 }}>
        <Toggle
          checked={verifyMode}
          onChange={(v) => { setVerifyMode(v); setStatus(null); setRecovered('') }}
          label="Verify mode"
          description="Read an existing watermark instead of writing one."
        />
      </div>

      <label style={labelStyle}>Carrier file</label>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <input readOnly value={file} placeholder="No file selected" style={inputStyle} />
        <button onClick={pick} style={{ ...btnStyle(false), display: 'flex', alignItems: 'center', gap: 6 }}>
          <FolderOpen size={15} /> Browse
        </button>
      </div>

      <div className={`sc-collapse ${!verifyMode ? 'open' : ''}`}>
        <div className="sc-collapse-inner">
          <label style={labelStyle}>Watermark text</label>
          <input
            value={mark}
            onChange={(e) => setMark(e.target.value)}
            placeholder="owner: Acme Corp; ref: INV-2026-001"
            style={{ ...inputStyle, marginBottom: 16 }}
          />
        </div>
      </div>

      <label style={labelStyle}>Passphrase</label>
      <div style={{ position: 'relative', marginBottom: 16 }}>
        <KeyRound size={15} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--ui-text2)' }} />
        <input
          type={showPass ? 'text' : 'password'}
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Passphrase"
          style={{ ...inputStyle, paddingLeft: 32, paddingRight: 36 }}
        />
        <button
          onClick={() => setShowPass((s) => !s)}
          aria-label={showPass ? 'Hide passphrase' : 'Show passphrase'}
          style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', display: 'flex', alignItems: 'center', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--ui-text2)' }}
        >
          {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>

      <div className={`sc-collapse ${!verifyMode ? 'open' : ''}`}>
        <div className="sc-collapse-inner">
          <label style={labelStyle}>Cipher</label>
          <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap' }}>
            {CIPHERS.map((c) => (
              <button
                key={c.id}
                onClick={() => { setCipher(c.id); setCipherTouched(true) }}
                style={{
                  ...btnStyle(cipher === c.id),
                  fontSize: 12,
                  opacity: cipher === c.id ? 1 : 0.7,
                }}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <button
        onClick={verifyMode ? doVerify : onApplyClick}
        disabled={!canSubmit || busy}
        style={{
          ...btnStyle(true),
          width: '100%', padding: '11px', fontSize: 14,
          opacity: !canSubmit || busy ? 0.5 : 1,
          cursor: !canSubmit || busy ? 'not-allowed' : 'pointer',
        }}
      >
        {busy ? 'Working…' : verifyMode ? 'Read watermark' : 'Apply watermark'}
      </button>

      {recovered && (
        <div style={{ marginTop: 18, padding: 14, borderRadius: 10, border: '1px solid var(--ui-border)', background: 'var(--ui-surface)' }}>
          <div style={{ fontSize: 11, color: 'var(--ui-text2)', marginBottom: 6 }}>Recovered mark</div>
          <div style={{ fontSize: 13, fontFamily: "'Space Mono', monospace", wordBreak: 'break-word' }}>{recovered}</div>
        </div>
      )}

      {status && (
        <div style={{
          marginTop: 16, fontSize: 13, lineHeight: 1.6,
          color: status.kind === 'ok' ? 'var(--ui-success, #4ade80)' : 'var(--ui-error, #f87171)',
        }}>
          {status.text}
        </div>
      )}

      {consentOpen && (
        <ConsentDialog onAccept={acceptConsent} onCancel={() => setConsentOpen(false)} />
      )}
    </div>
  )
}

const labelStyle: React.CSSProperties = {
  display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--ui-text2)', marginBottom: 6,
}

const inputStyle: React.CSSProperties = {
  flex: 1, width: '100%', padding: '9px 11px', borderRadius: 8, fontSize: 13,
  background: 'var(--ui-surface)', border: '1px solid var(--ui-border)', color: 'var(--ui-text)',
}
