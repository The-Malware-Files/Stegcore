// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

import { useState, useEffect, useCallback } from 'react'
import { Check } from 'lucide-react'
import './Installer.css'

interface InstallerProps {
  onComplete: (prefs: { theme: string; defaultCipher: string }) => void
}

const TOTAL_STEPS = 5

// ── Stegcore logo — looping slide-apart/reassemble animation ──────────────
// Mirrors the splash screen animation: bars slide in from opposite sides,
// hold, then slide apart, then reassemble. Infinite loop.

function Logo() {
  return (
    <svg className="inst-logo" width="44" height="44" viewBox="0 0 64 64" fill="none" style={{ overflow: 'visible' }}>
      <rect className="inst-bar inst-bar-top"    x="8" y="10" width="48" height="12" rx="2.5" fill="var(--sc-accent-light)" />
      <rect className="inst-bar inst-bar-mid-l"  x="8" y="28" width="21" height="12" rx="2.5" fill="var(--sc-accent)" />
      <rect className="inst-bar inst-bar-mid-r"  x="35" y="28" width="21" height="12" rx="2.5" fill="var(--sc-accent)" />
      <rect className="inst-bar inst-bar-bottom" x="8" y="46" width="48" height="12" rx="2.5" fill="var(--sc-accent-dark)" />
    </svg>
  )
}

// ── Segmented pill selector ───────────────────────────────────────────────

function SegmentedPill<T extends string>({ value, options, onChange }: {
  value: T
  options: Array<{ value: T; label: string }>
  onChange: (v: T) => void
}) {
  const idx = options.findIndex(o => o.value === value)
  const count = options.length
  return (
    <div className="inst-seg">
      {/* Sliding background indicator */}
      <div
        className="inst-seg-indicator"
        style={{
          width: `${100 / count}%`,
          left: `${(idx / count) * 100}%`,
        }}
      />
      {options.map((o) => (
        <button
          key={o.value}
          className={`inst-seg-btn${o.value === value ? ' active' : ''}`}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

// ── Step dots ─────────────────────────────────────────────────────────────

function Dots({ step }: { step: number }) {
  return (
    <div className="inst-dots">
      {Array.from({ length: TOTAL_STEPS }, (_, i) => {
        const s = i + 1
        return <div key={s} className={`inst-dot${s < step ? ' done' : ''}${s === step ? ' active' : ''}`} />
      })}
    </div>
  )
}

// ── Step 1: Acceptable Use Policy ─────────────────────────────────────────

function StepAUP({ accepted, onToggle }: { accepted: boolean; onToggle: () => void }) {
  return (
    <div className="inst-panel" style={{ display: 'flex', flexDirection: 'column' }}>
      <h3>Acceptable Use Policy</h3>
      <div className="inst-panel-body" style={{ maxHeight: 240, overflowY: 'auto' }}>
        <p>
          Stegcore is a steganography and encryption toolkit designed for legitimate privacy use cases:
        </p>
        <p>
          <strong>Intended users:</strong> Journalists protecting sources, activists in oppressive regimes,
          security researchers, CTF participants, and individuals exercising their right to personal privacy.
        </p>
        <p>
          <strong>Prohibited uses:</strong> This tool must not be used to conceal illegal content,
          circumvent lawful investigations, distribute malware, or facilitate any activity that causes
          harm to others. The developers do not condone and are not responsible for misuse.
        </p>
        <p>
          By using Stegcore, you acknowledge that you are solely responsible for ensuring your use
          complies with all applicable laws in your jurisdiction.
        </p>
      </div>
      <label className="inst-check" onClick={onToggle}>
        <input type="checkbox" checked={accepted} readOnly />
        <span className="inst-check-label">I understand and accept the acceptable use policy</span>
      </label>
    </div>
  )
}

// ── Step 2: AGPL-3.0 Licence ──────────────────────────────────────────────

function StepLicence({ accepted, onToggle }: { accepted: boolean; onToggle: () => void }) {
  return (
    <div className="inst-panel" style={{ display: 'flex', flexDirection: 'column' }}>
      <h3>AGPL-3.0 Licence</h3>
      <div className="inst-panel-body" style={{ maxHeight: 240, overflowY: 'auto' }}>
        <p>
          Stegcore is free software released under the GNU Affero General Public Licence v3.0.
        </p>
        <p>
          You may use, modify, and distribute this software freely. If you modify Stegcore and
          make it available over a network, you must release your modifications under the same licence.
        </p>
        <p>
          This software is provided without warranty. The full licence text is available in
          the <span className="inst-code">LICENSE</span> file in the application directory.
        </p>
        <p>
          Commercial licensing is available for organisations that cannot comply with AGPL terms.
        </p>
      </div>
      <label className="inst-check" onClick={onToggle}>
        <input type="checkbox" checked={accepted} readOnly />
        <span className="inst-check-label">I accept the licence terms</span>
      </label>
    </div>
  )
}

// ── Step 3: Initial Preferences ───────────────────────────────────────────

function StepPreferences({ theme, cipher, onTheme, onCipher }: {
  theme: string; cipher: string
  onTheme: (v: string) => void; onCipher: (v: string) => void
}) {
  return (
    <div className="inst-panel">
      <h3>Initial preferences</h3>
      <div className="inst-panel-body" style={{ marginBottom: 16 }}>
        <p>Set your preferred theme and default cipher. These can be changed anytime in Settings.</p>
      </div>

      <div style={{ marginBottom: 18 }}>
        <div className="inst-pref-label" style={{ marginBottom: 8 }}>Theme</div>
        <SegmentedPill
          value={theme}
          options={[
            { value: 'light', label: 'Light' },
            { value: 'dark', label: 'Dark' },
            { value: 'system', label: 'System' },
          ]}
          onChange={onTheme}
        />
      </div>

      <div>
        <div className="inst-pref-label" style={{ marginBottom: 8 }}>Default cipher</div>
        <SegmentedPill
          value={cipher}
          options={[
            { value: 'ascon-128', label: 'Ascon-128' },
            { value: 'aes-256-gcm', label: 'AES-256-GCM' },
            { value: 'chacha20-poly1305', label: 'ChaCha20' },
          ]}
          onChange={onCipher}
        />
      </div>
    </div>
  )
}

// ── Step 4: Progress ──────────────────────────────────────────────────────

const PROGRESS_STAGES: [number, string, number][] = [
  [15,  'Creating data folder…',              600],
  [30,  'Hiding your secrets…',              2200],
  [48,  'Verifying engine…',                  900],
  [62,  'Shredding evidence of this install…',2400],
  [75,  'Applying preferences…',              700],
  [85,  'Calibrating steganalysis suite…',   2000],
  [93,  'Almost there…',                      600],
  [100, 'Done.',                              800],
]

function StepProgress({ onDone }: { onDone: () => void }) {
  const [pct, setPct] = useState(0)
  const [msg, setMsg] = useState('Starting…')

  useEffect(() => {
    let cancelled = false
    let delay = 400

    const run = async () => {
      for (const [p, m, wait] of PROGRESS_STAGES) {
        await new Promise(r => setTimeout(r, delay))
        if (cancelled) return
        setPct(p)
        setMsg(m)
        delay = wait
      }
      await new Promise(r => setTimeout(r, 800))
      if (!cancelled) onDone()
    }
    run()
    return () => { cancelled = true }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="inst-panel">
      <h3>Setting up Stegcore</h3>
      <div className="inst-panel-body" style={{ marginBottom: 14 }}>
        <p>Creating your data folder, verifying files, and applying your preferences.</p>
      </div>
      <div className="inst-prog-track">
        <div className="inst-prog-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="inst-prog-msg">{msg}</div>
    </div>
  )
}

// ── Step 5: Ready ─────────────────────────────────────────────────────────

function StepReady({ onLaunch }: { onLaunch: () => void }) {
  return (
    <div className="inst-ready">
      <div className="inst-ready-check">
        <Check size={24} />
      </div>
      <h2 style={{ fontSize: 18, fontWeight: 600, margin: 0 }}>Stegcore is ready</h2>
      <button className="inst-btn inst-btn-primary" style={{ marginTop: 4, padding: '10px 28px' }} onClick={onLaunch}>
        Launch Stegcore
      </button>
    </div>
  )
}

// ── Main Installer ────────────────────────────────────────────────────────

export function Installer({ onComplete }: InstallerProps) {
  const [step, setStep] = useState(1)
  const [aupAccepted, setAupAccepted] = useState(false)
  const [licAccepted, setLicAccepted] = useState(false)
  const [theme, setThemeState] = useState('light')
  const [cipher, setCipher] = useState('chacha20-poly1305')

  // Apply theme in real-time as user changes it
  const handleTheme = useCallback((v: string) => {
    setThemeState(v)
    const doc = document.documentElement
    if (v === 'light') {
      doc.setAttribute('data-theme', 'light')
    } else if (v === 'dark') {
      doc.setAttribute('data-theme', 'dark')
    } else {
      // system
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
      if (prefersDark) doc.setAttribute('data-theme', 'dark')
      else doc.setAttribute('data-theme', 'light')
    }
  }, [])

  // Set initial theme to light on first mount
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', 'light')
  }, [])

  const canContinue =
    (step === 1 && aupAccepted) ||
    (step === 2 && licAccepted) ||
    step === 3

  const handleContinue = useCallback(() => {
    if (step === 3) {
      setStep(4)
      import('../lib/ipc').then(({ completeSetup }) => {
        completeSetup(theme, cipher).catch(() => {})
      }).catch(() => {})
    } else if (step < 4) {
      setStep(s => (s + 1) as 1 | 2 | 3 | 4 | 5)
    }
  }, [step, theme, cipher])

  const handleProgressDone = useCallback(() => setStep(5), [])

  const handleLaunch = useCallback(() => {
    onComplete({ theme, defaultCipher: cipher })
  }, [onComplete, theme, cipher])

  return (
    <div className="inst-root">
      <div className="inst-card">
        {/* Logo — constant across all steps */}
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 16 }}>
          <Logo />
        </div>

        <Dots step={step} />

        {step === 1 && <StepAUP accepted={aupAccepted} onToggle={() => setAupAccepted(v => !v)} />}
        {step === 2 && <StepLicence accepted={licAccepted} onToggle={() => setLicAccepted(v => !v)} />}
        {step === 3 && <StepPreferences theme={theme} cipher={cipher} onTheme={handleTheme} onCipher={setCipher} />}
        {step === 4 && <StepProgress onDone={handleProgressDone} />}
        {step === 5 && <StepReady onLaunch={handleLaunch} />}

        {step <= 3 && (
          <div className="inst-nav">
            <button
              className="inst-btn inst-btn-ghost"
              disabled={step === 1}
              onClick={() => setStep(s => (s - 1) as 1 | 2 | 3)}
            >
              Back
            </button>
            <button
              className="inst-btn inst-btn-primary"
              disabled={!canContinue}
              onClick={handleContinue}
            >
              Continue
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
