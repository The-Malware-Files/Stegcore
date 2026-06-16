// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, act, fireEvent } from '@testing-library/react'

// Stub the footer hook so the test doesn't need a FooterCtx provider.
vi.mock('../lib/footerContext', () => ({ useFooter: () => undefined }))

// Only watermarkHasConsent runs on mount; the rest just need to exist so the
// named imports resolve.
vi.mock('../lib/ipc', () => ({
  pickFiles: vi.fn(),
  watermarkFile: vi.fn(),
  readWatermark: vi.fn(),
  watermarkHasConsent: vi.fn(() => Promise.resolve(false)),
  grantWatermarkConsent: vi.fn(),
}))

import Watermark from './Watermark'
import { useSettingsStore } from '../lib/stores/settingsStore'

function setDefaultCipher(c: string) {
  act(() => {
    useSettingsStore.setState((s) => ({ settings: { ...s.settings, defaultCipher: c as never } }))
  })
}

/** The selected pill is rendered at full opacity; the others at 0.7. */
function selectedCipher(): string | null {
  for (const label of ['ChaCha20-Poly1305', 'AES-256-GCM', 'Ascon-128']) {
    const btn = screen.getByRole('button', { name: label })
    if (btn.style.opacity === '1') return label
  }
  return null
}

async function renderRoute() {
  await act(async () => {
    render(<Watermark />)
  })
}

describe('Watermark cipher seeding', () => {
  beforeEach(() => {
    setDefaultCipher('chacha20-poly1305')
  })

  it('seeds the cipher from the default-cipher setting, not a hardcoded value', async () => {
    setDefaultCipher('aes-256-gcm')
    await renderRoute()
    expect(selectedCipher()).toBe('AES-256-GCM')
  })

  it('follows a later change to the default-cipher setting until the user picks one', async () => {
    setDefaultCipher('aes-256-gcm')
    await renderRoute()
    expect(selectedCipher()).toBe('AES-256-GCM')

    // Setting changes (e.g. via the Settings panel) — the route should follow,
    // covering the async-settings-load race the seeding effect guards against.
    setDefaultCipher('ascon-128')
    expect(selectedCipher()).toBe('Ascon-128')
  })

  it('locks to the user choice and ignores later setting changes', async () => {
    setDefaultCipher('aes-256-gcm')
    await renderRoute()

    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'ChaCha20-Poly1305' }))
    })
    expect(selectedCipher()).toBe('ChaCha20-Poly1305')

    // A subsequent default change must NOT override the manual pick.
    setDefaultCipher('ascon-128')
    expect(selectedCipher()).toBe('ChaCha20-Poly1305')
  })
})
