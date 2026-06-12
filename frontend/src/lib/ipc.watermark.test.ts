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

// Mock the Tauri invoke bridge so we can drive both the real path and the
// "Tauri unavailable" fallback without a running runtime.
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }))
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }))

import {
  watermarkFormats,
  watermarkHasConsent,
  grantWatermarkConsent,
  watermarkFile,
  readWatermark,
} from './ipc'

describe('watermark IPC bindings', () => {
  beforeEach(() => invokeMock.mockReset())

  it('watermarkFormats invokes the right command and returns the backend list', async () => {
    invokeMock.mockResolvedValue(['png', 'pdf', 'docx'])
    await expect(watermarkFormats()).resolves.toEqual(['png', 'pdf', 'docx'])
    expect(invokeMock).toHaveBeenCalledWith('watermark_formats', undefined)
  })

  it('watermarkHasConsent forwards the boolean', async () => {
    invokeMock.mockResolvedValue(true)
    await expect(watermarkHasConsent()).resolves.toBe(true)
    expect(invokeMock).toHaveBeenCalledWith('watermark_has_consent', undefined)
  })

  it('grantWatermarkConsent invokes the grant command', async () => {
    invokeMock.mockResolvedValue(undefined)
    await grantWatermarkConsent()
    expect(invokeMock).toHaveBeenCalledWith('grant_watermark_consent', undefined)
  })

  it('watermarkFile passes the camelCase args and returns the written path', async () => {
    invokeMock.mockResolvedValue('/out/marked.png')
    const written = await watermarkFile({
      cover: 'a.png',
      mark: 'owner: Acme',
      passphrase: 'pass',
      cipher: 'aes-256-gcm',
      output: 'o.png',
    })
    expect(written).toBe('/out/marked.png')
    expect(invokeMock).toHaveBeenCalledWith('watermark_file', {
      cover: 'a.png',
      mark: 'owner: Acme',
      passphrase: 'pass',
      cipher: 'aes-256-gcm',
      output: 'o.png',
    })
  })

  it('readWatermark passes path and passphrase and returns the mark text', async () => {
    invokeMock.mockResolvedValue('owner: Acme')
    await expect(readWatermark('marked.png', 'pass')).resolves.toBe('owner: Acme')
    expect(invokeMock).toHaveBeenCalledWith('read_watermark_file', {
      path: 'marked.png',
      passphrase: 'pass',
    })
  })
})
