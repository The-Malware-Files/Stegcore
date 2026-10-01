// Author:  Daniel Iwugo
// Comment: Christ is King
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

const { invokeMock, saveMock, writeFileMock, writeTextFileMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  saveMock: vi.fn(),
  writeFileMock: vi.fn(),
  writeTextFileMock: vi.fn(),
}))
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }))
vi.mock('@tauri-apps/plugin-dialog', () => ({ save: saveMock }))
vi.mock('@tauri-apps/plugin-fs', () => ({
  writeFile: writeFileMock,
  writeTextFile: writeTextFileMock,
}))

import { saveToFile, SaveFailed } from './ipc'

const REQ = { title: 'Save report', defaultPath: 'stegcore-report.json' }

describe('saveToFile', () => {
  beforeEach(() => {
    invokeMock.mockReset()
    saveMock.mockReset()
    writeFileMock.mockReset()
    writeTextFileMock.mockReset()
  })

  it('takes permission for the chosen path before writing, and writes where it was told', async () => {
    saveMock.mockResolvedValue('/tmp/link/report.json')
    // The backend resolved the symbolic link, so the granted path differs.
    invokeMock.mockResolvedValue('/private/tmp/report.json')
    writeTextFileMock.mockResolvedValue(undefined)

    const outcome = await saveToFile(REQ, '{}')

    expect(invokeMock).toHaveBeenCalledWith('prepare_save', { path: '/tmp/link/report.json' })
    expect(writeTextFileMock).toHaveBeenCalledWith('/private/tmp/report.json', '{}')
    expect(outcome).toEqual({ kind: 'saved', path: '/private/tmp/report.json' })
  })

  it('sends bytes through writeFile rather than writeTextFile', async () => {
    saveMock.mockResolvedValue('/tmp/extracted')
    invokeMock.mockResolvedValue('/tmp/extracted')
    writeFileMock.mockResolvedValue(undefined)

    const bytes = new Uint8Array([1, 2, 3])
    await saveToFile({ title: 'Save extracted file', defaultPath: 'extracted' }, bytes)

    expect(writeFileMock).toHaveBeenCalledWith('/tmp/extracted', bytes)
    expect(writeTextFileMock).not.toHaveBeenCalled()
  })

  it('reports a cancelled dialog as cancelled, and grants nothing', async () => {
    saveMock.mockResolvedValue(null)

    await expect(saveToFile(REQ, '{}')).resolves.toEqual({ kind: 'cancelled' })
    expect(invokeMock).not.toHaveBeenCalled()
    expect(writeTextFileMock).not.toHaveBeenCalled()
  })

  // The bug this file exists for: a refused write used to fall through to a
  // blob download that goes nowhere inside the webview, so the user saw a save
  // that appeared to succeed and produced no file.
  it('throws with a readable reason when the write is refused', async () => {
    saveMock.mockResolvedValue('/tmp/report.json')
    invokeMock.mockResolvedValue('/tmp/report.json')
    writeTextFileMock.mockRejectedValue(new Error('forbidden path: /tmp/report.json'))

    const err = await saveToFile(REQ, '{}').catch((e) => e)
    expect(err).toBeInstanceOf(SaveFailed)
    expect(err.message).toContain('/tmp/report.json')
    expect(err.message).toContain('Nothing was saved')
    expect(err.detail).toContain('forbidden path')
  })

  it('throws when permission for the chosen path is refused', async () => {
    saveMock.mockResolvedValue('/etc/shadow')
    invokeMock.mockRejectedValue(new Error('The folder /etc does not exist.'))

    const err = await saveToFile(REQ, '{}').catch((e) => e)
    expect(err).toBeInstanceOf(SaveFailed)
    expect(err.message).toContain('/etc/shadow')
    expect(err.detail).toContain('does not exist')
    expect(writeTextFileMock).not.toHaveBeenCalled()
  })

  it('throws when the dialog itself fails, rather than downloading silently', async () => {
    saveMock.mockRejectedValue(new Error('dialog backend unavailable'))

    const err = await saveToFile(REQ, '{}').catch((e) => e)
    expect(err).toBeInstanceOf(SaveFailed)
    expect(err.detail).toContain('dialog backend unavailable')
  })

  it('falls back to a browser download only when Tauri is genuinely absent', async () => {
    saveMock.mockRejectedValue(new Error('window.__TAURI_INTERNALS__ is undefined'))
    const click = vi.fn()
    const createObjectURL = vi.fn().mockReturnValue('blob:x')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL })
    const anchor = { href: '', download: '', click } as unknown as HTMLAnchorElement
    const createElement = vi
      .spyOn(document, 'createElement')
      .mockReturnValue(anchor as HTMLElement as never)

    await expect(saveToFile(REQ, '{}')).resolves.toEqual({ kind: 'downloaded' })
    expect(click).toHaveBeenCalled()
    expect(anchor.download).toBe('stegcore-report.json')
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:x')

    createElement.mockRestore()
    vi.unstubAllGlobals()
  })
})
