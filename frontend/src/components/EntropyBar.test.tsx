// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render } from '@testing-library/react'

// Control the lazy zxcvbn upgrade so the render tests observe the synchronous
// heuristic and the upgrade path is exercised deterministically.
const { scoreWithZxcvbnMock } = vi.hoisted(() => ({ scoreWithZxcvbnMock: vi.fn() }))
vi.mock('../lib/passphraseStrength', () => ({ scoreWithZxcvbn: scoreWithZxcvbnMock }))

import { EntropyBar } from './EntropyBar'

describe('EntropyBar', () => {
  beforeEach(() => {
    scoreWithZxcvbnMock.mockReset()
    // Default: the upgrade never resolves, so assertions see the heuristic.
    scoreWithZxcvbnMock.mockReturnValue(new Promise(() => {}))
  })

  it('renders nothing for an empty passphrase', () => {
    const { container } = render(<EntropyBar value="" />)
    expect(container.firstChild).toBeNull()
  })

  it('labels a strong passphrase as Strong', () => {
    const { getByText } = render(<EntropyBar value="Tr0ub4dour&3xpl0it!2026" />)
    expect(getByText('Passphrase strength')).toBeTruthy()
    expect(getByText('Strong')).toBeTruthy()
  })

  it('labels a trivial passphrase as Weak', () => {
    const { getByText } = render(<EntropyBar value="password" />)
    expect(getByText('Weak')).toBeTruthy()
  })

  it('always shows at least one filled segment for non-empty input', () => {
    const { container } = render(<EntropyBar value="a" />)
    const segments = Array.from(container.querySelectorAll('div')).filter(
      (d) => (d as HTMLElement).style.height === '4px',
    )
    expect(segments.length).toBe(10)
    const filled = segments.filter(
      (d) => !(d as HTMLElement).style.background.includes('border2'),
    )
    expect(filled.length).toBeGreaterThanOrEqual(1)
  })

  it('upgrades the rating when zxcvbn resolves higher than the heuristic', async () => {
    // "aaaa" is heuristically Weak; the (mocked) zxcvbn refinement rates it 95.
    scoreWithZxcvbnMock.mockResolvedValue(95)
    const { findByText } = render(<EntropyBar value="aaaa" />)
    expect(await findByText('Strong')).toBeTruthy()
  })

  it('keeps the heuristic rating when the zxcvbn upgrade fails', async () => {
    scoreWithZxcvbnMock.mockRejectedValue(new Error('load failed'))
    const { getByText } = render(<EntropyBar value="password" />)
    // Let the rejected promise settle, then confirm the heuristic still stands.
    await Promise.resolve()
    expect(getByText('Weak')).toBeTruthy()
  })
})
