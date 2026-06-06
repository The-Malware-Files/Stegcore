// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { describe, it, expect } from 'vitest'
import { render } from '@testing-library/react'
import { EntropyBar } from './EntropyBar'

describe('EntropyBar', () => {
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
    // The 10 strength segments are the fixed-height bars.
    const segments = Array.from(container.querySelectorAll('div')).filter(
      (d) => (d as HTMLElement).style.height === '4px',
    )
    expect(segments.length).toBe(10)
    const filled = segments.filter(
      (d) => !(d as HTMLElement).style.background.includes('border2'),
    )
    expect(filled.length).toBeGreaterThanOrEqual(1)
  })
})
