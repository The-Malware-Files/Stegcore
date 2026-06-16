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
import { footerVisibility, escapeOutcome } from './footerNav'

const noop = () => undefined

describe('footerVisibility', () => {
  it('shows only Back on a single-action route (the Watermark case)', () => {
    expect(footerVisibility({ backAction: noop }, false)).toEqual({
      back: 'shown',
      continue: 'hidden',
    })
  })

  it('hides the phantom Continue when no continue action exists', () => {
    // Regression: previously a Back-only route rendered a greyed Continue.
    expect(footerVisibility({ backAction: noop }, false).continue).toBe('hidden')
  })

  it('shows an enabled Continue when the action exists and is not disabled', () => {
    expect(footerVisibility({ backAction: noop, continueAction: noop }, false)).toEqual({
      back: 'shown',
      continue: 'shown',
    })
  })

  it('greys a Continue that exists but cannot fire yet (wizard step)', () => {
    expect(
      footerVisibility({ backAction: noop, continueAction: noop, continueDisabled: true }, false).continue,
    ).toBe('disabled')
  })

  it('hides both buttons on Home regardless of config', () => {
    expect(footerVisibility({ backAction: noop, continueAction: noop }, true)).toEqual({
      back: 'hidden',
      continue: 'hidden',
    })
  })

  it('hides both when config is null or undefined', () => {
    expect(footerVisibility(null, false)).toEqual({ back: 'hidden', continue: 'hidden' })
    expect(footerVisibility(undefined, false)).toEqual({ back: 'hidden', continue: 'hidden' })
  })

  it('treats a null backAction as absent', () => {
    expect(footerVisibility({ backAction: null }, false).back).toBe('hidden')
  })
})

describe('escapeOutcome', () => {
  const base = {
    key: 'Escape',
    targetTag: 'BODY',
    modalOpen: false,
    hasBackAction: false,
    isHome: false,
  }

  it('ignores any key that is not Escape', () => {
    expect(escapeOutcome({ ...base, key: 'a' })).toBe('ignore')
  })

  it.each(['INPUT', 'TEXTAREA', 'SELECT'])('ignores Escape while focused in %s', (tag) => {
    expect(escapeOutcome({ ...base, targetTag: tag })).toBe('ignore')
  })

  it('ignores Escape while an overlay is open (the overlay closes itself)', () => {
    expect(escapeOutcome({ ...base, modalOpen: true })).toBe('ignore')
  })

  it('runs the route Back action when one exists (mirrors the Back button)', () => {
    expect(escapeOutcome({ ...base, hasBackAction: true })).toBe('run-back')
  })

  it('navigates back when no Back action exists but we are not on Home', () => {
    expect(escapeOutcome({ ...base, hasBackAction: false, isHome: false })).toBe('navigate-back')
  })

  it('is a no-op on Home with nothing behind it', () => {
    expect(escapeOutcome({ ...base, isHome: true })).toBe('ignore')
  })

  it('prefers the modal guard over a present Back action', () => {
    expect(escapeOutcome({ ...base, modalOpen: true, hasBackAction: true })).toBe('ignore')
  })

  it('handles an undefined target tag (no focused element)', () => {
    expect(escapeOutcome({ ...base, targetTag: undefined, hasBackAction: true })).toBe('run-back')
  })
})
