// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// Pure decision logic for the footer nav buttons and the global Escape
// shortcut. Kept out of App.tsx so the branches are unit-testable without a
// router, a DOM, or a Tauri runtime.

export interface FooterConfigLike {
  backAction?: (() => void) | null
  continueAction?: (() => void) | null
  continueDisabled?: boolean
}

export interface FooterVisibility {
  /** "shown" → fully visible/clickable; "hidden" → not rendered to the user. */
  back: 'shown' | 'hidden'
  /** "disabled" → visible but greyed (action exists, cannot fire yet). */
  continue: 'shown' | 'disabled' | 'hidden'
}

/**
 * Decide each footer button's state from the active route's footer config.
 * A button is shown only when its own action exists; the greyed "disabled"
 * state is reserved for a Continue that exists but cannot fire yet (a wizard
 * step that is not ready). No action at all means the button is hidden, so
 * single-action routes (e.g. Watermark) show only a Back button.
 */
export function footerVisibility(
  cfg: FooterConfigLike | null | undefined,
  isHome: boolean,
): FooterVisibility {
  const hasBack = !isHome && !!cfg?.backAction
  const hasContinue = !isHome && !!cfg?.continueAction
  return {
    back: hasBack ? 'shown' : 'hidden',
    continue: hasContinue ? (cfg?.continueDisabled ? 'disabled' : 'shown') : 'hidden',
  }
}

export type EscapeOutcome = 'ignore' | 'run-back' | 'navigate-back'

/**
 * Decide what the Escape key should do. It mirrors the footer Back button so
 * wizard steps unwind correctly, but never fires while a form control is
 * focused or an overlay is open (overlays close themselves on Escape), and is
 * a no-op on Home (nothing behind it).
 */
export function escapeOutcome(params: {
  key: string
  targetTag: string | undefined
  modalOpen: boolean
  hasBackAction: boolean
  isHome: boolean
}): EscapeOutcome {
  const { key, targetTag, modalOpen, hasBackAction, isHome } = params
  if (key !== 'Escape') return 'ignore'
  if (targetTag === 'INPUT' || targetTag === 'TEXTAREA' || targetTag === 'SELECT') return 'ignore'
  if (modalOpen) return 'ignore'
  if (hasBackAction) return 'run-back'
  if (!isHome) return 'navigate-back'
  return 'ignore'
}
