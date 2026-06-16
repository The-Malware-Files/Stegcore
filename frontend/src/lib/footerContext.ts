// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { createContext, useContext, useEffect, useRef } from 'react'

// Wizard routes provide their own back/continue actions to the shared footer.
// The context and its hook live here (not in App.tsx) so App.tsx only exports
// a component, which keeps Fast Refresh working.

export interface FooterConfig {
  backLabel?: string
  backAction?: (() => void) | null
  continueLabel?: string
  continueAction?: (() => void) | null
  continueDisabled?: boolean
  steps?: string[]
  currentStep?: number
}

export const FooterCtx = createContext<(cfg: FooterConfig | null) => void>(() => undefined)

export function useFooter(cfg: FooterConfig | null) {
  const set = useContext(FooterCtx)
  const backLabel = cfg?.backLabel
  const continueLabel = cfg?.continueLabel
  const continueDisabled = cfg?.continueDisabled
  const currentStep = cfg?.currentStep
  const hasBack = !!cfg?.backAction
  const hasContinue = !!cfg?.continueAction

  // Routes rebuild `cfg` and its action closures every render. Hold the latest
  // in a ref so the registration effect can read fresh actions without
  // re-running on their identity, which would thrash the footer state. It
  // re-registers only when a meaningful field (label/step/action presence)
  // changes.
  const latest = useRef(cfg)
  useEffect(() => { latest.current = cfg })

  useEffect(() => {
    set(latest.current)
    return () => set(null)
  }, [set, backLabel, continueLabel, continueDisabled, currentStep, hasBack, hasContinue])
}
