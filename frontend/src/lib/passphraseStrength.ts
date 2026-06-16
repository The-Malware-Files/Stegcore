// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// Lazy zxcvbn-ts strength refinement.
//
// The synchronous heuristic in `passphrase.ts` gives instant feedback and is the
// fallback. This module lazily loads zxcvbn-ts (the dictionary + adjacency graph
// data is a few hundred KB, so it is dynamically imported only on first use, not
// at first paint) and refines the score with proper guess-estimation. The result
// is advisory only: the >= 1-character floor and the Argon2 + AEAD crypto are the
// real guarantees, not this estimate.

import { scorePassphrase } from './passphrase'

/** Map zxcvbn's coarse 0-4 score onto the 0-100 scale the bar renders. */
export function zxcvbnPercent(score: number): number {
  const table = [8, 30, 55, 80, 100]
  const i = Math.max(0, Math.min(4, Math.round(score)))
  return table[i]
}

type ZxcvbnFn = (password: string) => { score: number }

let cached: Promise<ZxcvbnFn> | null = null

async function loadZxcvbn(): Promise<ZxcvbnFn> {
  if (!cached) {
    cached = (async () => {
      const core = await import('@zxcvbn-ts/core')
      const commonMod = await import('@zxcvbn-ts/language-common')
      const enMod = await import('@zxcvbn-ts/language-en')
      // Some bundlers wrap these in a default export; accept either shape.
      const common = (commonMod as { default?: unknown }).default ?? commonMod
      const en = (enMod as { default?: unknown }).default ?? enMod
      const c = common as { dictionary?: object; adjacencyGraphs?: object }
      const e = en as { dictionary?: object; translations?: object }
      core.zxcvbnOptions.setOptions({
        dictionary: { ...(c.dictionary ?? {}), ...(e.dictionary ?? {}) },
        graphs: c.adjacencyGraphs as never,
        translations: e.translations as never,
      })
      return (password: string) => core.zxcvbn(password)
    })()
  }
  return cached
}

/** Refined 0-100 strength via zxcvbn. Falls back to the heuristic score if the
 *  library fails to load (offline, blocked, or a bundling quirk). */
export async function scoreWithZxcvbn(value: string): Promise<number> {
  if (!value) return 0
  try {
    const zxcvbn = await loadZxcvbn()
    return zxcvbnPercent(zxcvbn(value).score)
  } catch {
    return scorePassphrase(value)
  }
}
