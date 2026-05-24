// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import type { FingerprintTier } from '../lib/ipc'

/** Tier-aware fingerprint badge.
 *
 *  Renders the tool name as a coloured pill keyed off the structural-match
 *  tier emitted by the engine:
 *
 *  - `"exact"` (red, decisive) — tool-specific magic / structural invariant
 *    matched. Verdict is `Stego`.
 *  - `"heuristic"` (amber, corroborating) — pattern is suggestive but could
 *    occur naturally; the engine floors the verdict at `Suspicious`.
 *  - `null` / missing — pre-v4.0.1 reports that carry a `tool_fingerprint`
 *    label but no tier; rendered neutrally.
 *
 *  The long-form label from `tool_fingerprint` ("LSBSteg (exact signature)")
 *  becomes the tooltip; the pill itself shows just the tool name so it stays
 *  readable in card layouts.
 */
export function FingerprintBadge({
  tool,
  tier,
}: {
  tool: string
  tier: FingerprintTier | null
}) {
  // Strip the " (exact signature)" / " (heuristic match)" suffix when we have
  // the tier — the pill colour says it more clearly. Keep the suffix when tier
  // is missing (legacy reports) so no information is lost.
  const display = tier
    ? tool.replace(/\s*\((?:exact signature|heuristic match)\)\s*$/, '')
    : tool

  const styles =
    tier === 'exact'
      ? {
          color: 'var(--ui-danger)',
          background: 'color-mix(in srgb, var(--ui-danger) 12%, transparent)',
          border: '1px solid color-mix(in srgb, var(--ui-danger) 35%, transparent)',
        }
      : tier === 'heuristic'
        ? {
            color: 'var(--ui-warn)',
            background: 'color-mix(in srgb, var(--ui-warn) 12%, transparent)',
            border: '1px solid color-mix(in srgb, var(--ui-warn) 35%, transparent)',
          }
        : {
            color: 'var(--ui-text2)',
            background: 'transparent',
            border: '1px solid var(--ui-border)',
          }

  const tooltip = tier
    ? `${tool} (${tier === 'exact' ? 'exact signature — decisive match' : 'heuristic match — corroborating only'})`
    : tool

  return (
    <span
      title={tooltip}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '1px 7px',
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 500,
        lineHeight: 1.6,
        ...styles,
      }}
    >
      {display}
    </span>
  )
}
