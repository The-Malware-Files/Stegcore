// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

/**
 * Animated SVG checkmark — stroke-draw animation on mount.
 * Used on embed/extract success screens.
 */
export function SuccessCheck({ size = 48 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 52 52"
      style={{ display: 'block' }}
    >
      {/* Circle */}
      <circle
        cx="26" cy="26" r="24"
        fill="none"
        stroke="var(--ui-success)"
        strokeWidth="2"
        strokeDasharray="151"
        strokeDashoffset="151"
        style={{ animation: 'sc-check-circle 0.4s ease-out 0.1s forwards' }}
      />
      {/* Checkmark */}
      <path
        d="M14 27l7 7 16-16"
        fill="none"
        stroke="var(--ui-success)"
        strokeWidth="3"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeDasharray="40"
        strokeDashoffset="40"
        style={{ animation: 'sc-check-tick 0.3s ease-out 0.45s forwards' }}
      />
      <style>{`
        @keyframes sc-check-circle {
          to { stroke-dashoffset: 0; }
        }
        @keyframes sc-check-tick {
          to { stroke-dashoffset: 0; }
        }
      `}</style>
    </svg>
  )
}
