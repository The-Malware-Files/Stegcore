// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// Vitest harness for the React/TypeScript surface. This is a separate
// coverage number from the Rust workspace llvm-cov gate (different toolchain);
// both must clear their floor (CLAUDE.md A7).
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'json', 'lcov'],
      // Only the units we have started covering count toward the gate; the
      // include list grows as the harness expands (routes, more components).
      include: [
        'src/lib/passphrase.ts',
        'src/lib/footerNav.ts',
        'src/components/EntropyBar.tsx',
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        statements: 90,
        branches: 85,
      },
    },
  },
})
