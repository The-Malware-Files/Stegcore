// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

export interface SteganalysisResult {
  filename: string
  format: string  // 'png', 'bmp', 'jpg', 'webp', 'wav', 'flac'
  filesize_bytes: number
  image_dimensions: [number, number]
  risk_score: number
  risk_label: 'clean' | 'uncertain' | 'suspicious' | 'likely_embedded'

  chi_squared: {
    r: number
    g: number
    b: number
    threshold: number
  }

  rs_analysis: {
    r: number[]
    s: number[]
    rm: number[]
    sm: number[]
    estimated_rate: number
  }

  sample_pair: {
    estimated_rate: number
    confidence: number
  }

  lsb_entropy: {
    grid: number[][]
    hot_zones: string[]
  }
}
