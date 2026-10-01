// Author:  Daniel Iwugo
// Comment: Christ is King
// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! JPEG DCT-domain steganalysis features, with calibration.
//!
//! # The blind spot this closes
//!
//! `analyse_image` decodes any image to RGB8 and runs spatial LSB detectors
//! over the pixels. JPEG steganography does not live in the pixels: it lives in
//! the quantised DCT coefficients, and JPEG decompression smooths the pixel
//! LSB plane, so the spatial detectors read the cover's noise and never the
//! payload. Measured over 120 matched steghide pairs, adding a payload changed
//! **0 of 120 verdicts** and moved the median score of all five detectors by
//! `+0.0000`; the four files flagged on the stego side were the same four
//! flagged as clean covers. That is no discriminating power at all, rather than
//! weak discriminating power, and no recalibration of a spatial detector can
//! change it because the information is not in the pixels it reads.
//!
//! # The three features, and why the third is what makes the first two work
//!
//! ```text
//!   JPEG bytes
//!      │
//!      ├── dct-io ────────────► quantised coefficients ──► histogram features
//!      │                                                      (F1)
//!      ├── decode to luma ───► 8x8 block boundaries ─────► blockiness
//!      │                                                      (F2)
//!      └── decode, crop 4px, forward-DCT with the SAME
//!          quantisation table ──► "what this image's statistics
//!                                  would look like if nothing were
//!                                  hidden in it"  ───────► calibration
//!                                                              (F3)
//! ```
//!
//! 1. **First-order coefficient histogram statistics.** Embedding that flips
//!    coefficient least-significant bits moves values within the pairs
//!    `(2k, 2k+1)`, which drives the two members of each pair toward equal
//!    counts. In a clean JPEG they are very unequal, because coefficient
//!    magnitude distribution decays steeply. [`DctFeatures::pov_equalisation`]
//!    measures that, and [`DctFeatures::ac_zero_ratio`] and
//!    [`DctFeatures::ac_one_ratio`] measure the shrinkage that matrix-encoding
//!    embedders (the F5 family) produce around zero.
//! 2. **Blockiness.** The sum of absolute differences across 8x8 block
//!    boundaries in the decompressed luma. Perturbing coefficients raises it.
//! 3. **Calibration.** The raw value of either feature above depends far more
//!    on the image than on whether anything is hidden in it, which is why a
//!    naive histogram detector does not work. So the image is decompressed,
//!    cropped by four pixels in each direction, and forward-DCT'd with the
//!    original quantisation table. The crop breaks the original block grid, so
//!    the result is a good estimate of the *cover's* statistics even when the
//!    input is a stego file, and the difference between a statistic and its
//!    calibrated estimate is what carries the signal.
//!
//! # What these features actually catch, measured
//!
//! Measured 2026-10-01 on 60 ALASKA2 covers with matched stego files, ROC AUC
//! against the same covers (0.5 is chance). The full procedure and the rest of
//! the sweep are recorded with the project's calibration harness, which is not
//! part of the distributed source because the corpora it uses are
//! dataset-licensed.
//!
//! | Embedder | Best feature | AUC | At |
//! |---|---|---|---|
//! | Stegcore's own JPEG path | `pov_equalisation` | 1.0000 | full capacity |
//! | Stegcore's own JPEG path | `pov_equalisation` | 0.6261 | 10% of capacity |
//! | outguess 0.4 | `delta_blockiness` | 0.8619 | 2% of file size |
//! | steghide 0.5.1 | `pov_equalisation` | 0.6497 | 90% of capacity |
//!
//! Three things in that table are worth saying plainly rather than burying.
//!
//! **steghide stays hard.** Its `ac_zero_ratio` AUC is exactly 0.5000 at every
//! rate measured, because steghide exchanges coefficient values by
//! graph matching and preserves the first-order histogram by construction.
//! No first-order statistic can detect it, and that is a property of the
//! algorithm rather than a gap in this implementation. 0.6497 at near-full
//! capacity is a real improvement on the 0.5000 the spatial detectors give, and
//! it is not a detector anyone should rely on. The literature reaches steghide
//! with a trained classifier over a rich feature set, which is a separate piece
//! of work and needs training data this project does not hold.
//!
//! **Calibration helps blockiness and hurts the pair statistic.** For outguess
//! `delta_blockiness` (0.8619) beats raw `blockiness` (0.5737) decisively, which
//! is the result the technique is famous for. For the engine's own JPEG output
//! raw `pov_equalisation` beats `delta_pov_equalisation` at every rate measured
//! (1.0000 against 0.9347 at full capacity). The crop that makes the reference
//! an estimate of the cover also puts an 8x8 grid across the original block
//! edges, which adds AC energy and moves the pair populations; for a statistic
//! about pair balance that is added noise rather than a baseline. So both the
//! raw and the calibrated form are reported and neither is assumed better.
//!
//! **A third of outguess output cannot be read at all.** `dct-io` refuses to
//! decode outguess files at a rate that rises with payload: 15 of 60 at a small
//! payload, 55 of 60 at a large one. Those files produce
//! [`StegError::CorruptedFile`] rather than a measurement, so the AUCs above are
//! over the files that decoded and a user would see an error rather than a
//! verdict. This is a `dct-io` limitation worth its own investigation and it is
//! recorded rather than worked around.
//!
//! # Thresholds are deliberately absent
//!
//! This module returns measurements. It does not decide. CLAUDE.md A3 forbids
//! guessed thresholds, and a guessed threshold here would be exactly the
//! mistake that put the spatial detectors in their current state, where one
//! global constant set is applied to two cover populations.
//!
//! **What setting them properly requires.** The calibration harness builds
//! matched pairs from the containerised third-party embedders and from the
//! engine's own JPEG path, and reports each feature's ROC AUC. To fix a
//! threshold rather than measure a separation it needs three things this module
//! cannot supply:
//!
//! 1. **A clean JPEG distribution wide enough to hold a false-positive
//!    ceiling.** ALASKA2's cover sample is one quality ladder from one
//!    acquisition pipeline. The 2026-06-14 recalibration learned this the
//!    expensive way in the spatial domain: thresholds set on Cassavia and
//!    BOSSbase alone leaked about 22% false positives on ALASKA2 because the
//!    covers were a different population. The same trap is open here, so the
//!    clean set needs at least a second independent JPEG source before any
//!    number is fixed.
//! 2. **A stated false-positive ceiling**, as the spatial thresholds have
//!    (about 4% combined), chosen before the sweep rather than read off it.
//! 3. **A payload-rate range to hold it over.** Separation is strongly
//!    rate-dependent: measured on 60 ALASKA2 pairs, the engine's own JPEG
//!    output separates at AUC 1.0000 at full capacity and 0.5258 at 2% of it.
//!    A threshold is only meaningful alongside the rate at which it was set.
//!
//! Until all three exist, a consumer should render these as measurements
//! alongside a coverage note, which is the honest output and is also what
//! `Verdict::NotAssessed` was introduced for.
//!
//! # Resource caps
//!
//! | Cap | Value | What it bounds |
//! |---|---|---|
//! | [`MAX_JPEG_BYTES`] | 67108864 | Input size accepted at all |
//! | [`MAX_PIXELS`] | 50000000 | Decoded pixel count |
//! | [`MAX_LUMA_BLOCKS`] | 1000000 | 8x8 luma blocks whose coefficients are counted |
//! | [`MIN_CALIBRATION_BLOCKS`] | 4 | Below this the crop leaves too little to calibrate against |
//! | [`LOW_FREQUENCY_AC`] | 9 | Zigzag AC modes the histogram features read |
//!
//! # Determinism
//!
//! Every statistic is a fixed-order sum over integer counts or over an
//! explicitly ordered traversal of blocks, rows and columns. The discrete
//! cosine tables are computed once from a closed form, and no collection with
//! an unspecified iteration order touches a result.

use std::collections::BTreeMap;

use dct_io::read_coefficients;
use serde::{Deserialize, Serialize};

use crate::container::visit_jpeg_segments;
use crate::errors::StegError;

// ── Resource caps ─────────────────────────────────────────────────────────────

/// Largest JPEG this module will look at. Above it, the caller gets a clear
/// refusal rather than a long wait.
pub const MAX_JPEG_BYTES: usize = 64 * 1024 * 1024;

/// Largest decoded pixel count. 50 megapixels is beyond any photograph the
/// tool is used on and matches the dimension cap in `utils`.
pub const MAX_PIXELS: u64 = 50_000_000;

/// Largest number of 8x8 luma blocks whose coefficients are histogrammed. One
/// million blocks is a 64 megapixel luma plane.
pub const MAX_LUMA_BLOCKS: usize = 1_000_000;

/// Below this many blocks after the calibration crop there is not enough left
/// to estimate anything, so calibration is reported as unavailable rather than
/// computed from noise.
pub const MIN_CALIBRATION_BLOCKS: usize = 4;

/// Number of low-frequency AC modes read by the histogram features, counted in
/// zigzag order from index 1. The first nine AC modes are where first-order
/// embedding artefacts concentrate, and where the coefficient distribution is
/// steep enough that pair equalisation is visible.
pub const LOW_FREQUENCY_AC: usize = 9;

/// Pixels cropped from the left and top for the calibrated reference. Four is
/// the standard choice: half a block in each direction maximally misaligns the
/// new block grid against the original one.
pub const CALIBRATION_CROP: usize = 4;

/// Coefficient magnitudes the pair statistic covers. Pairs are `(2,3)`,
/// `(4,5)`, `(6,7)` and `(8,9)` and their negatives; beyond that the counts are
/// too thin on a 512x512 cover to be worth including.
const MAX_PAIR_MAGNITUDE: i32 = 9;

// ── Feature record ────────────────────────────────────────────────────────────

/// DCT-domain measurements for one JPEG.
///
/// Every `delta_*` field is `raw - calibrated`, which is the quantity the
/// literature uses and the quantity that separates. When `calibrated` is false
/// the calibrated and delta fields are all zero and must be ignored: a zero
/// delta from a failed calibration and a zero delta from an untouched file are
/// different facts and the flag is how they are told apart.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DctFeatures {
    /// Image width in pixels, as the JPEG's frame header declares it.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// 8x8 luma blocks whose coefficients were read.
    pub luma_blocks: usize,
    /// Low-frequency AC coefficients counted, across all luma blocks.
    pub ac_samples: u64,

    /// Fraction of low-frequency AC coefficients equal to zero.
    pub ac_zero_ratio: f64,
    /// Fraction with absolute value exactly one.
    pub ac_one_ratio: f64,
    /// How nearly equal the members of each `(2k, 2k+1)` value pair are, from
    /// 0.0 (maximally unequal) to 1.0 (exactly equal). Least-significant-bit
    /// embedding in the coefficient domain drives this upward, because it moves
    /// values within pairs and cannot move them between pairs.
    pub pov_equalisation: f64,
    /// Mean absolute difference across 8x8 block boundaries in the decompressed
    /// luma plane, in grey levels.
    pub blockiness: f64,

    /// Whether a calibrated reference could be computed. False for an image too
    /// small to crop, or one whose luma quantisation table could not be read.
    pub calibrated: bool,
    /// [`Self::ac_zero_ratio`] measured on the calibrated reference.
    pub cal_ac_zero_ratio: f64,
    /// [`Self::ac_one_ratio`] measured on the calibrated reference.
    pub cal_ac_one_ratio: f64,
    /// [`Self::pov_equalisation`] measured on the calibrated reference.
    pub cal_pov_equalisation: f64,
    /// [`Self::blockiness`] measured on the calibrated reference.
    pub cal_blockiness: f64,

    /// `ac_zero_ratio - cal_ac_zero_ratio`. Positive when the file has more
    /// zeroes than its cover estimate, which is the F5 shrinkage signature.
    pub delta_ac_zero_ratio: f64,
    /// `ac_one_ratio - cal_ac_one_ratio`.
    pub delta_ac_one_ratio: f64,
    /// `pov_equalisation - cal_pov_equalisation`. The headline first-order
    /// statistic: positive means the value pairs are more equal than this
    /// image's own cover estimate says they should be.
    pub delta_pov_equalisation: f64,
    /// `blockiness - cal_blockiness`, in grey levels.
    pub delta_blockiness: f64,
}

/// Histogram statistics over one set of coefficients, shared by the raw and the
/// calibrated path so the two can never be computed differently.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct HistStats {
    samples: u64,
    zero_ratio: f64,
    one_ratio: f64,
    pov_equalisation: f64,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Measure the DCT-domain features of a baseline JPEG.
///
/// # Errors
///
/// - [`StegError::UnsupportedFormat`] for a non-JPEG, a progressive or
///   arithmetic-coded JPEG that `dct-io` cannot read, or an input past
///   [`MAX_JPEG_BYTES`] or [`MAX_PIXELS`].
/// - [`StegError::CorruptedFile`] for a JPEG whose entropy stream does not
///   decode.
///
/// A JPEG that is merely odd (no readable quantisation table, too small to
/// crop, chroma-only) is not an error: it comes back with `calibrated` false.
pub fn dct_features(jpeg: &[u8]) -> Result<DctFeatures, StegError> {
    if jpeg.len() > MAX_JPEG_BYTES {
        return Err(StegError::UnsupportedFormat(format!(
            "jpeg larger than the {MAX_JPEG_BYTES} byte analysis cap"
        )));
    }

    let coeffs = read_coefficients(jpeg).map_err(|err| match err {
        dct_io::DctError::Unsupported(msg) => StegError::UnsupportedFormat(format!("jpeg: {msg}")),
        _ => StegError::CorruptedFile,
    })?;
    let luma = coeffs
        .components
        .first()
        .ok_or_else(|| StegError::UnsupportedFormat("jpeg: no image components".to_string()))?;
    if luma.blocks.len() > MAX_LUMA_BLOCKS {
        return Err(StegError::UnsupportedFormat(format!(
            "jpeg has more than the {MAX_LUMA_BLOCKS} block analysis cap"
        )));
    }

    let frame = read_frame_header(jpeg)?;
    if u64::from(frame.width) * u64::from(frame.height) > MAX_PIXELS {
        return Err(StegError::UnsupportedFormat(format!(
            "jpeg larger than the {MAX_PIXELS} pixel analysis cap"
        )));
    }

    let raw_hist = histogram_stats(luma.blocks.iter().copied());
    let luma_plane = decode_luma(jpeg, frame.width, frame.height)?;
    let blockiness = block_boundary_discontinuity(&luma_plane);

    let mut features = DctFeatures {
        width: u32::from(frame.width),
        height: u32::from(frame.height),
        luma_blocks: luma.blocks.len(),
        ac_samples: raw_hist.samples,
        ac_zero_ratio: raw_hist.zero_ratio,
        ac_one_ratio: raw_hist.one_ratio,
        pov_equalisation: raw_hist.pov_equalisation,
        blockiness,
        calibrated: false,
        cal_ac_zero_ratio: 0.0,
        cal_ac_one_ratio: 0.0,
        cal_pov_equalisation: 0.0,
        cal_blockiness: 0.0,
        delta_ac_zero_ratio: 0.0,
        delta_ac_one_ratio: 0.0,
        delta_pov_equalisation: 0.0,
        delta_blockiness: 0.0,
    };

    // Calibration needs the original luma quantisation table; without it there
    // is no "same quality" to recompress at and the reference would be
    // meaningless rather than merely approximate.
    let Some(qtable) = luma_quantisation_table(jpeg)? else {
        return Ok(features);
    };
    let Some(reference) = calibrated_reference(&luma_plane, &qtable) else {
        return Ok(features);
    };

    let cal_hist = histogram_stats(reference.coefficients.iter().copied());
    let cal_blockiness = block_boundary_discontinuity(&reference.plane);

    features.calibrated = true;
    features.cal_ac_zero_ratio = cal_hist.zero_ratio;
    features.cal_ac_one_ratio = cal_hist.one_ratio;
    features.cal_pov_equalisation = cal_hist.pov_equalisation;
    features.cal_blockiness = cal_blockiness;
    features.delta_ac_zero_ratio = raw_hist.zero_ratio - cal_hist.zero_ratio;
    features.delta_ac_one_ratio = raw_hist.one_ratio - cal_hist.one_ratio;
    features.delta_pov_equalisation = raw_hist.pov_equalisation - cal_hist.pov_equalisation;
    features.delta_blockiness = blockiness - cal_blockiness;
    Ok(features)
}

// ── Feature 1: first-order coefficient histogram ──────────────────────────────

/// Histogram statistics over the low-frequency AC coefficients of a block
/// sequence. Blocks arrive in zigzag order, so indices 1 to
/// [`LOW_FREQUENCY_AC`] inclusive are the modes of interest.
fn histogram_stats<I: Iterator<Item = [i16; 64]>>(blocks: I) -> HistStats {
    // A BTreeMap rather than a HashMap because the pair sum below walks it, and
    // an unordered walk would let iteration order into a floating-point sum.
    let mut counts: BTreeMap<i32, u64> = BTreeMap::new();
    let mut samples = 0u64;
    for block in blocks {
        for &value in block.iter().take(LOW_FREQUENCY_AC + 1).skip(1) {
            *counts.entry(i32::from(value)).or_insert(0) += 1;
            samples += 1;
        }
    }
    if samples == 0 {
        return HistStats::default();
    }
    let total = samples as f64;
    let count_of = |v: i32| *counts.get(&v).unwrap_or(&0);
    let zero_ratio = count_of(0) as f64 / total;
    let one_ratio = (count_of(-1) + count_of(1)) as f64 / total;

    // Pairs of values: LSB embedding in the coefficient domain can move a value
    // from 2k to 2k+1 and back but never out of the pair, so it conserves each
    // pair's total while equalising its halves. Pairs are weighted by their
    // populations, otherwise a pair holding four coefficients would count as
    // much as one holding forty thousand.
    let mut weighted = 0.0;
    let mut weight = 0.0;
    let mut magnitude = 2;
    while magnitude <= MAX_PAIR_MAGNITUDE {
        for sign in [1, -1] {
            let low = count_of(sign * magnitude);
            let high = count_of(sign * (magnitude + 1));
            let pair_total = low + high;
            if pair_total > 0 {
                let difference = low.abs_diff(high) as f64 / pair_total as f64;
                weighted += (1.0 - difference) * pair_total as f64;
                weight += pair_total as f64;
            }
        }
        magnitude += 2;
    }
    HistStats {
        samples,
        zero_ratio,
        one_ratio,
        pov_equalisation: if weight > 0.0 { weighted / weight } else { 0.0 },
    }
}

// ── Feature 2: block-boundary discontinuity ───────────────────────────────────

/// A decoded single-channel plane.
struct Plane {
    width: usize,
    height: usize,
    samples: Vec<u8>,
}

impl Plane {
    fn at(&self, x: usize, y: usize) -> i32 {
        // Callers iterate strictly inside the bounds they read from this
        // struct's own fields, so an out-of-range index is a bug rather than an
        // input; the default keeps it from being a panic either way.
        i32::from(
            self.samples
                .get(y * self.width + x)
                .copied()
                .unwrap_or_default(),
        )
    }
}

/// Mean absolute difference across the 8x8 block boundaries, in grey levels.
///
/// Embedding perturbs coefficients, which the inverse DCT spreads over a whole
/// block and not over its neighbour, so the step across a block edge grows.
/// Normalised by the number of boundary pairs so images of different sizes are
/// comparable.
fn block_boundary_discontinuity(plane: &Plane) -> f64 {
    let mut total = 0u64;
    let mut pairs = 0u64;
    // Vertical boundaries: between column 8n-1 and column 8n.
    let mut x = 8;
    while x < plane.width {
        for y in 0..plane.height {
            total += plane.at(x - 1, y).abs_diff(plane.at(x, y)) as u64;
            pairs += 1;
        }
        x += 8;
    }
    // Horizontal boundaries: between row 8n-1 and row 8n.
    let mut y = 8;
    while y < plane.height {
        for x in 0..plane.width {
            total += plane.at(x, y - 1).abs_diff(plane.at(x, y)) as u64;
            pairs += 1;
        }
        y += 8;
    }
    if pairs == 0 {
        return 0.0;
    }
    total as f64 / pairs as f64
}

// ── Feature 3: the calibrated reference ───────────────────────────────────────

/// The cover estimate: the input decompressed, cropped and recompressed.
struct Reference {
    coefficients: Vec<[i16; 64]>,
    plane: Plane,
}

/// Build the calibrated reference.
///
/// Crop [`CALIBRATION_CROP`] pixels from the left and the top, forward-DCT the
/// result in 8x8 blocks and quantise with the original luma table. The crop is
/// what makes this an estimate of the cover rather than of the input: the new
/// block grid is misaligned with the original one, so the coefficients it
/// produces have not been touched by any embedding that was applied in the
/// original grid.
///
/// Returns None when the crop leaves fewer than [`MIN_CALIBRATION_BLOCKS`]
/// whole blocks.
fn calibrated_reference(plane: &Plane, qtable: &[u16; 64]) -> Option<Reference> {
    let width = plane.width.checked_sub(CALIBRATION_CROP)?;
    let height = plane.height.checked_sub(CALIBRATION_CROP)?;
    let blocks_x = width / 8;
    let blocks_y = height / 8;
    if blocks_x * blocks_y < MIN_CALIBRATION_BLOCKS {
        return None;
    }

    let mut coefficients = Vec::with_capacity(blocks_x * blocks_y);
    let mut reconstructed = vec![0u8; blocks_x * 8 * blocks_y * 8];
    let reconstructed_width = blocks_x * 8;
    let mut spatial = [0.0f64; 64];
    let mut frequency = [0.0f64; 64];

    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            for row in 0..8 {
                for col in 0..8 {
                    let x = CALIBRATION_CROP + bx * 8 + col;
                    let y = CALIBRATION_CROP + by * 8 + row;
                    // The JPEG level shift: samples are centred on zero before
                    // the transform.
                    spatial[row * 8 + col] = f64::from(plane.at(x, y)) - 128.0;
                }
            }
            forward_dct(&spatial, &mut frequency);

            let mut block = [0i16; 64];
            for zigzag in 0..64 {
                let natural = ZIGZAG_TO_NATURAL[zigzag];
                let divisor = f64::from(qtable[zigzag].max(1));
                block[zigzag] = quantise(frequency[natural] / divisor);
            }
            coefficients.push(block);

            // Reconstruct so blockiness can be measured on the reference the
            // same way it is measured on the input.
            for zigzag in 0..64 {
                let natural = ZIGZAG_TO_NATURAL[zigzag];
                frequency[natural] = f64::from(block[zigzag]) * f64::from(qtable[zigzag].max(1));
            }
            inverse_dct(&frequency, &mut spatial);
            for row in 0..8 {
                for col in 0..8 {
                    let value = (spatial[row * 8 + col] + 128.0).round();
                    let clamped = value.clamp(0.0, 255.0) as u8;
                    let index = (by * 8 + row) * reconstructed_width + bx * 8 + col;
                    if let Some(slot) = reconstructed.get_mut(index) {
                        *slot = clamped;
                    }
                }
            }
        }
    }

    Some(Reference {
        coefficients,
        plane: Plane {
            width: reconstructed_width,
            height: blocks_y * 8,
            samples: reconstructed,
        },
    })
}

/// Round half away from zero, saturating into `i16`.
///
/// Explicit rather than `as i16`, because `as` truncates toward zero and
/// because a coefficient outside the `i16` range would wrap. Both would be
/// silent, and a silent difference between the raw and calibrated paths is
/// exactly the bug that would make every delta meaningless.
fn quantise(value: f64) -> i16 {
    if !value.is_finite() {
        return 0;
    }
    let rounded = value.round();
    if rounded > f64::from(i16::MAX) {
        i16::MAX
    } else if rounded < f64::from(i16::MIN) {
        i16::MIN
    } else {
        rounded as i16
    }
}

/// Cosine table for the 8-point transform: `COS[u][x] = cos((2x+1)u*pi/16)`,
/// already scaled by the `1/sqrt(2)` normalisation at `u == 0`.
///
/// Built once at first use from the closed form, so the numbers are whatever
/// the platform's libm gives for `cos` and are identical for every block, which
/// is what keeps the whole transform reproducible.
fn cosine_table() -> &'static [[f64; 8]; 8] {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[[f64; 8]; 8]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [[0.0f64; 8]; 8];
        for (u, row) in table.iter_mut().enumerate() {
            let scale = if u == 0 { 1.0 / f64::sqrt(2.0) } else { 1.0 };
            for (x, cell) in row.iter_mut().enumerate() {
                let angle = (2.0 * x as f64 + 1.0) * u as f64 * std::f64::consts::PI / 16.0;
                *cell = scale * angle.cos();
            }
        }
        table
    })
}

/// Two-dimensional DCT-II over an 8x8 block, in natural (row-major) order.
/// Separable, so 8 one-dimensional transforms along rows then 8 along columns.
fn forward_dct(spatial: &[f64; 64], frequency: &mut [f64; 64]) {
    let cos = cosine_table();
    let mut rows = [0.0f64; 64];
    for y in 0..8 {
        for u in 0..8 {
            let mut sum = 0.0;
            for x in 0..8 {
                sum += spatial[y * 8 + x] * cos[u][x];
            }
            rows[y * 8 + u] = sum;
        }
    }
    for u in 0..8 {
        for v in 0..8 {
            let mut sum = 0.0;
            for y in 0..8 {
                sum += rows[y * 8 + u] * cos[v][y];
            }
            frequency[v * 8 + u] = sum / 4.0;
        }
    }
}

/// Inverse of [`forward_dct`].
fn inverse_dct(frequency: &[f64; 64], spatial: &mut [f64; 64]) {
    let cos = cosine_table();
    let mut rows = [0.0f64; 64];
    for v in 0..8 {
        for x in 0..8 {
            let mut sum = 0.0;
            for u in 0..8 {
                sum += frequency[v * 8 + u] * cos[u][x];
            }
            rows[v * 8 + x] = sum;
        }
    }
    for x in 0..8 {
        for y in 0..8 {
            let mut sum = 0.0;
            for v in 0..8 {
                sum += rows[v * 8 + x] * cos[v][y];
            }
            spatial[y * 8 + x] = sum / 4.0;
        }
    }
}

/// Natural (row-major) index for each zigzag position, the JPEG standard's
/// zigzag scan order. `dct-io` hands back blocks in zigzag order and the
/// transform above works in natural order, so every crossing between the two
/// goes through this table.
const ZIGZAG_TO_NATURAL: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

// ── Reading the JPEG's own tables ─────────────────────────────────────────────

/// What the frame header says about the image.
#[derive(Debug)]
struct FrameHeader {
    width: u16,
    height: u16,
    /// Quantisation table selector for the first component, which is luma.
    luma_table: u8,
}

/// Read the SOF (start of frame) header.
///
/// Uses the container module's JPEG walker rather than a second one of its own,
/// so there is one answer in the engine to where a JPEG segment begins.
///
/// # Errors
///
/// [`StegError::UnsupportedFormat`] when there is no readable baseline frame
/// header.
fn read_frame_header(jpeg: &[u8]) -> Result<FrameHeader, StegError> {
    let mut header: Option<FrameHeader> = None;
    visit_jpeg_segments(jpeg, |marker, offset, length| {
        // SOF0 baseline and SOF1 extended sequential are what dct-io reads.
        // Every other SOF is a format dct-io will already have refused.
        if marker != 0xC0 && marker != 0xC1 {
            return true;
        }
        let Some(body) = jpeg.get(offset..offset + length) else {
            return true;
        };
        // [precision u8][height u16][width u16][components u8][(id, hv, tq)..]
        if body.len() < 9 {
            return true;
        }
        header = Some(FrameHeader {
            height: u16::from_be_bytes([body[1], body[2]]),
            width: u16::from_be_bytes([body[3], body[4]]),
            luma_table: body[8] & 0x0F,
        });
        false
    })?;
    header.ok_or_else(|| {
        StegError::UnsupportedFormat("jpeg: no baseline frame header found".to_string())
    })
}

/// Read the quantisation table the luma component uses, in zigzag order.
///
/// Returns None when the frame header names a table the file does not define,
/// which is a malformed file that `dct-io` happened to decode anyway. The
/// caller degrades to uncalibrated features rather than failing, because the
/// raw features are still measurements and still better than nothing.
///
/// Public because `detego-ml` needs it to dequantise coefficients before a
/// JPEG-domain model sees them, and the dependency has to point from here into
/// that crate rather than back. Exposing the one function keeps a single DQT
/// reader in the tree: `dct-io` does not expose the tables at all, so the
/// alternative was a second parser that could disagree with this one about a
/// late-defined or 16-bit table. Zigzag order, which is also the order `dct-io`
/// indexes its blocks by, so a caller pairing the two needs no permutation.
///
/// # Errors
///
/// As [`read_frame_header`].
pub fn luma_quantisation_table(jpeg: &[u8]) -> Result<Option<[u16; 64]>, StegError> {
    let wanted = read_frame_header(jpeg)?.luma_table;
    let mut table: Option<[u16; 64]> = None;
    visit_jpeg_segments(jpeg, |marker, offset, length| {
        if marker != 0xDB {
            return true;
        }
        let Some(body) = jpeg.get(offset..offset + length) else {
            return true;
        };
        // A DQT segment holds one or more tables back to back, each introduced
        // by a byte whose low nibble is the table id and whose high nibble is 0
        // for 8-bit entries and 1 for 16-bit.
        let mut cursor = 0usize;
        while let Some(&spec) = body.get(cursor) {
            cursor += 1;
            let sixteen_bit = spec >> 4 == 1;
            let id = spec & 0x0F;
            let entry_bytes = if sixteen_bit { 2 } else { 1 };
            let Some(entries) = body.get(cursor..cursor + 64 * entry_bytes) else {
                return true;
            };
            cursor += 64 * entry_bytes;
            if id != wanted || table.is_some() {
                continue;
            }
            let mut values = [0u16; 64];
            for (zigzag, slot) in values.iter_mut().enumerate() {
                *slot = if sixteen_bit {
                    u16::from_be_bytes([entries[zigzag * 2], entries[zigzag * 2 + 1]])
                } else {
                    u16::from(entries[zigzag])
                };
            }
            table = Some(values);
        }
        // Keep walking: a file may define the luma table in a later DQT, and a
        // file may define several tables in several segments.
        true
    })?;
    Ok(table)
}

/// Decode the JPEG to a luma plane.
///
/// The luma is recomputed from RGB with the JFIF coefficients rather than taken
/// from the image crate's own greyscale conversion, which uses the Rec. 709
/// weights. JPEG is Rec. 601, and using the wrong weights would put a constant
/// bias between the input and its calibrated reference, which is precisely the
/// quantity every delta is built from.
///
/// # Errors
///
/// [`StegError::Image`] if the JPEG does not decode, or
/// [`StegError::Internal`] if a third-party decoder panics on it.
fn decode_luma(jpeg: &[u8], width: u16, height: u16) -> Result<Plane, StegError> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(jpeg));
    reader.set_format(image::ImageFormat::Jpeg);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(50_000);
    limits.max_image_height = Some(50_000);
    reader.limits(limits);

    // Malformed input has been observed to panic inside third-party image
    // decoders; the engine's convention is to contain that at the call site
    // rather than let it unwind out (see `utils::open_image_by_content`).
    let decoded =
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || reader.decode())) {
            Ok(result) => result.map_err(StegError::Image)?,
            Err(_) => {
                return Err(StegError::Internal(
                    "panic in jpeg decoder (caught)".to_string(),
                ))
            }
        };
    let rgb = decoded.to_rgb8();
    let (decoded_width, decoded_height) = (rgb.width() as usize, rgb.height() as usize);
    // The frame header and the decoder should agree; if they do not, trust the
    // decoder, because that is the plane actually in hand.
    debug_assert!(decoded_width == usize::from(width) || width == 0);
    debug_assert!(decoded_height == usize::from(height) || height == 0);

    let mut samples = Vec::with_capacity(decoded_width * decoded_height);
    for pixel in rgb.pixels() {
        let [r, g, b] = pixel.0;
        let luma = 0.299 * f64::from(r) + 0.587 * f64::from(g) + 0.114 * f64::from(b);
        samples.push(luma.round().clamp(0.0, 255.0) as u8);
    }
    Ok(Plane {
        width: decoded_width,
        height: decoded_height,
        samples,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny synthetic JPEG, encoded by the image crate so it is a genuine
    /// baseline file with real Huffman and quantisation tables. Built in code
    /// rather than read from a fixture, so the test states its own input.
    fn synthetic_jpeg(width: u32, height: u32, quality: u8) -> Vec<u8> {
        let mut image = image::RgbImage::new(width, height);
        // A textured pattern: flat images quantise to almost all zeroes and
        // would give every histogram statistic a degenerate value.
        for (x, y, pixel) in image.enumerate_pixels_mut() {
            let v = ((x * 7 + y * 13) % 251) as u8;
            let w = (((x * 29) ^ (y * 17)) % 241) as u8;
            *pixel = image::Rgb([v, w, v.wrapping_add(w)]);
        }
        let mut out = Vec::new();
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(
            std::io::Cursor::new(&mut out),
            quality,
        );
        encoder
            .encode_image(&image)
            .expect("the image crate must encode its own buffer");
        out
    }

    #[test]
    fn features_are_measured_on_a_real_baseline_jpeg() {
        let jpeg = synthetic_jpeg(64, 64, 85);
        let features = dct_features(&jpeg).expect("a baseline jpeg must measure");
        assert_eq!(features.width, 64);
        assert_eq!(features.height, 64);
        assert!(features.luma_blocks > 0);
        assert!(features.ac_samples > 0);
        assert!(features.blockiness > 0.0);
        assert!(features.calibrated, "64x64 is big enough to calibrate");
        assert!(features.cal_blockiness > 0.0);
    }

    #[test]
    fn every_ratio_stays_inside_its_range() {
        let features = dct_features(&synthetic_jpeg(64, 64, 70)).expect("measure");
        for ratio in [
            features.ac_zero_ratio,
            features.ac_one_ratio,
            features.pov_equalisation,
            features.cal_ac_zero_ratio,
            features.cal_ac_one_ratio,
            features.cal_pov_equalisation,
        ] {
            assert!((0.0..=1.0).contains(&ratio), "out of range: {ratio}");
        }
    }

    #[test]
    fn the_same_input_measures_identically_twice() {
        let jpeg = synthetic_jpeg(48, 48, 90);
        let first = dct_features(&jpeg).expect("measure");
        let second = dct_features(&jpeg).expect("measure");
        assert_eq!(first, second);
        let a = serde_json::to_string(&first).expect("serialisable");
        let b = serde_json::to_string(&second).expect("serialisable");
        assert_eq!(a, b);
    }

    /// A JSON round trip of these features is accurate to within one unit in
    /// the last place and not to the bit.
    ///
    /// Not a defect here: measured against serde_json 1.0.149, parsing the
    /// shortest representation of `0.020061728395061734` yields the adjacent
    /// double (`0x3f948b0fcd6e9e08` goes out and `...09` comes back). Every
    /// `f64` the engine puts in a JSON report is subject to it, so a consumer
    /// must not compare these values for exact equality across a serialisation
    /// boundary. The module's own output is byte-identical run to run, which is
    /// what the determinism requirement actually asks and what
    /// `the_same_input_measures_identically_twice` checks.
    #[test]
    fn a_scan_round_trips_through_json_to_within_one_unit_in_the_last_place() {
        let features = dct_features(&synthetic_jpeg(32, 32, 80)).expect("measure");
        let json = serde_json::to_string(&features).expect("serialisable");
        let back: DctFeatures = serde_json::from_str(&json).expect("deserialisable");
        assert_eq!(features.width, back.width);
        assert_eq!(features.luma_blocks, back.luma_blocks);
        assert_eq!(features.ac_samples, back.ac_samples);
        assert_eq!(features.calibrated, back.calibrated);
        let pairs = [
            (features.ac_zero_ratio, back.ac_zero_ratio),
            (features.ac_one_ratio, back.ac_one_ratio),
            (features.pov_equalisation, back.pov_equalisation),
            (features.blockiness, back.blockiness),
            (features.cal_pov_equalisation, back.cal_pov_equalisation),
            (features.cal_blockiness, back.cal_blockiness),
            (features.delta_ac_zero_ratio, back.delta_ac_zero_ratio),
            (features.delta_ac_one_ratio, back.delta_ac_one_ratio),
            (features.delta_pov_equalisation, back.delta_pov_equalisation),
            (features.delta_blockiness, back.delta_blockiness),
        ];
        for (sent, received) in pairs {
            let tolerance = sent.abs().max(1.0) * f64::EPSILON * 4.0;
            assert!(
                (sent - received).abs() <= tolerance,
                "{sent} came back as {received}"
            );
        }
    }

    // ── The features against real embedding ───────────────────────────────

    #[test]
    fn lsb_embedding_in_the_coefficient_domain_raises_pair_equalisation() {
        // Stegcore's own JPEG path is JSteg-style: it flips the LSB of AC
        // coefficients with |v| >= 2. That is exactly the family the pair
        // statistic targets, and this is the measurement rather than a claim
        // about it. A large cover so the payload reaches a useful rate.
        let cover = synthetic_jpeg(256, 256, 90);
        let capacity = crate::jpeg_dct::jpeg_capacity(&cover).expect("capacity");
        assert!(capacity > 64, "need a usable capacity, got {capacity}");
        let payload = vec![0xA5u8; capacity - 8];
        let stego = crate::jpeg_dct::embed_jpeg(&cover, &payload, b"passphrase").expect("embed");

        let clean = dct_features(&cover).expect("measure cover");
        let dirty = dct_features(&stego).expect("measure stego");

        assert!(
            dirty.pov_equalisation > clean.pov_equalisation,
            "embedding must equalise the value pairs: {} against {}",
            dirty.pov_equalisation,
            clean.pov_equalisation
        );
        assert!(
            dirty.delta_pov_equalisation > clean.delta_pov_equalisation,
            "the calibrated delta must separate too: {} against {}",
            dirty.delta_pov_equalisation,
            clean.delta_pov_equalisation
        );
    }

    #[test]
    fn embedding_raises_the_block_boundary_discontinuity() {
        let cover = synthetic_jpeg(256, 256, 90);
        let capacity = crate::jpeg_dct::jpeg_capacity(&cover).expect("capacity");
        let payload = vec![0x5Au8; capacity - 8];
        let stego = crate::jpeg_dct::embed_jpeg(&cover, &payload, b"passphrase").expect("embed");
        let clean = dct_features(&cover).expect("measure");
        let dirty = dct_features(&stego).expect("measure");
        assert!(
            dirty.blockiness > clean.blockiness,
            "blockiness should rise: {} against {}",
            dirty.blockiness,
            clean.blockiness
        );
    }

    // ── Calibration ───────────────────────────────────────────────────────

    #[test]
    fn an_image_too_small_to_crop_reports_calibration_unavailable() {
        // 8x8 is one block; cropping four pixels leaves nothing whole.
        let features = dct_features(&synthetic_jpeg(8, 8, 80)).expect("measure");
        assert!(!features.calibrated);
        assert_eq!(features.cal_blockiness, 0.0);
        assert_eq!(features.delta_pov_equalisation, 0.0);
        // The raw features are still real measurements.
        assert!(features.ac_samples > 0);
    }

    #[test]
    fn the_calibrated_reference_of_a_clean_file_is_close_to_the_file_itself() {
        // The whole premise: on an untouched cover the calibrated estimate and
        // the measurement should nearly agree, because the estimate is of the
        // cover and the file is the cover. "Nearly" is the point; the crop and
        // the requantisation are an approximation, and how close is an
        // empirical question this records rather than asserts tightly.
        let features = dct_features(&synthetic_jpeg(128, 128, 90)).expect("measure");
        assert!(features.calibrated);
        assert!(
            features.delta_pov_equalisation.abs() < 0.5,
            "clean delta should be small, got {}",
            features.delta_pov_equalisation
        );
    }

    #[test]
    fn the_cosine_transform_round_trips() {
        let mut spatial = [0.0f64; 64];
        for (i, slot) in spatial.iter_mut().enumerate() {
            *slot = ((i * 37) % 255) as f64 - 128.0;
        }
        let mut frequency = [0.0f64; 64];
        forward_dct(&spatial, &mut frequency);
        let mut back = [0.0f64; 64];
        inverse_dct(&frequency, &mut back);
        for (original, recovered) in spatial.iter().zip(back.iter()) {
            assert!(
                (original - recovered).abs() < 1e-9,
                "{original} did not round trip to {recovered}"
            );
        }
    }

    #[test]
    fn the_dc_coefficient_of_a_flat_block_is_its_mean_and_the_ac_are_zero() {
        let spatial = [40.0f64; 64];
        let mut frequency = [0.0f64; 64];
        forward_dct(&spatial, &mut frequency);
        assert!((frequency[0] - 320.0).abs() < 1e-9, "{}", frequency[0]);
        for &value in frequency.iter().skip(1) {
            assert!(value.abs() < 1e-9);
        }
    }

    #[test]
    fn the_zigzag_table_is_a_permutation() {
        let mut seen = [false; 64];
        for &natural in ZIGZAG_TO_NATURAL.iter() {
            assert!(natural < 64);
            assert!(!seen[natural], "{natural} appears twice");
            seen[natural] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    // ── Statistics in isolation ───────────────────────────────────────────

    #[test]
    fn histogram_stats_of_nothing_are_all_zero() {
        let stats = histogram_stats(std::iter::empty());
        assert_eq!(stats, HistStats::default());
        assert_eq!(stats.samples, 0);
    }

    #[test]
    fn pair_equalisation_is_one_for_equal_pairs_and_zero_for_one_sided_ones() {
        // Two blocks whose low-frequency AC modes hold 2 and 3 in equal numbers.
        let mut equal_a = [0i16; 64];
        let mut equal_b = [0i16; 64];
        for k in 1..=LOW_FREQUENCY_AC {
            equal_a[k] = 2;
            equal_b[k] = 3;
        }
        let stats = histogram_stats([equal_a, equal_b].into_iter());
        assert!((stats.pov_equalisation - 1.0).abs() < 1e-12);

        // And one-sided: only the low member of the pair ever appears.
        let stats = histogram_stats([equal_a, equal_a].into_iter());
        assert!(stats.pov_equalisation.abs() < 1e-12);
    }

    #[test]
    fn the_zero_and_one_ratios_count_what_they_say() {
        let mut block = [0i16; 64];
        // Of the nine low-frequency AC modes: three zeroes, three ones (mixed
        // sign), three twos.
        block[1] = 0;
        block[2] = 0;
        block[3] = 0;
        block[4] = 1;
        block[5] = -1;
        block[6] = 1;
        block[7] = 2;
        block[8] = 2;
        block[9] = 2;
        let stats = histogram_stats(std::iter::once(block));
        assert_eq!(stats.samples, 9);
        assert!((stats.zero_ratio - 3.0 / 9.0).abs() < 1e-12);
        assert!((stats.one_ratio - 3.0 / 9.0).abs() < 1e-12);
    }

    #[test]
    fn blockiness_is_zero_on_a_flat_plane_and_positive_on_a_stepped_one() {
        let flat = Plane {
            width: 24,
            height: 24,
            samples: vec![128u8; 24 * 24],
        };
        assert_eq!(block_boundary_discontinuity(&flat), 0.0);

        // A step at every block boundary: column 8 and 16 jump by 10.
        let mut stepped = vec![0u8; 24 * 24];
        for y in 0..24 {
            for x in 0..24 {
                stepped[y * 24 + x] = (100 + 10 * (x / 8)) as u8;
            }
        }
        let plane = Plane {
            width: 24,
            height: 24,
            samples: stepped,
        };
        // Two vertical boundaries step by 10, two horizontal ones do not step
        // at all, and all four carry 24 pairs: mean is 10 * 2 / 4 = 5.
        assert!((block_boundary_discontinuity(&plane) - 5.0).abs() < 1e-12);
    }

    #[test]
    fn blockiness_of_a_plane_with_no_boundaries_is_zero() {
        let tiny = Plane {
            width: 4,
            height: 4,
            samples: vec![7u8; 16],
        };
        assert_eq!(block_boundary_discontinuity(&tiny), 0.0);
    }

    #[test]
    fn a_plane_read_out_of_bounds_returns_zero_rather_than_panicking() {
        let plane = Plane {
            width: 2,
            height: 2,
            samples: vec![1u8, 2, 3, 4],
        };
        assert_eq!(plane.at(1, 1), 4);
        assert_eq!(plane.at(99, 99), 0);
    }

    #[test]
    fn quantise_rounds_half_away_from_zero_and_saturates() {
        assert_eq!(quantise(0.5), 1);
        assert_eq!(quantise(-0.5), -1);
        assert_eq!(quantise(1.4), 1);
        assert_eq!(quantise(-1.6), -2);
        assert_eq!(quantise(1e9), i16::MAX);
        assert_eq!(quantise(-1e9), i16::MIN);
        assert_eq!(quantise(f64::NAN), 0);
        assert_eq!(quantise(f64::INFINITY), 0);
    }

    // ── Header and table reading ──────────────────────────────────────────

    #[test]
    fn the_frame_header_and_the_luma_table_are_read_from_a_real_jpeg() {
        let jpeg = synthetic_jpeg(64, 48, 75);
        let frame = read_frame_header(&jpeg).expect("frame header");
        assert_eq!(frame.width, 64);
        assert_eq!(frame.height, 48);
        let table = luma_quantisation_table(&jpeg)
            .expect("walk")
            .expect("a real jpeg defines its luma table");
        // Quantisation entries are positive and the DC entry is the smallest or
        // near it, which is what any sane table looks like.
        assert!(table.iter().all(|&q| q > 0));
        assert!(table[0] <= table[63]);
    }

    #[test]
    fn a_sixteen_bit_quantisation_table_is_read_at_the_right_width() {
        // Hand-built DQT: Pq = 1 (16-bit entries), Tq = 0, entries counting up.
        let mut body = vec![0x10u8];
        for k in 0..64u16 {
            body.extend_from_slice(&(k + 1).to_be_bytes());
        }
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xC0];
        // SOF0 with one component using table 0.
        let sof: Vec<u8> = vec![8, 0, 16, 0, 16, 1, 1, 0x11, 0x00];
        jpeg.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&sof);
        jpeg.extend_from_slice(&[0xFF, 0xDB]);
        jpeg.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&body);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);

        let table = luma_quantisation_table(&jpeg)
            .expect("walk")
            .expect("table present");
        assert_eq!(table[0], 1);
        assert_eq!(table[63], 64);
    }

    #[test]
    fn two_tables_in_one_dqt_segment_are_both_stepped_over() {
        // Table 1 first, then table 0, which is the one the frame header wants.
        // Reading the second requires the first to have been skipped by exactly
        // 65 bytes.
        let mut body = vec![0x01u8];
        body.extend_from_slice(&[9u8; 64]);
        body.push(0x00);
        body.extend_from_slice(&[3u8; 64]);

        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xC0];
        let sof: Vec<u8> = vec![8, 0, 16, 0, 16, 1, 1, 0x11, 0x00];
        jpeg.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&sof);
        jpeg.extend_from_slice(&[0xFF, 0xDB]);
        jpeg.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&body);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);

        let table = luma_quantisation_table(&jpeg)
            .expect("walk")
            .expect("table present");
        assert!(table.iter().all(|&q| q == 3), "read the wrong table");
    }

    #[test]
    fn a_truncated_quantisation_table_is_not_read_and_does_not_panic() {
        let mut body = vec![0x00u8];
        body.extend_from_slice(&[5u8; 40]); // 40 entries where 64 are needed
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xC0];
        let sof: Vec<u8> = vec![8, 0, 16, 0, 16, 1, 1, 0x11, 0x00];
        jpeg.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&sof);
        jpeg.extend_from_slice(&[0xFF, 0xDB]);
        jpeg.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&body);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        assert!(luma_quantisation_table(&jpeg).expect("walk").is_none());
    }

    #[test]
    fn a_frame_header_naming_a_table_the_file_never_defines_yields_none() {
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xC0];
        // Component 1 wants table 3; the file defines only table 0.
        let sof: Vec<u8> = vec![8, 0, 16, 0, 16, 1, 1, 0x11, 0x03];
        jpeg.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&sof);
        let mut body = vec![0x00u8];
        body.extend_from_slice(&[7u8; 64]);
        jpeg.extend_from_slice(&[0xFF, 0xDB]);
        jpeg.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&body);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        assert!(luma_quantisation_table(&jpeg).expect("walk").is_none());
    }

    #[test]
    fn a_short_frame_header_is_refused_rather_than_indexed_into() {
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xC0];
        let sof: Vec<u8> = vec![8, 0, 16];
        jpeg.extend_from_slice(&((sof.len() + 2) as u16).to_be_bytes());
        jpeg.extend_from_slice(&sof);
        jpeg.extend_from_slice(&[0xFF, 0xD9]);
        let err = read_frame_header(&jpeg).expect_err("must refuse");
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn a_jpeg_with_no_frame_header_is_refused() {
        let jpeg = vec![0xFF, 0xD8, 0xFF, 0xD9];
        let err = read_frame_header(&jpeg).expect_err("must refuse");
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    // ── Error paths ───────────────────────────────────────────────────────

    #[test]
    fn a_file_that_is_not_a_jpeg_is_refused_loudly() {
        let err = dct_features(b"not a jpeg at all, not even close").expect_err("must refuse");
        assert!(matches!(
            err,
            StegError::UnsupportedFormat(_) | StegError::CorruptedFile
        ));
    }

    #[test]
    fn an_empty_input_is_refused_without_panicking() {
        assert!(dct_features(&[]).is_err());
    }

    #[test]
    fn an_oversized_input_is_refused_before_any_parsing() {
        let huge = vec![0u8; MAX_JPEG_BYTES + 1];
        let err = dct_features(&huge).expect_err("must refuse");
        match err {
            StegError::UnsupportedFormat(msg) => assert!(msg.contains("larger than")),
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn a_truncated_jpeg_is_an_error_rather_than_a_panic() {
        let jpeg = synthetic_jpeg(64, 64, 80);
        for keep in [4, 20, 100, jpeg.len() / 2, jpeg.len() - 1] {
            let truncated = &jpeg[..keep.min(jpeg.len())];
            // Either it measures or it errors; it must not panic or hang.
            let _ = dct_features(truncated);
        }
    }

    #[test]
    fn a_jpeg_with_corrupted_entropy_data_does_not_panic() {
        let mut jpeg = synthetic_jpeg(64, 64, 80);
        let len = jpeg.len();
        for byte in jpeg.iter_mut().skip(len * 2 / 3) {
            *byte ^= 0x5A;
        }
        let _ = dct_features(&jpeg);
    }

    #[test]
    fn a_jpeg_with_no_quantisation_table_is_refused_with_a_clear_reason() {
        // Strip every DQT segment out of a real JPEG. dct-io still reads the
        // coefficients, because they are stored already quantised and need no
        // table, but the spatial decode needs one and says so. Recorded as a
        // test because it establishes which layer refuses: the uncalibrated
        // fallback in `dct_features` is defensive and is not reached this way.
        let jpeg = synthetic_jpeg(64, 64, 85);
        let mut cuts = Vec::new();
        visit_jpeg_segments(&jpeg, |marker, offset, length| {
            if marker == 0xDB {
                // Back up over the two marker bytes and the two length bytes.
                cuts.push((offset - 4, offset + length));
            }
            true
        })
        .expect("walk");
        assert!(!cuts.is_empty(), "a real jpeg defines a quantisation table");
        let mut stripped = Vec::with_capacity(jpeg.len());
        let mut cursor = 0usize;
        for (start, end) in cuts {
            stripped.extend_from_slice(&jpeg[cursor..start]);
            cursor = end;
        }
        stripped.extend_from_slice(&jpeg[cursor..]);

        let err = dct_features(&stripped).expect_err("no table means no spatial decode");
        assert!(matches!(err, StegError::Image(_)));
        assert!(err.to_string().to_lowercase().contains("quantization"));
    }

    #[test]
    fn a_greyscale_jpeg_measures_the_same_way_a_colour_one_does() {
        let mut image = image::GrayImage::new(64, 64);
        for (x, y, pixel) in image.enumerate_pixels_mut() {
            *pixel = image::Luma([((x * 11 + y * 5) % 251) as u8]);
        }
        let mut out = Vec::new();
        let mut encoder =
            image::codecs::jpeg::JpegEncoder::new_with_quality(std::io::Cursor::new(&mut out), 85);
        encoder.encode_image(&image).expect("encode");
        let features = dct_features(&out).expect("a greyscale jpeg must measure");
        assert_eq!(features.width, 64);
        assert!(features.calibrated);
        assert!(features.blockiness > 0.0);
    }
}
