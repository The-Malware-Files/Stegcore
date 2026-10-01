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

//! What the model sees, and why getting this wrong makes the whole crate
//! pointless.
//!
//! # The measurement this module exists because of
//!
//! On 120 matched steghide pairs the existing statistical detectors moved **0
//! of 120 verdicts**, with a median score change of 0.0000 and a maximum
//! absolute change of 0.00e+00. That is not a weak classifier. It is
//! information that never arrived.
//!
//! The reason is mechanical. JPEG steganography perturbs **quantised DCT
//! coefficients**. Reading the file back as RGB runs an inverse DCT, which
//! spreads each coefficient change across an 8x8 block of pixels and then
//! rounds and clips to 8-bit integers. The per-pixel LSB evidence the spatial
//! detectors read is destroyed by that round trip. A convolutional network fed
//! the same decompressed RGB is blind for the same reason: no amount of
//! training recovers a signal the input does not contain.
//!
//! So this crate refuses to have one input. It has two, chosen by container:
//!
//! | Container | Representation | Why |
//! |---|---|---|
//! | PNG, BMP | [`Representation::Spatial`] | Every pixel the embedder wrote survives, so pixel residuals are measuring the thing that was attacked |
//! | JPEG | [`Representation::JpegDct`] | The payload lives in the coefficients, so the model reads the coefficients |
//!
//! **A JPEG is never routed to a spatial model.** [`crate::router`] enforces
//! that, and [`crate::model::ModelCard`] declares which representation a given
//! artefact was trained on, so an artefact and an extractor cannot silently
//! disagree.
//!
//! # Why the SRM filter bank is not in this file
//!
//! YedroudjNet's first layer is a fixed high-pass filter bank (the 30 basic
//! SRM kernels) whose job is to suppress image content and leave the stego
//! residual. It is tempting to implement that bank here in Rust.
//!
//! That would be a mistake, and the kind that produces confident wrong answers
//! rather than errors. If the Rust bank differs from the bank the Python side
//! trained with, in a sign, a scale factor, or a kernel ordering, every
//! inference is wrong and nothing reports a problem. The bank is therefore
//! **frozen into the exported graph as a constant convolution**: it ships
//! inside the ONNX artefact, trained and served by construction identical. This
//! module's job stops at handing over a correctly-scaled plane.

use crate::error::{MlError, Result};

/// Hard caps. Documented numbers, enforced at the boundary, per baseline 2.1.
pub mod limits {
    /// Largest spatial cover this crate will build a tensor for. 64 megapixels
    /// at one f32 channel is 256 MB of working set, which is the most a desktop
    /// run should claim without the operator having asked for it.
    pub const MAX_PIXELS: u64 = 64_000_000;

    /// Largest JPEG, in 8x8 blocks per component. 1,048,576 blocks matches
    /// `dct-io`'s own `MAX_MCU_COUNT`, so this cap is the same ceiling the
    /// parser already enforces rather than a second, looser one.
    pub const MAX_BLOCKS: usize = 1_048_576;

    /// Smallest side either model accepts. Both architectures were trained on
    /// 256x256 crops; below that the receptive field of the deepest layer
    /// exceeds the image and the result is not what was validated.
    pub const MIN_SIDE: u32 = 256;
}

/// Which domain a tensor is in. Carried alongside the data so a mismatch
/// against the model card is an error rather than a wrong answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Domain {
    /// Single-channel luminance pixels, as written by a lossless embedder.
    Spatial,
    /// Quantised DCT coefficients, 64 per 8x8 block, laid out as 64 planes.
    /// This is the layout a JPEG-phase-aware network wants: plane `k` holds
    /// coefficient `k` of every block, so a convolution over a plane sees
    /// spatially adjacent blocks at a fixed frequency.
    JpegDctQuantised,
    /// Dequantised DCT coefficients, same layout, each coefficient multiplied
    /// by its quantisation step. **Needs the quantisation tables, which
    /// `dct-io` 0.1.1 does not expose.** See the module note below.
    JpegDctDequantised,
}

impl Domain {
    /// How many channels a graph in this domain takes on its input layer.
    ///
    /// This is the one property of a graph a backend can read back from the
    /// file, so it is the one cross-check available against a card that lies
    /// about its domain. It does not separate the two DCT domains from each
    /// other, which both carry 64 planes; see [`crate::model::Backend`].
    pub fn channels(self) -> usize {
        match self {
            Domain::Spatial => 1,
            Domain::JpegDctQuantised | Domain::JpegDctDequantised => 64,
        }
    }

    /// Tensor side length corresponding to a cover crop of `cover_side` pixels.
    ///
    /// A model card's `input_side` is always in **cover pixels**, because that
    /// is the number the training config used and the only one a reader can
    /// compare across domains. In the DCT domains one tensor element per plane
    /// covers an 8x8 block, so the tensor is eight times smaller per side. Had
    /// this been left implicit, a 256 pixel card would have been compared
    /// against a 32 element tensor and every JPEG would have looked too small.
    pub fn tensor_side(self, cover_side: u32) -> usize {
        match self {
            Domain::Spatial => cover_side as usize,
            Domain::JpegDctQuantised | Domain::JpegDctDequantised => (cover_side / 8) as usize,
        }
    }

    /// For error messages and card comparison.
    pub fn name(self) -> &'static str {
        match self {
            Domain::Spatial => "spatial luminance",
            Domain::JpegDctQuantised => "quantised DCT",
            Domain::JpegDctDequantised => "dequantised DCT",
        }
    }
}

/// A model input: the data, its domain, and its shape.
///
/// Deliberately not an image type. By the time a `Representation` exists the
/// container is gone and only the numbers the model was trained on remain.
#[derive(Debug, Clone, PartialEq)]
pub struct Representation {
    domain: Domain,
    /// Channels-first, row-major: `[c][y][x]` flattened.
    data: Vec<f32>,
    channels: usize,
    height: usize,
    width: usize,
}

impl Representation {
    /// Build one, checking that the shape and the buffer agree.
    ///
    /// `pub(crate)` rather than private: a backend's tests need to construct a
    /// tensor of a known shape without an encoder for the domain in question,
    /// and there is no real JPEG that produces a chosen 64 plane tensor. Still
    /// not public, so no caller outside this crate can bypass an extractor.
    pub(crate) fn new(
        domain: Domain,
        data: Vec<f32>,
        channels: usize,
        height: usize,
        width: usize,
    ) -> Result<Self> {
        let want = channels
            .checked_mul(height)
            .and_then(|n| n.checked_mul(width))
            .ok_or(MlError::CapExceeded {
                what: "tensor element count",
                limit: "usize overflow".to_string(),
            })?;
        if data.len() != want {
            return Err(MlError::CapExceeded {
                what: "tensor shape does not match its buffer",
                limit: format!("{want} elements expected, {} present", data.len()),
            });
        }
        Ok(Self {
            domain,
            data,
            channels,
            height,
            width,
        })
    }

    /// Which domain this is in.
    pub fn domain(&self) -> Domain {
        self.domain
    }

    /// `[channels, height, width]`, excluding the batch dimension.
    pub fn shape(&self) -> [usize; 3] {
        [self.channels, self.height, self.width]
    }

    /// The flat buffer, channels-first.
    pub fn data(&self) -> &[f32] {
        &self.data
    }

    /// Split into non-overlapping `side` by `side` tiles, in raster order.
    ///
    /// Both architectures are trained on fixed crops (256 pixels in the
    /// published work), so a 4000 by 3000 cover is not something either model
    /// has ever seen. Resizing it would destroy the very residual the model
    /// detects, and running a convolutional stack over an input eight times
    /// larger than the training crop changes what the global pooling layer
    /// averages over, which moves the operating point the card measured. Tiling
    /// keeps every tile at exactly the trained geometry, so the card's
    /// thresholds still mean what they were measured to mean.
    ///
    /// A partial tile at the right or bottom edge is dropped rather than padded:
    /// padding invents pixels, and an invented pixel has no LSB residual, so a
    /// padded tile would read as unusually clean and drag a maximum-over-tiles
    /// decision in the safe direction for the wrong reason.
    pub fn tiles(&self, side: usize) -> Result<Vec<Representation>> {
        if side == 0 {
            return Err(MlError::CapExceeded {
                what: "tile side",
                limit: "zero is not a tile size".to_string(),
            });
        }
        if self.height < side || self.width < side {
            return Err(MlError::TooSmall {
                got: self.width as u32,
                got_h: self.height as u32,
                need: side as u32,
            });
        }
        let down = self.height / side;
        let across = self.width / side;
        let mut out = Vec::with_capacity(down * across);
        for ty in 0..down {
            for tx in 0..across {
                let mut data = Vec::with_capacity(self.channels * side * side);
                for c in 0..self.channels {
                    let plane = c * self.height * self.width;
                    for y in 0..side {
                        let row = plane + (ty * side + y) * self.width + tx * side;
                        data.extend_from_slice(&self.data[row..row + side]);
                    }
                }
                out.push(Representation::new(
                    self.domain,
                    data,
                    self.channels,
                    side,
                    side,
                )?);
            }
        }
        Ok(out)
    }

    /// Build a tensor from parts a caller already holds.
    ///
    /// The shape is checked against the buffer; the domain is taken on trust,
    /// because only the caller knows what it decoded. That trust is bounded: a
    /// wrong domain is caught by [`crate::model::Model::score`], which refuses a
    /// mismatch against the card, and a tensor whose statistics are unlike the
    /// training distribution is declined by the envelope check whatever it claims
    /// to be.
    ///
    /// This exists because [`crate::router::Router::assess_representation`] is
    /// public and, without it, there was no way for anything outside this crate to
    /// produce its argument. The two callers it is for are a batch job that
    /// decoded elsewhere and the `verify-artefact` example, which proves the
    /// serving runtime reproduces the training runtime on a real artefact.
    pub fn from_parts(
        domain: Domain,
        data: Vec<f32>,
        channels: usize,
        height: usize,
        width: usize,
    ) -> Result<Self> {
        Self::new(domain, data, channels, height, width)
    }

    /// Summary statistics, used by the out-of-distribution check. Computed here
    /// rather than in the detector so the numbers describe exactly the tensor
    /// the model saw, not the file it came from.
    pub fn statistics(&self) -> TensorStats {
        TensorStats::of(&self.data)
    }
}

/// Cheap, order-independent summary of a tensor.
///
/// Order independence matters: the baseline forbids iteration order of an
/// unordered collection leaking into a result, and a reduction over a slice is
/// deterministic, so two runs on one input agree bit for bit.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TensorStats {
    /// Arithmetic mean of every element.
    pub mean: f64,
    /// Population variance, computed by Welford's method so a large tensor does
    /// not lose precision to catastrophic cancellation.
    pub variance: f64,
    /// Fraction of elements that are exactly zero. On a quantised-DCT tensor
    /// this is the single most diagnostic number about JPEG quality, which is
    /// why the envelope check uses it.
    pub zero_fraction: f64,
    /// Smallest element.
    pub min: f64,
    /// Largest element.
    pub max: f64,
}

impl TensorStats {
    fn of(data: &[f32]) -> Self {
        if data.is_empty() {
            return Self {
                mean: 0.0,
                variance: 0.0,
                zero_fraction: 0.0,
                min: 0.0,
                max: 0.0,
            };
        }
        // Welford, for numerical stability over tens of millions of elements.
        // A naive sum of squares loses precision at this length and the
        // variance is an envelope input, so it has to be right.
        let mut n = 0u64;
        let mut mean = 0.0f64;
        let mut m2 = 0.0f64;
        let mut zeros = 0u64;
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for &v in data {
            let v = v as f64;
            n += 1;
            let delta = v - mean;
            mean += delta / n as f64;
            m2 += delta * (v - mean);
            if v == 0.0 {
                zeros += 1;
            }
            if v < min {
                min = v;
            }
            if v > max {
                max = v;
            }
        }
        Self {
            mean,
            variance: if n > 1 { m2 / (n - 1) as f64 } else { 0.0 },
            zero_fraction: zeros as f64 / n as f64,
            min,
            max,
        }
    }
}

/// Turns a file into the tensor a model wants.
///
/// A trait, not a function, because the two domains have nothing in common and
/// because the scale rules want the boundary between feature extraction and
/// inference to be explicit and swappable. An implementation never decides
/// *which* domain is correct; [`crate::router`] does that from the container.
pub trait FeatureExtractor {
    /// What this extractor produces.
    fn domain(&self) -> Domain;

    /// Build the tensor from the file's bytes.
    ///
    /// Takes bytes rather than a path on purpose: **nothing on the inference
    /// path touches the filesystem.** The caller reads the file, which keeps IO
    /// policy, size pre-flight and sandboxing with the caller and makes this
    /// whole trait trivially testable from a byte literal.
    fn extract(&self, bytes: &[u8]) -> Result<Representation>;
}

/// Spatial extractor: decode to single-channel luminance, centred.
///
/// Luminance rather than RGB because both architectures were published and
/// trained on greyscale, and because an embedder that writes all three channels
/// leaves its residual in the luminance combination too. Feeding three channels
/// to a model trained on one is the representation mismatch this crate errors
/// on rather than guesses about.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpatialExtractor;

impl FeatureExtractor for SpatialExtractor {
    fn domain(&self) -> Domain {
        Domain::Spatial
    }

    fn extract(&self, bytes: &[u8]) -> Result<Representation> {
        let img = image::load_from_memory(bytes).map_err(|e| MlError::Decode(e.to_string()))?;
        let (w, h) = (img.width(), img.height());

        if (w as u64) * (h as u64) > limits::MAX_PIXELS {
            return Err(MlError::CapExceeded {
                what: "cover pixel count",
                limit: format!("{} pixels", limits::MAX_PIXELS),
            });
        }
        if w < limits::MIN_SIDE || h < limits::MIN_SIDE {
            return Err(MlError::TooSmall {
                got: w,
                got_h: h,
                need: limits::MIN_SIDE,
            });
        }

        let grey = img.to_luma8();
        // Centre to [-0.5, 0.5] rather than scaling to [0, 1]. The first layer
        // is a high-pass bank, so a DC offset is removed either way; centring
        // just keeps the activations symmetric, and it is what the Python side
        // does. The two must match, which is why the constant is named in both.
        let data: Vec<f32> = grey
            .as_raw()
            .iter()
            .map(|&p| (p as f32 / 255.0) - 0.5)
            .collect();
        Representation::new(Domain::Spatial, data, 1, h as usize, w as usize)
    }
}

/// JPEG extractor: DCT coefficients as 64 planes, quantised or dequantised.
///
/// # Where the quantisation table comes from
///
/// `dct-io` 0.1.1 exposes `read_coefficients` (quantised values), `inspect`
/// (dimensions and per-component sampling factors) and `block_count`. It does
/// **not** expose the quantisation tables: `0xDB` appears nowhere in its source
/// and DQT segments fall through its generic skip branch. That is filed as item
/// D2 against `dct-io` and will be fixed there in time.
///
/// Meanwhile the table is supplied by the caller through
/// [`QuantisationTables`], because Stegcore's engine already reads it: its
/// `dct_analysis` module walks DQT through `container::visit_jpeg_segments` and
/// has handled 8-bit and 16-bit entries, late-defined tables and truncated
/// segments since v5. **This crate deliberately does not read DQT itself.** A
/// second DQT reader in the same repository is two things that can disagree
/// about the same bytes, and the one that disagrees silently is the one that
/// produces a wrong amplitude for every coefficient in the image.
///
/// # Why the dequantised domain matters
///
/// Quantised coefficients are only comparable **within one quality setting**,
/// because the same stored integer means a different physical amplitude under a
/// different table. A model trained across mixed qualities on quantised input
/// has to learn the table implicitly from the data, and this project has
/// measured what happens when a detector learns the compressor instead of the
/// payload: a vendor's score followed the JPEG writer rather than the hiding,
/// scoring an altered file cleaner than its own original in 89.6% of pairs.
///
/// So quantised input is usable for a quality-stratified model and that is why
/// `--stratify-quality` is mandatory on the JPEG training jobs. Dequantised
/// input removes the need for that stratification. Which one actually detects
/// better is now a question that can be **measured**, because both are
/// reachable; it is not settled here by argument.
#[derive(Debug, Clone, Copy)]
pub struct JpegDctExtractor {
    /// The luma quantisation table in **zigzag** order, matching the order
    /// `dct-io` stores coefficients in and the order a DQT segment declares
    /// them in. `None` means produce quantised coefficients unchanged.
    table: Option<[u16; 64]>,
}

/// Something that can supply a JPEG's luma quantisation table.
///
/// A trait rather than a function so this crate needs no dependency on
/// Stegcore's engine, which is the layer that owns the only DQT reader in the
/// repository. The engine implements this over its existing
/// `luma_quantisation_table`, and the dependency points the right way round:
/// the engine depends on this crate, never the reverse.
///
/// # Contract
///
/// - 64 entries in **zigzag** order, as the DQT segment declares them.
/// - `Ok(None)` for a JPEG whose frame header names a table the file never
///   defines. That is a malformed file which some decoders accept anyway, and
///   the right answer is to decline the dequantised domain for it rather than
///   to invent a table.
/// - Every entry must be non-zero. A zero divisor cannot have produced the
///   stored coefficient, so a table containing one is not the table that was
///   used, and multiplying by it would be arithmetic on a lie.
pub trait QuantisationTables: Send + Sync {
    /// Read the luma table for this JPEG.
    fn luma_table(&self, jpeg: &[u8]) -> Result<Option<[u16; 64]>>;
}

impl Default for JpegDctExtractor {
    fn default() -> Self {
        Self::quantised()
    }
}

impl JpegDctExtractor {
    /// Quantised coefficients, exactly as stored. Needs no table.
    pub fn quantised() -> Self {
        Self { table: None }
    }

    /// Dequantised coefficients: each stored value multiplied by its own
    /// quantisation step, which puts every image on one physical scale whatever
    /// quality it was written at.
    ///
    /// # Errors
    ///
    /// Refuses a table containing a zero entry. JPEG divides by these values, so
    /// a zero cannot be the divisor that produced the file, and accepting it
    /// would silently zero a whole frequency plane.
    pub fn dequantised(table: [u16; 64]) -> Result<Self> {
        if let Some(i) = table.iter().position(|&q| q == 0) {
            return Err(MlError::Coefficients(format!(
                "quantisation table entry {i} is zero, which cannot have been the divisor"
            )));
        }
        Ok(Self { table: Some(table) })
    }
}

impl FeatureExtractor for JpegDctExtractor {
    fn domain(&self) -> Domain {
        match self.table {
            None => Domain::JpegDctQuantised,
            Some(_) => Domain::JpegDctDequantised,
        }
    }

    fn extract(&self, bytes: &[u8]) -> Result<Representation> {
        let info = dct_io::inspect(bytes).map_err(|e| MlError::Coefficients(format!("{e:?}")))?;
        let coeffs = dct_io::read_coefficients(bytes)
            .map_err(|e| MlError::Coefficients(format!("{e:?}")))?;

        let luma = coeffs
            .components
            .first()
            .ok_or_else(|| MlError::Coefficients("no components".to_string()))?;

        if luma.blocks.len() > limits::MAX_BLOCKS {
            return Err(MlError::CapExceeded {
                what: "JPEG block count",
                limit: format!("{} blocks", limits::MAX_BLOCKS),
            });
        }
        if info.width < limits::MIN_SIDE as u16 || info.height < limits::MIN_SIDE as u16 {
            return Err(MlError::TooSmall {
                got: info.width as u32,
                got_h: info.height as u32,
                need: limits::MIN_SIDE,
            });
        }

        // Block grid for the luminance component. The MCU geometry means the
        // stored block count can exceed width/8 * height/8 when the image is
        // not a whole number of MCUs, so the grid is derived from the declared
        // sampling factors rather than from the block count, and any trailing
        // padding blocks are dropped. Deriving it the other way around silently
        // shears the plane by one column on a non-multiple-of-16 image.
        let comp = info
            .components
            .first()
            .ok_or_else(|| MlError::Coefficients("no component info".to_string()))?;
        let h_max = info
            .components
            .iter()
            .map(|c| c.h_samp)
            .max()
            .unwrap_or(1)
            .max(1);
        let v_max = info
            .components
            .iter()
            .map(|c| c.v_samp)
            .max()
            .unwrap_or(1)
            .max(1);
        let mcu_w = 8usize * h_max as usize;
        let mcu_h = 8usize * v_max as usize;
        let mcus_x = (info.width as usize).div_ceil(mcu_w);
        let mcus_y = (info.height as usize).div_ceil(mcu_h);
        let blocks_x = mcus_x * comp.h_samp.max(1) as usize;
        let blocks_y = mcus_y * comp.v_samp.max(1) as usize;

        if blocks_x * blocks_y > luma.blocks.len() {
            return Err(MlError::Coefficients(format!(
                "declared geometry needs {} blocks but only {} were decoded",
                blocks_x * blocks_y,
                luma.blocks.len()
            )));
        }

        // 64 planes of blocks_y x blocks_x. Plane k is coefficient k of every
        // block, so a convolution over one plane sees neighbouring blocks at a
        // fixed frequency, which is the "phase aware" part.
        //
        // The scale factor is per plane, not per element, because a plane IS one
        // zigzag index and therefore one table entry. Hoisting it out of the
        // inner loop is also what keeps the two domains one code path rather
        // than two that could drift apart in their geometry.
        let mut data = vec![0f32; 64 * blocks_y * blocks_x];
        for k in 0..64 {
            let scale = match self.table {
                None => 1.0f32,
                Some(t) => f32::from(t[k]),
            };
            let plane = k * blocks_y * blocks_x;
            for by in 0..blocks_y {
                for bx in 0..blocks_x {
                    let block = &luma.blocks[by * blocks_x + bx];
                    data[plane + by * blocks_x + bx] = block[k] as f32 * scale;
                }
            }
        }

        Representation::new(self.domain(), data, 64, blocks_y, blocks_x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut img = image::RgbImage::new(w, h);
        // Deterministic texture, no rng dependency.
        let mut s: u64 = 0x2545_F491;
        for p in img.pixels_mut() {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            let v = (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8;
            *p = image::Rgb([v, v.wrapping_add(7), v.wrapping_sub(11)]);
        }
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .expect("encode");
        buf
    }

    #[test]
    fn spatial_extractor_produces_one_centred_channel() {
        let r = SpatialExtractor.extract(&png(256, 256)).expect("extract");
        assert_eq!(r.domain(), Domain::Spatial);
        assert_eq!(r.shape(), [1, 256, 256]);
        for &v in r.data() {
            assert!((-0.5..=0.5).contains(&v), "value {v} outside centred range");
        }
    }

    #[test]
    fn spatial_extractor_refuses_a_cover_below_the_trained_minimum() {
        // The honest failure. A 128x128 cover is not "probably fine"; it is
        // outside what was validated, and a number from it would be a guess.
        let err = SpatialExtractor.extract(&png(128, 128)).unwrap_err();
        match err {
            MlError::TooSmall { got, need, .. } => {
                assert_eq!(got, 128);
                assert_eq!(need, limits::MIN_SIDE);
            }
            other => panic!("expected TooSmall, got {other:?}"),
        }
    }

    #[test]
    fn spatial_extractor_reports_a_decode_failure_rather_than_guessing() {
        let err = SpatialExtractor
            .extract(b"not an image at all")
            .unwrap_err();
        assert!(matches!(err, MlError::Decode(_)), "got {err:?}");
    }

    #[test]
    fn representation_rejects_a_shape_that_contradicts_its_buffer() {
        let err = Representation::new(Domain::Spatial, vec![0.0; 10], 1, 4, 4).unwrap_err();
        assert!(matches!(err, MlError::CapExceeded { .. }), "got {err:?}");
    }

    #[test]
    fn statistics_are_order_independent_and_stable() {
        let r = SpatialExtractor.extract(&png(256, 256)).expect("extract");
        let a = r.statistics();
        let b = r.statistics();
        assert_eq!(a, b, "two reductions over one tensor disagreed");
        // Centred data over a full-range texture: mean near zero, real spread.
        assert!(a.mean.abs() < 0.1, "mean {} not centred", a.mean);
        assert!(a.variance > 0.0, "variance should be non-zero on texture");
        assert!(a.min >= -0.5 && a.max <= 0.5);
    }

    #[test]
    fn empty_tensor_statistics_do_not_divide_by_zero() {
        let s = TensorStats::of(&[]);
        assert_eq!(s.mean, 0.0);
        assert_eq!(s.variance, 0.0);
        assert_eq!(s.zero_fraction, 0.0);
    }

    #[test]
    fn domain_names_are_distinct_so_a_mismatch_message_is_readable() {
        let names = [
            Domain::Spatial.name(),
            Domain::JpegDctQuantised.name(),
            Domain::JpegDctDequantised.name(),
        ];
        let mut sorted = names;
        sorted.sort_unstable();
        sorted.iter().zip(sorted.iter().skip(1)).for_each(|(a, b)| {
            assert_ne!(a, b, "two domains share a name");
        });
    }

    /// JPEGs written by Pillow on the ROG on 2026-10-01 (see
    /// `scratchpad/mkjpeg2.sh`): a smooth gradient plus a gentle ripple, so each
    /// compresses to a few kilobytes while still carrying non-zero AC
    /// coefficients in every block. They are assets rather than generated in the
    /// test because this crate enables only `png` and `bmp` on `image`, and
    /// enabling a JPEG encoder for the tests would mean the tests exercise a
    /// configuration the shipped library does not have.
    const JPEG_256_420: &[u8] = include_bytes!("../tests/assets/cover-256.jpg");
    const JPEG_256_444: &[u8] = include_bytes!("../tests/assets/cover-256-444.jpg");
    const JPEG_520X392: &[u8] = include_bytes!("../tests/assets/cover-520x392.jpg");

    #[test]
    fn a_256_pixel_jpeg_yields_exactly_the_tensor_side_the_card_convention_implies() {
        // This is the test that ties the two halves of the unit convention
        // together: `Domain::tensor_side(256)` is 32, and the extractor must
        // actually produce 32. If these ever disagree the backend refuses every
        // JPEG, which is safe but useless, and nothing else would catch it.
        let r = JpegDctExtractor::quantised()
            .extract(JPEG_256_420)
            .expect("extract");
        assert_eq!(r.domain(), Domain::JpegDctQuantised);
        assert_eq!(r.shape(), [64, 32, 32]);
        assert_eq!(r.shape()[1], Domain::JpegDctQuantised.tensor_side(256));
    }

    #[test]
    fn chroma_subsampling_does_not_change_the_luminance_block_grid() {
        // 4:2:0 has 16 pixel MCUs and two luma blocks per MCU per axis; 4:4:4 has
        // 8 pixel MCUs and one. Both must land on 32, and they reach it by
        // different arithmetic, which is what makes this worth asserting.
        let a = JpegDctExtractor::quantised()
            .extract(JPEG_256_420)
            .expect("4:2:0");
        let b = JpegDctExtractor::quantised()
            .extract(JPEG_256_444)
            .expect("4:4:4");
        assert_eq!(a.shape(), b.shape(), "subsampling changed the luma grid");
    }

    #[test]
    fn a_jpeg_that_is_not_a_whole_number_of_mcus_is_not_sheared() {
        // 520 by 392 at 4:2:0: MCUs are 16 pixels, so 33 across and 25 down, and
        // the luma grid is twice that. Deriving the grid from the block count
        // instead would shear the plane by a column and every convolution after
        // it would see neighbours that are not neighbours.
        let r = JpegDctExtractor::quantised()
            .extract(JPEG_520X392)
            .expect("extract");
        assert_eq!(r.shape(), [64, 50, 66]);

        // And it tiles to the trained geometry: 66 across admits two 32 tiles,
        // 50 down admits one, and the leftovers are dropped rather than padded.
        let tiles = r.tiles(32).expect("tiles");
        assert_eq!(tiles.len(), 2);
        assert_eq!(tiles[0].shape(), [64, 32, 32]);
    }

    /// A table whose entries are the zigzag index plus one, so a dequantised
    /// plane is exactly `(k + 1)` times its quantised counterpart and a
    /// transposed or off-by-one indexing mistake is visible rather than merely
    /// plausible.
    fn indexed_table() -> [u16; 64] {
        let mut t = [0u16; 64];
        for (k, slot) in t.iter_mut().enumerate() {
            *slot = (k + 1) as u16;
        }
        t
    }

    #[test]
    fn dequantising_scales_each_plane_by_its_own_table_entry() {
        let q = JpegDctExtractor::quantised()
            .extract(JPEG_256_420)
            .expect("quantised");
        let d = JpegDctExtractor::dequantised(indexed_table())
            .expect("table")
            .extract(JPEG_256_420)
            .expect("dequantised");

        assert_eq!(q.domain(), Domain::JpegDctQuantised);
        assert_eq!(d.domain(), Domain::JpegDctDequantised);
        assert_eq!(
            q.shape(),
            d.shape(),
            "dequantising must not change geometry"
        );

        let plane = 32 * 32;
        let mut checked = 0usize;
        for k in 0..64 {
            let scale = (k + 1) as f32;
            for i in 0..plane {
                let (a, b) = (q.data()[k * plane + i], d.data()[k * plane + i]);
                assert_eq!(b, a * scale, "plane {k} element {i}");
                if a != 0.0 {
                    checked += 1;
                }
            }
        }
        // Non-vacuity: if every coefficient were zero the loop above would pass
        // against any scale factor at all, including none.
        assert!(
            checked > 1000,
            "only {checked} non-zero coefficients, so the scaling was barely tested"
        );
    }

    #[test]
    fn a_quantisation_table_containing_a_zero_is_refused() {
        // JPEG divides by these values, so a zero cannot have produced the file.
        // Accepting it would silently flatten a whole frequency plane.
        let mut t = indexed_table();
        t[17] = 0;
        let err = JpegDctExtractor::dequantised(t).unwrap_err();
        match err {
            MlError::Coefficients(d) => assert!(d.contains("entry 17 is zero"), "{d}"),
            other => panic!("expected Coefficients, got {other:?}"),
        }
    }

    #[test]
    fn the_extractors_domain_follows_whether_it_holds_a_table() {
        assert_eq!(
            JpegDctExtractor::quantised().domain(),
            Domain::JpegDctQuantised
        );
        assert_eq!(
            JpegDctExtractor::dequantised(indexed_table())
                .unwrap()
                .domain(),
            Domain::JpegDctDequantised
        );
        // `Default` must stay the cheap one that needs no table, because a
        // default that silently needed external data would be a trap.
        assert_eq!(
            JpegDctExtractor::default().domain(),
            Domain::JpegDctQuantised
        );
    }

    #[test]
    fn dequantisation_is_deterministic() {
        let e = JpegDctExtractor::dequantised(indexed_table()).unwrap();
        assert_eq!(
            e.extract(JPEG_520X392).unwrap(),
            e.extract(JPEG_520X392).unwrap()
        );
    }

    #[test]
    fn jpeg_extraction_is_deterministic() {
        let a = JpegDctExtractor::quantised().extract(JPEG_520X392).unwrap();
        let b = JpegDctExtractor::quantised().extract(JPEG_520X392).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn jpeg_extractor_rejects_bytes_that_are_not_a_jpeg() {
        let err = JpegDctExtractor::quantised()
            .extract(&png(256, 256))
            .unwrap_err();
        assert!(matches!(err, MlError::Coefficients(_)), "got {err:?}");
    }

    /// Two channels of a known ramp, so a wrongly strided tile is visible rather
    /// than merely the wrong length.
    fn ramp(channels: usize, height: usize, width: usize) -> Representation {
        let mut data = Vec::with_capacity(channels * height * width);
        for c in 0..channels {
            for y in 0..height {
                for x in 0..width {
                    data.push((c * 10_000 + y * 100 + x) as f32);
                }
            }
        }
        Representation::new(Domain::Spatial, data, channels, height, width).unwrap()
    }

    #[test]
    fn tiles_cover_the_image_in_raster_order_with_the_right_pixels() {
        let r = ramp(2, 512, 768);
        let tiles = r.tiles(256).expect("tiles");
        assert_eq!(tiles.len(), 2 * 3, "2 down by 3 across");
        for t in &tiles {
            assert_eq!(t.shape(), [2, 256, 256]);
            assert_eq!(t.domain(), Domain::Spatial);
        }
        // Tile index 4 is row 1, column 1, so its top-left pixel is (y=256,
        // x=256) of channel 0 and its second channel starts 10_000 higher.
        assert_eq!(tiles[4].data()[0], (256 * 100 + 256) as f32);
        assert_eq!(
            tiles[4].data()[256 * 256],
            (10_000 + 256 * 100 + 256) as f32
        );
        // Second row of that tile, to pin the stride rather than just the origin.
        assert_eq!(tiles[4].data()[256], (257 * 100 + 256) as f32);
    }

    #[test]
    fn a_partial_edge_tile_is_dropped_rather_than_padded() {
        // 300 wide admits one 256 tile and leaves 44 columns, which are dropped.
        let tiles = ramp(1, 300, 300).tiles(256).expect("tiles");
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].shape(), [1, 256, 256]);
    }

    #[test]
    fn tiling_an_image_smaller_than_the_tile_is_refused_not_padded() {
        let err = ramp(1, 128, 512).tiles(256).unwrap_err();
        assert!(
            matches!(err, MlError::TooSmall { need: 256, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_zero_tile_side_is_refused_rather_than_dividing_by_zero() {
        let err = ramp(1, 256, 256).tiles(0).unwrap_err();
        assert!(matches!(err, MlError::CapExceeded { .. }), "{err:?}");
    }

    #[test]
    fn tensor_side_is_in_cover_pixels_for_spatial_and_blocks_for_dct() {
        assert_eq!(Domain::Spatial.tensor_side(256), 256);
        assert_eq!(Domain::JpegDctQuantised.tensor_side(256), 32);
        assert_eq!(Domain::JpegDctDequantised.tensor_side(512), 64);
        assert_eq!(Domain::Spatial.channels(), 1);
        assert_eq!(Domain::JpegDctQuantised.channels(), 64);
    }

    #[test]
    fn tiling_is_deterministic_across_runs() {
        // Reproducibility is a baseline requirement and tiling is the one place
        // in this module where an ordering mistake would be invisible: the tiles
        // would still have the right shapes.
        let r = ramp(1, 512, 512);
        let a = r.tiles(256).unwrap();
        let b = r.tiles(256).unwrap();
        assert_eq!(a, b);
    }
}
