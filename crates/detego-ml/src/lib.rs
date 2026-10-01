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

//! Learned steganalysis for the detego family.
//!
//! # What this crate is for
//!
//! The classical detectors this project ships are strong on spatial LSB
//! replacement and blind to JPEG DCT steganography. Measured on 120 matched
//! steghide pairs: **0 of 120 verdicts changed**, median score delta 0.0000,
//! maximum absolute delta 0.00e+00. This crate exists to answer the files those
//! detectors cannot speak to, and it is built around one idea:
//!
//! > A model is only allowed to answer inside the envelope it was measured in.
//!
//! Everything else follows from that. The model card is mandatory and validated.
//! A tensor from the wrong domain is an error rather than a number. An input
//! outside the trained distribution is **declined**, not scored. Results are
//! carried per cover source, because a pooled figure across mixed sources is
//! the number that lies.
//!
//! # The four boundaries
//!
//! ```text
//!   bytes ──► FeatureExtractor ──► Representation ──► Model ──► RawScore
//!              (representation.rs)                     │  (model.rs)
//!                                                      │
//!   WeightStore ─────────────────────────────────────── ┘
//!    (weights.rs)                                       │
//!                                             Router ───┘──► MlAssessment
//!                                            (router.rs)
//! ```
//!
//! - [`representation::FeatureExtractor`] turns bytes into a tensor. It takes
//!   bytes, never a path, so **nothing on the inference path touches the
//!   filesystem**.
//! - [`model::Backend`] runs a graph. One trait, so the runtime is swappable;
//!   see the backend note below.
//! - [`weights::WeightStore`] supplies artefacts and verifies them.
//! - [`router::Router`] is the only thing that decides which representation a
//!   container gets, and it is what the engine calls.
//!
//! # The backend
//!
//! No backend is compiled in by default. `--features backend-tract` selects
//! `tract-onnx`, which is pure Rust and links statically. The reasoning, with
//! the measured numbers behind it, is in [`backend`]; [`model::Backend`] exists
//! so the judgement can be revisited with a measurement rather than a rewrite.
//!
//! # Tiling
//!
//! Both architectures are trained on a fixed crop and their operating points
//! were measured there, so a larger cover is split into tiles at exactly that
//! geometry and the strongest tile that was inside the envelope is reported.
//! The trade-off this makes, and the per-tile false-positive rate it leaves to
//! be calibrated, are documented on `Router::assess_with` and surfaced on every
//! result as [`router::MlAssessment::tiles_scored`].
//!
//! # Using it
//!
//! ```no_run
//! use detego_ml::{router::Router, weights::{FsWeightStore, WeightStore}};
//!
//! # fn main() -> Result<(), detego_ml::MlError> {
//! let store = FsWeightStore::new("/var/cache/detego-ml");
//! let _artefact = store.load("yedroudj-net-spatial-v1")?;
//! // A backend turns `_artefact.onnx` into a `Backend`; see `backend-tract`.
//! let router = Router::new();
//! let _ = router.assess(b"\x89PNG...", "png");
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod error;
pub mod model;
pub mod representation;
pub mod router;
pub mod weights;

pub use error::{MlError, Result};
pub use model::{Architecture, Model, ModelCard};
pub use representation::{Domain, Representation};
pub use router::{MlAssessment, MlVerdict, Router};

/// Shared fixtures. Test-only, so the crate ships no image encoder it does not
/// otherwise need.
#[cfg(test)]
pub(crate) mod test_support {
    /// A deterministic textured PNG. No rng dependency, and reproducible across
    /// machines so a test that fails here fails everywhere.
    pub fn png(w: u32, h: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut img = image::RgbImage::new(w, h);
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
            .expect("encode test png");
        buf
    }
}
