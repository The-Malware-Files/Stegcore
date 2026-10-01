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

//! Error type.
//!
//! Every variant names something a caller can act on. There is deliberately no
//! catch-all `Other(String)`: a failure nobody can describe is a failure nobody
//! can fix, and the baseline's fail-loud rule means the shape of the problem
//! has to survive to the surface.

use std::path::PathBuf;

/// What went wrong, in terms a caller can route on.
#[derive(Debug, thiserror::Error)]
pub enum MlError {
    /// The file is not a format this crate can represent for any model.
    #[error("{0} is not a format learned steganalysis can read here")]
    UnsupportedFormat(String),

    /// The spatial decoder refused the file.
    #[error("could not decode the image: {0}")]
    Decode(String),

    /// The JPEG coefficient reader refused the file.
    #[error("could not read JPEG coefficients: {0}")]
    Coefficients(String),

    /// The model wants a representation the extractor was not asked to build,
    /// or vice versa. This is the mismatch that silently produces confident
    /// nonsense if it is not an error, so it is an error.
    #[error("model expects {expected} input but was handed {actual}")]
    RepresentationMismatch {
        /// What the model's graph declares it consumes.
        expected: &'static str,
        /// What the caller actually handed it.
        actual: &'static str,
    },

    /// The cover is smaller than the model's receptive field needs.
    #[error("cover is {got}x{got_h}, below the {need}x{need} minimum this model was trained for")]
    TooSmall {
        /// Width of the cover that was offered.
        got: u32,
        /// Height of the cover that was offered.
        got_h: u32,
        /// The minimum side length the model was trained for.
        need: u32,
    },

    /// A cap was hit. Carries the limit so the message can state it.
    #[error("{what} exceeds the {limit} cap this crate enforces")]
    CapExceeded {
        /// Which quantity went over, named so the message reads as English.
        what: &'static str,
        /// The limit itself, so the user learns the bound and not just that one exists.
        limit: String,
    },

    /// Weights are not present locally and no fetch was permitted.
    #[error("weights for {model} are not available locally; nothing was downloaded because fetching was not enabled")]
    WeightsMissing {
        /// Identifier of the model whose weights are absent.
        model: String,
    },

    /// Weights were found but are not what they claim to be.
    #[error("weights for {model} failed verification: {detail}")]
    WeightsCorrupt {
        /// Identifier of the model that failed verification.
        model: String,
        /// What disagreed, including both digests where that is the cause.
        detail: String,
    },

    /// The model card beside the weights could not be read, so the envelope,
    /// the calibration and the expected representation are all unknown. Running
    /// the graph anyway would produce an uncalibrated number with no declared
    /// validity, which is the thing this crate exists not to do.
    #[error("model card for {model} is unusable: {detail}")]
    CardInvalid {
        /// Identifier of the model whose card is unusable.
        model: String,
        /// Which card rule was broken.
        detail: String,
    },

    /// The inference backend failed.
    #[error("inference backend failed: {0}")]
    Backend(String),

    /// No backend was compiled in.
    #[error("this build has no inference backend; enable a `backend-*` feature")]
    NoBackend,

    /// Filesystem trouble, with the path, because an IO error without a path is
    /// not a diagnostic.
    #[error("could not read {path}: {source}")]
    Io {
        /// The path that could not be read, which is what makes this a diagnostic.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, MlError>;
