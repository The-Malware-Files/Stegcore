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

//! The entry point the engine calls, and the only place that decides which
//! representation a container gets.
//!
//! # The escalation contract
//!
//! The engine's `Verdict::NotAssessed` is the trigger, and it is **coverage
//! based rather than confidence based on purpose**. The classical detectors on
//! JPEG do not report uncertainty; they confidently report clean. A confidence
//! threshold would therefore never fire on exactly the files that need
//! escalating, which is why the engine asks "was the principal threat for this
//! format examined at all" instead.
//!
//! So the flow is: the engine runs its own detectors, finds coverage inadequate,
//! and hands the file here. This crate picks the representation from the
//! container, scores it with the matching model, and returns an
//! [`MlAssessment`] carrying a verdict, a calibrated probability, and the
//! envelope result. The engine never learns which architecture ran.
//!
//! # What the engine should declare
//!
//! So that `crates/engine` keeps no dependency on this crate (sprint decision
//! 5), the engine declares its own one-method trait and this crate's
//! [`Router`] satisfies it through a thin adapter in the CLI/GUI layer:
//!
//! ```text
//! // in crates/engine/src/analysis.rs, owned by the engine
//! pub trait LearnedDetector: Send + Sync {
//!     /// Assess a file whose coverage was inadequate. `bytes` is the file,
//!     /// `format` is the detected container ("png", "jpg", ...).
//!     fn assess(&self, bytes: &[u8], format: &str)
//!         -> Result<LearnedAssessment, String>;
//! }
//!
//! pub struct LearnedAssessment {
//!     pub verdict: Verdict,          // the engine's own enum
//!     pub probability: Option<f64>,  // None when out of envelope
//!     pub declined: Option<String>,  // why, when it declined
//!     pub model: String,             // for the report's provenance line
//! }
//! ```
//!
//! `analyse` then holds an `Option<Box<dyn LearnedDetector>>`, absent by
//! default. Nothing in the engine changes when this crate is not linked, and the
//! inference runtime never enters the engine's dependency graph.

use crate::error::{MlError, Result};
use crate::model::{Calibration, EnvelopeVerdict, Model, RawScore};
use crate::representation::{
    Domain, FeatureExtractor, JpegDctExtractor, QuantisationTables, Representation,
    SpatialExtractor,
};

/// Turn a logit into a probability through the card's fitted Platt parameters.
///
/// Separate from the network on purpose: the network's own output is a score on
/// a balanced training prior, and reporting that as a probability is what makes
/// a detector's number worse than useless to an examiner. This is the only place
/// a probability is produced.
pub fn probability(logit: f64, c: &Calibration) -> f64 {
    let z = c.a * logit + c.b;
    // Numerically stable logistic. The naive form overflows for |z| around 710
    // and a saturated logit is exactly when a caller most wants a sane 0 or 1.
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

/// What this crate concluded.
///
/// `Declined` is a first-class outcome, not an error. An out-of-distribution
/// input has no honest number attached to it, and saying so is what makes the
/// hybrid trustworthy: the engine can render "not assessed, and here is why"
/// rather than a figure nobody should act on.
#[derive(Debug, Clone, PartialEq)]
pub enum MlVerdict {
    /// Scored, inside the envelope. `probability` is calibrated.
    Scored {
        /// Calibrated probability that the cover carries a payload.
        probability: f64,
        /// True when the logit cleared the card's own 1% false-positive-rate
        /// threshold on its weakest held-out source. Carried separately from
        /// the probability because an operating point and a probability answer
        /// different questions.
        above_fpr_1pc_threshold: bool,
    },
    /// The input is unlike the training distribution, so no number is offered.
    Declined {
        /// Why no number is being offered, in plain language.
        reason: String,
    },
}

/// The full result, including provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct MlAssessment {
    /// What the model concluded, or its refusal.
    pub verdict: MlVerdict,
    /// Architecture and domain that ran, for the report's provenance line.
    pub model: String,
    /// The raw logit, kept so a future recalibration can be applied to stored
    /// results without re-running inference. `NaN` when nothing was scored.
    pub logit: f64,
    /// How many tiles were inside the envelope and therefore scored. The
    /// per-tile false-positive rate makes this load bearing: a verdict drawn
    /// from thirty tiles is not the same claim as one drawn from one, and a
    /// report that does not say so is overstating itself.
    pub tiles_scored: usize,
    /// How many tiles the cover yielded in total, so `tiles_total -
    /// tiles_scored` is how much of it the model declined to judge.
    pub tiles_total: usize,
}

/// Holds one model per domain and dispatches by container.
///
/// Both slots are optional because a build may legitimately ship only the
/// spatial model: YedroudjNet trains in hours and SRNet in days, so the two will
/// not necessarily land together, and a missing JPEG model must produce an
/// honest refusal rather than a spatial model being used as a stand-in.
#[derive(Default)]
pub struct Router {
    spatial: Option<Model>,
    jpeg: Option<Model>,
    tables: Option<Box<dyn QuantisationTables>>,
}

// Hand written because `dyn QuantisationTables` cannot derive it. Which models
// are installed, and whether a table source is, is the whole of what a failure
// message needs.
impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("spatial", &self.spatial)
            .field("jpeg", &self.jpeg)
            .field("quantisation_tables", &self.tables.is_some())
            .finish()
    }
}

impl Router {
    /// An empty router, which refuses every container until a model is installed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the spatial model. Refuses a model whose card is not spatial.
    pub fn with_spatial(mut self, model: Model) -> Result<Self> {
        if model.card().domain != Domain::Spatial {
            return Err(MlError::RepresentationMismatch {
                expected: Domain::Spatial.name(),
                actual: model.card().domain.name(),
            });
        }
        self.spatial = Some(model);
        Ok(self)
    }

    /// Install the JPEG model. Refuses a model whose card is not a DCT domain,
    /// which is the guard that stops a spatial artefact being wired to the JPEG
    /// slot and quietly answering for every JPEG the engine escalates.
    pub fn with_jpeg(mut self, model: Model) -> Result<Self> {
        match model.card().domain {
            Domain::JpegDctQuantised | Domain::JpegDctDequantised => {
                self.jpeg = Some(model);
                Ok(self)
            }
            other => Err(MlError::RepresentationMismatch {
                expected: "a DCT domain",
                actual: other.name(),
            }),
        }
    }

    /// Install the source of JPEG quantisation tables.
    ///
    /// Required only by a model whose card declares
    /// [`Domain::JpegDctDequantised`]. Without it such a model refuses every
    /// JPEG with a message naming this method, rather than quietly falling back
    /// to quantised coefficients, which would feed the graph numbers on a
    /// different scale from everything it was trained on.
    pub fn with_quantisation_tables(mut self, tables: Box<dyn QuantisationTables>) -> Self {
        self.tables = Some(tables);
        self
    }

    /// The extractor a JPEG model needs, built from its card's declared domain.
    ///
    /// The card chooses, not the caller and not a feature flag. That is what
    /// makes it impossible to serve a dequantised-trained graph with quantised
    /// input, which would be wrong by a factor of the quantisation step at every
    /// coefficient and would still produce a plausible looking number.
    fn jpeg_extractor(&self, model: &Model, bytes: &[u8]) -> Result<JpegDctExtractor> {
        match model.card().domain {
            Domain::JpegDctQuantised => Ok(JpegDctExtractor::quantised()),
            Domain::JpegDctDequantised => {
                let tables = self.tables.as_ref().ok_or_else(|| {
                    MlError::Coefficients(
                        "this model was trained on dequantised coefficients and no quantisation \
                         table source is installed; call Router::with_quantisation_tables"
                            .to_string(),
                    )
                })?;
                let table = tables.luma_table(bytes)?.ok_or_else(|| {
                    MlError::Coefficients(
                        "this JPEG's frame header names a quantisation table the file never \
                         defines, so dequantised coefficients cannot be built from it"
                            .to_string(),
                    )
                })?;
                JpegDctExtractor::dequantised(table)
            }
            // `with_jpeg` refuses a spatial card, so this is unreachable through
            // any public route. It returns an error rather than panicking,
            // because a panic in a library is the engine's crash.
            Domain::Spatial => Err(MlError::RepresentationMismatch {
                expected: "a DCT domain",
                actual: Domain::Spatial.name(),
            }),
        }
    }

    /// Assess a file.
    ///
    /// `format` is the container as the engine detected it, lowercased, without
    /// a dot. Unknown containers are refused by name rather than guessed at.
    pub fn assess(&self, bytes: &[u8], format: &str) -> Result<MlAssessment> {
        let (model, representation) = match format {
            "png" | "bmp" => {
                let m = self
                    .spatial
                    .as_ref()
                    .ok_or_else(|| MlError::WeightsMissing {
                        model: "spatial".to_string(),
                    })?;
                (m, SpatialExtractor.extract(bytes)?)
            }
            "jpg" | "jpeg" => {
                let m = self.jpeg.as_ref().ok_or_else(|| MlError::WeightsMissing {
                    model: "jpeg-dct".to_string(),
                })?;
                let extractor = self.jpeg_extractor(m, bytes)?;
                (m, extractor.extract(bytes)?)
            }
            other => {
                return Err(MlError::UnsupportedFormat(other.to_string()));
            }
        };

        Self::assess_with(model, &representation)
    }

    /// Assess a representation that was already built. Exposed so a caller
    /// holding a decoded tensor (a batch job, a test) does not re-decode, and so
    /// the conclusion logic has a seam that can be tested without a file.
    pub fn assess_representation(&self, input: &Representation) -> Result<MlAssessment> {
        let model = match input.domain() {
            Domain::Spatial => self.spatial.as_ref(),
            Domain::JpegDctQuantised | Domain::JpegDctDequantised => self.jpeg.as_ref(),
        }
        .ok_or_else(|| MlError::WeightsMissing {
            model: input.domain().name().to_string(),
        })?;
        Self::assess_with(model, input)
    }

    /// Tile to the model's trained geometry, score every tile, and report the
    /// strongest tile that was inside the envelope.
    ///
    /// **Maximum over tiles, not mean.** A payload is usually confined to part
    /// of a cover, so averaging dilutes the one tile that carries it by however
    /// many clean tiles sit beside it: on a 12 tile cover with one embedded
    /// tile, a mean moves the score by a twelfth of the signal, which is below
    /// the operating point the card measured. The maximum is also what makes
    /// the card's thresholds still applicable, because they were measured on
    /// single crops.
    ///
    /// The cost accepted: the false-positive rate is per tile, so a cover with
    /// twelve tiles gets twelve chances to cross the 1% threshold. That is a
    /// real effect and it is not corrected for here, because the correction
    /// (a per-cover threshold measured at the cover sizes being scored) is a
    /// measurement to make during evaluation, not a constant to invent in
    /// library code. `tiles_scored` is carried on the result so the report can
    /// state it and so a later calibration pass has the number it needs.
    fn assess_with(model: &Model, input: &Representation) -> Result<MlAssessment> {
        let card = model.card();
        let side = card.domain.tensor_side(card.input_side);
        let [_, h, w] = input.shape();

        let tiles = if h == side && w == side {
            vec![input.clone()]
        } else {
            input.tiles(side)?
        };

        let mut best: Option<RawScore> = None;
        let mut scored = 0usize;
        let mut declined: Option<String> = None;
        for tile in &tiles {
            let raw = model.score(tile)?;
            match &raw.envelope {
                EnvelopeVerdict::Outside { reason } => {
                    if declined.is_none() {
                        declined = Some(reason.clone());
                    }
                }
                EnvelopeVerdict::Inside => {
                    scored += 1;
                    // Spelled out rather than `is_none_or`, which is Rust 1.82
                    // and this crate declares 1.77.2.
                    let better = match &best {
                        None => true,
                        Some(b) => raw.logit > b.logit,
                    };
                    if better {
                        best = Some(raw);
                    }
                }
            }
        }

        let total = tiles.len();
        match best {
            Some(raw) => Ok(Self::conclude(model, raw, scored, total)),
            None => {
                // Every tile was out of distribution, so there is no number to
                // report. The reason from the first such tile is carried rather
                // than a generic one, because an unactionable refusal is the
                // failure mode this crate is built to avoid.
                let reason = declined.unwrap_or_else(|| {
                    "the cover yielded no tile at the model's trained geometry".to_string()
                });
                Ok(MlAssessment {
                    verdict: MlVerdict::Declined { reason },
                    model: Self::model_name(model),
                    logit: f64::NAN,
                    tiles_scored: 0,
                    tiles_total: total,
                })
            }
        }
    }

    fn model_name(model: &Model) -> String {
        let card = model.card();
        format!(
            "{} ({}, {})",
            card.architecture.name(),
            card.domain.name(),
            model.backend_name()
        )
    }

    fn conclude(model: &Model, raw: RawScore, scored: usize, total: usize) -> MlAssessment {
        let card = model.card();
        let name = Self::model_name(model);
        let verdict = match raw.envelope {
            EnvelopeVerdict::Outside { reason } => MlVerdict::Declined { reason },
            EnvelopeVerdict::Inside => {
                // The weakest held-out source sets the bar. Taking the most
                // favourable source instead is how a model ends up advertised
                // at a number it only reaches on the corpus it likes, which is
                // the per-source reporting rule applied to the threshold too.
                let bar = card
                    .operating_points
                    .per_source
                    .iter()
                    .filter(|r| r.held_out)
                    .map(|r| r.threshold_at_fpr_1pc)
                    .fold(f64::NEG_INFINITY, f64::max);
                MlVerdict::Scored {
                    probability: probability(raw.logit, &card.calibration),
                    above_fpr_1pc_threshold: bar.is_finite() && raw.logit >= bar,
                }
            }
        };
        MlAssessment {
            verdict,
            model: name,
            logit: raw.logit,
            tiles_scored: scored,
            tiles_total: total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::{valid_card, FixedBackend};
    use crate::test_support::png;

    fn spatial_router(logit: f64) -> Router {
        let model = Model::new(
            valid_card(Domain::Spatial),
            Box::new(FixedBackend {
                value: logit,
                domain: Domain::Spatial,
            }),
        )
        .expect("model");
        Router::new().with_spatial(model).expect("install")
    }

    /// A 512 by 512 spatial tensor whose four 256 tiles each begin with a
    /// different, known value, so a maximum and a first are distinguishable.
    fn four_tiles(firsts: [f32; 4]) -> Representation {
        let mut data = textured(512 * 512);
        for (i, v) in firsts.iter().enumerate() {
            let (ty, tx) = (i / 2, i % 2);
            data[(ty * 256) * 512 + tx * 256] = *v;
        }
        Representation::new(Domain::Spatial, data, 1, 512, 512).expect("tensor")
    }

    /// A non-degenerate filler: variance inside the card's declared range and a
    /// zero fraction of zero, so a tile built from it is entitled to a score.
    /// An all-zero buffer is not, which is correct behaviour and was the first
    /// version of these tests failing for the right reason.
    fn textured(n: usize) -> Vec<f32> {
        (0..n).map(|i| (i % 97) as f32 / 97.0 - 0.5).collect()
    }

    fn first_element_router(scale: f64) -> Router {
        let model = Model::new(
            valid_card(Domain::Spatial),
            Box::new(crate::model::testing::FirstElementBackend {
                scale,
                domain: Domain::Spatial,
            }),
        )
        .expect("model");
        Router::new().with_spatial(model).expect("install")
    }

    #[test]
    fn a_cover_larger_than_the_trained_crop_is_tiled_and_the_strongest_tile_wins() {
        let router = first_element_router(1.0);
        let a = router
            .assess_representation(&four_tiles([0.1, 9.0, 0.2, 0.3]))
            .expect("assess");
        assert_eq!(a.tiles_total, 4);
        assert_eq!(a.tiles_scored, 4);
        assert!((a.logit - 9.0).abs() < 1e-12, "logit was {}", a.logit);

        // The strongest tile in a different position, so the result cannot be
        // the first tile dressed up as the maximum.
        let b = router
            .assess_representation(&four_tiles([0.1, 0.2, 0.3, 7.0]))
            .expect("assess");
        assert!((b.logit - 7.0).abs() < 1e-12, "logit was {}", b.logit);
    }

    #[test]
    fn a_cover_already_at_the_trained_crop_is_scored_as_one_tile() {
        let router = first_element_router(1.0);
        let mut data = textured(256 * 256);
        data[0] = 3.0;
        let t = Representation::new(Domain::Spatial, data, 1, 256, 256).unwrap();
        let a = router.assess_representation(&t).expect("assess");
        assert_eq!((a.tiles_total, a.tiles_scored), (1, 1));
        assert!((a.logit - 3.0).abs() < 1e-12);
    }

    #[test]
    fn a_cover_whose_every_tile_is_out_of_distribution_is_declined_with_a_reason() {
        // An all-zero tensor has zero variance and a zero fraction of 1.0, both
        // outside the card's declared ranges, so no tile is entitled to a score.
        let router = first_element_router(1.0);
        let t = Representation::new(Domain::Spatial, vec![0.0; 512 * 512], 1, 512, 512).unwrap();
        let a = router.assess_representation(&t).expect("assess");
        match &a.verdict {
            MlVerdict::Declined { reason } => assert!(!reason.is_empty()),
            other => panic!("expected Declined, got {other:?}"),
        }
        assert_eq!((a.tiles_scored, a.tiles_total), (0, 4));
        assert!(a.logit.is_nan(), "no number should be offered");
    }

    #[test]
    fn a_png_smaller_than_one_tile_is_refused_by_the_extractor_not_padded() {
        let router = first_element_router(1.0);
        let err = router.assess(&png(200, 200), "png").unwrap_err();
        assert!(matches!(err, MlError::TooSmall { .. }), "{err:?}");
    }

    /// Stand-in for the engine's DQT reader. Three behaviours, because all three
    /// are reachable in the field: a table, a malformed file with none, and a
    /// reader that failed.
    struct FakeTables(std::result::Result<Option<[u16; 64]>, &'static str>);

    impl QuantisationTables for FakeTables {
        fn luma_table(&self, _jpeg: &[u8]) -> Result<Option<[u16; 64]>> {
            match &self.0 {
                Ok(t) => Ok(*t),
                Err(e) => Err(MlError::Coefficients((*e).to_string())),
            }
        }
    }

    fn jpeg_router(domain: Domain) -> Router {
        let mut card = valid_card(domain);
        card.domain = domain;
        let model = Model::new(card, Box::new(FixedBackend { value: 0.0, domain })).expect("model");
        Router::new().with_jpeg(model).expect("install")
    }

    #[test]
    fn a_dequantised_model_without_a_table_source_says_exactly_what_is_missing() {
        // It must not fall back to quantised coefficients. That would be wrong
        // by a factor of the quantisation step at every coefficient and would
        // still produce a plausible looking number, which is the failure this
        // whole crate is shaped to prevent.
        let router = jpeg_router(Domain::JpegDctDequantised);
        let err = router
            .assess(include_bytes!("../tests/assets/cover-256.jpg"), "jpg")
            .unwrap_err();
        match err {
            MlError::Coefficients(d) => {
                assert!(d.contains("with_quantisation_tables"), "{d}");
            }
            other => panic!("expected Coefficients, got {other:?}"),
        }
    }

    #[test]
    fn a_quantised_model_needs_no_table_source() {
        let router = jpeg_router(Domain::JpegDctQuantised);
        let a = router
            .assess(include_bytes!("../tests/assets/cover-256.jpg"), "jpg")
            .expect("assess");
        assert_eq!(
            a.tiles_total, 1,
            "a 256px cover is exactly one 32 block tile"
        );
    }

    #[test]
    fn a_dequantised_model_with_a_table_source_scores() {
        let mut t = [0u16; 64];
        for (k, slot) in t.iter_mut().enumerate() {
            *slot = (k + 1) as u16;
        }
        let router = jpeg_router(Domain::JpegDctDequantised)
            .with_quantisation_tables(Box::new(FakeTables(Ok(Some(t)))));
        let a = router
            .assess(include_bytes!("../tests/assets/cover-256.jpg"), "jpg")
            .expect("assess");
        assert!(a.model.contains("dequantised"), "{}", a.model);
    }

    #[test]
    fn a_jpeg_with_no_defined_table_is_declined_rather_than_guessed_at() {
        let router = jpeg_router(Domain::JpegDctDequantised)
            .with_quantisation_tables(Box::new(FakeTables(Ok(None))));
        let err = router
            .assess(include_bytes!("../tests/assets/cover-256.jpg"), "jpg")
            .unwrap_err();
        match err {
            MlError::Coefficients(d) => {
                assert!(
                    d.contains("names a quantisation table the file never"),
                    "{d}"
                )
            }
            other => panic!("expected Coefficients, got {other:?}"),
        }
    }

    #[test]
    fn a_failing_table_reader_propagates_rather_than_degrading_silently() {
        let router = jpeg_router(Domain::JpegDctDequantised).with_quantisation_tables(Box::new(
            FakeTables(Err("dqt walk hit a truncated segment")),
        ));
        let err = router
            .assess(include_bytes!("../tests/assets/cover-256.jpg"), "jpg")
            .unwrap_err();
        assert!(err.to_string().contains("truncated segment"), "{err}");
    }

    #[test]
    fn probability_is_monotonic_and_bounded() {
        let c = Calibration { a: 1.0, b: 0.0 };
        let mut last = -1.0;
        for logit in [-50.0, -5.0, -1.0, 0.0, 1.0, 5.0, 50.0] {
            let p = probability(logit, &c);
            assert!((0.0..=1.0).contains(&p), "p={p} out of range at {logit}");
            assert!(p > last, "not monotonic at {logit}");
            last = p;
        }
        assert!((probability(0.0, &c) - 0.5).abs() < 1e-12);
    }

    #[test]
    fn probability_does_not_overflow_on_a_saturated_logit() {
        let c = Calibration { a: 1.0, b: 0.0 };
        assert!(probability(1e6, &c).is_finite());
        assert!(probability(-1e6, &c).is_finite());
        assert_eq!(probability(1e6, &c), 1.0);
        assert_eq!(probability(-1e6, &c), 0.0);
    }

    #[test]
    fn a_jpeg_is_never_scored_by_the_spatial_model() {
        // The whole point of the crate. With only a spatial model installed, a
        // JPEG must be refused, not quietly handed to it.
        let router = spatial_router(5.0);
        let err = router
            .assess(b"\xff\xd8\xff\xe0 not really", "jpg")
            .unwrap_err();
        match err {
            MlError::WeightsMissing { model } => assert_eq!(model, "jpeg-dct"),
            other => panic!("expected WeightsMissing for the jpeg slot, got {other:?}"),
        }
    }

    #[test]
    fn installing_a_spatial_artefact_in_the_jpeg_slot_is_refused() {
        let model = Model::new(
            valid_card(Domain::Spatial),
            Box::new(FixedBackend {
                value: 0.0,
                domain: Domain::Spatial,
            }),
        )
        .expect("model");
        let err = Router::new().with_jpeg(model).unwrap_err();
        assert!(
            matches!(err, MlError::RepresentationMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn an_unknown_container_is_refused_by_name() {
        let router = spatial_router(1.0);
        let err = router.assess(b"RIFF....WAVE", "wav").unwrap_err();
        match err {
            MlError::UnsupportedFormat(f) => assert_eq!(f, "wav"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn a_png_inside_the_envelope_is_scored_with_a_calibrated_probability() {
        let router = spatial_router(4.0);
        let a = router.assess(&png(256, 256), "png").expect("assess");
        match a.verdict {
            MlVerdict::Scored {
                probability: p,
                above_fpr_1pc_threshold,
            } => {
                assert!((0.0..=1.0).contains(&p));
                // Card's held-out threshold is 1.5 and the logit is 4.0.
                assert!(above_fpr_1pc_threshold, "4.0 should clear the 1.5 bar");
            }
            MlVerdict::Declined { reason } => panic!("unexpectedly declined: {reason}"),
        }
        assert!(
            a.model.contains("yedroudj-net"),
            "provenance missing: {}",
            a.model
        );
        assert_eq!(a.logit, 4.0);
    }

    #[test]
    fn a_logit_below_the_held_out_threshold_does_not_claim_the_operating_point() {
        let router = spatial_router(0.5);
        match router
            .assess(&png(256, 256), "png")
            .expect("assess")
            .verdict
        {
            MlVerdict::Scored {
                above_fpr_1pc_threshold,
                ..
            } => assert!(!above_fpr_1pc_threshold, "0.5 must not clear the 1.5 bar"),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn an_out_of_envelope_cover_is_declined_rather_than_scored() {
        // The honest output for an input unlike the training distribution.
        let mut card = valid_card(Domain::Spatial);
        card.envelope.variance_range = (100.0, 200.0);
        let model = Model::new(
            card,
            Box::new(FixedBackend {
                value: 99.0,
                domain: Domain::Spatial,
            }),
        )
        .expect("model");
        let router = Router::new().with_spatial(model).expect("install");
        match router
            .assess(&png(256, 256), "png")
            .expect("assess")
            .verdict
        {
            MlVerdict::Declined { reason } => {
                assert!(reason.contains("trained on"), "unhelpful reason: {reason}");
            }
            MlVerdict::Scored { probability, .. } => {
                panic!("scored {probability} on an out-of-envelope cover")
            }
        }
    }

    #[test]
    fn an_empty_router_refuses_everything_it_is_asked() {
        let router = Router::new();
        assert!(router.assess(&png(256, 256), "png").is_err());
        assert!(router.assess(b"\xff\xd8", "jpg").is_err());
    }

    #[test]
    fn assess_representation_routes_on_the_tensors_own_domain() {
        let router = spatial_router(2.0);
        let r = SpatialExtractor.extract(&png(256, 256)).expect("extract");
        let a = router.assess_representation(&r).expect("assess");
        assert_eq!(a.logit, 2.0);
    }
}
