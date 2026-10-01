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

//! The model, its backend, and the card that makes an artefact self-describing.
//!
//! # Why the card exists
//!
//! A bare `.onnx` file is a graph and nothing else. It does not say which domain
//! it was trained on, which cover sources it saw, what its false-positive rate
//! was, or how to turn its output logit into a probability anybody should act
//! on. Shipping weights without that is how a detector ends up reporting a
//! confident number outside the envelope it was validated in, which is the
//! failure mode the whole release theme is against.
//!
//! So every artefact ships a [`ModelCard`] beside it, and this crate **refuses
//! to run a graph whose card it cannot read**. The card is not documentation; it
//! is load-bearing configuration, and it is what makes
//! [`crate::calibration`]'s probability and the out-of-distribution check
//! possible at all.

use crate::error::{MlError, Result};
use crate::representation::{Domain, Representation, TensorStats};

/// Which published architecture an artefact implements.
///
/// Not an open string: the two are implemented, trained and validated here, and
/// a third would arrive with its own card schema review rather than by someone
/// typing a new name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Architecture {
    /// Yedroudj-Net. Small (roughly 500k parameters), fixed SRM high-pass first
    /// layer, five convolutional blocks. Cheap to train and cheap to run, and
    /// the right first model because it establishes the pipeline end to end at
    /// a fraction of SRNet's cost.
    YedroudjNet,
    /// SRNet. Deeper residual network, roughly 4.8M parameters, no fixed front
    /// end: it learns its own residual. Stronger and markedly more expensive,
    /// and the literature trains it by curriculum rather than from random
    /// initialisation (see `private/ml/README.md`).
    SrNet,
}

impl Architecture {
    /// Stable lowercase identifier, used in card JSON and artefact names.
    pub fn name(self) -> &'static str {
        match self {
            Architecture::YedroudjNet => "yedroudj-net",
            Architecture::SrNet => "srnet",
        }
    }
}

/// The validated envelope: what this artefact was trained and measured on.
///
/// Every field is here because its absence has cost this project or a vendor it
/// reviewed a wrong answer.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Envelope {
    /// Cover sources in the training set, named. Plural is enforced by
    /// [`ModelCard::validate`]: a single-source model is the mistake that leaked
    /// about 22% false positives when thresholds fitted to Cassavia plus
    /// BOSSbase met ALASKA2's JPEG-decompressed covers.
    pub trained_on: Vec<String>,
    /// Cover sources held out entirely. Also required to be non-empty: a model
    /// with nothing held out has no generalisation measurement, only a fit.
    pub held_out: Vec<String>,
    /// Embedders and payload rates the artefact was measured against, so a
    /// caller can see what it cannot speak to.
    pub embedders: Vec<String>,
    /// Payload rates in bits per pixel (spatial) or bits per non-zero AC
    /// coefficient (JPEG).
    pub payload_rates: Vec<f64>,
    /// Accepted range of [`TensorStats::variance`] for an in-distribution
    /// input, measured over the training covers. Outside it, the honest answer
    /// is "unlike anything I was trained on".
    pub variance_range: (f64, f64),
    /// Accepted range of [`TensorStats::zero_fraction`]. On quantised DCT this
    /// is effectively a JPEG-quality gate, which is exactly the axis the domain
    /// shift runs along.
    pub zero_fraction_range: (f64, f64),
}

/// Measured operating points. Deliberately not accuracy and not AUC alone.
///
/// A pooled AUC on a mixed corpus is the number that lies: it can be high while
/// the model is at chance on one source and excellent on another. So results are
/// carried **per source**, and the headline figures are true-positive rates at
/// fixed false-positive rates, because that is the number an operator acting on
/// a single file needs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OperatingPoints {
    /// Per cover source. Key is the source name as it appears in
    /// [`Envelope::trained_on`] or [`Envelope::held_out`].
    pub per_source: Vec<SourceResult>,
}

/// One cover source's measured result.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SourceResult {
    /// Name of the cover source these numbers were measured on.
    pub source: String,
    /// Whether this source was held out of training.
    pub held_out: bool,
    /// Logit threshold achieving a 1% false-positive rate on this source's
    /// covers, and the true-positive rate there.
    pub threshold_at_fpr_1pc: f64,
    /// True-positive rate at that threshold.
    pub tpr_at_fpr_1pc: f64,
    /// The same at 0.1%, which is the regime a forensic examiner works in.
    pub threshold_at_fpr_0p1pc: f64,
    /// True-positive rate at that threshold.
    pub tpr_at_fpr_0p1pc: f64,
    /// Carried for completeness and explicitly not used as the headline.
    pub auc: f64,
    /// The null arm: covers pushed through the identical pipeline with a zero
    /// payload. If this separates from the clean arm the pipeline has a
    /// confound and every other number in this struct is void, so it is
    /// recorded next to them rather than in a separate report nobody reads.
    pub null_arm_auc: f64,
}

/// Parameters that turn a raw logit into a probability somebody can act on.
///
/// Platt scaling, fitted on a held-out calibration split. A bare softmax output
/// from a network trained on a balanced set is not a probability on a realistic
/// prior, and reporting it as one is the mistake the project's own DFRWS
/// submission is about: 21 of 21 detector/payload cells returned a
/// log-likelihood-ratio cost above 1.0, meaning an examiner acting on them was
/// worse off than reporting nothing.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Calibration {
    /// Slope. Negative values are legitimate; validation only rejects zero,
    /// which would collapse every input to one probability.
    pub a: f64,
    /// Intercept.
    pub b: f64,
}

/// Everything about an artefact that is not the graph.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ModelCard {
    /// Card schema version, so a future field addition is a migration rather
    /// than a silent misparse.
    pub card_version: u32,
    /// Which network this artefact holds.
    pub architecture: Architecture,
    /// Which representation the graph's input layer expects. Compared against
    /// the extractor's domain on every inference.
    pub domain: Domain,
    /// Side length of the crop the model was trained on.
    pub input_side: u32,
    /// Hex SHA-256 of the `.onnx` file this card describes.
    pub weights_sha256: String,
    /// What the model saw in training and what it was held out against.
    pub envelope: Envelope,
    /// The measured thresholds and true-positive rates, per source.
    pub operating_points: OperatingPoints,
    /// Platt parameters turning a logit into a probability.
    pub calibration: Calibration,
}

impl ModelCard {
    /// Parse and validate. The validation is the point: a card that parses but
    /// claims a single training source, or no held-out source, describes a model
    /// whose numbers this project has already learned not to trust.
    pub fn from_json(s: &str) -> Result<Self> {
        let card: ModelCard = serde_json::from_str(s).map_err(|e| MlError::CardInvalid {
            model: "unknown".to_string(),
            detail: e.to_string(),
        })?;
        card.validate()?;
        Ok(card)
    }

    /// Invariants a usable card must satisfy.
    pub fn validate(&self) -> Result<()> {
        let bad = |d: String| MlError::CardInvalid {
            model: self.architecture.name().to_string(),
            detail: d,
        };
        if self.card_version != 1 {
            return Err(bad(format!(
                "card_version {} is not supported by this build",
                self.card_version
            )));
        }
        if self.envelope.trained_on.len() < 2 {
            return Err(bad(
                "fewer than two training cover sources; single-source calibration is forbidden \
                 (it leaked about 22% false positives on a second source once already)"
                    .to_string(),
            ));
        }
        if self.envelope.held_out.is_empty() {
            return Err(bad(
                "no held-out cover source, so the card reports a fit rather than a \
                 generalisation measurement"
                    .to_string(),
            ));
        }
        if self.operating_points.per_source.is_empty() {
            return Err(bad(
                "no per-source results; a pooled number is not accepted".to_string(),
            ));
        }
        if !self.operating_points.per_source.iter().any(|r| r.held_out) {
            return Err(bad(
                "no result on a held-out source, so nothing here measures transfer".to_string(),
            ));
        }
        if self.calibration.a == 0.0 {
            return Err(bad(
                "calibration slope is zero, which maps every input to one probability".to_string(),
            ));
        }
        if self.weights_sha256.len() != 64
            || !self.weights_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(bad(
                "weights_sha256 is not a 64 character hex digest".to_string()
            ));
        }
        if self.input_side < crate::representation::limits::MIN_SIDE {
            return Err(bad(format!(
                "input_side {} is below this crate's {} minimum",
                self.input_side,
                crate::representation::limits::MIN_SIDE
            )));
        }
        Ok(())
    }

    /// Is this tensor inside the envelope the artefact was validated in?
    ///
    /// Returns the reason when it is not, because "out of distribution" without
    /// a reason is not actionable.
    pub fn envelope_check(&self, stats: &TensorStats) -> EnvelopeVerdict {
        let (vlo, vhi) = self.envelope.variance_range;
        if stats.variance < vlo || stats.variance > vhi {
            return EnvelopeVerdict::Outside {
                reason: format!(
                    "cover texture (variance {:.5}) is outside the {:.5} to {:.5} range this \
                     model was trained on",
                    stats.variance, vlo, vhi
                ),
            };
        }
        let (zlo, zhi) = self.envelope.zero_fraction_range;
        if stats.zero_fraction < zlo || stats.zero_fraction > zhi {
            return EnvelopeVerdict::Outside {
                reason: format!(
                    "coefficient sparsity ({:.3} zero) is outside the {:.3} to {:.3} range this \
                     model was trained on, which usually means a different JPEG quality",
                    stats.zero_fraction, zlo, zhi
                ),
            };
        }
        EnvelopeVerdict::Inside
    }
}

/// Result of the out-of-distribution check.
#[derive(Debug, Clone, PartialEq)]
pub enum EnvelopeVerdict {
    /// The cover's statistics fall within the trained envelope.
    Inside,
    /// The cover is unlike anything the model was trained on.
    Outside {
        /// Which statistic fell outside which range, in plain language.
        reason: String,
    },
}

/// A loaded inference graph.
///
/// The trait exists so the backend is swappable, which the project's scale rules
/// require of anything between logic and an external runtime. Implementations
/// must be `Send + Sync`: the CLI batches files across rayon and the GUI calls
/// from a Tauri worker.
pub trait Backend: Send + Sync {
    /// Run the graph on one tensor and return the raw logit for the "carries a
    /// payload" class. One number, not a distribution, because every caller
    /// wants the scalar and a two-element softmax is the backend's business.
    fn logit(&self, input: &Representation) -> Result<f64>;

    /// Which domain the loaded graph's input layer accepts, read from the graph
    /// itself where the backend can, so a card that lies is caught.
    fn graph_domain(&self) -> Domain;

    /// For diagnostics.
    fn backend_name(&self) -> &'static str;
}

/// A model: a card, and a backend that satisfies it.
///
/// Construction is where the card and the graph are reconciled, so by the time a
/// `Model` exists the mismatch class is gone.
pub struct Model {
    card: ModelCard,
    backend: Box<dyn Backend>,
}

// Hand written because `dyn Backend` cannot derive it. The backend's name and
// the card's architecture are the two things worth seeing in a failure message,
// and a dump of the weights would not be.
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Model")
            .field("architecture", &self.card.architecture)
            .field("domain", &self.card.domain)
            .field("backend", &self.backend.backend_name())
            .finish()
    }
}

impl Model {
    /// Pair a card with a backend, refusing the pairing if they disagree.
    pub fn new(card: ModelCard, backend: Box<dyn Backend>) -> Result<Self> {
        if backend.graph_domain() != card.domain {
            return Err(MlError::RepresentationMismatch {
                expected: card.domain.name(),
                actual: backend.graph_domain().name(),
            });
        }
        card.validate()?;
        Ok(Self { card, backend })
    }

    /// The validated card this model was built from.
    pub fn card(&self) -> &ModelCard {
        &self.card
    }

    /// Which inference backend is executing the graph.
    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }

    /// Score one representation.
    ///
    /// Refuses a domain mismatch rather than running the graph on the wrong
    /// numbers, which is the single most important line in this crate: a JPEG
    /// tensor handed to a spatial model would otherwise produce a confident
    /// figure that means nothing.
    pub fn score(&self, input: &Representation) -> Result<RawScore> {
        if input.domain() != self.card.domain {
            return Err(MlError::RepresentationMismatch {
                expected: self.card.domain.name(),
                actual: input.domain().name(),
            });
        }
        let stats = input.statistics();
        let logit = self.backend.logit(input)?;
        Ok(RawScore {
            logit,
            stats,
            envelope: self.card.envelope_check(&stats),
        })
    }
}

/// What the graph said, plus whether it was entitled to say it.
#[derive(Debug, Clone, PartialEq)]
pub struct RawScore {
    /// The graph's raw output, before calibration.
    pub logit: f64,
    /// Statistics of the tensor that was scored, which the envelope check used.
    pub stats: TensorStats,
    /// Whether this cover was inside the trained envelope.
    pub envelope: EnvelopeVerdict,
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A backend that returns a fixed logit. Lets every trait boundary in this
    /// crate be tested without a model runtime, which is why `backend-tract` is
    /// off by default.
    pub struct FixedBackend {
        pub value: f64,
        pub domain: Domain,
    }

    impl Backend for FixedBackend {
        fn logit(&self, _input: &Representation) -> Result<f64> {
            Ok(self.value)
        }
        fn graph_domain(&self) -> Domain {
            self.domain
        }
        fn backend_name(&self) -> &'static str {
            "fixed-test"
        }
    }

    /// A backend whose logit is the tile's first element, scaled. Lets the
    /// maximum-over-tiles rule be tested: a fixed backend cannot distinguish
    /// "took the maximum" from "took the first".
    pub struct FirstElementBackend {
        pub scale: f64,
        pub domain: Domain,
    }

    impl Backend for FirstElementBackend {
        fn logit(&self, input: &Representation) -> Result<f64> {
            Ok(input.data().first().copied().unwrap_or(0.0) as f64 * self.scale)
        }
        fn graph_domain(&self) -> Domain {
            self.domain
        }
        fn backend_name(&self) -> &'static str {
            "first-element-test"
        }
    }

    pub fn valid_card(domain: Domain) -> ModelCard {
        ModelCard {
            card_version: 1,
            architecture: Architecture::YedroudjNet,
            domain,
            input_side: 256,
            weights_sha256: "a".repeat(64),
            envelope: Envelope {
                trained_on: vec!["bossbase".into(), "pentimento".into()],
                held_out: vec!["reveal".into()],
                embedders: vec!["lsb-replacement".into()],
                payload_rates: vec![0.4, 0.2, 0.1],
                variance_range: (0.0001, 1.0),
                zero_fraction_range: (0.0, 0.99),
            },
            operating_points: OperatingPoints {
                per_source: vec![SourceResult {
                    source: "reveal".into(),
                    held_out: true,
                    threshold_at_fpr_1pc: 1.5,
                    tpr_at_fpr_1pc: 0.82,
                    threshold_at_fpr_0p1pc: 2.9,
                    tpr_at_fpr_0p1pc: 0.55,
                    auc: 0.96,
                    null_arm_auc: 0.501,
                }],
            },
            calibration: Calibration { a: 1.2, b: -0.3 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use crate::representation::FeatureExtractor;

    #[test]
    fn a_card_naming_one_training_source_is_refused() {
        let mut card = valid_card(Domain::Spatial);
        card.envelope.trained_on = vec!["bossbase".into()];
        let err = card.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("single-source"), "unhelpful message: {msg}");
    }

    #[test]
    fn a_card_with_nothing_held_out_is_refused() {
        let mut card = valid_card(Domain::Spatial);
        card.envelope.held_out.clear();
        assert!(card.validate().is_err());
    }

    #[test]
    fn a_card_with_no_held_out_result_is_refused() {
        let mut card = valid_card(Domain::Spatial);
        card.operating_points.per_source[0].held_out = false;
        let err = card.validate().unwrap_err();
        assert!(err.to_string().contains("transfer"), "{err}");
    }

    #[test]
    fn a_zero_calibration_slope_is_refused() {
        let mut card = valid_card(Domain::Spatial);
        card.calibration.a = 0.0;
        assert!(card.validate().is_err());
    }

    #[test]
    fn a_short_digest_is_refused() {
        let mut card = valid_card(Domain::Spatial);
        card.weights_sha256 = "abc".into();
        assert!(card.validate().is_err());
    }

    #[test]
    fn a_card_round_trips_through_json() {
        let card = valid_card(Domain::JpegDctQuantised);
        let json = serde_json::to_string(&card).expect("serialise");
        let back = ModelCard::from_json(&json).expect("parse");
        assert_eq!(card, back);
    }

    #[test]
    fn pairing_a_card_with_a_backend_in_another_domain_is_refused() {
        // The mismatch that would otherwise score a JPEG with a spatial graph.
        let card = valid_card(Domain::JpegDctQuantised);
        let backend = Box::new(FixedBackend {
            value: 0.0,
            domain: Domain::Spatial,
        });
        let err = Model::new(card, backend).unwrap_err();
        assert!(
            matches!(err, MlError::RepresentationMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn scoring_a_tensor_from_the_wrong_domain_is_refused() {
        let card = valid_card(Domain::JpegDctQuantised);
        let model = Model::new(
            card,
            Box::new(FixedBackend {
                value: 3.0,
                domain: Domain::JpegDctQuantised,
            }),
        )
        .expect("model");
        // A spatial tensor, which is what a careless router would hand over.
        let spatial = crate::representation::SpatialExtractor
            .extract(&crate::test_support::png(256, 256))
            .expect("extract");
        let err = model.score(&spatial).unwrap_err();
        assert!(
            matches!(err, MlError::RepresentationMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn envelope_check_names_the_axis_that_failed() {
        let mut card = valid_card(Domain::Spatial);
        card.envelope.variance_range = (10.0, 20.0);
        let stats = TensorStats {
            mean: 0.0,
            variance: 0.001,
            zero_fraction: 0.1,
            min: -0.5,
            max: 0.5,
        };
        match card.envelope_check(&stats) {
            EnvelopeVerdict::Outside { reason } => {
                assert!(
                    reason.contains("texture"),
                    "reason should name the axis: {reason}"
                );
            }
            EnvelopeVerdict::Inside => panic!("should be outside"),
        }
    }

    #[test]
    fn envelope_check_accepts_an_input_inside_both_ranges() {
        let card = valid_card(Domain::Spatial);
        let stats = TensorStats {
            mean: 0.0,
            variance: 0.01,
            zero_fraction: 0.2,
            min: -0.5,
            max: 0.5,
        };
        assert_eq!(card.envelope_check(&stats), EnvelopeVerdict::Inside);
    }
}
