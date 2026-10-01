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

//! Grading a wild corpus: detector scores in, per-family detection rates out.
//!
//! # The shape of the thing
//!
//! ```text
//!   manifest (ids, labels, families)
//!         │
//!         ▼
//!   ┌───────────────┐   bytes    ┌──────────┐   score   ┌──────────────┐
//!   │ SampleSource  │ ─────────▶ │ Detector │ ────────▶ │   grading    │
//!   │  (EMPTY seam) │            │  (seam)  │           │ per family   │
//!   └───────────────┘            └──────────┘           └──────────────┘
//! ```
//!
//! Everything in the right-hand box is built and tested here against synthetic
//! fixtures. Neither seam is implemented anywhere in this tree, and
//! `mod.rs` explains why at length: the implementations end in handing real
//! malware to a parser, which happens on the isolated machine or nowhere.
//!
//! # Why the numbers are shaped the way they are
//!
//! Three deliberate refusals, each of which is a way wild-corpus results get
//! reported badly.
//!
//! **No accuracy, anywhere.** There is no `accuracy` field and there will not
//! be one. Accuracy over an unbalanced corpus measures the balance, not the
//! detector: a corpus of 90 stego samples and 10 clean ones hands 90% to a
//! detector that says "stego" to everything. A wild corpus is always
//! unbalanced, because clean files are the boring half nobody collects.
//!
//! **A true-positive rate is only meaningful beside a false-positive rate.**
//! So the threshold is not a constant from the calibration profile; it is
//! derived here from this corpus's own clean arm at the target false-positive
//! rate, and both the achieved rate and the number of clean samples it rests on
//! are in the report. A TPR quoted without its FPR is a number that can be set
//! to anything.
//!
//! **Per family, never pooled.** One pooled rate over Worok plus SteamHide plus
//! a MalwareBazaar grab bag is an average over populations with different
//! embedding tools, payload sizes and carrier formats, weighted by how many of
//! each happened to be obtainable. It is not an estimate of anything. Families
//! are reported separately, each with its sample count and a 95% Wilson
//! interval, so a rate resting on four samples cannot be read as a rate.
//!
//! # What the harness does with failure
//!
//! A sample that will not load, or a detector that errors on it, is recorded in
//! [`Grading::errored`] with its family and the reason, and excluded from both
//! arms. It is not silently dropped: dropping the samples a detector choked on
//! inflates the rate of the detector that choked, which is precisely backwards.
//! A run with errors is still a run, and the report says how many.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::errors::StegError;
use crate::repro::real::Real;
use crate::wild::manifest::{Payload, WildManifest};

/// Default target false-positive rate for a grading run.
///
/// One in a hundred clean files raising an alarm. The engine's own calibration
/// profile sits at roughly four per hundred combined across three detectors
/// (see `private/calibration/`), so 1% is a deliberately stricter operating
/// point for a single detector on wild data, where a false positive costs an
/// examiner's afternoon.
pub const DEFAULT_TARGET_FPR: f64 = 0.01;

/// Samples a family needs before its rate is reported without a caveat.
///
/// Twenty. At twenty samples a 95% Wilson interval on a measured 100% still
/// runs down to roughly 83%, which is the honest width; below twenty the
/// interval is wider than the range anybody would act on, and the number is
/// decoration. Families under this are still reported, flagged.
pub const MIN_FAMILY_SUPPORT: usize = 20;

/// Largest sample the harness will ask a source for, by default.
///
/// A cap belongs in the contract rather than in the source's judgement, so
/// [`SampleSource::load`] takes it as an argument and a source that cannot
/// honour it must refuse.
pub const DEFAULT_MAX_SAMPLE_BYTES: u64 = 256 * 1024 * 1024;

/// Where sample bytes come from.
///
/// **Nothing in this tree implements this trait, on purpose.** The one
/// implementation that matters reads files on an isolated machine, and it is
/// written there, by whoever provisions it, against
/// `private/plans/wild-sample-isolation.md`. A fetching implementation is
/// explicitly out of scope: a fetch function that exists will eventually be
/// called, and this machine is the one place it must never be called from.
pub trait SampleSource {
    /// Manifest ids this source can supply, in any order.
    fn ids(&self) -> Vec<String>;

    /// The bytes of one sample, refusing anything larger than `max_bytes`.
    ///
    /// The cap is an argument rather than a property of the source so that the
    /// resource bound is the harness's to set and the source's to honour. A
    /// source that cannot tell the size in advance must still refuse once it
    /// has read past the cap, and must not return a truncated buffer, because
    /// a truncated sample scores like a different file.
    fn load(&self, id: &str, max_bytes: u64) -> Result<Vec<u8>, StegError>;
}

/// Something that scores one sample for hidden content.
///
/// Higher means more suspicious. The scale is the detector's own; the harness
/// only ever compares scores from the same detector against each other, which
/// is what lets Aletheia be a second implementation of this trait rather than a
/// second harness. That is the cross-validation D2 asks for.
pub trait Detector {
    /// Short, stable name for the report. Lowercase, no version.
    fn name(&self) -> &str;

    /// Score one sample's bytes.
    fn score(&self, bytes: &[u8]) -> Result<Real, StegError>;
}

/// Progress out of a long grading run.
///
/// A corpus of several thousand samples at Argon2id-and-decode speeds is a long
/// silent wait, and baseline Section 2 wants a heartbeat out of any long loop.
/// The harness reads no clock, so the observer owns the interval and the report
/// stays reproducible.
pub trait GradeObserver {
    /// Called once per labelled sample, before it is loaded.
    fn sample_started(&mut self, _done: usize, _total: usize, _id: &str) {}

    /// Called once when every sample has been attempted.
    fn finished(&mut self, _total: usize) {}
}

/// An observer that says nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Silent;

impl GradeObserver for Silent {}

/// How a grading run is to be conducted.
#[derive(Debug, Clone, PartialEq)]
pub struct GradeSettings {
    /// The false-positive rate the threshold is set to hold on this corpus's
    /// clean arm.
    pub target_fpr: f64,
    /// Largest sample to ask the source for.
    pub max_sample_bytes: u64,
    /// Did the caller check the sample set against the manifest with
    /// [`crate::wild::verify`] before this run?
    ///
    /// The harness cannot find this out for itself: it sees bytes from a source
    /// and a label from a manifest, and it has no way to know the two belong
    /// together. So the caller states it, and an unverified run is labelled as
    /// one in the report rather than quietly producing numbers about files
    /// nobody confirmed were the right files.
    pub integrity_verified: bool,
}

impl Default for GradeSettings {
    fn default() -> Self {
        Self {
            target_fpr: DEFAULT_TARGET_FPR,
            max_sample_bytes: DEFAULT_MAX_SAMPLE_BYTES,
            integrity_verified: false,
        }
    }
}

impl GradeSettings {
    fn validate(&self) -> Result<(), StegError> {
        if !self.target_fpr.is_finite() || self.target_fpr < 0.0 || self.target_fpr >= 1.0 {
            return Err(StegError::Internal(format!(
                "a target false-positive rate of {} is not a rate in [0, 1); grading needs \
                 an operating point it can actually set a threshold for",
                self.target_fpr
            )));
        }
        if self.max_sample_bytes == 0 {
            return Err(StegError::Internal(
                "a maximum sample size of zero bytes would refuse every sample".to_string(),
            ));
        }
        Ok(())
    }
}

/// Which half of the run a sample fell over in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The source would not supply the bytes.
    Load,
    /// The detector would not score them.
    Score,
}

/// A sample that could not be graded, kept in the report rather than dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradeError {
    /// Manifest id.
    pub id: String,
    /// Family, so errors concentrated in one family are visible as such.
    pub family: String,
    /// Where it fell over.
    pub stage: Stage,
    /// The reason, as the error reported it.
    pub reason: String,
}

/// The threshold the run used, or why it has none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum Threshold {
    /// Derived from this corpus's clean arm.
    Set {
        /// A sample counts as detected when its score is strictly greater than
        /// this.
        at: Real,
        /// Clean samples the threshold was derived from.
        from_clean: usize,
        /// False positives the target rate allowed on that arm, which is
        /// `floor(target_fpr * from_clean)`.
        allowed_false_positives: usize,
    },
    /// No clean samples were graded, so there is no operating point and no
    /// true-positive rate is reported.
    ///
    /// This is a refusal, not a zero. A corpus with no clean arm cannot
    /// measure a detector at all, and the usual cause is a wild corpus
    /// collected entirely from malware repositories, where every file is there
    /// because it is malicious.
    NoCleanArm,
}

/// A measured rate with the sample count it rests on and its interval.
///
/// The interval is a 95% Wilson score interval, which is the one that behaves
/// at the edges: a measured 20 out of 20 has a normal-approximation interval of
/// exactly zero width, which is nonsense, and a Wilson interval of roughly
/// 0.83 to 1.00, which is the truth.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rate {
    /// Samples in this group.
    pub samples: usize,
    /// How many of them landed above the threshold.
    pub hits: usize,
    /// `hits / samples`.
    pub rate: Real,
    /// Lower bound of the 95% Wilson interval.
    pub ci95_low: Real,
    /// Upper bound of the 95% Wilson interval.
    pub ci95_high: Real,
    /// Whether the group reaches [`MIN_FAMILY_SUPPORT`]. A group that does not
    /// is still reported, because hiding it would hide the family, but the flag
    /// is there so a reader does not quote a rate off six samples.
    pub sufficient_support: bool,
}

impl Rate {
    fn new(samples: usize, hits: usize) -> Result<Self, StegError> {
        if samples == 0 {
            return Err(StegError::Internal(
                "a rate over zero samples was asked for, which is a bug in the caller: an \
                 empty group should not reach the report at all"
                    .to_string(),
            ));
        }
        let n = samples as f64;
        let p = hits as f64 / n;
        // 1.959964 is the two-sided 95% normal quantile.
        const Z: f64 = 1.959_964;
        let denom = 1.0 + Z * Z / n;
        let centre = (p + Z * Z / (2.0 * n)) / denom;
        let half = (Z / denom) * (p * (1.0 - p) / n + Z * Z / (4.0 * n * n)).sqrt();
        Ok(Self {
            samples,
            hits,
            rate: Real::new(p)?,
            ci95_low: Real::new((centre - half).max(0.0))?,
            ci95_high: Real::new((centre + half).min(1.0))?,
            sufficient_support: samples >= MIN_FAMILY_SUPPORT,
        })
    }
}

/// The result of grading one corpus with one detector.
///
/// Every collection is ordered, so two runs over the same inputs produce the
/// same report bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grading {
    /// Corpus name from the manifest.
    pub corpus: String,
    /// Detector name.
    pub detector: String,
    /// The operating point asked for.
    pub target_fpr: Real,
    /// The threshold that was derived, or the refusal.
    pub threshold: Threshold,
    /// The false-positive rate actually achieved on the clean arm, which is at
    /// or below the target and is reported rather than assumed. `None` when
    /// there was no clean arm.
    pub achieved_fpr: Option<Rate>,
    /// Whether the clean arm is large enough for the target rate to mean
    /// anything.
    ///
    /// `false` when `clean_samples * target_fpr < 1`, which is the case where
    /// the achieved rate is zero by arithmetic rather than by merit: you cannot
    /// measure one false positive in a hundred with fifty clean files.
    pub clean_support_sufficient: bool,
    /// True-positive rate per family, over the samples labelled as carrying.
    pub stego_families: BTreeMap<String, Rate>,
    /// False-positive rate per family, over the samples labelled clean. Per
    /// family here too, because a clean arm drawn from one source and a clean
    /// arm drawn from four behave differently and the pooled rate hides it.
    pub clean_families: BTreeMap<String, Rate>,
    /// Ids the manifest labels but the source does not have.
    pub missing_from_source: Vec<String>,
    /// Ids skipped because their ground truth is unknown.
    pub skipped_unlabelled: Vec<String>,
    /// Samples that could not be graded.
    pub errored: Vec<GradeError>,
    /// Whether the sample set was checked against the manifest first.
    pub integrity_verified: bool,
}

impl Grading {
    /// One paragraph a person can read, leading with whatever would make the
    /// numbers wrong.
    pub fn human_summary(&self) -> String {
        let mut lines = Vec::new();

        if !self.integrity_verified {
            lines.push(
                "Caution: the sample set was not checked against the manifest before this \
                 run, so these numbers are attached to files nobody confirmed."
                    .to_string(),
            );
        }
        match &self.threshold {
            Threshold::NoCleanArm => {
                lines.push(format!(
                    "Corpus {} with detector {}: no clean samples, so no threshold and no \
                     detection rate. A corpus of nothing but malware cannot measure a \
                     detector.",
                    self.corpus, self.detector
                ));
                return lines.join(" ");
            }
            Threshold::Set { at, from_clean, .. } => {
                let achieved = self
                    .achieved_fpr
                    .as_ref()
                    .map(|r| format!("{:.3}", r.rate.get()))
                    .unwrap_or_else(|| "unknown".to_string());
                lines.push(format!(
                    "Corpus {} with detector {}: threshold {} set on {} clean samples for a \
                     target false-positive rate of {:.3}, achieved {}.",
                    self.corpus,
                    self.detector,
                    at,
                    from_clean,
                    self.target_fpr.get(),
                    achieved
                ));
            }
        }
        if !self.clean_support_sufficient {
            lines.push(
                "The clean arm is too small for that target: at this size the achieved rate \
                 is zero by arithmetic rather than by merit."
                    .to_string(),
            );
        }
        for (family, rate) in &self.stego_families {
            lines.push(format!(
                "{}: {:.1}% of {} detected ({:.1}% to {:.1}%){}.",
                family,
                rate.rate.get() * 100.0,
                rate.samples,
                rate.ci95_low.get() * 100.0,
                rate.ci95_high.get() * 100.0,
                if rate.sufficient_support {
                    ""
                } else {
                    ", too few samples to quote"
                }
            ));
        }
        if !self.errored.is_empty() {
            lines.push(format!(
                "{} samples could not be graded and are in neither arm.",
                self.errored.len()
            ));
        }
        if !self.missing_from_source.is_empty() {
            lines.push(format!(
                "{} labelled samples are in the manifest and not in the sample set.",
                self.missing_from_source.len()
            ));
        }
        lines.join(" ")
    }
}

/// Grade a corpus: score every labelled sample, set the threshold on the clean
/// arm, report per-family rates.
///
/// Reads no clock, holds one sample in memory at a time, and never aborts the
/// run for a single bad sample. Returns an error only for the things that make
/// the whole run meaningless: unusable settings, or a manifest that does not
/// validate.
pub fn grade(
    manifest: &WildManifest,
    source: &dyn SampleSource,
    detector: &dyn Detector,
    settings: &GradeSettings,
    observer: &mut dyn GradeObserver,
) -> Result<Grading, StegError> {
    settings.validate()?;
    manifest.validate()?;

    let mut available = source.ids();
    available.sort();

    let labelled = manifest.labelled();
    let total = labelled.len();

    let mut clean_scores: Vec<f64> = Vec::new();
    // (family, score) for the carrying arm, and the same for the clean arm, so
    // the per-family split happens once the threshold is known.
    let mut stego_scored: Vec<(String, f64)> = Vec::new();
    let mut clean_scored: Vec<(String, f64)> = Vec::new();
    let mut errored: Vec<GradeError> = Vec::new();
    let mut missing: Vec<String> = Vec::new();

    for (index, sample) in labelled.iter().enumerate() {
        observer.sample_started(index, total, &sample.id);

        if available.binary_search(&sample.id).is_err() {
            missing.push(sample.id.clone());
            continue;
        }

        let bytes = match source.load(&sample.id, settings.max_sample_bytes) {
            Ok(bytes) => bytes,
            Err(e) => {
                errored.push(GradeError {
                    id: sample.id.clone(),
                    family: sample.family.clone(),
                    stage: Stage::Load,
                    reason: e.to_string(),
                });
                continue;
            }
        };
        let score = match detector.score(&bytes) {
            Ok(score) => score.get(),
            Err(e) => {
                errored.push(GradeError {
                    id: sample.id.clone(),
                    family: sample.family.clone(),
                    stage: Stage::Score,
                    reason: e.to_string(),
                });
                continue;
            }
        };

        match sample.payload {
            Payload::Carries => stego_scored.push((sample.family.clone(), score)),
            Payload::Clean => {
                clean_scores.push(score);
                clean_scored.push((sample.family.clone(), score));
            }
            // `labelled` filtered these out already; matching exhaustively
            // rather than with a catch-all so adding a fourth state is a
            // compile error here and not a silent reclassification.
            Payload::Unknown => {}
        }
    }
    observer.finished(total);

    let skipped_unlabelled = {
        let mut ids: Vec<String> = manifest
            .samples
            .iter()
            .filter(|s| s.payload == Payload::Unknown)
            .map(|s| s.id.clone())
            .collect();
        ids.sort();
        ids
    };

    let target = Real::new(settings.target_fpr)?;
    let mut grading = Grading {
        corpus: manifest.corpus.clone(),
        detector: detector.name().to_string(),
        target_fpr: target,
        threshold: Threshold::NoCleanArm,
        achieved_fpr: None,
        clean_support_sufficient: false,
        stego_families: BTreeMap::new(),
        clean_families: BTreeMap::new(),
        missing_from_source: missing,
        skipped_unlabelled,
        errored,
        integrity_verified: settings.integrity_verified,
    };
    grading.missing_from_source.sort();
    grading.errored.sort_by(|a, b| a.id.cmp(&b.id));

    if clean_scores.is_empty() {
        return Ok(grading);
    }

    let (cut, allowed) = threshold_from_clean_arm(&mut clean_scores, settings.target_fpr);
    grading.threshold = Threshold::Set {
        at: Real::new(cut)?,
        from_clean: clean_scores.len(),
        allowed_false_positives: allowed,
    };
    grading.clean_support_sufficient = clean_scores.len() as f64 * settings.target_fpr >= 1.0;

    let clean_hits = clean_scores.iter().filter(|s| **s > cut).count();
    grading.achieved_fpr = Some(Rate::new(clean_scores.len(), clean_hits)?);
    grading.stego_families = per_family(&stego_scored, cut)?;
    grading.clean_families = per_family(&clean_scored, cut)?;
    Ok(grading)
}

/// The score a sample has to beat, for at most `floor(target * n)` of the clean
/// arm to beat it.
///
/// Sorts the clean scores in descending order and takes the one at index
/// `allowed`. Deciding with a strict `>` is what makes the bound hold rather
/// than nearly hold: with ties at the cut, fewer clean samples clear it, so the
/// achieved rate comes in under target rather than over. The achieved rate is
/// measured afterwards either way, never assumed from this.
fn threshold_from_clean_arm(clean: &mut [f64], target: f64) -> (f64, usize) {
    clean.sort_by(|a, b| b.total_cmp(a));
    let allowed = ((target * clean.len() as f64).floor() as usize).min(clean.len() - 1);
    (clean[allowed], allowed)
}

fn per_family(scored: &[(String, f64)], cut: f64) -> Result<BTreeMap<String, Rate>, StegError> {
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for (family, score) in scored {
        let entry = counts.entry(family.as_str()).or_insert((0, 0));
        entry.0 += 1;
        if *score > cut {
            entry.1 += 1;
        }
    }
    let mut out = BTreeMap::new();
    for (family, (samples, hits)) in counts {
        out.insert(family.to_string(), Rate::new(samples, hits)?);
    }
    Ok(out)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wild::manifest::tests::{manifest, sample};
    use crate::wild::manifest::WildSample;
    use std::collections::HashMap;

    /// A source over bytes held in the test, which is the only implementation
    /// of the seam that exists anywhere and is the only one that should.
    struct FixtureSource {
        files: HashMap<String, Vec<u8>>,
        refuse: Vec<String>,
    }

    impl SampleSource for FixtureSource {
        fn ids(&self) -> Vec<String> {
            self.files
                .keys()
                .cloned()
                .chain(self.refuse.iter().cloned())
                .collect()
        }

        fn load(&self, id: &str, max_bytes: u64) -> Result<Vec<u8>, StegError> {
            if self.refuse.iter().any(|r| r == id) {
                return Err(StegError::Internal(format!("{id} is quarantined")));
            }
            let bytes = self
                .files
                .get(id)
                .ok_or_else(|| StegError::FileNotFound(id.to_string()))?;
            if bytes.len() as u64 > max_bytes {
                return Err(StegError::Internal(format!(
                    "{id} is {} bytes, past the {max_bytes} cap",
                    bytes.len()
                )));
            }
            Ok(bytes.clone())
        }
    }

    /// Scores a sample as its first byte over 255, so a fixture can place a
    /// sample anywhere on the scale by its content and the arithmetic under
    /// test is exactly visible.
    struct FirstByteDetector {
        panic_on: Option<u8>,
    }

    impl Detector for FirstByteDetector {
        fn name(&self) -> &str {
            "first-byte"
        }

        fn score(&self, bytes: &[u8]) -> Result<Real, StegError> {
            let first = *bytes.first().unwrap_or(&0);
            if self.panic_on == Some(first) {
                return Err(StegError::CorruptedFile);
            }
            Real::new(f64::from(first) / 255.0)
        }
    }

    struct Counting {
        started: Vec<(usize, usize, String)>,
        finished: Option<usize>,
    }

    impl GradeObserver for Counting {
        fn sample_started(&mut self, done: usize, total: usize, id: &str) {
            self.started.push((done, total, id.to_string()));
        }
        fn finished(&mut self, total: usize) {
            self.finished = Some(total);
        }
    }

    /// `n` samples in one family with the given label, scored by the byte
    /// value given for each.
    fn arm(prefix: &str, family: &str, payload: Payload, scores: &[u8]) -> Vec<WildSample> {
        let seed: u128 = prefix.bytes().map(u128::from).sum();
        (0..scores.len())
            .map(|i| {
                let mut s = sample(&format!("{prefix}-{i:03}"), 'a', payload);
                s.family = family.to_string();
                s.campaign = None;
                // Distinct non-placeholder digests, so manifest validation is
                // satisfied. The grader never looks at them; the verifier is
                // the half that does.
                s.sha256 = format!("{:064x}", seed * 1_000_000_000 + i as u128);
                s
            })
            .collect()
    }

    fn fixture(samples: Vec<(WildSample, u8)>) -> (WildManifest, FixtureSource) {
        let mut m = manifest();
        m.samples.clear();
        let mut files = HashMap::new();
        for (sample, byte) in samples {
            files.insert(sample.id.clone(), vec![byte, 1, 2, 3]);
            m.samples.push(sample);
        }
        m.canonicalise();
        m.validate().expect("the fixture manifest is valid");
        (
            m,
            FixtureSource {
                files,
                refuse: Vec::new(),
            },
        )
    }

    /// A corpus with a clean arm of 100 at low scores and two stego families.
    fn two_family_corpus() -> (WildManifest, FixtureSource) {
        let clean_scores: Vec<u8> = (0..100).map(|i| (i % 20) as u8).collect();
        let worok: Vec<u8> = (0..30).map(|i| if i < 27 { 200 } else { 5 }).collect();
        let steamhide: Vec<u8> = (0..10).map(|i| if i < 2 { 200 } else { 5 }).collect();

        let mut pairs = Vec::new();
        for (s, b) in arm("clean", "benign-png", Payload::Clean, &clean_scores)
            .into_iter()
            .zip(clean_scores.iter())
        {
            pairs.push((s, *b));
        }
        for (s, b) in arm("worok", "worok", Payload::Carries, &worok)
            .into_iter()
            .zip(worok.iter())
        {
            pairs.push((s, *b));
        }
        for (s, b) in arm("steam", "steamhide", Payload::Carries, &steamhide)
            .into_iter()
            .zip(steamhide.iter())
        {
            pairs.push((s, *b));
        }
        fixture(pairs)
    }

    fn settings() -> GradeSettings {
        GradeSettings {
            integrity_verified: true,
            ..Default::default()
        }
    }

    fn detector() -> FirstByteDetector {
        FirstByteDetector { panic_on: None }
    }

    #[test]
    fn it_reports_per_family_rates_at_the_target_false_positive_rate() {
        let (m, source) = two_family_corpus();
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");

        match g.threshold {
            Threshold::Set {
                from_clean,
                allowed_false_positives,
                ..
            } => {
                assert_eq!(from_clean, 100);
                assert_eq!(allowed_false_positives, 1, "floor(0.01 * 100)");
            }
            Threshold::NoCleanArm => panic!("there is a clean arm"),
        }
        let achieved = g.achieved_fpr.as_ref().expect("measured");
        assert!(
            achieved.rate.get() <= 0.01,
            "achieved {} is at or under target",
            achieved.rate
        );

        let worok = g.stego_families.get("worok").expect("worok");
        assert_eq!((worok.samples, worok.hits), (30, 27));
        assert!((worok.rate.get() - 0.9).abs() < 1e-12);
        assert!(worok.sufficient_support);

        let steam = g.stego_families.get("steamhide").expect("steamhide");
        assert_eq!((steam.samples, steam.hits), (10, 2));
        assert!(
            !steam.sufficient_support,
            "ten samples is under the support floor and must be flagged"
        );
    }

    #[test]
    fn there_is_no_pooled_rate_and_no_accuracy_to_quote() {
        let (m, source) = two_family_corpus();
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        let json = serde_json::to_string(&g).expect("serialise");
        assert!(!json.contains("accuracy"));
        assert!(!json.contains("pooled"));
        assert_eq!(
            g.stego_families.len(),
            2,
            "two families, two rows, no total"
        );
    }

    #[test]
    fn the_clean_arm_is_reported_per_family_too() {
        let (m, source) = two_family_corpus();
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        let clean = g.clean_families.get("benign-png").expect("clean family");
        assert_eq!(clean.samples, 100);
        assert_eq!(
            clean.hits,
            g.achieved_fpr.as_ref().expect("measured").hits,
            "one clean family, so the per-family and pooled clean counts agree"
        );
    }

    #[test]
    fn a_corpus_with_no_clean_arm_refuses_to_report_a_detection_rate() {
        let scores = [200u8; 5];
        let pairs: Vec<(WildSample, u8)> = arm("worok", "worok", Payload::Carries, &scores)
            .into_iter()
            .zip(scores.iter().copied())
            .collect();
        let (m, source) = fixture(pairs);
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        assert_eq!(g.threshold, Threshold::NoCleanArm);
        assert!(g.stego_families.is_empty());
        assert!(g.achieved_fpr.is_none());
        assert!(g.human_summary().contains("cannot measure a detector"));
    }

    #[test]
    fn a_clean_arm_too_small_for_the_target_is_flagged_rather_than_quietly_zero() {
        let clean = [1u8, 2, 3];
        let stego = [200u8, 201];
        let mut pairs: Vec<(WildSample, u8)> = arm("clean", "benign", Payload::Clean, &clean)
            .into_iter()
            .zip(clean.iter().copied())
            .collect();
        pairs.extend(
            arm("worok", "worok", Payload::Carries, &stego)
                .into_iter()
                .zip(stego.iter().copied()),
        );
        let (m, source) = fixture(pairs);
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        assert!(!g.clean_support_sufficient, "3 * 0.01 is under one");
        assert!(g.human_summary().contains("zero by arithmetic"));
    }

    #[test]
    fn an_unlabelled_sample_is_skipped_and_said_to_have_been() {
        let (mut m, source) = two_family_corpus();
        let mut unknown = sample("unknown-001", 'f', Payload::Unknown);
        unknown.family = "mixed-bazaar".to_string();
        unknown.campaign = None;
        unknown.sha256 = "f".repeat(63) + "e";
        m.samples.push(unknown);
        m.canonicalise();
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        assert_eq!(g.skipped_unlabelled, vec!["unknown-001"]);
        assert!(!g.stego_families.contains_key("mixed-bazaar"));
    }

    #[test]
    fn a_sample_the_source_does_not_have_is_reported_not_counted() {
        let (m, mut source) = two_family_corpus();
        let dropped = m.samples[0].id.clone();
        source.files.remove(&dropped);
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        assert_eq!(g.missing_from_source, vec![dropped]);
        let counted: usize = g
            .stego_families
            .values()
            .chain(g.clean_families.values())
            .map(|r| r.samples)
            .sum();
        assert_eq!(counted, 139, "140 labelled samples, one of them absent");
    }

    #[test]
    fn a_sample_the_source_refuses_lands_in_errored_and_in_neither_arm() {
        let (m, mut source) = two_family_corpus();
        let quarantined = m.samples[0].id.clone();
        source.files.remove(&quarantined);
        source.refuse.push(quarantined.clone());
        let g = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        assert_eq!(g.errored.len(), 1);
        assert_eq!(g.errored[0].id, quarantined);
        assert_eq!(g.errored[0].stage, Stage::Load);
        assert!(g.missing_from_source.is_empty());
        assert!(g.human_summary().contains("could not be graded"));
    }

    #[test]
    fn a_sample_the_detector_chokes_on_is_recorded_rather_than_inflating_the_rate() {
        let (m, source) = two_family_corpus();
        let g = grade(
            &m,
            &source,
            &FirstByteDetector {
                panic_on: Some(200),
            },
            &settings(),
            &mut Silent,
        )
        .expect("grade");
        assert_eq!(g.errored.len(), 29, "27 worok plus 2 steamhide score 200");
        assert!(g.errored.iter().all(|e| e.stage == Stage::Score));
        let worok = g.stego_families.get("worok").expect("worok");
        assert_eq!(
            (worok.samples, worok.hits),
            (3, 0),
            "the three that survived, and the rate is 0% rather than a silent 90%"
        );
    }

    #[test]
    fn an_unverified_run_says_so_before_it_says_anything_else() {
        let (m, source) = two_family_corpus();
        let g = grade(
            &m,
            &source,
            &detector(),
            &GradeSettings::default(),
            &mut Silent,
        )
        .expect("grade");
        assert!(!g.integrity_verified);
        assert!(g.human_summary().starts_with("Caution:"));
    }

    #[test]
    fn grading_is_reproducible_and_round_trips_through_json() {
        let (m, source) = two_family_corpus();
        let once = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        let twice = grade(&m, &source, &detector(), &settings(), &mut Silent).expect("grade");
        assert_eq!(once, twice);
        let text = serde_json::to_string_pretty(&once).expect("write");
        assert_eq!(
            text,
            serde_json::to_string_pretty(&twice).expect("write"),
            "two runs produce the same bytes"
        );
        let read: Grading = serde_json::from_str(&text).expect("read");
        assert_eq!(once, read);
    }

    #[test]
    fn the_observer_sees_every_sample_and_one_finish() {
        let (m, source) = two_family_corpus();
        let mut counting = Counting {
            started: Vec::new(),
            finished: None,
        };
        let g = grade(&m, &source, &detector(), &settings(), &mut counting).expect("grade");
        assert_eq!(counting.started.len(), 140);
        assert_eq!(counting.finished, Some(140));
        assert_eq!(counting.started[0].1, 140);
        assert!(g.errored.is_empty());
    }

    #[test]
    fn unusable_settings_fail_loudly_rather_than_being_clamped() {
        let (m, source) = two_family_corpus();
        for bad in [
            GradeSettings {
                target_fpr: 1.0,
                ..settings()
            },
            GradeSettings {
                target_fpr: -0.1,
                ..settings()
            },
            GradeSettings {
                target_fpr: f64::NAN,
                ..settings()
            },
            GradeSettings {
                max_sample_bytes: 0,
                ..settings()
            },
        ] {
            assert!(
                grade(&m, &source, &detector(), &bad, &mut Silent).is_err(),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn an_invalid_manifest_stops_the_run_rather_than_grading_against_a_bad_label() {
        let (mut m, source) = two_family_corpus();
        m.samples[0].tool = Some("steghide".to_string());
        m.samples[0].payload = Payload::Clean;
        assert!(grade(&m, &source, &detector(), &settings(), &mut Silent).is_err());
    }

    #[test]
    fn the_cap_is_part_of_the_contract_and_a_source_that_refuses_is_recorded() {
        let (m, source) = two_family_corpus();
        let tiny = GradeSettings {
            max_sample_bytes: 1,
            ..settings()
        };
        let g = grade(&m, &source, &detector(), &tiny, &mut Silent).expect("grade");
        assert_eq!(g.errored.len(), 140, "every fixture sample is four bytes");
        assert!(g.errored.iter().all(|e| e.reason.contains("past the")));
    }

    #[test]
    fn a_wilson_interval_has_width_at_the_edges_where_the_normal_one_has_none() {
        let perfect = Rate::new(20, 20).expect("rate");
        assert_eq!(perfect.rate.get(), 1.0);
        assert!(perfect.ci95_high.get() <= 1.0);
        assert!(
            perfect.ci95_low.get() > 0.80 && perfect.ci95_low.get() < 0.86,
            "20 of 20 is roughly 0.83 to 1.00, got {}",
            perfect.ci95_low
        );

        let none = Rate::new(20, 0).expect("rate");
        assert_eq!(none.rate.get(), 0.0);
        assert!(none.ci95_low.get() >= 0.0);
        assert!(
            none.ci95_high.get() > 0.14 && none.ci95_high.get() < 0.20,
            "0 of 20 tops out near 0.16, got {}",
            none.ci95_high
        );

        let wide = Rate::new(4, 4).expect("rate");
        assert!(
            wide.ci95_low.get() < perfect.ci95_low.get(),
            "four samples is a wider claim than twenty"
        );
        assert!(!wide.sufficient_support);
    }

    #[test]
    fn a_rate_over_nothing_is_a_bug_and_says_so() {
        let err = Rate::new(0, 0).expect_err("no samples");
        assert!(err.to_string().contains("bug in the caller"));
    }

    #[test]
    fn the_threshold_holds_the_bound_rather_than_nearly_holding_it() {
        // Ten clean scores and a 25% target allows two false positives.
        let mut clean = vec![0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0];
        let (cut, allowed) = threshold_from_clean_arm(&mut clean, 0.25);
        assert_eq!(allowed, 2);
        assert_eq!(cut, 0.7);
        assert_eq!(clean.iter().filter(|s| **s > cut).count(), 2);

        // Ties at the cut come in under target, never over.
        let mut tied = vec![0.5; 10];
        let (cut, _) = threshold_from_clean_arm(&mut tied, 0.25);
        assert_eq!(tied.iter().filter(|s| **s > cut).count(), 0);
    }

    #[test]
    fn a_zero_target_allows_no_false_positive_at_all() {
        let mut clean = vec![0.1, 0.9, 0.5];
        let (cut, allowed) = threshold_from_clean_arm(&mut clean, 0.0);
        assert_eq!(allowed, 0);
        assert_eq!(cut, 0.9);
        assert_eq!(clean.iter().filter(|s| **s > cut).count(), 0);
    }
}
