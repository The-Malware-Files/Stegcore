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

//! The community corpus contribution format.
//!
//! # What this is
//!
//! A file format and a validator, nothing else. A contributor runs the engine
//! over files they own, exports the measurements, and opens a pull request
//! against a public git repository. There is no server, no account, no upload
//! and **no network client anywhere in this module**: the transport is git and a
//! human reviewer, which is the point. A reviewer can read a diff; a reviewer
//! cannot read a POST body.
//!
//! The corpus exists so detector thresholds can be calibrated against something
//! broader than the datasets one developer can lawfully redistribute. That is a
//! real gap: the 2026-06-14 recalibration found that thresholds set on two
//! corpora leaked roughly 22% false positives on a third, because the third had
//! been JPEG-decompressed and the first two had not.
//!
//! # What a contribution carries, and what it must never carry
//!
//! A record is a row of numbers and a label. It carries:
//!
//! - the detector scores, as lossless decimal strings;
//! - what the file was, coarsely: media type, pixel count or sample count;
//! - the ground truth, when the contributor knows it, including which tool
//!   embedded and at roughly what payload rate;
//! - the engine version and threshold profile that produced the numbers.
//!
//! It carries no payload content, no pixel data, no file name, no path and no
//! passphrase. Three of those are enforced structurally rather than by review:
//! there is no field of type `Vec<u8>` anywhere in the format, so there is
//! nowhere for content to sit, and [`CorpusRecord::validate`] refuses a record
//! whose label fields look like a path or hold anything but a short identifier.
//!
//! # The decision a contributor makes, and why it is theirs
//!
//! Identifying a record by the SHA-256 of the file is convenient and it is also
//! a confirmation oracle: anybody holding a copy of a file can ask the public
//! corpus whether that exact file was analysed, and read the verdict. For a
//! forensic examiner's working set that is a disclosure, not a convenience.
//!
//! Calibration does not need the identity. It needs the feature values and the
//! label. So the digest is **optional and off by default**, and a record without
//! one is identified by a contributor-chosen opaque id that means nothing
//! outside their own notes. A contributor who wants deduplication across
//! contributions can opt in; one who does not, loses nothing a calibration run
//! would have used.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::errors::StegError;
use crate::repro::real::Real;

/// Format version of a contribution file.
pub const CORPUS_FORMAT: u32 = 1;

/// Largest contribution file accepted.
///
/// A record is a few hundred bytes, so this is room for roughly a hundred
/// thousand of them, which is larger than any single pull request a human could
/// review. A contributor with more than that should send several files, and a
/// reviewer should be glad they did.
pub const MAX_CORPUS_BYTES: u64 = 32 * 1024 * 1024;

/// Most records in one file, bounding the validator's work.
pub const MAX_RECORDS: usize = 100_000;

/// Longest opaque record id, and longest tool name.
///
/// Short enough that nothing descriptive fits, which is deliberate: the id is
/// not a place to write a case reference.
pub const MAX_ID_BYTES: usize = 64;

/// Most detector scores in one record.
pub const MAX_SCORES_PER_RECORD: usize = 64;

/// What the contributor knows about the file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "truth", rename_all = "snake_case")]
pub enum GroundTruth {
    /// Known to carry nothing. The arm that sets the false-positive rate, and
    /// the one the corpus is short of, because clean files feel less
    /// interesting to contribute and are worth more.
    Clean,
    /// Known to carry a payload.
    Stego {
        /// Embedding tool, lowercase, no version. A bare name so records from
        /// different contributors group together.
        tool: String,
        /// Payload as a fraction of capacity, when the contributor knows it.
        #[serde(skip_serializing_if = "Option::is_none")]
        payload_rate: Option<Real>,
    },
    /// The contributor does not know. Recorded honestly rather than guessed,
    /// and excluded from calibration by [`Contribution::calibration_arms`].
    Unknown,
}

impl GroundTruth {
    /// Whether a calibration run may use this record.
    ///
    /// Only the labelled arms. An unknown record cannot tell you anything about
    /// a false-positive rate, and quietly treating it as clean is how a
    /// threshold ends up calibrated against stego files.
    pub fn is_labelled(&self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// One measured file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorpusRecord {
    /// Opaque identifier, unique within the contribution.
    pub id: String,
    /// SHA-256 of the file, only when the contributor opted in. See the module
    /// docs on why this is off by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Media type, such as `image/png`.
    pub media: String,
    /// Size in bytes, which stands in for capacity closely enough to bucket by.
    pub bytes: u64,
    /// Pixels for an image, samples for audio. Coarse on purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elements: Option<u64>,
    /// Detector scores by name.
    pub scores: BTreeMap<String, Real>,
    /// What the contributor knows about it.
    #[serde(flatten)]
    pub ground_truth: GroundTruth,
    /// Engine version that measured it.
    pub engine_version: String,
    /// Threshold profile in force at the time.
    pub threshold_profile: String,
}

/// A whole contribution file, which is one pull request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contribution {
    /// Format version.
    pub format: u32,
    /// Free-text description of where the files came from, for the reviewer.
    /// Not machine-read, and the one field a human writes.
    pub provenance_note: String,
    /// Licence the contributor asserts over the measurements.
    pub licence: String,
    /// The records, sorted by id.
    pub records: Vec<CorpusRecord>,
}

impl CorpusRecord {
    /// Check a record carries what it should and nothing it should not.
    pub fn validate(&self) -> Result<(), StegError> {
        check_opaque_id("record id", &self.id)?;

        if let Some(digest) = &self.sha256 {
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(reject(format!(
                    "record {:?} has a sha256 field that is not 64 hex characters",
                    self.id
                )));
            }
            if digest.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(reject(format!(
                    "record {:?} writes its sha256 in uppercase; the corpus uses \
                     lowercase so the same file is one row and not two",
                    self.id
                )));
            }
        }

        if self.media.is_empty() || self.media.len() > MAX_ID_BYTES {
            return Err(reject(format!(
                "record {:?} has no usable media type",
                self.id
            )));
        }

        if self.scores.is_empty() {
            return Err(reject(format!(
                "record {:?} carries no detector scores, so it measures nothing",
                self.id
            )));
        }
        if self.scores.len() > MAX_SCORES_PER_RECORD {
            return Err(reject(format!(
                "record {:?} carries {} scores, past the {MAX_SCORES_PER_RECORD} limit",
                self.id,
                self.scores.len()
            )));
        }
        for name in self.scores.keys() {
            check_opaque_id("detector name", name)?;
        }

        if let GroundTruth::Stego { tool, payload_rate } = &self.ground_truth {
            check_opaque_id("tool name", tool)?;
            if tool.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(reject(format!(
                    "record {:?} names the tool {tool:?} in mixed case; the corpus \
                     uses lowercase so records from different contributors group",
                    self.id
                )));
            }
            if let Some(rate) = payload_rate {
                if rate.get() < 0.0 || rate.get() > 1.0 {
                    return Err(reject(format!(
                        "record {:?} claims a payload rate of {rate}, which is not a \
                         fraction of capacity",
                        self.id
                    )));
                }
            }
        }

        check_opaque_id("engine version", &self.engine_version)?;
        check_opaque_id("threshold profile", &self.threshold_profile)?;
        Ok(())
    }
}

impl Contribution {
    /// Put a contribution into its one canonical shape, so two contributors who
    /// measured the same files produce the same diff.
    pub fn canonicalise(&mut self) {
        self.records.sort_by(|a, b| a.id.cmp(&b.id));
    }

    /// Check the whole file. Reports the first problem with the record named,
    /// because a contributor fixing a pull request wants to know which row.
    pub fn validate(&self) -> Result<(), StegError> {
        if self.format != CORPUS_FORMAT {
            return Err(StegError::UnsupportedFormat(format!(
                "contribution format {} is not the format {CORPUS_FORMAT} this build reads",
                self.format
            )));
        }
        if self.licence.trim().is_empty() {
            return Err(reject(
                "a contribution has to state the licence its measurements are \
                 offered under, or the corpus cannot redistribute them"
                    .to_string(),
            ));
        }
        if self.records.is_empty() {
            return Err(reject("a contribution with no records".to_string()));
        }
        if self.records.len() > MAX_RECORDS {
            return Err(reject(format!(
                "{} records, past the {MAX_RECORDS} limit for one contribution",
                self.records.len()
            )));
        }

        let mut seen: Vec<&str> = Vec::with_capacity(self.records.len());
        for record in &self.records {
            record.validate()?;
            seen.push(&record.id);
        }
        seen.sort_unstable();
        for pair in seen.windows(2) {
            if pair[0] == pair[1] {
                return Err(reject(format!(
                    "two records share the id {:?}, so one of them would be lost",
                    pair[0]
                )));
            }
        }
        Ok(())
    }

    /// Serialise for a pull request: pretty-printed, because this file's reader
    /// is a human looking at a diff, not a verifier comparing bytes.
    ///
    /// This is the deliberate opposite of the manifest's compact form, and the
    /// reason is the audience. One line per field means a changed score shows as
    /// a one-line diff.
    pub fn to_review_json(&self) -> Result<String, StegError> {
        let mut ordered = self.clone();
        ordered.canonicalise();
        Ok(serde_json::to_string_pretty(&ordered)?)
    }

    /// Parse and validate in one step, so no caller can hold an unvalidated one.
    pub fn from_json(text: &str) -> Result<Self, StegError> {
        let contribution: Self = serde_json::from_str(text)?;
        contribution.validate()?;
        Ok(contribution)
    }

    /// The labelled records, split into the two arms a calibration run needs.
    ///
    /// Unlabelled records are dropped here rather than earlier, so they survive
    /// in the file for a contributor who later learns the truth.
    pub fn calibration_arms(&self) -> (Vec<&CorpusRecord>, Vec<&CorpusRecord>) {
        let mut clean = Vec::new();
        let mut stego = Vec::new();
        for record in &self.records {
            match record.ground_truth {
                GroundTruth::Clean => clean.push(record),
                GroundTruth::Stego { .. } => stego.push(record),
                GroundTruth::Unknown => {}
            }
        }
        (clean, stego)
    }
}

/// A short, boring identifier: printable ASCII without path separators.
///
/// The separators matter more than the length. A corpus record is published, so
/// a field that accepted `/home/examiner/case-2026-114/exhibit-3.png` would turn
/// an opt-in measurement into a disclosure, and a contributor filling in a field
/// called "id" would have no reason to think twice about it.
fn check_opaque_id(field: &str, value: &str) -> Result<(), StegError> {
    if value.is_empty() {
        return Err(reject(format!("an empty {field}")));
    }
    if value.len() > MAX_ID_BYTES {
        return Err(reject(format!(
            "a {field} of {} bytes, past the {MAX_ID_BYTES} limit",
            value.len()
        )));
    }
    if let Some(bad) = value.chars().find(|c| {
        matches!(c, '/' | '\\' | ':') || c.is_whitespace() || c.is_control() || !c.is_ascii()
    }) {
        return Err(reject(format!(
            "the {field} {value:?} contains {bad:?}; these fields are published, \
             so they hold a short identifier and never a path or a description"
        )));
    }
    Ok(())
}

fn reject(reason: String) -> StegError {
    StegError::Internal(format!("this contribution cannot be accepted: {reason}"))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn real(value: f64) -> Real {
        Real::new(value).expect("finite")
    }

    fn record(id: &str, truth: GroundTruth) -> CorpusRecord {
        CorpusRecord {
            id: id.to_string(),
            sha256: None,
            media: "image/png".to_string(),
            bytes: 2_048,
            elements: Some(262_144),
            scores: BTreeMap::from([
                ("spa".to_string(), real(0.41)),
                ("rs".to_string(), real(0.2890123456789012)),
            ]),
            ground_truth: truth,
            engine_version: "4.1.0".to_string(),
            threshold_profile: "default".to_string(),
        }
    }

    fn contribution() -> Contribution {
        Contribution {
            format: CORPUS_FORMAT,
            provenance_note: "Photographs I took, resized and saved as PNG.".to_string(),
            licence: "CC0-1.0".to_string(),
            records: vec![
                record("b-002", GroundTruth::Clean),
                record(
                    "a-001",
                    GroundTruth::Stego {
                        tool: "steghide".to_string(),
                        payload_rate: Some(real(0.1)),
                    },
                ),
                record("c-003", GroundTruth::Unknown),
            ],
        }
    }

    #[test]
    fn a_well_formed_contribution_validates() {
        contribution().validate().expect("valid");
    }

    #[test]
    fn it_round_trips_through_json_with_every_score_intact() {
        let written = contribution();
        let text = written.to_review_json().expect("json");
        let read = Contribution::from_json(&text).expect("read");
        for (a, b) in written
            .records
            .iter()
            .flat_map(|r| r.scores.values())
            .zip(read.records.iter().flat_map(|r| r.scores.values()))
        {
            assert_eq!(a.get().to_bits(), b.get().to_bits());
        }
    }

    #[test]
    fn canonicalising_sorts_records_so_a_diff_is_stable() {
        let mut first = contribution();
        let mut second = contribution();
        second.records.reverse();
        first.canonicalise();
        second.canonicalise();
        assert_eq!(first.records, second.records);
        assert_eq!(
            first
                .records
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            ["a-001", "b-002", "c-003"]
        );
    }

    #[test]
    fn the_review_form_is_pretty_printed_for_a_human_reading_a_diff() {
        let text = contribution().to_review_json().expect("json");
        assert!(text.contains('\n'), "a reviewer cannot diff one long line");
    }

    #[test]
    fn calibration_uses_only_the_labelled_arms() {
        let mixed = contribution();
        let (clean, stego) = mixed.calibration_arms();
        assert_eq!(clean.len(), 1);
        assert_eq!(stego.len(), 1);
        assert!(GroundTruth::Clean.is_labelled());
        assert!(!GroundTruth::Unknown.is_labelled());
    }

    #[test]
    fn a_path_in_an_identifier_is_refused_and_the_reason_is_explained() {
        let mut bad = contribution();
        bad.records[0].id = "/home/examiner/case-114/exhibit-3.png".to_string();
        let err = bad.validate().expect_err("must refuse");
        assert!(err.to_string().contains("never a path"), "{err}");
    }

    #[test]
    fn a_windows_path_in_an_identifier_is_refused_too() {
        let mut bad = contribution();
        bad.records[0].id = r"C:\cases\exhibit.png".to_string();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn whitespace_and_non_ascii_in_an_identifier_are_refused() {
        for id in ["case 114", "case\u{0}114", "exhibit-ü"] {
            let mut bad = contribution();
            bad.records[0].id = id.to_string();
            assert!(bad.validate().is_err(), "{id} was accepted");
        }
    }

    #[test]
    fn an_empty_identifier_is_refused() {
        let mut bad = contribution();
        bad.records[0].id = String::new();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn an_over_long_identifier_is_refused() {
        let mut bad = contribution();
        bad.records[0].id = "a".repeat(MAX_ID_BYTES + 1);
        let err = bad.validate().expect_err("must refuse");
        assert!(err.to_string().contains("past the"), "{err}");
    }

    #[test]
    fn an_opt_in_digest_must_be_lowercase_hex() {
        let mut good = contribution();
        good.records[0].sha256 = Some("f".repeat(64));
        good.validate().expect("valid");

        for bad_digest in ["F".repeat(64), "f".repeat(63), "g".repeat(64)] {
            let mut bad = contribution();
            bad.records[0].sha256 = Some(bad_digest.clone());
            assert!(bad.validate().is_err(), "{bad_digest} was accepted");
        }
    }

    #[test]
    fn a_record_with_no_scores_measures_nothing_and_is_refused() {
        let mut bad = contribution();
        bad.records[0].scores.clear();
        let err = bad.validate().expect_err("must refuse");
        assert!(err.to_string().contains("measures nothing"), "{err}");
    }

    #[test]
    fn too_many_scores_in_one_record_is_refused() {
        let mut bad = contribution();
        for i in 0..=MAX_SCORES_PER_RECORD {
            bad.records[0].scores.insert(format!("d{i}"), real(0.5));
        }
        assert!(bad.validate().is_err());
    }

    #[test]
    fn an_empty_media_type_is_refused() {
        let mut bad = contribution();
        bad.records[0].media = String::new();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn a_tool_name_is_lowercased_so_records_group() {
        let mut bad = contribution();
        bad.records[1].ground_truth = GroundTruth::Stego {
            tool: "StegHide".to_string(),
            payload_rate: None,
        };
        let err = bad.validate().expect_err("must refuse");
        assert!(err.to_string().contains("mixed case"), "{err}");
    }

    #[test]
    fn a_payload_rate_outside_zero_to_one_is_refused() {
        for rate in [-0.1, 1.5] {
            let mut bad = contribution();
            bad.records[1].ground_truth = GroundTruth::Stego {
                tool: "steghide".to_string(),
                payload_rate: Some(real(rate)),
            };
            assert!(bad.validate().is_err(), "{rate} was accepted");
        }
    }

    #[test]
    fn a_stego_record_may_omit_the_payload_rate() {
        let mut ok = contribution();
        ok.records[1].ground_truth = GroundTruth::Stego {
            tool: "outguess".to_string(),
            payload_rate: None,
        };
        ok.validate().expect("valid");
    }

    #[test]
    fn a_missing_licence_is_refused_because_the_corpus_could_not_redistribute() {
        let mut bad = contribution();
        bad.licence = "   ".to_string();
        let err = bad.validate().expect_err("must refuse");
        assert!(err.to_string().contains("licence"), "{err}");
    }

    #[test]
    fn an_empty_contribution_is_refused() {
        let mut bad = contribution();
        bad.records.clear();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn a_duplicate_record_id_is_refused_rather_than_silently_dropped() {
        let mut bad = contribution();
        bad.records[0].id = bad.records[1].id.clone();
        let err = bad.validate().expect_err("must refuse");
        assert!(err.to_string().contains("share the id"), "{err}");
    }

    #[test]
    fn a_wrong_format_version_is_refused() {
        let mut bad = contribution();
        bad.format = CORPUS_FORMAT + 1;
        let err = bad.validate().expect_err("must refuse");
        assert!(err.to_string().contains("format"), "{err}");
    }

    #[test]
    fn an_unvalidated_contribution_cannot_be_obtained_from_text() {
        let mut bad = contribution();
        bad.records[0].scores.clear();
        let text = serde_json::to_string(&bad).expect("json");
        assert!(Contribution::from_json(&text).is_err());
    }

    #[test]
    fn a_detector_name_that_is_really_a_sentence_is_refused() {
        let mut bad = contribution();
        bad.records[0]
            .scores
            .insert("sample pulled from exhibit 3".to_string(), real(0.5));
        assert!(bad.validate().is_err());
    }
}
