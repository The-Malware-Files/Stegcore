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

//! The reproducibility manifest: what was analysed, by what, and with what result.
//!
//! # The shape, and why it is split in two
//!
//! A manifest has to answer two different questions, and they have opposite
//! requirements:
//!
//! ```text
//!   run         what the answer was    must be byte-identical on a re-run
//!   provenance  who ran it and when    cannot possibly be, and should not be
//! ```
//!
//! Wall-clock time, host name and command line are exactly the fields a
//! reviewer wants, and exactly the fields that guarantee two runs of the same
//! analysis produce different files. Folding them into one flat object forces a
//! choice between a useful record and a verifiable one. So they live in separate
//! sections, the digest covers `run` alone, and the claim the manifest makes is
//! precise: **the `run` section is byte-identical across runs on the same
//! inputs, and `provenance` is explicitly not covered.**
//!
//! # What makes the bytes identical
//!
//! Four things, each of which has been a reproducibility bug in some tool:
//!
//! 1. **Every real number is a decimal string.** `serde_json`'s float parser
//!    loses a unit in the last place on roughly a tenth of values; see
//!    [`crate::repro::real`] for the measurement. Integers and strings round
//!    trip exactly, so the manifest uses only those.
//! 2. **Every map is a `BTreeMap`.** A `HashMap`'s iteration order is seeded per
//!    process, so it would reorder the keys between two runs on one machine.
//! 3. **Every list is sorted at the serialisation boundary**, by a key that is
//!    unique within the list, so detector order cannot leak the order the
//!    detectors happened to finish in.
//! 4. **Compact serialisation, not pretty-printed.** Indentation is a rendering
//!    choice; keeping it out of the canonical bytes means a reformatted file
//!    still verifies.
//!
//! The digest is SHA-256 over those canonical bytes, using the engine's own
//! implementation, so a verifier needs nothing the engine does not already
//! carry.
//!
//! One caveat worth stating rather than discovering: the canonical bytes are
//! whatever `serde_json` writes for this structure, so a future `serde_json`
//! that changed its string escaping would change every digest, even though no
//! score moved. The scope of the claim is therefore **the same engine build**,
//! which is also what `engine_version` in the record already pins. Comparing
//! manifests written by two different builds is a question about the parsed
//! fields, not about the digests, and [`Manifest::records_the_same_run_as`] is
//! deliberately named so a caller cannot mistake it for the stronger claim.
//!
//! # What a manifest does not prove
//!
//! It proves that this engine, at this version, with this threshold profile,
//! produced this answer for this input. It does not prove the answer is right,
//! and it is not a signature: anybody holding the file can edit a score and
//! recompute the digest. Binding a manifest to an identity is the engagement
//! manifest's job, not this one's.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

use crate::bruteforce::digest::{hex, Sha256};
use crate::errors::StegError;
use crate::repro::real::Real;

/// Conventional file name, written beside the analysed input.
pub const MANIFEST_FILENAME: &str = ".stegcore-manifest.json";

/// Format version of the manifest itself.
///
/// Bumped when a field changes meaning, so a reader can refuse a file it would
/// misinterpret rather than silently reading an old field as a new one.
pub const MANIFEST_FORMAT: u32 = 1;

/// Largest manifest accepted from disk.
///
/// A manifest for one input is a few kilobytes. The bound is three orders of
/// magnitude above that, so it never refuses a legitimate file, and it stops a
/// hostile one exhausting memory before the parser sees a single field.
pub const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Bytes read at a time when hashing an input.
const HASH_CHUNK_BYTES: usize = 64 * 1024;

/// How a detector's number should be read, carried so a consumer cannot render
/// a descriptive statistic as a finding.
///
/// This mirrors the covert detector's `FeatureRole` for the same reason: a
/// number in a report is not automatically evidence, and the manifest is read by
/// machines that have no way to know which is which unless it is written down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputRole {
    /// Calibrated against a clean corpus and allowed to move the verdict.
    Calibrated,
    /// Measured, real, but not yet calibrated, so it informs a human and not the
    /// verdict.
    Advisory,
    /// Descriptive only. Reporting it is useful; thresholding it is not.
    Descriptive,
}

impl OutputRole {
    /// Whether a consumer may let this number affect a verdict.
    pub fn may_inform_a_verdict(self) -> bool {
        matches!(self, Self::Calibrated)
    }
}

/// The input, identified by content rather than by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputRecord {
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// Size in bytes, which catches a truncated re-run before the digest does.
    pub bytes: u64,
    /// The media type the engine decided it was, or `unknown`.
    pub media: String,
}

/// The threshold profile a verdict was reached under.
///
/// Recorded by name *and* by value, because a profile name alone is not enough
/// to reproduce a verdict: the 2026-06-14 recalibration changed what
/// `default` meant without changing the word.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThresholdProfile {
    /// Name of the profile, as the operator selected it.
    pub name: String,
    /// What the profile was calibrated against, in plain words.
    pub calibrated_on: String,
    /// Every threshold the profile sets, by detector name.
    pub thresholds: BTreeMap<String, Real>,
}

/// One detector's result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectorOutput {
    /// Detector name, unique within a manifest.
    pub name: String,
    /// The number it produced.
    pub score: Real,
    /// How that number may be read.
    pub role: OutputRole,
}

/// The reproducible half: a pure function of the inputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    /// Manifest format version.
    pub format: u32,
    /// Engine version that produced the result.
    pub engine_version: String,
    /// What was analysed.
    pub input: InputRecord,
    /// The thresholds in force.
    pub threshold_profile: ThresholdProfile,
    /// Detector results, sorted by name.
    pub detectors: Vec<DetectorOutput>,
    /// The verdict word, as the user saw it.
    pub verdict: String,
    /// The combined score behind that verdict.
    pub verdict_score: Real,
    /// Caveats that belong with the result, sorted so two runs agree.
    pub notes: Vec<String>,
}

/// The half that cannot be reproduced, and is deliberately outside the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// RFC 3339 timestamp, captured once per analysis.
    pub created: String,
    /// Tool and version that wrote the file.
    pub tool: String,
    /// Host name, when the operator chose to record it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// A manifest as it sits on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// The reproducible section. The digest covers this and nothing else.
    pub run: Run,
    /// Who ran it and when. Not covered by the digest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// Hex SHA-256 of [`Run`]'s canonical bytes.
    pub run_digest: String,
}

impl Run {
    /// Put the manifest into its one canonical shape.
    ///
    /// Called before serialising and before verifying, so a manifest written by
    /// a caller that forgot to sort still digests to the same value as one that
    /// remembered. Without this the ordering rule would be a convention that
    /// each call site has to honour, which is the kind of rule that holds until
    /// the second call site.
    pub fn canonicalise(&mut self) {
        self.detectors.sort_by(|a, b| a.name.cmp(&b.name));
        self.detectors.dedup_by(|a, b| a.name == b.name);
        self.notes.sort();
        self.notes.dedup();
    }

    /// The exact bytes the digest is taken over.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StegError> {
        let mut ordered = self.clone();
        ordered.canonicalise();
        Ok(serde_json::to_vec(&ordered)?)
    }

    /// Hex SHA-256 of [`Self::canonical_bytes`].
    pub fn digest(&self) -> Result<String, StegError> {
        Ok(hex(&sha256(&self.canonical_bytes()?)))
    }
}

impl Manifest {
    /// Seal a run: canonicalise it, compute its digest, and attach provenance.
    pub fn seal(mut run: Run, provenance: Option<Provenance>) -> Result<Self, StegError> {
        run.canonicalise();
        let run_digest = run.digest()?;
        Ok(Self {
            run,
            provenance,
            run_digest,
        })
    }

    /// Serialise for writing. Compact, because indentation is not part of the
    /// record.
    pub fn to_json(&self) -> Result<String, StegError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Read a manifest from text and check its digest.
    pub fn from_json(text: &str) -> Result<Self, StegError> {
        let manifest: Self = serde_json::from_str(text)?;
        manifest.verify()?;
        Ok(manifest)
    }

    /// Read a manifest from disk, bounded, and check its digest.
    pub fn read(path: &Path) -> Result<Self, StegError> {
        let meta = std::fs::metadata(path)
            .map_err(|_| StegError::FileNotFound(path.display().to_string()))?;
        if meta.len() > MAX_MANIFEST_BYTES {
            return Err(StegError::UnsupportedFormat(format!(
                "{} is {} bytes, past the {MAX_MANIFEST_BYTES} byte manifest limit",
                path.display(),
                meta.len()
            )));
        }
        let text = std::fs::read_to_string(path)?;
        Self::from_json(&text)
    }

    /// Does the recorded digest match the run it claims to cover?
    pub fn verify(&self) -> Result<(), StegError> {
        if self.run.format != MANIFEST_FORMAT {
            return Err(StegError::UnsupportedFormat(format!(
                "manifest format {} was written by a different version of Stegcore; \
                 this build reads format {MANIFEST_FORMAT}",
                self.run.format
            )));
        }
        let expected = self.run.digest()?;
        if expected == self.run_digest {
            Ok(())
        } else {
            Err(StegError::Internal(format!(
                "this manifest's contents do not match its own digest: \
                 it records {} and the contents hash to {expected}. \
                 The file has been edited since it was written.",
                self.run_digest
            )))
        }
    }

    /// Do two manifests record the same analysis?
    ///
    /// Compares the run digests, which is the whole point of having them: it
    /// ignores provenance, ignores formatting, and ignores the order the
    /// detectors were written in.
    pub fn records_the_same_run_as(&self, other: &Self) -> bool {
        self.run_digest == other.run_digest
    }
}

/// SHA-256 of a byte slice, via the engine's own implementation.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalise()
}

/// Hex SHA-256 of a file, read in chunks so a large cover never lands in memory.
pub fn hash_input(path: &Path) -> Result<(String, u64), StegError> {
    use std::io::Read;

    let file = std::fs::File::open(path)
        .map_err(|_| StegError::FileNotFound(path.display().to_string()))?;
    let bytes = file.metadata()?.len();
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; HASH_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok((hex(&hasher.finalise()), bytes))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn real(value: f64) -> Real {
        Real::new(value).expect("finite")
    }

    fn sample_run() -> Run {
        Run {
            format: MANIFEST_FORMAT,
            engine_version: "4.1.0".to_string(),
            input: InputRecord {
                sha256: "a".repeat(64),
                bytes: 1024,
                media: "image/png".to_string(),
            },
            threshold_profile: ThresholdProfile {
                name: "default".to_string(),
                calibrated_on: "Cassavia 2022 + BOSSbase 1.01 + ALASKA2 sample".to_string(),
                thresholds: BTreeMap::from([
                    ("spa".to_string(), real(0.377)),
                    ("rs".to_string(), real(0.305)),
                    ("ws".to_string(), real(0.195)),
                ]),
            },
            detectors: vec![
                DetectorOutput {
                    name: "ws".to_string(),
                    score: real(0.401_234_567_890_123_4),
                    role: OutputRole::Calibrated,
                },
                DetectorOutput {
                    name: "spa".to_string(),
                    score: real(0.512),
                    role: OutputRole::Calibrated,
                },
                DetectorOutput {
                    name: "entropy".to_string(),
                    score: real(7.98),
                    role: OutputRole::Descriptive,
                },
            ],
            verdict: "Suspicious".to_string(),
            verdict_score: real(0.71),
            notes: vec!["low payload rates are below this detector's floor".to_string()],
        }
    }

    #[test]
    fn a_sealed_manifest_verifies() {
        let manifest = Manifest::seal(sample_run(), None).expect("seal");
        manifest.verify().expect("verify");
    }

    #[test]
    fn the_run_section_is_byte_identical_across_two_seals() {
        let first = Manifest::seal(sample_run(), None).expect("seal");
        let second = Manifest::seal(sample_run(), None).expect("seal");
        assert_eq!(
            first.run.canonical_bytes().expect("bytes"),
            second.run.canonical_bytes().expect("bytes")
        );
        assert_eq!(first.run_digest, second.run_digest);
    }

    #[test]
    fn provenance_changes_the_file_but_not_the_digest() {
        let bare = Manifest::seal(sample_run(), None).expect("seal");
        let dated = Manifest::seal(
            sample_run(),
            Some(Provenance {
                created: "2026-10-01T18:00:00Z".to_string(),
                tool: "stegcore 4.1.0".to_string(),
                host: Some("atlas".to_string()),
            }),
        )
        .expect("seal");

        assert_ne!(
            bare.to_json().expect("json"),
            dated.to_json().expect("json")
        );
        assert_eq!(bare.run_digest, dated.run_digest);
        assert!(bare.records_the_same_run_as(&dated));
    }

    /// The claim the whole module makes, tested rather than asserted: write a
    /// manifest, read it back, write it again, and compare the bytes.
    #[test]
    fn a_manifest_survives_a_json_round_trip_byte_for_byte() {
        let written = Manifest::seal(sample_run(), None).expect("seal");
        let text = written.to_json().expect("json");
        let read = Manifest::from_json(&text).expect("read");
        assert_eq!(read.to_json().expect("json"), text);
        assert_eq!(read, written);
        assert_eq!(read.run_digest, written.run_digest);
    }

    #[test]
    fn every_score_survives_the_round_trip_bit_exactly() {
        let written = Manifest::seal(sample_run(), None).expect("seal");
        let read = Manifest::from_json(&written.to_json().expect("json")).expect("read");
        for (a, b) in written.run.detectors.iter().zip(read.run.detectors.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.score.get().to_bits(), b.score.get().to_bits());
        }
        assert_eq!(
            written.run.verdict_score.get().to_bits(),
            read.run.verdict_score.get().to_bits()
        );
    }

    #[test]
    fn detector_order_does_not_change_the_digest() {
        let mut shuffled = sample_run();
        shuffled.detectors.reverse();
        shuffled.notes.push("a second note".to_string());
        let mut also = sample_run();
        also.notes.insert(0, "a second note".to_string());

        assert_eq!(
            Manifest::seal(shuffled, None).expect("seal").run_digest,
            Manifest::seal(also, None).expect("seal").run_digest
        );
    }

    #[test]
    fn canonicalising_sorts_detectors_by_name() {
        let mut run = sample_run();
        run.canonicalise();
        let names: Vec<&str> = run.detectors.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["entropy", "spa", "ws"]);
    }

    #[test]
    fn a_duplicate_detector_name_collapses_to_one() {
        let mut run = sample_run();
        run.detectors.push(DetectorOutput {
            name: "spa".to_string(),
            score: real(0.9),
            role: OutputRole::Calibrated,
        });
        run.canonicalise();
        assert_eq!(run.detectors.iter().filter(|d| d.name == "spa").count(), 1);
    }

    #[test]
    fn an_edited_score_fails_verification_with_both_digests_named() {
        let manifest = Manifest::seal(sample_run(), None).expect("seal");
        let tampered = manifest.to_json().expect("json").replace("0.512", "0.012");
        let err = Manifest::from_json(&tampered).expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("do not match its own digest"), "{message}");
        assert!(message.contains("edited since it was written"), "{message}");
    }

    #[test]
    fn a_future_format_is_refused_rather_than_misread() {
        let mut manifest = Manifest::seal(sample_run(), None).expect("seal");
        manifest.run.format = MANIFEST_FORMAT + 1;
        manifest.run_digest = manifest.run.digest().expect("digest");
        let err = manifest.verify().expect_err("must refuse");
        assert!(err.to_string().contains("different version"), "{err}");
    }

    #[test]
    fn a_score_written_as_a_json_number_is_refused_on_read() {
        let text = Manifest::seal(sample_run(), None)
            .expect("seal")
            .to_json()
            .expect("json")
            .replace("\"0.512\"", "0.512");
        let err = Manifest::from_json(&text).expect_err("must refuse");
        assert!(err.to_string().contains("JSON number"), "{err}");
    }

    #[test]
    fn roles_say_which_numbers_may_move_a_verdict() {
        assert!(OutputRole::Calibrated.may_inform_a_verdict());
        assert!(!OutputRole::Advisory.may_inform_a_verdict());
        assert!(!OutputRole::Descriptive.may_inform_a_verdict());
    }

    #[test]
    fn hashing_a_file_agrees_with_hashing_its_bytes_in_one_go() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cover.bin");
        // Larger than one read chunk, so the streaming path is actually exercised.
        let bytes: Vec<u8> = (0..HASH_CHUNK_BYTES * 2 + 7)
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&path, &bytes).expect("write");

        let (digest, size) = hash_input(&path).expect("hash");
        assert_eq!(size, bytes.len() as u64);
        assert_eq!(digest, hex(&sha256(&bytes)));
    }

    #[test]
    fn hashing_an_empty_file_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").expect("write");
        let (digest, size) = hash_input(&path).expect("hash");
        assert_eq!(size, 0);
        assert_eq!(digest, hex(&sha256(b"")));
    }

    #[test]
    fn hashing_a_missing_file_names_the_path() {
        let err = hash_input(Path::new("/nonexistent/cover.png")).expect_err("must fail");
        assert!(err.to_string().contains("cover.png"), "{err}");
    }

    #[test]
    fn reading_a_missing_manifest_names_the_path() {
        let err = Manifest::read(Path::new("/nonexistent/.stegcore-manifest.json"))
            .expect_err("must fail");
        assert!(err.to_string().contains("stegcore-manifest"), "{err}");
    }

    #[test]
    fn an_over_large_manifest_is_refused_before_it_is_parsed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(MANIFEST_FILENAME);
        std::fs::write(&path, vec![b'{'; MAX_MANIFEST_BYTES as usize + 1]).expect("write");
        let err = Manifest::read(&path).expect_err("must refuse");
        assert!(err.to_string().contains("manifest limit"), "{err}");
    }

    #[test]
    fn a_manifest_written_to_disk_reads_back_identically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(MANIFEST_FILENAME);
        let written = Manifest::seal(sample_run(), None).expect("seal");
        std::fs::write(&path, written.to_json().expect("json")).expect("write");
        let read = Manifest::read(&path).expect("read");
        assert_eq!(read, written);
    }

    #[test]
    fn malformed_json_is_refused() {
        assert!(Manifest::from_json("{").is_err());
        assert!(Manifest::from_json("").is_err());
    }
}
