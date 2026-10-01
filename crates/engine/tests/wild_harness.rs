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

//! The wild-sample run, end to end, from outside the crate.
//!
//! This is the sequence the isolated machine will execute: read a manifest that
//! a human wrote, check the sample set against it, then grade. It is run from a
//! test binary rather than from inside the engine because the isolated machine
//! will be a caller, not a contributor, and a public surface that is only ever
//! exercised from inside its own crate has not been shown to be usable.
//!
//! The sample source here is a map of bytes written by this file. **It is the
//! only implementation of [`SampleSource`] anywhere**, and it exists so the
//! harness can be tested without a corpus. The real one belongs on the machine
//! that holds the corpus; see `private/plans/wild-sample-isolation.md`.
//!
//! [`SampleSource`]: stegcore_engine::wild::grade::SampleSource

use std::collections::BTreeMap;
use std::fs;

use stegcore_engine::bruteforce::digest::{hex, sha256_bytes};
use stegcore_engine::errors::StegError;
use stegcore_engine::repro::real::Real;
use stegcore_engine::wild::grade::{grade, Detector, GradeSettings, Grading, SampleSource, Silent};
use stegcore_engine::wild::manifest::WildManifest;
use stegcore_engine::wild::verify::verify_directory;

/// Bytes this file wrote, keyed by manifest id.
struct MapSource(BTreeMap<String, Vec<u8>>);

impl SampleSource for MapSource {
    fn ids(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    fn load(&self, id: &str, max_bytes: u64) -> Result<Vec<u8>, StegError> {
        let bytes = self
            .0
            .get(id)
            .ok_or_else(|| StegError::FileNotFound(id.to_string()))?;
        if bytes.len() as u64 > max_bytes {
            return Err(StegError::Internal(format!(
                "{id} is past the {max_bytes} byte cap"
            )));
        }
        Ok(bytes.clone())
    }
}

/// Scores a sample by how many of its bytes are odd, which is a deliberately
/// silly stand-in for a least-significant-bit statistic: it has the right
/// shape (a number in [0, 1] that rises with payload) and none of the real
/// detector's cost.
struct OddByteDetector;

impl Detector for OddByteDetector {
    fn name(&self) -> &str {
        "odd-byte-fixture"
    }

    fn score(&self, bytes: &[u8]) -> Result<Real, StegError> {
        if bytes.is_empty() {
            return Err(StegError::EmptyPayload);
        }
        let odd = bytes.iter().filter(|b| *b % 2 == 1).count();
        Real::new(odd as f64 / bytes.len() as f64)
    }
}

/// A sample's bytes: `odd` of them odd and the rest even, so its score is
/// known before the detector runs, with `salt` varying the values so that two
/// samples at the same score are still two different files with two different
/// digests. A corpus where every carrier is byte-identical would not exercise
/// anything, and the manifest refuses it anyway.
fn bytes_with(odd: usize, total: usize, salt: usize) -> Vec<u8> {
    (0..total)
        .map(|i| {
            let step = (2 * ((salt + i) % 100)) as u8;
            if i < odd {
                1 + step
            } else {
                2 + step
            }
        })
        .collect()
}

struct Corpus {
    dir: tempfile::TempDir,
    manifest: WildManifest,
    source: MapSource,
}

/// Write a corpus to disk, and write the manifest that describes it as TOML
/// text, so the test goes through the parser a human's file would.
fn corpus() -> Corpus {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut entries = String::new();
    let mut source = BTreeMap::new();

    // Twenty-five carriers at 70% odd bytes, five at 10%, and forty clean
    // files at 2% to 12%. The clean arm sets the threshold; the carriers at 10%
    // sit inside the clean range on purpose, because a wild corpus always has
    // some, and a harness that reports 100% on a corpus like this is a harness
    // with a bug.
    let mut plan: Vec<(String, usize, bool, &str)> = Vec::new();
    for i in 0..25 {
        plan.push((format!("worok-{i:03}"), 700, true, "worok"));
    }
    for i in 0..5 {
        plan.push((format!("worok-quiet-{i:03}"), 50, true, "worok"));
    }
    for i in 0..8 {
        plan.push((format!("steam-{i:03}"), 700, true, "steamhide"));
    }
    for i in 0..40 {
        plan.push((format!("clean-{i:03}"), 20 + i * 2, false, "benign-png"));
    }

    for (salt, (id, odd, carries, family)) in plan.iter().enumerate() {
        let bytes = bytes_with(*odd, 1000, salt);
        let digest = hex(&sha256_bytes(&bytes));
        fs::write(dir.path().join(&digest), &bytes).expect("write the sample");
        source.insert(id.clone(), bytes);

        let (payload, tool) = if *carries {
            ("carries", "tool = \"fixture-lsb\"\n")
        } else {
            ("clean", "")
        };
        entries.push_str(&format!(
            "\n[[sample]]\n\
             id = \"{id}\"\n\
             sha256 = \"{digest}\"\n\
             bytes = 1000\n\
             media = \"application/octet-stream\"\n\
             family = \"{family}\"\n\
             payload = \"{payload}\"\n\
             {tool}\
             truth_basis = \"Written by this test, so the label is the construction.\"\n\
             \n\
             [sample.provenance]\n\
             origin = \"Written by tests/wild_harness.rs.\"\n\
             reobtain = \"Re-run the test.\"\n\
             verified = \"2026-10-01\"\n\
             note = \"These bytes exist only inside this test. Nothing was fetched, and \
             nothing here describes a real sample.\"\n\
             \n\
             [sample.terms]\n\
             licence = \"AGPL-3.0-or-later\"\n\
             redistributable = true\n\
             note = \"Test fixture.\"\n"
        ));
    }

    let text = format!(
        "format = 1\n\
         corpus = \"harness-fixture\"\n\
         note = \"\"\"\n\
         A synthetic stand-in for the D2 corpus. Every byte in it was written by the \n\
         test that reads it, so the ground truth is the construction rather than a \n\
         claim about a real file.\n\
         \"\"\"\n\
         compiled = \"2026-10-01\"\n{entries}"
    );

    let manifest = WildManifest::from_toml(&text).expect("the fixture manifest parses");
    Corpus {
        dir,
        manifest,
        source: MapSource(source),
    }
}

fn run(corpus: &Corpus, integrity_verified: bool) -> Grading {
    grade(
        &corpus.manifest,
        &corpus.source,
        &OddByteDetector,
        &GradeSettings {
            target_fpr: 0.05,
            integrity_verified,
            ..Default::default()
        },
        &mut Silent,
    )
    .expect("grade")
}

#[test]
fn the_whole_run_goes_manifest_then_verify_then_grade() {
    let corpus = corpus();

    let integrity = verify_directory(&corpus.manifest, corpus.dir.path()).expect("verify");
    assert!(integrity.is_clean(), "{}", integrity.human_summary());
    assert_eq!(integrity.matched.len(), 78);

    let grading = run(&corpus, integrity.is_clean());
    assert!(grading.integrity_verified);

    // Forty clean samples at a 5% target allows two false positives, so the
    // threshold sits at the third-highest clean score.
    let achieved = grading.achieved_fpr.as_ref().expect("a clean arm exists");
    assert!(
        achieved.rate.get() <= 0.05,
        "achieved {} must be at or under the target",
        achieved.rate
    );
    assert!(grading.clean_support_sufficient, "40 * 0.05 is over one");

    // Worok: 25 loud carriers detected, 5 quiet ones missed. The harness is
    // expected to report 83%, not 100%, and this is the assertion that would
    // fail if the quiet arm were silently dropped.
    let worok = grading.stego_families.get("worok").expect("worok");
    assert_eq!((worok.samples, worok.hits), (30, 25));
    assert!(worok.sufficient_support);
    assert!(worok.ci95_low.get() < worok.rate.get());

    let steam = grading.stego_families.get("steamhide").expect("steamhide");
    assert_eq!((steam.samples, steam.hits), (8, 8));
    assert!(
        !steam.sufficient_support,
        "eight samples is under the floor and must be flagged, not quoted"
    );

    assert!(grading.errored.is_empty());
    assert!(grading.missing_from_source.is_empty());
    assert!(grading.skipped_unlabelled.is_empty());
}

#[test]
fn the_grading_report_is_the_artefact_that_leaves_the_machine() {
    // Results leave the isolated machine as JSON and nothing else does. So the
    // report has to carry everything a reader needs and nothing a sample could
    // hide in: no bytes, no paths, no file names.
    let corpus = corpus();
    let grading = run(&corpus, true);
    let text = serde_json::to_string_pretty(&grading).expect("write");

    assert!(!text.contains(&corpus.dir.path().display().to_string()));
    assert!(!text.contains("/tmp"));
    assert!(!text.contains("accuracy"));
    assert!(text.contains("worok"));
    assert!(text.contains("ci95_low"));

    let read: Grading = serde_json::from_str(&text).expect("read");
    assert_eq!(grading, read);
    assert!(read.human_summary().contains("harness-fixture"));
}

#[test]
fn a_verification_failure_is_visible_before_any_grading_happens() {
    let corpus = corpus();
    let victim = corpus.manifest.samples[0].sha256.clone();
    fs::write(
        corpus.dir.path().join(&victim),
        bytes_with(999, 1000, 7), // same length, different content
    )
    .expect("substitute");

    let integrity = verify_directory(&corpus.manifest, corpus.dir.path()).expect("verify");
    assert!(!integrity.is_clean());
    assert_eq!(integrity.digest_mismatch.len(), 1);
    assert!(integrity.size_mismatch.is_empty());

    // The grader cannot tell, which is exactly why the caller has to state it
    // and the report has to carry the statement.
    let grading = run(&corpus, integrity.is_clean());
    assert!(!grading.integrity_verified);
    assert!(grading.human_summary().starts_with("Caution:"));
}

#[test]
fn a_stale_manifest_is_reported_against_a_date_the_caller_supplies() {
    let corpus = corpus();
    assert!(corpus
        .manifest
        .stale("2026-10-01")
        .expect("today")
        .is_empty());
    let stale = corpus.manifest.stale("2027-12-01").expect("much later");
    assert_eq!(stale.len(), 78);
    assert!(stale[0].age_days > 180);
}
