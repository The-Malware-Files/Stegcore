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

//! A score that goes into a JSON report has to come back out of it unchanged.
//!
//! It did not. `serde_json`'s default number parser is a fast approximation that
//! can land one unit in the last place away from the value that was written:
//! `0x3f948b0fcd6e9e08` was written as `0.020061728395061734`, which is the
//! correct shortest decimal for it, and read back as `0x3f948b0fcd6e9e09`.
//! Measured over 200,000 pseudo-random values in [0, 1), the range most of an
//! analysis report's numbers live in, 21,153 of them (10.6%) came back changed.
//!
//! **What was actually broken, and what was not.** The writer was always correct:
//! it emits the shortest decimal that identifies the value uniquely, and both
//! Python's `json` and JavaScript's `JSON.parse` read those back bit for bit,
//! measured on the same corpus with zero losses. The lossy reader was ours. So
//! the fix is serde_json's `float_roundtrip` feature, enabled in every crate in
//! this workspace that touches a report, and it changes no output byte, no stored
//! report and no consumer. Serialising scores as fixed-point integers or as
//! decimal strings would have changed the wire format to fix a bug that was never
//! in the wire format.
//!
//! This file is the gate. The claim stayed wrong because nothing asserted it.

use stegcore_engine::analysis::{
    AnalysisReport, BlockEntropy, Confidence, Coverage, DistBin, TestResult, Verdict,
};

/// The value from the original report, plus the neighbours either side of it, the
/// classic awkward binary fractions, and the extremes of the f64 range.
fn awkward_values() -> Vec<f64> {
    let mut v: Vec<f64> = vec![
        f64::from_bits(0x3f94_8b0f_cd6e_9e08),
        f64::from_bits(0x3f94_8b0f_cd6e_9e07),
        f64::from_bits(0x3f94_8b0f_cd6e_9e09),
        0.1,
        0.2,
        0.3,
        1.0 / 3.0,
        2.0 / 3.0,
        f64::MIN_POSITIVE,
        f64::MAX,
        -f64::MAX,
        0.0,
        -0.0,
        1.0,
        // The neighbour above 0.5, spelled through the bits because `next_up`
        // only stabilised in 1.86 and this workspace targets 1.77.2.
        f64::from_bits(0.5_f64.to_bits() + 1),
        0.9999999999999999,
    ];
    // And a spread of ordinary scores, since that is what a real report holds.
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    for _ in 0..5_000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        v.push((state >> 11) as f64 / (1u64 << 53) as f64);
    }
    v
}

#[test]
fn every_f64_a_report_can_hold_survives_a_json_round_trip_exactly() {
    for value in awkward_values() {
        let text = serde_json::to_string(&value).unwrap();
        let back: f64 = serde_json::from_str(&text).unwrap();
        assert_eq!(
            back.to_bits(),
            value.to_bits(),
            "{value} serialised as {text} and came back as {back}"
        );
    }
}

/// Build a report whose every numeric field holds a value known to be awkward.
fn report_with(values: &[f64]) -> AnalysisReport {
    let pick = |i: usize| values[i % values.len()];
    AnalysisReport {
        file: std::path::PathBuf::from("/covers/holiday.png"),
        format: "png".into(),
        tests: (0..5)
            .map(|t| TestResult {
                name: format!("Detector {t}"),
                score: pick(t),
                confidence: Confidence::Medium,
                detail: format!("score {:.2}", pick(t)),
                distribution: Some(
                    (0..16)
                        .map(|b| DistBin {
                            label: format!("bin {b}"),
                            expected: pick(t * 16 + b),
                            observed: pick(t * 16 + b + 1),
                        })
                        .collect(),
                ),
            })
            .collect(),
        verdict: Verdict::Suspicious,
        overall_score: pick(7),
        tool_fingerprint: Some("something".into()),
        tool_fingerprint_tier: Some("heuristic".into()),
        block_entropy: Some(BlockEntropy {
            cols: 8,
            rows: 6,
            values: (0..48).map(|i| pick(i + 11)).collect(),
        }),
        coverage: Some(Coverage {
            checked: vec!["everything".into()],
            not_checked: vec![],
            adequate: true,
        }),
    }
}

#[test]
fn a_whole_report_round_trips_bit_for_bit_and_reserialises_byte_for_byte() {
    let values = awkward_values();
    let original = report_with(&values);

    let json = serde_json::to_string(&original).unwrap();
    let parsed: AnalysisReport = serde_json::from_str(&json).unwrap();

    // Every number, by its bits. Comparing with `==` would pass on a value one
    // unit in the last place out, which is the whole defect.
    assert_eq!(
        parsed.overall_score.to_bits(),
        original.overall_score.to_bits(),
        "overall_score drifted"
    );
    assert_eq!(parsed.tests.len(), original.tests.len());
    for (p, o) in parsed.tests.iter().zip(&original.tests) {
        assert_eq!(p.score.to_bits(), o.score.to_bits(), "{}: score", o.name);
        let pb = p.distribution.as_ref().unwrap();
        let ob = o.distribution.as_ref().unwrap();
        for (a, b) in pb.iter().zip(ob) {
            assert_eq!(a.expected.to_bits(), b.expected.to_bits(), "{}", b.label);
            assert_eq!(a.observed.to_bits(), b.observed.to_bits(), "{}", b.label);
        }
    }
    let pe = parsed.block_entropy.as_ref().unwrap();
    let oe = original.block_entropy.as_ref().unwrap();
    for (a, b) in pe.values.iter().zip(&oe.values) {
        assert_eq!(a.to_bits(), b.to_bits(), "block entropy value");
    }

    // The property a consumer actually cares about: read a report, write it
    // again, get the same bytes. This is what "byte-identical output" has to mean
    // for a JSON report, and it was not true.
    assert_eq!(
        serde_json::to_string(&parsed).unwrap(),
        json,
        "a report does not survive a read and a write unchanged"
    );
}

#[test]
fn a_real_analysis_report_reserialises_byte_for_byte() {
    // The synthetic report above covers the awkward values; this covers the real
    // pipeline, so a future change to the report's shape cannot slip past by
    // adding a field nothing round trips.
    let path = std::env::temp_dir().join("report_roundtrip_cover.png");
    let mut img = image::RgbImage::new(64, 64);
    let mut state: u64 = 7;
    for p in img.pixels_mut() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let b = (state >> 56) as u8;
        *p = image::Rgb([b, b.wrapping_add(31), b.wrapping_add(97)]);
    }
    img.save(&path).unwrap();

    let json = stegcore_engine::analysis::analyse(&path).unwrap();
    let parsed: AnalysisReport = serde_json::from_str(&json).unwrap();
    assert_eq!(serde_json::to_string(&parsed).unwrap(), json);

    std::fs::remove_file(&path).ok();
}
