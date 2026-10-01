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

//! End-to-end attribution against files written by the real tools.
//!
//! The unit tests in `bruteforce::openstego` plant a header with the same code
//! that reads it, which proves the reader is self-consistent and nothing more.
//! These tests read files produced by **OpenStego 0.8.6 itself** (the vendored
//! jar at `vendor/openstego.jar`) and by **Steghide 0.5.1 itself**, so they
//! would fail if the reconstruction drifted away from the tools it claims to
//! reproduce.
//!
//! How the fixtures in `tests/assets/bruteforce` were produced, so they can be
//! regenerated:
//!
//! ```text
//! java -jar vendor/openstego.jar embed -a randomlsb -mf tiny.txt \
//!      -cf clean_cover.png -sf openstego_randomlsb_password.png -p hunter2
//! java -jar vendor/openstego.jar embed -a randomlsb -mf tiny.txt \
//!      -cf clean_cover.png -sf openstego_randomlsb_nopassword.png
//! steghide embed -cf clean_cover.bmp -ef tiny.txt -sf steghide_bmp_password_x.bmp -p x
//! ```
//!
//! where `tiny.txt` holds the ten bytes `top secret`.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use stegcore_engine::bruteforce::{openstego, search, steghide, Probe, SearchLimits, StopReason};

/// Checked when this file compiles rather than when it runs. The Steghide tests
/// below assert the *current* state of attribution, which is unfinished; the day
/// somebody reconstructs the traversal, this stops the build and makes them
/// rewrite those expectations rather than letting a now-wrong one pass silently.
const _: () = assert!(!steghide::TRAVERSAL_RECONSTRUCTED);

fn asset(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("assets")
        .join("bruteforce")
        .join(name)
}

fn no_cancel() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

// ---------------------------------------------------------------------------
// OpenStego Random LSB (E2)
// ---------------------------------------------------------------------------

#[test]
fn a_wordlist_recovers_the_password_from_a_real_openstego_file() {
    let carrier = openstego::Carrier::load(&asset("openstego_randomlsb_password.png")).unwrap();
    let probe = openstego::WordlistProbe::new(
        &carrier,
        vec![
            "password".into(),
            "letmein".into(),
            "qwerty".into(),
            "hunter2".into(),
            "dragon".into(),
        ],
    );
    let limits = SearchLimits {
        max_attempts: 100,
        chunk: 1,
        threads: 4,
        ..Default::default()
    };
    let report = search(&probe, &limits, &no_cancel(), |_| {}).unwrap();

    let hit = report
        .hit
        .expect("the password is in the wordlist, so the search must find it");
    assert_eq!(hit.index, 3, "hunter2 is the fourth candidate");
    assert_eq!(hit.label, "password \"hunter2\"");
    assert_eq!(report.stop_reason, StopReason::Found);
    assert_eq!(report.tool, "OpenStego");

    let header = hit.evidence;
    assert_eq!(header.header_version, openstego::HEADER_VERSION);
    assert_eq!(header.channel_bits_used, 1);
    assert_eq!(header.file_name_length, 8, "tiny.txt is eight characters");
    assert!(header.compressed, "OpenStego compresses by default");
    assert!(!header.encrypted);
    assert!(header.is_self_consistent());
    assert!(header.data_length > 0 && header.data_length < 1000);
    assert_eq!(header.seed, openstego::password_seed("hunter2"));
}

#[test]
fn the_no_password_case_needs_a_single_candidate_and_no_search_at_all() {
    // The finding worth having: OpenStego short-circuits an absent password to
    // a fixed constant, so a Random LSB embed with no password is identified by
    // trying exactly one seed. The engine does not currently make this check.
    let carrier = openstego::Carrier::load(&asset("openstego_randomlsb_nopassword.png")).unwrap();
    let header = carrier
        .header_for_seed(openstego::EMPTY_PASSWORD_SEED)
        .expect("a no-password Random LSB embed is readable with no search");
    assert_eq!(header.channel_bits_used, 1);
    assert!(header.is_self_consistent());

    let probe = openstego::SeedRangeProbe::empty_password(&carrier);
    assert_eq!(probe.space_size(), 1);
    let report = search(&probe, &SearchLimits::default(), &no_cancel(), |_| {}).unwrap();
    assert_eq!(report.stop_reason, StopReason::Found);
    assert_eq!(report.attempted, 1);
}

#[test]
fn a_password_protected_file_is_not_mistaken_for_the_no_password_case() {
    let carrier = openstego::Carrier::load(&asset("openstego_randomlsb_password.png")).unwrap();
    assert!(
        carrier
            .header_for_seed(openstego::EMPTY_PASSWORD_SEED)
            .is_none(),
        "the fixed no-password seed must not read a header out of a password-protected file"
    );
}

#[test]
fn a_clean_cover_is_not_attributed_to_openstego_by_any_candidate() {
    // The false-positive side of the claim. The stamp is nine bytes, so a wrong
    // read matching it has a probability of about 2^-72; this is a sanity floor
    // under that arithmetic rather than a measurement of it.
    let carrier = openstego::Carrier::load(&asset("clean_cover.png")).unwrap();
    let probe = openstego::SeedRangeProbe::new(&carrier, 0, 50_000);
    let limits = SearchLimits {
        max_attempts: 50_000,
        threads: 4,
        ..Default::default()
    };
    let report = search(&probe, &limits, &no_cancel(), |_| {}).unwrap();
    assert!(
        report.hit.is_none(),
        "a clean cover was attributed to OpenStego, which would be a false positive"
    );
    assert_eq!(report.stop_reason, StopReason::Exhausted);
    assert_eq!(report.attempted, 50_000);
}

#[test]
fn a_real_openstego_file_is_found_at_the_same_index_at_every_thread_count() {
    let carrier = openstego::Carrier::load(&asset("openstego_randomlsb_password.png")).unwrap();
    let words: Vec<String> = (0..200)
        .map(|i| {
            if i == 137 {
                "hunter2".into()
            } else {
                format!("wrong{i}")
            }
        })
        .collect();
    for threads in [1usize, 2, 8] {
        let probe = openstego::WordlistProbe::new(&carrier, words.clone());
        let limits = SearchLimits {
            max_attempts: 200,
            chunk: 7,
            threads,
            ..Default::default()
        };
        let report = search(&probe, &limits, &no_cancel(), |_| {}).unwrap();
        assert_eq!(
            report.hit.map(|h| h.index),
            Some(137),
            "thread count {threads} changed the answer"
        );
    }
}

/// Measured throughput, printed rather than asserted.
///
/// There is no threshold here on purpose. A timing assertion on shared
/// continuous-integration hardware is the textbook flaky test, and baseline
/// section 7 forbids those. What this does is make the number observable with
/// `cargo test -- --nocapture`, so the figure quoted to an operator can be
/// re-measured on the machine they are actually running on rather than taken
/// from a document.
#[test]
fn throughput_is_measured_and_reported() {
    let carrier = openstego::Carrier::load(&asset("clean_cover.png")).unwrap();
    let probe = openstego::SeedRangeProbe::new(&carrier, 1, 40_000);
    let limits = SearchLimits {
        max_attempts: 40_000,
        threads: 0,
        ..Default::default()
    };
    let report = search(&probe, &limits, &no_cancel(), |_| {}).unwrap();
    let rate = report.rate_per_second;
    let full_32_bit_seconds = (u64::from(u32::MAX) as f64) / rate.max(1.0);
    println!(
        "OpenStego probe: {:.0} candidates per second over {} attempts in {:?}. \
         A full 32 bit sweep at that rate would take {:.1} hours; OpenStego's own key space is \
         60 bits, which is {:.0} times larger again.",
        rate,
        report.attempted,
        report.elapsed,
        full_32_bit_seconds / 3600.0,
        (1u64 << 60) as f64 / (u64::from(u32::MAX) as f64),
    );
    assert!(rate > 0.0, "the search reported no throughput at all");
}

// ---------------------------------------------------------------------------
// Steghide (E1)
// ---------------------------------------------------------------------------

#[test]
fn a_real_steghide_bmp_parses_into_a_sample_space() {
    // What is built for Steghide, measured against a file Steghide wrote: the
    // sample space is read correctly, and it has the size the BMP implies.
    let space = steghide::SampleSpace::load(&asset("steghide_bmp_password_x.bmp")).unwrap();
    assert_eq!(space.carrier(), steghide::CarrierKind::Bmp24);
    // 96 by 96 pixels, three bytes each, with no row padding needed at 96 wide.
    assert_eq!(space.len(), 96 * 96 * 3);
    assert!(space.bit(0).is_some());
    assert!(space.bit(space.len()).is_none());
}

#[test]
fn a_real_steghide_file_differs_from_its_cover_only_in_sample_parities() {
    // Evidence that the sample space is the right one: everything Steghide
    // changed is inside it, and the header bytes before it are untouched.
    let stego = std::fs::read(asset("steghide_bmp_password_x.bmp")).unwrap();
    let cover = std::fs::read(asset("clean_cover.bmp")).unwrap();
    assert_eq!(stego.len(), cover.len(), "Steghide did not change the size");
    assert_eq!(
        stego[..54],
        cover[..54],
        "the BMP headers must be byte identical, which is why the file still looks like a BMP"
    );
    let changed = stego[54..]
        .iter()
        .zip(cover[54..].iter())
        .filter(|(a, b)| a != b)
        .count();
    assert!(
        changed > 0,
        "the fixture is supposed to carry a Steghide payload"
    );
    println!(
        "Steghide changed {changed} of {} pixel bytes.",
        stego.len() - 54
    );
}

#[test]
fn steghide_attribution_declares_itself_unfinished_rather_than_guessing() {
    // The guard that keeps this honest. While the traversal is unreconstructed,
    // no read of a real Steghide file can confirm the signature, and nothing
    // here may be wired into the analyser as though it could.

    let space = steghide::SampleSpace::load(&asset("steghide_bmp_password_x.bmp")).unwrap();
    let mut sequential = steghide::SequentialTraversal::new(space.len());
    let bits = space.read_bits(&mut sequential, 24).unwrap();
    let prefix = steghide::confirm(&bits).unwrap();
    assert!(
        !prefix.magic_matched,
        "file order is not Steghide's order, so this must not confirm; if it ever does, \
         the traversal has been reconstructed and this test needs rewriting"
    );
}

#[test]
fn a_steghide_jpeg_is_refused_with_the_reason_rather_than_silently_missed() {
    let bytes = [0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    let err = steghide::SampleSpace::from_bytes(&bytes).unwrap_err();
    let message = err.to_string();
    assert!(message.contains("JPEG"), "got: {message}");
}
