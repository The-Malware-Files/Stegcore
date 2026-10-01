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
//
// The slot-uniqueness invariant behind the one production `unsafe` island.
//
// `embed_bits` in `crates/engine/src/steg.rs` switches to scoped threads and
// raw-pointer writes once a payload needs more than 512,000 bits, roughly a
// 64 KiB message. Those writes are sound only while no two threads touch the
// same byte, which means the slot list must contain no duplicate index and no
// index past the end of the pixel buffer.
//
// The engine checks both preconditions at runtime, in every build, right before
// the unsafe block, and returns `StegError::Internal` rather than racing:
//
//     "internal error: embed slot out of bounds"
//     "internal error: duplicate embed slot would race"
//
// So a violated invariant is a loud error, not undefined behaviour, and these
// tests measure it from outside the crate. A successful embed above the
// threshold is positive evidence that the check passed on that input; a
// successful round-trip is positive evidence that every bit landed where
// extraction expects it, which a race would not reliably produce.
//
// Why the invariant holds structurally, which is what these tests sample:
//
//   sequential  slots = permute_set((0..total).collect(), pass)
//   adaptive    slots = permute_set(index_set_adaptive(rgb), pass)
//
// `(0..total)` is distinct by construction. `index_set_adaptive` walks a grid
// of non-overlapping 8x8 blocks, each pixel belongs to exactly one block, and
// each selected pixel contributes its three distinct channel offsets, so it too
// is distinct. `permute_set` is a `slice::shuffle` of an owned Vec: a
// permutation cannot create a duplicate or an out-of-range value. Both paths
// therefore satisfy the precondition for any cover.

use std::path::{Path, PathBuf};

use proptest::prelude::*;
use stegcore_engine::crypto::Cipher;
use stegcore_engine::steg;

/// Payload size that forces the parallel path. The threshold is 512,000 bits,
/// so 96 KiB of payload is comfortably past it even after the metadata header
/// and the AEAD tag are accounted for.
const PARALLEL_PAYLOAD: usize = 96 * 1024;

/// A textured cover large enough to hold `PARALLEL_PAYLOAD` in adaptive mode,
/// which only uses high-variance blocks and so has far less capacity than the
/// full pixel count suggests.
fn textured_png(dir: &Path, w: u32, h: u32, seed: u64) -> PathBuf {
    let path = dir.join(format!("cover-{w}x{h}-{seed}.png"));
    let mut state = seed | 1;
    let mut data = vec![0u8; (w * h * 3) as usize];
    for b in data.iter_mut() {
        // xorshift64*, inline so the fixture needs no rng dependency and is
        // reproducible across machines.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        *b = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as u8;
    }
    image::RgbImage::from_raw(w, h, data)
        .expect("raw buffer matches dimensions")
        .save(&path)
        .expect("write cover");
    path
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The direct assertion: cross the threshold and the embed must succeed, which
/// means the duplicate-slot and out-of-bounds checks both passed.
#[test]
fn parallel_path_embed_accepts_the_slot_set_in_both_modes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cover = textured_png(dir.path(), 900, 900, 0xA11CE);
    let msg = payload(PARALLEL_PAYLOAD);

    for mode in ["sequential", "adaptive"] {
        let out = dir.path().join(format!("stego-{mode}.png"));
        let r = steg::embed(
            &cover,
            &msg,
            b"slot-uniqueness-probe",
            Cipher::ChaCha20Poly1305,
            mode,
            &out,
            false,
        );
        match r {
            Ok(_) => {}
            Err(e) => panic!("{mode} embed above the parallel threshold failed: {e:?}"),
        }
    }
}

/// A race would corrupt bits non-deterministically, so a byte-exact round-trip
/// above the threshold is the strongest cheap evidence the writes did not
/// overlap. Repeated, because a race that fires rarely would not fire once.
#[test]
fn parallel_path_round_trips_byte_for_byte_repeatedly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cover = textured_png(dir.path(), 900, 900, 0xBEEF);
    let msg = payload(PARALLEL_PAYLOAD);

    for attempt in 0..4 {
        let out = dir.path().join(format!("stego-{attempt}.png"));
        steg::embed(
            &cover,
            &msg,
            b"slot-uniqueness-probe",
            Cipher::ChaCha20Poly1305,
            "adaptive",
            &out,
            false,
        )
        .unwrap_or_else(|e| panic!("attempt {attempt} embed failed: {e:?}"));
        let got = steg::extract(&out, b"slot-uniqueness-probe")
            .unwrap_or_else(|e| panic!("attempt {attempt} extract failed: {e:?}"));
        assert_eq!(got, msg, "attempt {attempt} recovered a different payload");
    }
}

// A "two embeds of the same input produce identical bytes" test was written
// here first and removed, because it asserted a property the design
// deliberately does not have: `embed` draws a fresh salt and nonce from
// `OsRng` on every call, so identical inputs must produce different stego
// bytes. Reproducibility in the baseline sense governs analysis output, not a
// ciphertext whose whole purpose is to differ. The repeated round-trip above is
// what actually bounds the race.

proptest! {
    // The randomised arm: vary cover geometry and passphrase, stay above the
    // parallel threshold, and require the embed to be accepted every time.
    // Few cases by design, because each one is a 96 KiB embed over an 800k
    // subpixel cover.
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(6)
    ))]

    #[test]
    fn parallel_path_never_reports_a_duplicate_or_out_of_bounds_slot(
        w in 820u32..=900,
        h in 820u32..=900,
        seed in any::<u64>(),
        pass in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cover = textured_png(dir.path(), w, h, seed);
        let msg = payload(PARALLEL_PAYLOAD);
        let out = dir.path().join("prop.png");

        let r = steg::embed(
            &cover,
            &msg,
            &pass,
            Cipher::ChaCha20Poly1305,
            "adaptive",
            &out,
            false,
        );
        match r {
            Ok(_) => {}
            // Capacity is a legitimate refusal for a cover whose textured
            // fraction is small; the invariant violations are not.
            Err(e) => {
                let s = format!("{e:?}");
                prop_assert!(
                    !s.contains("duplicate embed slot") && !s.contains("slot out of bounds"),
                    "slot invariant violated at {w}x{h}: {s}"
                );
            }
        }
    }
}
