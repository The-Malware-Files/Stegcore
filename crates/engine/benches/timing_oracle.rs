// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Threat E: does extraction leak, through timing, what its error messages
//! deliberately refuse to say?
//!
//! `oracle_normalise` collapses "wrong passphrase", "legacy key file" and
//! "corrupted payload" into a single `NoPayloadFound`, so a failed extraction
//! never tells an examiner whether the file carries anything. That guarantee is
//! about the returned error. It says nothing about how long the attempt took,
//! and an examiner with a stopwatch does not need the error text.
//!
//! The comparison that matters is therefore **wrong_passphrase against
//! no_payload**: two files that both fail, one carrying a hidden payload and
//! one carrying nothing. If those two separate cleanly in time, the oracle
//! resistance is defeated without reading a single error message.
//!
//! The secondary comparison is **short against long passphrases**, which should
//! be flat because Argon2id's cost is set by its parameters rather than by the
//! length of what it is fed.
//!
//! Run:  cargo bench -p stegcore-engine --bench timing_oracle
//! Read: target/criterion/*/report/index.html, or the medians printed here.

use std::path::PathBuf;

use criterion::{criterion_group, criterion_main, Criterion};
use image::RgbImage;
use stegcore_engine::crypto::Cipher;
use stegcore_engine::steg;
use tempfile::TempDir;

const CORRECT: &[u8] = b"the-correct-passphrase-0123";
/// Same length as CORRECT, so a difference between them cannot be length.
const WRONG_SAME_LEN: &[u8] = b"the-wrongXXX-passphrase-0123";
const WRONG_SHORT: &[u8] = b"abcdefgh";
const WRONG_LONG: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123";

/// A noisy cover, large enough to be realistic and small enough that the
/// measurement is dominated by the key derivation rather than by image I/O.
fn noisy_png(path: &std::path::Path, seed: u64, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state = seed | 1;
    for px in pixels.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *px = (state >> 56) as u8;
    }
    RgbImage::from_raw(w, h, pixels)
        .expect("raw buffer")
        .save(path)
        .expect("png write");
}

struct Fixtures {
    _dir: TempDir,
    /// A cover carrying a payload.
    stego: PathBuf,
    /// A cover that has never been embedded into.
    clean: PathBuf,
}

fn build() -> Fixtures {
    let dir = TempDir::new().expect("tmp");
    let cover = dir.path().join("cover.png");
    let stego = dir.path().join("stego.png");
    let clean = dir.path().join("clean.png");

    // The clean file must be the SAME image as the stego one, differing only
    // in the embedded bits. Two independently generated images differ in
    // content, which changes adaptive block selection and shows up in the
    // timing as a difference that has nothing to do with a payload.
    noisy_png(&cover, 0xC0FFEE, 512, 512);
    std::fs::copy(&cover, &clean).expect("clone cover");

    steg::embed(
        &cover,
        b"a payload of no particular significance",
        CORRECT,
        Cipher::ChaCha20Poly1305,
        "adaptive",
        &stego,
        false,
    )
    .expect("embed");

    Fixtures {
        _dir: dir,
        stego,
        clean,
    }
}

fn timing_oracle(c: &mut Criterion) {
    let fx = build();

    let mut group = c.benchmark_group("extract");
    // Argon2id at 128 MiB by 4 iterations is paid on every attempt, so each
    // sample costs a few hundred milliseconds. Fewer samples than criterion's
    // default, traded against a run that finishes; enough to separate effects
    // that matter, since a usable oracle has to be much larger than the noise.
    group.sample_size(30);
    group.warm_up_time(std::time::Duration::from_secs(1));

    // Baseline: the payload is found. Included for scale, not for comparison:
    // an examiner who can already extract does not need a timing side channel.
    group.bench_function("correct_passphrase", |b| {
        b.iter(|| std::hint::black_box(steg::extract(&fx.stego, CORRECT).is_ok()))
    });

    // THE COMPARISON THAT MATTERS. Both of these fail with the same error.
    // If they separate in time, the error normalisation is cosmetic.
    group.bench_function("wrong_passphrase_payload_present", |b| {
        b.iter(|| std::hint::black_box(steg::extract(&fx.stego, WRONG_SAME_LEN).is_ok()))
    });
    group.bench_function("no_payload_at_all", |b| {
        b.iter(|| std::hint::black_box(steg::extract(&fx.clean, WRONG_SAME_LEN).is_ok()))
    });

    // Secondary: passphrase length must not show up in the time.
    group.bench_function("wrong_passphrase_short", |b| {
        b.iter(|| std::hint::black_box(steg::extract(&fx.stego, WRONG_SHORT).is_ok()))
    });
    group.bench_function("wrong_passphrase_long", |b| {
        b.iter(|| std::hint::black_box(steg::extract(&fx.stego, WRONG_LONG).is_ok()))
    });

    group.finish();
}

criterion_group!(benches, timing_oracle);
criterion_main!(benches);
