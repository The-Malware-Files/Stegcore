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

//! What a passphrase guess actually costs on the shipped `extract` path.
//!
//! Run with `--release`; a debug build measures the compiler, not the algorithm.
//!
//! This times the real public entry point rather than a helper, so the figure
//! includes decode, slot generation, the length check and the error path exactly
//! as an attacker's loop would pay for them. The absolute numbers move with the
//! machine. The ratio between a wrong guess and one key derivation is the
//! property the design is trying to change, and it is machine-independent enough
//! to reason from.

use std::time::Instant;

use stegcore_engine::crypto::{self, Cipher};
use stegcore_engine::steg;

/// Carriers to measure, as (label, width, height).
///
/// A 200x200 cover is about the smallest anyone embeds into, so it is the
/// cheapest filter an attacker is handed. The large one is there to show the
/// ratio closing as the permutation grows.
const CARRIERS: &[(&str, u32, u32)] = &[("200x200", 200, 200), ("800x800", 800, 800)];

/// Repetitions for the expensive measurement. Argon2id at 128 MiB is slow enough
/// that a few runs give a stable median and more would only cost minutes.
const KDF_RUNS: usize = 3;

/// Repetitions for the cheap measurement, which is noisy at this scale.
const GUESS_RUNS: usize = 9;

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).expect("a duration is never NaN"));
    values[values.len() / 2]
}

/// A cover with enough local variation that `assess` does not reject it.
fn write_cover(path: &std::path::Path, width: u32, height: u32) {
    let mut image = image::RgbImage::new(width, height);
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for pixel in image.pixels_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        *pixel = image::Rgb([bytes[0], bytes[1], bytes[2]]);
    }
    image.save(path).expect("write the cover");
}

fn main() {
    let dir = tempfile::tempdir().expect("a scratch directory");

    println!("# Passphrase-guess cost on the shipped extract path");
    println!();

    // ── One key derivation, in isolation ────────────────────────────────────
    let salt = [0x5au8; 32];
    let kdf = median(
        (0..KDF_RUNS)
            .map(|_| {
                let start = Instant::now();
                let key = crypto::derive_key(b"a passphrase", &salt, Cipher::ChaCha20Poly1305)
                    .expect("derive_key");
                let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                std::hint::black_box(key.as_slice()[0]);
                elapsed
            })
            .collect(),
    );
    println!("Argon2id 128 MiB x 4, one derivation : {kdf:8.1} ms");
    println!();

    // ── A wrong guess against a real stego file ─────────────────────────────
    println!("| carrier | slots | wrong guess today | share that is one KDF | guesses per KDF |");
    println!("|---|---|---|---|---|");

    for (label, width, height) in CARRIERS {
        let cover = dir.path().join(format!("cover-{label}.png"));
        let stego = dir.path().join(format!("stego-{label}.png"));
        write_cover(&cover, *width, *height);

        steg::embed(
            &cover,
            b"a short message",
            b"the real passphrase",
            Cipher::ChaCha20Poly1305,
            "sequential",
            &stego,
            false,
        )
        .expect("embed");

        let guess = median(
            (0..GUESS_RUNS)
                .map(|attempt| {
                    let candidate = format!("wrong guess {attempt}");
                    let start = Instant::now();
                    let result = steg::extract(&stego, candidate.as_bytes());
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    assert!(result.is_err(), "a wrong passphrase must not extract");
                    elapsed
                })
                .collect(),
        );

        let slots = (*width as usize) * (*height as usize) * 3;
        println!(
            "| {label} | {slots} | {guess:.2} ms | {:.3}% | {:.0} |",
            guess / kdf * 100.0,
            kdf / guess
        );
    }

    println!();
    println!("## What the change costs each side");
    println!();
    println!("Seeding the permutation from the key-derivation output means a guess");
    println!("cannot reach the length check without deriving a key first.");
    println!();
    println!("wrong passphrase, after the change   : {kdf:8.1} ms  (one derivation)");
    println!(
        "legitimate extract, after the change : {:8.1} ms  (two derivations)",
        kdf * 2.0
    );
    println!();
    println!("Both sit well above the ~100 ms at which an interface has to say it is");
    println!("working, so the wizard and the GUI need a progress signal either way.");
}
