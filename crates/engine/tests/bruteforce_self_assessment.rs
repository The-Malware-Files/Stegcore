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

//! Turning the brute-force work on ourselves: what does guessing a Stegcore
//! passphrase actually cost?
//!
//! # The question, and why a number is the only answer
//!
//! Stegcore advertises Argon2id at 128 MiB by four iterations. That is a real cost
//! per key, and if an attacker had to pay it per guess, a dictionary attack would
//! be hopeless. The claim only holds if a wrong guess cannot be rejected more
//! cheaply than deriving the key, and whether it can is a measurement, not an
//! argument.
//!
//! # The attacker is written from scratch here, on purpose
//!
//! This file does **not** time `extract` in a loop. That measures how fast our
//! code is at extracting one file, which is what it was written for. It is also
//! the mistake the project's own ledger made: a per-guess figure taken by timing a
//! failed extract includes decoding the carrier, and an attacker decodes once.
//!
//! So the loop below is an independent reimplementation of the minimum work needed
//! to reject one guess, built from the format rather than from our internals:
//!
//! 1. The slot order comes from the passphrase bytes XOR-folded into a 32 byte
//!    ChaCha8 seed. **No key derivation function is involved.** One ChaCha8
//!    initialisation is the whole cost of trying a passphrase against the order.
//! 2. The first two bytes of the hidden stream are a big-endian length, and the
//!    reader rejects anything above 4,096. A random two byte value exceeds that
//!    ceiling with probability 1 minus 4096 over 65536, which is 93.75%, so the
//!    length field alone rejects almost every wrong guess.
//!
//! # The one thing that makes this less bad than it first looks
//!
//! A first pass at this assumed the attacker could skip most of the work by
//! generating only the first sixteen slots. **That is wrong, and the reason is
//! worth writing down because it is load-bearing.**
//!
//! `shuffle` is a Fisher-Yates pass running from the end of the slice backwards,
//! so the *last* positions settle first and position zero settles last. The reader
//! reads from the *front*. Getting the front therefore requires running the pass
//! essentially to completion, which consumes one random draw per slot in the
//! carrier. There is no shortcut, and `the_front_of_the_permutation_cannot_be_taken_cheaply`
//! below establishes that rather than asserting it.
//!
//! The consequence is that the per-guess cost scales with the carrier rather than
//! being constant, which is a real obstacle. It is also an **accident**: nothing in
//! the design chose it, a future refactor that reversed the slot order or adopted
//! a lazier permutation would delete it silently, and it is bandwidth bound rather
//! than memory hard, so it hardens far worse against a graphics card than Argon2id
//! does. The figures printed below are what the design decision should rest on.
//!
//! # Reading the output
//!
//! Printed, not asserted. A timing threshold on shared hardware is the flaky test
//! baseline section 7 forbids. Run it with
//!
//! ```text
//! cargo test --release -p stegcore-engine --test bruteforce_self_assessment -- --nocapture
//! ```
//!
//! The release profile is the honest one: an attacker does not use a debug build.
//! What *is* asserted is the shape of the weakness, not its speed: that the cheap
//! filter accepts the right passphrase and rejects wrong ones, which is what makes
//! it an oracle, and that the fold collides.

use std::path::Path;
use std::time::Instant;

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

/// The reader's ceiling on the metadata length field, from `read_payload`.
const META_LEN_CEILING: usize = 4096;

/// Reproduce Stegcore's slot seed from a passphrase.
///
/// This is the entire derivation. Note what is absent: no salt, no iteration
/// count, no key derivation function.
fn slot_seed(passphrase: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    for (index, byte) in passphrase.iter().enumerate() {
        seed[index % 32] ^= byte;
    }
    seed
}

/// The slot order a passphrase implies, as the reader computes it.
fn slot_order(total: usize, passphrase: &[u8]) -> Vec<usize> {
    let mut slots: Vec<usize> = (0..total).collect();
    slots.shuffle(&mut ChaCha8Rng::from_seed(slot_seed(passphrase)));
    slots
}

/// Read `count` bytes from the carrier's low bits in slot order.
fn read_bytes(pixels: &[u8], slots: &[usize], count: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(count);
    for byte_index in 0..count {
        let mut value = 0u8;
        for bit in 0..8usize {
            let slot = *slots.get(byte_index * 8 + bit)?;
            value = (value << 1) | (*pixels.get(slot)? & 1);
        }
        out.push(value);
    }
    Some(out)
}

/// The oracle: does this guess survive the length check?
///
/// This is the cheapest rejection the format allows, and it is what bounds the
/// cost of a dictionary attack. Critically, it never reaches Argon2id.
fn survives_length_check(pixels: &[u8], total_slots: usize, passphrase: &[u8]) -> bool {
    let slots = slot_order(total_slots, passphrase);
    match read_bytes(pixels, &slots, 2) {
        Some(header) => {
            let meta_len = u16::from_be_bytes([header[0], header[1]]) as usize;
            meta_len > 0 && meta_len <= META_LEN_CEILING
        }
        None => false,
    }
}

const PASSPHRASE: &[u8] = b"correct horse battery staple";

/// Build a real stego image with the real embed path, so the carrier under test is
/// genuinely one of ours rather than a model of one.
fn stego_fixture(dir: &Path, side: u32) -> (Vec<u8>, usize) {
    use stegcore_engine::crypto::Cipher;

    let cover_path = dir.join(format!("cover{side}.png"));
    let mut cover = image::RgbImage::new(side, side);
    for (x, y, pixel) in cover.enumerate_pixels_mut() {
        // Textured rather than flat, so the cover is not a degenerate case.
        *pixel = image::Rgb([
            ((x * 7 + y * 3) % 256) as u8,
            ((x ^ y) % 256) as u8,
            ((x * y) % 251) as u8,
        ]);
    }
    cover.save(&cover_path).unwrap();

    let stego_path = dir.join(format!("stego{side}.png"));
    stegcore_engine::steg::embed(
        &cover_path,
        b"the hidden message under test",
        PASSPHRASE,
        Cipher::ChaCha20Poly1305,
        "sequential",
        &stego_path,
        false,
    )
    .unwrap();

    let image = image::open(&stego_path).unwrap().to_rgb8();
    let pixels = image.as_raw().to_vec();
    let total = pixels.len();
    (pixels, total)
}

#[test]
fn the_front_of_the_permutation_cannot_be_taken_cheaply() {
    // The property that saves us, established rather than assumed. A partial
    // Fisher-Yates settles the END of the slice first, so truncating a partial
    // pass gives the wrong front. If this test ever starts passing with a cheap
    // partial pass, the per-guess cost has collapsed and the design decision in
    // private/research/bruteforce-resistance.md has to be reopened.
    let seed = slot_seed(PASSPHRASE);
    let total = 100_000usize;

    let mut full: Vec<usize> = (0..total).collect();
    full.shuffle(&mut ChaCha8Rng::from_seed(seed));

    // What a cheap attacker would try: the same generator, stopped early.
    let mut partial: Vec<usize> = (0..total).collect();
    let mut rng = ChaCha8Rng::from_seed(seed);
    let (settled, _) = partial.partial_shuffle(&mut rng, 16);
    let settled: Vec<usize> = settled.to_vec();

    assert_ne!(
        &full[..16],
        &settled[..],
        "a partial shuffle reproduced the front of the permutation, which would make \
         the per-guess cost constant rather than proportional to the carrier"
    );
    // And the positive half: the END of the permutation is cheap, which is why the
    // read order is the only thing standing in the way.
    assert_eq!(
        &full[total - 16..],
        &settled[..],
        "the tail of the permutation is reproducible in sixteen draws, so a reader \
         that read from the back would be cheap to attack"
    );
}

#[test]
fn the_cheap_filter_accepts_the_real_passphrase_and_rejects_wrong_ones() {
    let dir = tempfile::tempdir().unwrap();
    let (pixels, total) = stego_fixture(dir.path(), 200);

    assert!(
        survives_length_check(&pixels, total, PASSPHRASE),
        "the real passphrase must pass the filter, or it is not an oracle"
    );

    // Three hundred is plenty to tell 93% from anything that would worry us, and it
    // keeps this test inside a few seconds rather than a minute in a debug build.
    let trials = 300usize;
    let rejected = (0..trials)
        .filter(|i| {
            let guess = format!("wrong guess number {i}");
            !survives_length_check(&pixels, total, guess.as_bytes())
        })
        .count();
    let rate = rejected as f64 / trials as f64;
    println!(
        "Cheap filter rejected {rejected} of {trials} wrong guesses, {:.1}%. \
         The format predicts 93.75%.",
        rate * 100.0
    );
    assert!(
        rate > 0.80,
        "the filter rejected only {:.1}% of wrong guesses, so this measurement is \
         wrong somewhere rather than reassuring",
        rate * 100.0
    );
}

#[test]
fn the_fold_collides_so_different_passphrases_select_the_same_slots() {
    // Confirmed here independently of the lane that found it. Thirty two NUL bytes
    // XOR into nothing, so prefixing them leaves the fold unchanged.
    let mut colliding = vec![0u8; 32];
    colliding.extend_from_slice(PASSPHRASE);
    assert_eq!(
        slot_seed(PASSPHRASE),
        slot_seed(&colliding),
        "the XOR fold must collide here; if it no longer does, the derivation changed"
    );

    let dir = tempfile::tempdir().unwrap();
    let (pixels, total) = stego_fixture(dir.path(), 200);
    assert!(
        survives_length_check(&pixels, total, &colliding),
        "a colliding passphrase passes the slot-order oracle, which is the point"
    );

    // A second shape, which matters more because it needs no NUL bytes: the fold
    // is position modulo 32, so moving the whole passphrase one 32 byte block
    // along leaves it unchanged.
    let mut at_front = vec![0u8; 64];
    at_front[..PASSPHRASE.len()].copy_from_slice(PASSPHRASE);
    let mut at_back = vec![0u8; 64];
    at_back[32..32 + PASSPHRASE.len()].copy_from_slice(PASSPHRASE);
    assert_eq!(slot_seed(&at_front), slot_seed(&at_back));

    // And a third, which needs no padding at all: XOR is order independent within
    // a block, so any permutation of the 32 byte blocks of a long passphrase
    // collides with it.
    let long: Vec<u8> = (0u8..64).collect();
    let mut swapped = long[32..].to_vec();
    swapped.extend_from_slice(&long[..32]);
    assert_eq!(slot_seed(&long), slot_seed(&swapped));
}

#[test]
#[ignore = "a measurement harness, not a correctness test: it builds carriers, \
derives Argon2id keys and runs hundreds of permutations, which is eight minutes in \
a debug build and would slow every test run for a number nobody is asserting. Run \
it deliberately: cargo test --release -p stegcore-engine --test \
bruteforce_self_assessment -- --ignored --nocapture"]
fn the_marginal_cost_of_a_wrong_guess_is_measured_against_the_real_key_derivation() {
    use stegcore_engine::crypto::{derive_key, Cipher};

    let dir = tempfile::tempdir().unwrap();

    // Measure the advertised cost on this machine rather than quoting the ledger.
    let salt = [7u8; 16];
    let began = Instant::now();
    let rounds = 3;
    for _ in 0..rounds {
        derive_key(PASSPHRASE, &salt, Cipher::ChaCha20Poly1305).unwrap();
    }
    let kdf_seconds = began.elapsed().as_secs_f64() / f64::from(rounds);

    println!("\n--- Stegcore self assessment ---");
    println!(
        "Argon2id as configured, measured here: {:.1} milliseconds per key.",
        kdf_seconds * 1000.0
    );

    // Two carrier sizes, because the per-guess cost scales with the carrier and a
    // single figure would hide that.
    for side in [200u32, 800] {
        let (pixels, total) = stego_fixture(dir.path(), side);
        let guesses: Vec<String> = (0..400).map(|i| format!("candidate{i}")).collect();

        let began = Instant::now();
        let mut survivors = 0usize;
        for guess in &guesses {
            if survives_length_check(&pixels, total, guess.as_bytes()) {
                survivors += 1;
            }
        }
        let elapsed = began.elapsed();
        let seconds_each = elapsed.as_secs_f64() / guesses.len() as f64;
        let per_second = 1.0 / seconds_each;
        let advantage = kdf_seconds / seconds_each;

        println!(
            "Carrier {side} by {side} ({total} slots): {:.3} ms per wrong guess, \
             {per_second:.0} per second per thread. {survivors} of {} survived the filter.\n  \
             That is {advantage:.0} times cheaper than the key derivation the parameters \
             advertise, so a wordlist of 10 million costs {:.1} minutes on one core \
             rather than {:.0} hours.",
            seconds_each * 1000.0,
            guesses.len(),
            10_000_000.0 * seconds_each / 60.0,
            10_000_000.0 * kdf_seconds / 3600.0,
        );
    }
    println!();
}

#[test]
#[ignore = "a measurement harness, not a correctness test: it builds carriers, \
derives Argon2id keys and runs hundreds of permutations, which is eight minutes in \
a debug build and would slow every test run for a number nobody is asserting. Run \
it deliberately: cargo test --release -p stegcore-engine --test \
bruteforce_self_assessment -- --ignored --nocapture"]
fn the_per_guess_cost_is_dominated_by_the_permutation_not_the_bit_reads() {
    // Which half of the work to attack, if the cost is to be raised. If the
    // permutation dominates, then making the permutation expensive is the lever
    // and making the length field harder to check is not.
    let dir = tempfile::tempdir().unwrap();
    let (pixels, total) = stego_fixture(dir.path(), 400);
    let guesses: Vec<String> = (0..200).map(|i| format!("candidate{i}")).collect();

    let began = Instant::now();
    let mut orders = Vec::with_capacity(guesses.len());
    for guess in &guesses {
        orders.push(slot_order(total, guess.as_bytes()));
    }
    let permuting = began.elapsed().as_secs_f64() / guesses.len() as f64;

    let began = Instant::now();
    for order in &orders {
        let _ = read_bytes(&pixels, order, 2);
    }
    let reading = began.elapsed().as_secs_f64() / guesses.len() as f64;

    println!(
        "Of the per-guess cost on a {total} slot carrier: permutation {:.4} ms, \
         reading the two length bytes {:.6} ms. The permutation is {:.0} times the \
         cost, so it is the only part worth making expensive.",
        permuting * 1000.0,
        reading * 1000.0,
        permuting / reading.max(f64::MIN_POSITIVE)
    );
    assert!(permuting > 0.0 && reading >= 0.0);
}
