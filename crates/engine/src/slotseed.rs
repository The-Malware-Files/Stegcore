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

//! Where the slot permutation's seed comes from, in the `rust-v3` layout.
//!
//! # The problem this exists to solve
//!
//! Until `rust-v3`, slot order came from [`steg::permute_set`](crate::steg)
//! seeded by an XOR fold of the passphrase. That is not a key derivation, it is
//! a few hundred microseconds of arithmetic. Extraction read the two-byte length
//! header out of those slots, parsed the metadata, and only then called
//! `derive_key`. So a wrong passphrase was thrown out *before* Argon2id ran.
//!
//! Measured on the build box, 2026-10-01, by `examples/kdf_cost.rs`:
//!
//! ```text
//!   one Argon2id derivation (128 MiB x 4)          284.9 ms
//!   one wrong guess, 200x200 carrier                 2.39 ms   119 per derivation
//!   one wrong guess, 800x800 carrier                57.78 ms     5 per derivation
//! ```
//!
//! Argon2id at those parameters exists to make guessing expensive. Against
//! somebody holding a small stego file it did not: they filtered candidates at
//! one hundred and nineteenth of the advertised cost and paid the real price
//! once, on the survivor.
//!
//! # The circle, and how `rust-v3` breaks it
//!
//! Seeding the permutation from the key is circular, which is the whole reason
//! this is a format change rather than a patch:
//!
//! ```text
//!   derive_key(passphrase, salt)   needs the salt
//!   the salt                        is a field of Meta
//!   Meta                            is read through the permutation
//! ```
//!
//! `rust-v3` breaks it with two stages and two derivations:
//!
//! ```text
//!   stage one    32 random bytes, the salt block
//!                at slots from the cheap passphrase permutation
//!
//!   stage two    metadata and ciphertext
//!                at slots from Argon2id(passphrase, salt block)
//! ```
//!
//! Reading: run the cheap permutation, lift the salt block, derive the stage-two
//! seed from it, permute again, read the payload. Guessing: a wrong candidate
//! selects the wrong stage-one slots, so the "salt block" is whatever bytes
//! happen to sit there, and there is no way to tell it is wrong without running
//! Argon2id over it and finding that stage two does not parse. Every candidate
//! costs one full derivation.
//!
//! Nothing sits at a fixed offset. That was the reason ADR-002 rejected option
//! B: a constant-position header is exactly the shape Stegcore's own
//! `check_openstego` and `check_camouflage` detectors hunt for, and buying
//! resistance to passphrase guessing by handing every steganalyst a signature is
//! the wrong trade for a tool whose promise is that the artefact does not
//! announce itself. The salt block lives at passphrase-dependent slots, exactly
//! as the payload does.
//!
//! # What this does not fix, stated plainly
//!
//! **The cheap pre-filter is repriced, not removed.** A wrong guess still dies
//! at the same sixteen-bit length check that killed it before, the one that
//! rejects roughly 93% of candidates on the first comparison. What changed is
//! the toll at the door: reaching that check now costs a full key derivation
//! instead of 2.39 ms. The filter is still there and still cheap once you are
//! past the derivation; it is no longer free to get there.
//!
//! And none of this raises the Argon2id parameters. A weak passphrase is still
//! weak against somebody willing to spend 285 ms a guess. This closes the gap
//! between the advertised cost and the real one. It does not move the advertised
//! cost.
//!
//! # Deniable mode uses none of it
//!
//! The dual-payload construction needs no salt block at all, which is the
//! happiest finding in the whole change. `embed_deniable` already writes the
//! salt into the exported key file, and `extract_with_keyfile` is holding that
//! key file before it touches a pixel, so the stage-two seed comes from
//! `derive_slot_seed(passphrase, keyfile.salt)` directly. No stage-one block, no
//! second block per half, and therefore nothing for the real/decoy coin to leak
//! through. See `steg::embed_deniable` for the proof that the two halves stay
//! structurally indistinguishable.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::errors::StegError;

// ── The salt block ────────────────────────────────────────────────────────────

/// Bytes of per-file random in the stage-one block.
///
/// Thirty-two, matching `crypto::generate_salt`, so the stage-two seed is salted
/// as strongly as the message key is.
pub const SALT_BLOCK_LEN: usize = 32;

/// Carrier slots the stage-one block occupies: one bit per slot.
pub const SALT_BLOCK_BITS: usize = SALT_BLOCK_LEN * 8;

/// Slots a carrier needs before the `rust-v3` layout will fit at all: the salt
/// block, plus the sixteen slots the two-byte metadata length header needs.
///
/// A carrier below this cannot hold a `rust-v3` payload, and the read path must
/// decline it as `NoPayloadFound` rather than with a distinct error, so a
/// too-small file is not told apart from a payload-free one.
pub const MIN_V3_SLOTS: usize = SALT_BLOCK_BITS + 16;

// ── Stage-two seed derivation ─────────────────────────────────────────────────

/// Domain separator mixed into the stage-two seed's salt.
///
/// This is load-bearing, not decoration. The deniable path derives the
/// stage-two seed from the *same* salt the message key uses, and both
/// derivations run Argon2id at identical parameters. Without this prefix the
/// two calls would be the same function of the same inputs, so for
/// ChaCha20-Poly1305 and AES-256-GCM, whose keys are 32 bytes like this seed,
/// **the slot seed would literally equal the message key**. The prefix makes
/// them independent outputs of the same primitive.
const SLOT_SEED_DOMAIN: &[u8] = b"stegcore/slot-seed/rust-v3|";

/// Argon2id memory cost, in KiB. Identical to `crypto::derive_key`, deliberately:
/// a cheaper stage-one derivation would just move the filter rather than close it.
const KDF_MEMORY_KIB: u32 = 131_072;

/// Argon2id time cost, in passes. Identical to `crypto::derive_key`.
const KDF_ITERATIONS: u32 = 4;

/// Argon2id lanes. Identical to `crypto::derive_key`.
const KDF_LANES: u32 = 2;

/// Length of the derived stage-two seed, in bytes.
///
/// Fixed at 32 regardless of cipher, and that is the second reason this is a
/// separate derivation rather than a slice of the message key. The message key's
/// length is a function of the cipher, the cipher is a field of `Meta`, and
/// `Meta` lives inside the stage-two permutation, so the key's length is not
/// known until after the permutation it would have seeded. Memoising the two
/// into one would also make the derivation's duration a function of the cipher,
/// which is a timing side channel announcing which cipher the file was written
/// with.
pub const SLOT_SEED_LEN: usize = 32;

/// Derive the `rust-v3` stage-two permutation seed.
///
/// `salt` is the stage-one salt block for an ordinary file, or the key file's
/// salt for a deniable one. Both are 32 bytes of per-file random, so neither
/// admits precomputation: this is the property that ruled out ADR-002 option C,
/// where a constant salt would have let one dictionary attack every Stegcore
/// file ever written.
///
/// Costs one full Argon2id derivation, 285 ms on the build box and about 811 ms
/// on the reference laptop. That is the point of it.
pub fn derive_slot_seed(passphrase: &[u8], salt: &[u8]) -> Result<[u8; SLOT_SEED_LEN], StegError> {
    if salt.is_empty() {
        return Err(StegError::CorruptedFile);
    }

    let mut salted = Vec::with_capacity(SLOT_SEED_DOMAIN.len() + salt.len());
    salted.extend_from_slice(SLOT_SEED_DOMAIN);
    salted.extend_from_slice(salt);

    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_LANES,
        Some(SLOT_SEED_LEN),
    )
    .map_err(|_| StegError::CorruptedFile)?;

    let mut seed = [0u8; SLOT_SEED_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, &salted, &mut seed)
        .map_err(|_| StegError::DecryptionFailed)?;
    Ok(seed)
}

// ── What the interface has to be told ─────────────────────────────────────────

/// Key derivations a `rust-v3` extract performs when it succeeds: the stage-two
/// seed, then the message key.
///
/// Published so the wizard and the GUI can describe the wait from the real
/// figure rather than guessing at it.
pub const DERIVATIONS_PER_V3_EXTRACT: u32 = 2;

/// How long an interface must keep its "unlocking" signal up, in milliseconds,
/// whatever the outcome.
///
/// # Why a floor rather than a progress bar
///
/// Argon2id cannot report intermediate progress. Verified against the `argon2`
/// 0.5.3 source rather than assumed: its entire public surface is
/// `hash_password_into`, `hash_password_into_with_memory` and `fill_memory`,
/// every one a single blocking call with no callback, no pass counter and no
/// iterator. There is no honest percentage to show, so neither surface shows
/// one.
///
/// There is a sharper reason than the missing callback, and it is the one that
/// actually settles the design. **A progress signal driven by real engine
/// progress is a passphrase oracle.** A wrong passphrase stops after one
/// derivation; a right one goes on to a second. An interface that advanced a
/// step when stage one succeeded would be announcing "the passphrase was right"
/// roughly 811 ms before it had any business saying so, straight onto the screen
/// where a shoulder-surfer, a screen recording or a scripted driver can read it.
///
/// So the signal is driven by this constant and by elapsed wall-clock time, and
/// by nothing the engine reports. Both outcomes display for the same duration.
///
/// # What this floor does not close
///
/// The *process* is still distinguishable: one derivation against two, and
/// anyone able to time `stegcore extract` can see it. This closes the interface
/// as a second, easier oracle; it does not make the engine constant-time. Doing
/// that needs the read path to perform a fixed number of derivations whatever
/// the outcome, which would also double the cost of a bulk "does this file carry
/// anything" sweep, and that is the operator's call, not this module's.
///
/// 2500 ms covers two derivations on the reference laptop (1.62 s measured) with
/// margin. A slower machine will exceed it, and there the signal stays up for as
/// long as the work takes, which is correct behaviour and also the case where
/// the floor stops levelling.
pub const UNLOCK_SIGNAL_FLOOR_MS: u64 = 2_500;

/// One plain-language sentence explaining the wait, for reuse across the CLI and
/// the GUI so the two cannot drift apart.
///
/// Deliberately says nothing about key derivation functions, Argon2, or memory
/// cost. Per the documentation rules, a reader with no prior context and thirty
/// seconds of attention has to understand it.
pub const UNLOCK_EXPLANATION: &str =
    "Checking your passphrase is deliberately slow, so guessing one is expensive.";

// Checked at compile time rather than in a test, because both sides are
// constants: a runtime assertion on a constant is what clippy's
// `assertions_on_constants` objects to, and it is right that a build which
// cannot satisfy this should not compile rather than fail a test later.
//
// Two derivations at the reference laptop's measured 811 ms is about 1.62 s, so
// the floor has to sit above that or it is not levelling anything.
const _: () = assert!(DERIVATIONS_PER_V3_EXTRACT == 2);
const _: () = assert!(UNLOCK_SIGNAL_FLOOR_MS >= 1_620);

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &[u8] = b"correct horse battery staple";
    const SALT: &[u8] = &[0x5au8; SALT_BLOCK_LEN];

    #[test]
    fn slot_seed_is_deterministic() {
        let a = derive_slot_seed(PASS, SALT).unwrap();
        let b = derive_slot_seed(PASS, SALT).unwrap();
        assert_eq!(a, b, "the same inputs must give the same seed");
    }

    #[test]
    fn slot_seed_changes_with_the_passphrase() {
        let a = derive_slot_seed(PASS, SALT).unwrap();
        let b = derive_slot_seed(b"a different passphrase", SALT).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn slot_seed_changes_with_the_salt() {
        let a = derive_slot_seed(PASS, SALT).unwrap();
        let b = derive_slot_seed(PASS, &[0xa5u8; SALT_BLOCK_LEN]).unwrap();
        assert_ne!(a, b);
    }

    /// The one that matters: the slot seed must not be the message key.
    ///
    /// Both run Argon2id over the same passphrase and the same salt at identical
    /// parameters, and for a 32-byte cipher key the outputs would be identical
    /// byte for byte without the domain separator. This is the test that fails
    /// if somebody removes it.
    #[test]
    fn slot_seed_is_not_the_message_key() {
        use crate::crypto::{derive_key, Cipher};

        for cipher in [Cipher::ChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = derive_key(PASS, SALT, cipher).unwrap();
            let seed = derive_slot_seed(PASS, SALT).unwrap();
            assert_eq!(
                key.as_slice().len(),
                SLOT_SEED_LEN,
                "same length, so the comparison is meaningful"
            );
            assert_ne!(
                key.as_slice(),
                &seed[..],
                "the slot seed collided with the {cipher:?} message key; the domain separator is gone"
            );
        }
    }

    #[test]
    fn empty_salt_is_refused_rather_than_hashed() {
        assert!(matches!(
            derive_slot_seed(PASS, b""),
            Err(StegError::CorruptedFile)
        ));
    }

    #[test]
    fn an_empty_passphrase_still_derives() {
        // The no-password path is supported elsewhere in the engine, so it must
        // not fail here.
        assert!(derive_slot_seed(b"", SALT).is_ok());
    }

    #[test]
    fn the_salt_block_is_a_whole_number_of_bytes_of_slots() {
        assert_eq!(SALT_BLOCK_BITS, SALT_BLOCK_LEN * 8);
        assert_eq!(MIN_V3_SLOTS, SALT_BLOCK_BITS + 16);
    }

    #[test]
    fn the_explanation_avoids_jargon() {
        for banned in ["KDF", "Argon2", "derivation", "entropy"] {
            assert!(
                !UNLOCK_EXPLANATION.contains(banned),
                "the user-facing explanation should not say {banned:?}"
            );
        }
    }
}
