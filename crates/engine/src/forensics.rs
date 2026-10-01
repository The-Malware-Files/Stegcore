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

//! Copyright-detection forensics: the engine-side half of making the dual
//! licence enforceable.
//!
//! Two output-forensics surfaces live here.
//!
//! 1. **Canonical embedding positions.** Given a passphrase and a slot count,
//!    Stegcore selects the same positions in the same order every time. A
//!    third-party tool that reproduces these exact positions is running
//!    Stegcore's seed derivation, not landing on it by chance: the published
//!    permutation vectors pin specific (passphrase, count) inputs to their
//!    outputs, so a match is evidence of copying.
//!
//!    **There are now two layouts, and identification has to try both.** For
//!    `rust-v1` and `rust-v2` the order comes from folding the passphrase bytes
//!    into a 32-byte seed, running a ChaCha8 stream from it, and Fisher-Yates
//!    shuffling the slot indices: [`embedding_positions`]. For `rust-v3` that
//!    cheap permutation only locates a 32-byte salt block
//!    ([`salt_block_positions`]), and the payload sits at positions derived from
//!    `Argon2id(passphrase, salt block)` ([`embedding_positions_v3`]).
//!
//!    This matters for copyright detection specifically: a tool checking only
//!    the legacy derivation would fail to recognise Stegcore's own `rust-v3`
//!    output, which would make the licence unenforceable against exactly the
//!    files the current release writes.
//!
//! 2. **The on-disk wire format** of an embedded payload: a two-byte
//!    big-endian metadata length, a JSON metadata block whose `engine` field
//!    is the format tag, then the ciphertext. [`identify_wire_format`]
//!    recognises a payload that has been extracted from a cover (with the
//!    passphrase) as Stegcore output.
//!
//! The third and fourth mechanisms live elsewhere: the build-time fingerprint
//! is in the CLI's `build-info` command, and the byte-perfect output vectors
//! are golden fixtures under `tests/`.

use crate::errors::StegError;
use crate::slotseed::{self, SALT_BLOCK_LEN};
use crate::steg;

/// The current wire-format tag carried in every embedded payload's metadata.
///
/// Bump this (and add new vectors rather than editing the old ones) whenever
/// the on-disk payload layout changes, so the published vectors stay honest
/// about which format they describe.
///
/// `rust-v2`, 2026-08-20: payloads are compressed with lz4 rather than zstd,
/// which removed the last C dependency from the engine. Slot selection did not
/// change, so the permutation vectors carry over unaltered; the byte-perfect
/// payload vector did change and was regenerated. `rust-v1` payloads remain
/// readable.
///
/// `rust-v3`, 2026-10-01: slot selection changed. A per-file salt block goes in
/// first, at slots from the cheap passphrase permutation, and the metadata and
/// ciphertext go at slots derived from `Argon2id(passphrase, salt block)`. The
/// bytes of the metadata-plus-ciphertext block itself are unchanged, so the
/// byte-perfect payload vector carries over; the *positions* changed, so the
/// permutation vectors gained a v3 set alongside the v1 and v2 one rather than
/// replacing it. See [`crate::slotseed`]. `rust-v1` and `rust-v2` payloads
/// remain readable.
pub const WIRE_FORMAT_VERSION: &str = "rust-v3";

/// The tag written by the two carriers whose slot selection `rust-v3` did not
/// change, so their metadata stays honest about the layout it describes.
///
/// 1. **Sealed blobs** ([`steg::seal_blob`], the document and watermark
///    carriers). A blob stores the metadata at a known offset in a byte string
///    it owns outright, so there is no permutation to seed and nothing the
///    two-stage layout would buy.
/// 2. **The JPEG DCT carrier.** `jpeg_dct` runs its own independent shuffle over
///    coefficient positions and never calls `steg::permute_set`, so `rust-v3`
///    does not reach it. Its pre-derivation filter is the strongest in the
///    codebase: a 32-bit length prefix read from permuted positions, rejecting
///    all but roughly one wrong guess in 10^6 on one integer comparison. That
///    gap is open and this constant is what records it, rather than letting a
///    `rust-v3` tag imply a protection the file does not have.
pub const WIRE_FORMAT_LEGACY_SHUFFLE: &str = "rust-v2";

/// Compute the **legacy** embedding positions for `passphrase` over a cover
/// with `slot_count` embeddable slots (pixels times channels for images, or
/// samples for audio).
///
/// This is the `rust-v1` and `rust-v2` layout: one passphrase-seeded permutation
/// carrying the payload from its first slot. It is still how files written by
/// 4.1.0 and earlier are laid out, so it is still how they are identified, and
/// it is still how the JPEG DCT carrier and sealed blobs are laid out today.
///
/// For a `rust-v3` carrier these positions hold the salt block, not the payload.
/// Use [`salt_block_positions`] and [`embedding_positions_v3`] for those.
///
/// The result is a permutation of `0..slot_count`. It is pure and deterministic,
/// so two calls with the same inputs always agree.
pub fn embedding_positions(passphrase: &[u8], slot_count: usize) -> Vec<usize> {
    steg::permute_set((0..slot_count).collect(), passphrase)
}

/// The `rust-v3` stage-one positions: the slots carrying the per-file salt
/// block, in the order its 256 bits are written.
///
/// Returns `None` when `slot_count` is below [`slotseed::MIN_V3_SLOTS`], because
/// a carrier that small cannot hold the layout at all.
///
/// These come from the same cheap passphrase permutation as
/// [`embedding_positions`], truncated to the block, so a third-party tool
/// reproducing them is running Stegcore's stage-one derivation.
pub fn salt_block_positions(passphrase: &[u8], slot_count: usize) -> Option<Vec<usize>> {
    steg::v3_salt_block_slots(slot_count, passphrase)
}

/// The `rust-v3` stage-two positions: the slots carrying the metadata and the
/// ciphertext, given the salt block recovered from stage one.
///
/// This is the half of the reconstruction that costs real work. It runs the
/// stage-two key derivation, so it takes roughly one Argon2id derivation
/// (285 ms on the build box) per call, by design.
///
/// `slot_count` is the sequential slot set, which is the only one reconstructible
/// without the carrier itself: adaptive mode picks its raw slots from pixel
/// variance, so identifying an adaptive-mode file needs the image, not just a
/// count. That is a limit of this function, not of the format.
pub fn embedding_positions_v3(
    passphrase: &[u8],
    salt_block: &[u8],
    slot_count: usize,
) -> Result<Vec<usize>, StegError> {
    if salt_block.len() != SALT_BLOCK_LEN {
        return Err(StegError::CorruptedFile);
    }
    let salt_slots =
        steg::v3_salt_block_slots(slot_count, passphrase).ok_or(StegError::NoPayloadFound)?;
    let seed = slotseed::derive_slot_seed(passphrase, salt_block)?;
    Ok(steg::v3_payload_slots(
        (0..slot_count).collect(),
        &salt_slots,
        slot_count,
        &seed,
    ))
}

/// True when `extracted` (a payload already lifted out of a cover with the
/// correct passphrase) carries Stegcore's wire format: a metadata length that
/// fits, valid metadata JSON, and the current `engine` tag.
///
/// This is an output-forensics check: it confirms a recovered payload was
/// produced by Stegcore's embedder, independent of which cover carried it.
pub fn identify_wire_format(extracted: &[u8]) -> bool {
    steg::looks_like_stego_payload(extracted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_are_a_permutation() {
        let p = embedding_positions(b"correct horse battery staple", 1000);
        assert_eq!(p.len(), 1000);
        let mut sorted = p.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 1000, "positions must be a permutation");
        assert_eq!(*sorted.first().unwrap(), 0);
        assert_eq!(*sorted.last().unwrap(), 999);
    }

    #[test]
    fn positions_are_deterministic() {
        let a = embedding_positions(b"pass", 256);
        let b = embedding_positions(b"pass", 256);
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrases_give_different_orders() {
        let a = embedding_positions(b"alpha", 256);
        let b = embedding_positions(b"bravo", 256);
        assert_ne!(a, b);
    }

    #[test]
    fn wire_format_rejects_noise() {
        assert!(!identify_wire_format(b""));
        assert!(!identify_wire_format(&[0u8; 64]));
        assert!(!identify_wire_format(b"not a stego payload"));
    }
}
