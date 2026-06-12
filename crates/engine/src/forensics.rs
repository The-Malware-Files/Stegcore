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
//!    Stegcore selects the same positions in the same order every time. The
//!    order is derived from the passphrase by folding its bytes into a 32-byte
//!    seed, running a ChaCha8 stream from that seed, and Fisher-Yates shuffling
//!    the slot indices. A third-party tool that reproduces these exact
//!    positions is running Stegcore's seed derivation, not landing on it by
//!    chance: the published permutation vectors pin specific (passphrase,
//!    count) inputs to their outputs, so a match is evidence of copying.
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

use crate::steg;

/// The current wire-format tag carried in every embedded payload's metadata.
///
/// Bump this (and add new vectors rather than editing the old ones) whenever
/// the on-disk payload layout changes, so the published vectors stay honest
/// about which format they describe.
pub const WIRE_FORMAT_VERSION: &str = "rust-v1";

/// Compute the canonical embedding positions for `passphrase` over a cover with
/// `slot_count` embeddable slots (pixels times channels for images, or samples
/// for audio).
///
/// The result is a permutation of `0..slot_count`: the payload bits occupy the
/// returned positions, in order. This is the function the permutation vectors
/// lock down. It is pure and deterministic, so two calls with the same inputs
/// always agree.
pub fn embedding_positions(passphrase: &[u8], slot_count: usize) -> Vec<usize> {
    steg::permute_set((0..slot_count).collect(), passphrase)
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
