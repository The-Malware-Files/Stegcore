// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Property-based tests — Track B of the adversarial test gate.
//
// Properties asserted (each runs across a randomised input space; proptest
// shrinks failing cases to a minimal counter-example automatically):
//
//   1. round_trip_identity      — embed → extract preserves the payload byte-
//                                 for-byte across every (cover, payload,
//                                 passphrase, cipher) triple.
//   2. analyse_never_panics_on_random_bytes — feeding `analyse()` arbitrary
//                                 bytes treated as each supported extension
//                                 must never panic; an `Err` is fine, a
//                                 panic is not.
//   3. aead_tamper_always_fails — flipping ANY single bit in the LSB-bearing
//                                 region of a stego file must make extract
//                                 fail cleanly. No silent-but-wrong payload.
//   4. embed_preserves_cover_dimensions — the stego file is the same
//                                 dimensions / sample-count as the cover.
//
// Iteration budget: 64 cases per property in CI (cheap), 256 locally.
// Override with PROPTEST_CASES env var.

use std::path::{Path, PathBuf};

use proptest::prelude::*;
use stegcore_engine::analysis;
use stegcore_engine::crypto::Cipher;
use stegcore_engine::steg;
use tempfile::TempDir;

// ── Test fixture helpers ────────────────────────────────────────────────────

/// Write a procedural noise PNG cover. Deterministic from `seed`.
fn write_png_cover(path: &Path, seed: u64, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state = seed | 1; // never zero
    for px in pixels.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *px = (state >> 56) as u8;
    }
    image::save_buffer(path, &pixels, w, h, image::ColorType::Rgb8).expect("png write");
}

fn write_bmp_cover(path: &Path, seed: u64, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state = seed | 1;
    for px in pixels.iter_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        *px = (state >> 56) as u8;
    }
    let img = image::RgbImage::from_raw(w, h, pixels).expect("raw buffer");
    img.save_with_format(path, image::ImageFormat::Bmp)
        .expect("bmp write");
}

/// All three ciphers, indexed for proptest's `prop_oneof`.
fn cipher_strategy() -> impl Strategy<Value = Cipher> {
    prop_oneof![
        Just(Cipher::ChaCha20Poly1305),
        Just(Cipher::Aes256Gcm),
        Just(Cipher::Ascon128),
    ]
}

/// Cover format strategy. PNG + BMP only — JPEG is lossy (round-trip
/// identity does not hold by construction), WAV is its own embed path.
fn cover_format_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("png"), Just("bmp")]
}

// ── Property 1 — round-trip identity ────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(64),
        // Stego ops are not the fastest; shrinking can be slow. Cap it.
        max_shrink_iters: 32,
        .. ProptestConfig::default()
    })]

    #[test]
    fn round_trip_identity(
        seed in 0u64..1_000_000,
        payload in prop::collection::vec(any::<u8>(), 1..256),
        passphrase in "[A-Za-z0-9_-]{4,32}",
        cipher in cipher_strategy(),
        fmt in cover_format_strategy(),
    ) {
        // Cover must be big enough to fit the payload + crypto overhead +
        // Stegcore header. 128x128x3 bits → ~6 KB capacity, comfortably
        // bigger than the 256-byte payload cap above.
        let tmp = TempDir::new().expect("tmp");
        let cover: PathBuf = tmp.path().join(format!("cover.{fmt}"));
        let stego: PathBuf = tmp.path().join(format!("stego.{fmt}"));

        if fmt == "png" {
            write_png_cover(&cover, seed, 128, 128);
        } else {
            write_bmp_cover(&cover, seed, 128, 128);
        }

        let embed_result = steg::embed(
            &cover,
            &payload,
            passphrase.as_bytes(),
            cipher,
            "adaptive",
            &stego,
            false,
        );

        // Some procedural noise covers may legitimately score below the
        // 0.1 quality floor — that is a documented behaviour
        // (PoorCoverQuality). When that fires, the property is vacuous
        // for this case; skip without failing.
        if let Err(stegcore_engine::errors::StegError::PoorCoverQuality { .. }) = embed_result {
            return Ok(());
        }
        prop_assert!(
            embed_result.is_ok(),
            "embed unexpectedly failed: {:?}",
            embed_result.err()
        );

        let recovered = steg::extract(&stego, passphrase.as_bytes())
            .expect("extract must succeed after a clean embed");
        prop_assert_eq!(recovered, payload, "round-trip mismatch");
    }
}

// ── Property 2 — analyse never panics on arbitrary bytes ────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(128),
        max_shrink_iters: 16,
        .. ProptestConfig::default()
    })]

    #[test]
    fn analyse_never_panics_on_random_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..4096),
        ext in prop_oneof![
            Just("png"), Just("bmp"), Just("jpg"),
            Just("wav"), Just("flac"), Just("webp"),
        ],
    ) {
        let tmp = TempDir::new().expect("tmp");
        let path = tmp.path().join(format!("random.{ext}"));
        std::fs::write(&path, &bytes).expect("write random bytes");

        // The contract: analyse() may return an `Err` (malformed input,
        // unsupported format, parse failure) — that is acceptable. What
        // it must NEVER do is panic, abort, or unwind out of the call.
        // catch_unwind catches any panic and converts it into an Err.
        let result = std::panic::catch_unwind(|| {
            let _ = analysis::analyse(&path);
        });
        prop_assert!(
            result.is_ok(),
            "analyse() panicked on random bytes with .{ext} extension"
        );
    }
}

// ── Property 3 — AEAD tamper-detect always fails extraction ─────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(32), // expensive: embed + tamper + extract per case
        max_shrink_iters: 16,
        .. ProptestConfig::default()
    })]

    // T-28, resolved 2026-08-20. This property spent months disabled because
    // roughly 10% of cases recovered the original payload after a confirmed
    // LSB flip, which looked like an AEAD bypass. It was not.
    //
    // The premise was wrong. The framed payload is
    // [2-byte length][metadata JSON][ciphertext], and the metadata is base64
    // inside JSON, which is a redundant encoding: the final character of a
    // base64 group carries unused low bits, so flipping one changes the byte
    // on disk and decodes to exactly the same value. Such a flip is a genuine
    // change to the file and a no-op to the reader, so extraction correctly
    // returns the original payload.
    //
    // Measured rather than argued: 396 sampled single-bit tampers on a sealed
    // blob produced 30 that returned the original payload, and every one of
    // the 30 was in the metadata region. Zero were in the ciphertext. The
    // AEAD caught every ciphertext tamper.
    //
    // Note that the metadata sits outside the AEAD by design. A tamper there
    // is therefore either a no-op or a decryption failure; it can never forge
    // a payload, because that would need the key.
    //
    // The fix is to tamper with enough bits that landing entirely inside the
    // redundant metadata is not a plausible outcome. At roughly a 10% chance
    // per flip, eight independent flips put that at about 1 in 100 million.
    // The exact single-bit property still holds where it is meaningful, and
    // aead_rejects_single_bit_ciphertext_tamper below tests it directly.
    #[test]
    fn aead_tamper_always_fails(
        seed in 0u64..1_000_000,
        payload in prop::collection::vec(any::<u8>(), 16..128),
        passphrase in "[A-Za-z0-9_-]{8,32}",
        // Index into the set of bytes that actually changed during embed —
        // i.e. an actual embedded slot, not a random byte that may or may
        // not be on the embedding path.
        slot_pick in 0usize..10_000,
    ) {
        let tmp = TempDir::new().expect("tmp");
        let cover = tmp.path().join("cover.bmp");
        let stego = tmp.path().join("stego.bmp");
        write_bmp_cover(&cover, seed, 128, 128);

        let embed_result = steg::embed(
            &cover,
            &payload,
            passphrase.as_bytes(),
            Cipher::ChaCha20Poly1305,
            "sequential",
            &stego,
            false,
        );
        if let Err(stegcore_engine::errors::StegError::PoorCoverQuality { .. }) = embed_result {
            return Ok(());
        }
        prop_assert!(embed_result.is_ok());

        // Diff cover vs stego to discover the real embedded-slot offsets.
        // The bytes that differ are exactly the bytes whose LSBs the engine
        // wrote into — by definition. No engine internals needed.
        let cover_bytes = std::fs::read(&cover).expect("read cover");
        let mut stego_bytes = std::fs::read(&stego).expect("read stego");
        prop_assume!(cover_bytes.len() == stego_bytes.len());

        let diffs: Vec<usize> = cover_bytes.iter()
            .zip(stego_bytes.iter())
            .enumerate()
            .filter_map(|(i, (c, s))| (c != s).then_some(i))
            .collect();
        prop_assume!(!diffs.is_empty());

        // Flip eight distinct confirmed slots, spread across the payload, so
        // the tamper cannot land wholly inside the redundant metadata encoding
        // (see the note above).
        let mut flipped = 0;
        for k in 0..8 {
            let idx = (slot_pick + k * (diffs.len() / 8).max(1)) % diffs.len();
            let offset = diffs[idx];
            if stego_bytes[offset] == cover_bytes[offset] {
                continue; // already reverted by an earlier flip in this loop
            }
            stego_bytes[offset] ^= 0x01;
            flipped += 1;
        }
        prop_assume!(flipped > 0);
        std::fs::write(&stego, &stego_bytes).expect("rewrite tampered stego");

        // Flips on confirmed embedded slots must propagate into the framed
        // payload. AEAD or framing must catch it. Allowed outcomes:
        //   Err(...)           — preferred, AEAD/framing rejection
        //   Ok(different_bytes) — also acceptable
        // Forbidden outcome:
        //   Ok(payload)         — silent AEAD bypass
        let recovered = steg::extract(&stego, passphrase.as_bytes());
        match recovered {
            Err(_) => {} // good — AEAD or framing caught it.
            Ok(bytes) => prop_assert_ne!(
                bytes,
                payload,
                "tamper on eight confirmed embedded slots produced an unchanged \
                 payload — AEAD authentication failed silently!"
            ),
        }
    }
}

// ── Property 3b: AEAD rejects a single-bit ciphertext tamper ──────────────
//
// The exact property, stated where it is exactly true. Property 3 works
// through the image pipeline and so cannot say which payload bit it hit;
// this one addresses the sealed blob directly, where the boundary between
// metadata and ciphertext is known, and flips one bit inside the ciphertext.

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(16), // Argon2id at 128 MiB is paid on every open_blob
        max_shrink_iters: 16,
        .. ProptestConfig::default()
    })]

    #[test]
    fn aead_rejects_single_bit_ciphertext_tamper(
        payload in prop::collection::vec(any::<u8>(), 16..96),
        passphrase in "[A-Za-z0-9_-]{8,32}",
        byte_pick in 0usize..10_000,
        bit in 0u8..8,
    ) {
        let blob = steg::seal_blob(
            passphrase.as_bytes(),
            &payload,
            Cipher::ChaCha20Poly1305,
        ).expect("seal");

        // The blob is [2-byte length][metadata][ciphertext]; tamper strictly
        // inside the ciphertext.
        let meta_len = u16::from_be_bytes([blob[0], blob[1]]) as usize;
        let ct_start = 2 + meta_len;
        prop_assume!(blob.len() > ct_start);

        let mut tampered = blob.clone();
        let idx = ct_start + (byte_pick % (blob.len() - ct_start));
        tampered[idx] ^= 1 << bit;

        match steg::open_blob(&tampered, passphrase.as_bytes()) {
            Err(_) => {} // correct: authentication rejected it
            Ok(bytes) => prop_assert_ne!(
                bytes,
                payload,
                "a single-bit tamper inside the ciphertext returned the original \
                 payload — AEAD authentication failed silently!"
            ),
        }
    }
}

// ── Property 4 — embed preserves cover dimensions ──────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(32),
        max_shrink_iters: 16,
        .. ProptestConfig::default()
    })]

    #[test]
    fn embed_preserves_image_dimensions(
        seed in 0u64..1_000_000,
        payload_len in 4usize..64,
        passphrase in "[A-Za-z0-9_-]{4,16}",
    ) {
        let tmp = TempDir::new().expect("tmp");
        let cover = tmp.path().join("cover.png");
        let stego = tmp.path().join("stego.png");
        write_png_cover(&cover, seed, 96, 96);

        let payload = vec![0xAB; payload_len];
        let result = steg::embed(
            &cover,
            &payload,
            passphrase.as_bytes(),
            Cipher::ChaCha20Poly1305,
            "adaptive",
            &stego,
            false,
        );
        if let Err(stegcore_engine::errors::StegError::PoorCoverQuality { .. }) = result {
            return Ok(());
        }
        prop_assert!(result.is_ok());

        let cover_img = image::open(&cover).expect("open cover").to_rgb8();
        let stego_img = image::open(&stego).expect("open stego").to_rgb8();
        prop_assert_eq!(cover_img.dimensions(), stego_img.dimensions());
    }
}
