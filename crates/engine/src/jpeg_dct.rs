// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// JPEG DCT coefficient steganography — JSteg-style LSB embedding.
//
// Coefficient access (parse, Huffman decode, re-encode) is delegated to the
// `dct_io` crate, the project's pure-Rust baseline-JPEG coefficient codec.
// This module only owns the steganography on top of it: pick the eligible
// AC coefficients, permute them with a passphrase-seeded RNG, and flip LSBs.
//
// Technique: skip DC coefficients and any AC coefficient whose absolute value
// is 0 or 1. Modifying only |v| >= 2 coefficients keeps every value inside its
// original JPEG value-category, so zero-runs, EOB positions and the Huffman
// symbol set are preserved and `dct_io::write_coefficients` re-encodes without
// going out of the original tables. One payload bit per eligible coefficient
// LSB; selection is permuted by a ChaCha8 RNG seeded from the passphrase so the
// positions stay secret.

use dct_io::{read_coefficients, write_coefficients, DctError, JpegCoefficients};
use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::errors::StegError;

/// Map a `dct_io` error onto the engine's error type. Unsupported JPEG
/// variants (progressive, arithmetic, lossless) get a clear format error;
/// everything else is treated as a corrupt/unparseable file.
fn map_dct_err(e: DctError) -> StegError {
    match e {
        DctError::Unsupported(msg) => StegError::UnsupportedFormat(format!("jpeg: {msg}")),
        _ => StegError::CorruptedFile,
    }
}

// ── Eligible coefficient positions ─────────────────────────────────────────────

/// Collect `(component_index, block_index, ac_index)` for every AC coefficient
/// whose `|value| >= 2`. `dct_io` already stores each block in JPEG zigzag
/// order, so index 0 is the DC coefficient (skipped) and 1..64 are the AC
/// coefficients in zigzag order.
fn eligible_positions(coeffs: &JpegCoefficients) -> Vec<(usize, usize, usize)> {
    let mut positions = Vec::new();
    for (ci, comp) in coeffs.components.iter().enumerate() {
        for (di, block) in comp.blocks.iter().enumerate() {
            // Skip index 0 (DC); 1..64 are the AC coefficients in zigzag order.
            for (k, &v) in block.iter().enumerate().skip(1) {
                if v.abs() >= 2 {
                    positions.push((ci, di, k));
                }
            }
        }
    }
    positions
}

/// Permute the eligible positions list using ChaCha8 seeded from the
/// passphrase. The passphrase is XOR-folded into the 32-byte seed so its full
/// entropy is used rather than silently truncated at 32 bytes.
fn permute_positions(
    mut positions: Vec<(usize, usize, usize)>,
    passphrase: &[u8],
) -> Vec<(usize, usize, usize)> {
    let mut seed = [0u8; 32];
    for (i, &b) in passphrase.iter().enumerate() {
        seed[i % 32] ^= b;
    }
    let mut rng = ChaCha8Rng::from_seed(seed);
    positions.shuffle(&mut rng);
    positions
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Capacity: how many payload bytes can be hidden in this JPEG (after the
/// 4-byte length prefix is accounted for by the caller).
pub fn jpeg_capacity(data: &[u8]) -> Result<usize, StegError> {
    let coeffs = read_coefficients(data).map_err(map_dct_err)?;
    Ok(eligible_positions(&coeffs).len() / 8)
}

/// Embed `payload` into `jpeg_data`, using the passphrase to permute
/// coefficient selection. Returns the modified JPEG bytes.
pub fn embed_jpeg(
    jpeg_data: &[u8],
    payload: &[u8],
    passphrase: &[u8],
) -> Result<Vec<u8>, StegError> {
    if payload.is_empty() {
        return Err(StegError::EmptyPayload);
    }

    let mut coeffs = read_coefficients(jpeg_data).map_err(map_dct_err)?;
    let positions = permute_positions(eligible_positions(&coeffs), passphrase);

    // 4-byte length prefix + payload, one bit per eligible coefficient.
    let bits_needed = (4 + payload.len()) * 8;
    if positions.len() < bits_needed {
        return Err(StegError::InsufficientCapacity {
            required: bits_needed,
            available: positions.len(),
        });
    }

    // Build bit stream: [32-bit payload length BE][payload bytes].
    let mut bit_stream: Vec<u8> = Vec::with_capacity(4 + payload.len());
    bit_stream.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bit_stream.extend_from_slice(payload);

    for (bit_idx, &(ci, di, k)) in positions.iter().enumerate().take(bits_needed) {
        let byte_idx = bit_idx / 8;
        let bit_pos = 7 - (bit_idx % 8);
        let bit = (bit_stream[byte_idx] >> bit_pos) & 1;

        let coeff = &mut coeffs.components[ci].blocks[di][k];
        // Preserve sign and set the LSB of the absolute value. The coefficient
        // is guaranteed |v| >= 2, so the result is never 0 or ±1 and stays in
        // the same value-category.
        if *coeff > 0 {
            *coeff = (*coeff & !1) | bit as i16;
        } else {
            let abs_val = (-*coeff & !1) | bit as i16;
            *coeff = -abs_val;
        }
    }

    write_coefficients(jpeg_data, &coeffs).map_err(map_dct_err)
}

/// Extract bytes previously embedded by [`embed_jpeg`].
pub fn extract_jpeg(jpeg_data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    let coeffs = read_coefficients(jpeg_data).map_err(map_dct_err)?;
    let positions = permute_positions(eligible_positions(&coeffs), passphrase);

    if positions.len() < 32 {
        return Err(StegError::NoPayloadFound);
    }

    // Read the 32-bit length prefix.
    let mut len_bits = 0u32;
    for &(ci, di, k) in positions.iter().take(32) {
        let coeff = coeffs.components[ci].blocks[di][k];
        len_bits = (len_bits << 1) | (coeff.abs() & 1) as u32;
    }

    let payload_len = len_bits as usize;
    // Cap to what the coefficients can actually hold (minus the prefix), reject
    // zero, and hard-cap at 16 MB so a wrong passphrase can't drive a huge alloc.
    let max_payload = positions.len().saturating_sub(32) / 8;
    if payload_len == 0 || payload_len > max_payload || payload_len > 16_000_000 {
        return Err(StegError::NoPayloadFound);
    }

    let bits_needed = (4 + payload_len) * 8;
    if positions.len() < bits_needed {
        return Err(StegError::NoPayloadFound);
    }

    let mut payload = vec![0u8; payload_len];
    for bit_idx in 0..payload_len * 8 {
        let (ci, di, k) = positions[32 + bit_idx];
        let lsb = (coeffs.components[ci].blocks[di][k].abs() & 1) as u8;
        let byte_idx = bit_idx / 8;
        let bit_pos = 7 - (bit_idx % 8);
        payload[byte_idx] |= lsb << bit_pos;
    }

    Ok(payload)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use image::{codecs::jpeg::JpegEncoder, ImageEncoder, RgbImage};

    /// A noisy RGB JPEG with enough high-variance content to yield plenty of
    /// eligible (|v| >= 2) AC coefficients.
    fn noisy_jpeg(w: u32, h: u32) -> Vec<u8> {
        let img = RgbImage::from_fn(w, h, |x, y| {
            image::Rgb([
                ((x * 11 + y * 3) % 200 + 28) as u8,
                ((x * 5 + y * 17) % 200 + 28) as u8,
                ((x * 3 + y * 7) % 200 + 28) as u8,
            ])
        });
        let mut buf = Vec::new();
        JpegEncoder::new_with_quality(&mut buf, 90)
            .write_image(img.as_raw(), w, h, image::ExtendedColorType::Rgb8)
            .unwrap();
        buf
    }

    #[test]
    fn capacity_is_positive_for_natural_image() {
        let jpeg = noisy_jpeg(64, 64);
        assert!(jpeg_capacity(&jpeg).unwrap() > 0);
    }

    #[test]
    fn eligible_positions_skip_dc_and_small_values() {
        let jpeg = noisy_jpeg(32, 32);
        let coeffs = read_coefficients(&jpeg).unwrap();
        let positions = eligible_positions(&coeffs);
        // Never index the DC coefficient (k == 0) and only |v| >= 2.
        for &(ci, di, k) in &positions {
            assert!(k >= 1, "DC coefficient must never be eligible");
            assert!(coeffs.components[ci].blocks[di][k].abs() >= 2);
        }
    }

    #[test]
    fn embed_extract_roundtrip() {
        let jpeg = noisy_jpeg(96, 96);
        let payload = b"jpeg dct roundtrip via dct_io";
        let stego = embed_jpeg(&jpeg, payload, b"passphrase").unwrap();
        // Output is still a valid JPEG (SOI/EOI).
        assert_eq!(&stego[..2], &[0xFF, 0xD8]);
        assert_eq!(&stego[stego.len() - 2..], &[0xFF, 0xD9]);
        let recovered = extract_jpeg(&stego, b"passphrase").unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn wrong_passphrase_does_not_recover_payload() {
        let jpeg = noisy_jpeg(96, 96);
        let stego = embed_jpeg(&jpeg, b"secret payload here", b"right").unwrap();
        // A different passphrase permutes to different positions; it must not
        // reproduce the payload (it returns either NoPayloadFound or garbage).
        if let Ok(data) = extract_jpeg(&stego, b"wrong") {
            assert_ne!(data, b"secret payload here");
        }
    }

    #[test]
    fn embed_rejects_empty_payload() {
        let jpeg = noisy_jpeg(32, 32);
        assert!(matches!(
            embed_jpeg(&jpeg, b"", b"p"),
            Err(StegError::EmptyPayload)
        ));
    }

    #[test]
    fn embed_rejects_oversized_payload() {
        let jpeg = noisy_jpeg(16, 16);
        let cap = jpeg_capacity(&jpeg).unwrap();
        let payload = vec![0xABu8; cap + 64];
        assert!(matches!(
            embed_jpeg(&jpeg, &payload, b"p"),
            Err(StegError::InsufficientCapacity { .. })
        ));
    }

    #[test]
    fn invalid_jpeg_is_corrupted_file() {
        assert!(matches!(
            jpeg_capacity(b"not a jpeg at all"),
            Err(StegError::CorruptedFile)
        ));
        assert!(matches!(
            extract_jpeg(b"\xFF\xD8 garbage", b"p"),
            Err(StegError::CorruptedFile)
        ));
    }
}
