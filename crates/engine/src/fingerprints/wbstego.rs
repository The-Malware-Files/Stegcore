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

//! wbStego: the header it writes into the low bits of a bitmap.
//!
//! # Where this layout came from
//!
//! Not from a specification and not from a guess. wbStego 4.3 is a 2004 Delphi
//! program for Windows and was not available on the machine this was built on, so
//! the header layout was read out of **zsteg 0.2.13's own wbStego reader**, which
//! is the reference implementation that successfully parses real wbStego samples
//! (zsteg ships those samples and tests against them). The file read was
//! `lib/zsteg/checker/wbstego.rb`, taken from the local `stegcore-cmp/zsteg:0.2.13`
//! container image, together with `lib/zsteg/extractor/byte_extractor.rb`, which
//! is where the traversal is defined. Both are quoted below in the detail that
//! matters, because a reader checking this detector should not have to go and
//! fetch a Ruby gem to do it.
//!
//! # The layout
//!
//! wbStego writes into the lowest bit of every byte of a bitmap's pixel array,
//! and the bits assemble into a stream shaped like this:
//!
//! ```text
//! offset 0..3   size     payload length in bytes, 24 bit little endian
//! offset 3..6   discriminator, one of three things:
//!
//!                 00 FF L   wbStego 4.x. L is the length of an inner header
//!                           that follows at offset 6, and that header's first
//!                           byte names the cipher:
//!                             0 none, 1 Blowfish, 2 Twofish,
//!                             3 CAST128, 4 Rijndael
//!
//!                 cb ? ?    wbStego 2.x or 3.x, when cb & 0xC0 is non-zero.
//!                           Bit 0x80 means encrypted, bit 0x40 means the
//!                           extension field is mixed into the payload.
//!
//!                 else      a three character ASCII file extension
//! ```
//!
//! **Only the 4.x form is detected here**, and that is a deliberate narrowing.
//! The 2.x/3.x control byte constrains two bits, and the extension form
//! constrains three bytes to printable ASCII; neither is a signature, both would
//! fire on clean images constantly, and an unmeasurable detector is worse than no
//! detector. The `00 FF` marker plus a cipher byte from a closed set of five is
//! the part of this layout that is actually distinctive.
//!
//! # The traversal, which is the part that is easy to get wrong
//!
//! From `byte_extractor.rb`, whose own comment reads "actual for BMP+wbStego
//! combination":
//!
//! - One bit per byte of the pixel array, bit 0, **not** one bit per pixel. Row
//!   padding bytes are included, because zsteg's capacity calculation uses the
//!   whole pixel array and iterates whole scanlines.
//! - Scanlines are walked in the order the file stores them, bytes ascending
//!   within each. Reading the pixel array in raw file order reproduces that for
//!   both bottom-up and top-down bitmaps, which is why this module never has to
//!   decide which way up the image is.
//! - The first bit read becomes the **most significant** bit of the first
//!   assembled byte. zsteg calls this `bit_order: :lsb` and its wbStego check
//!   refuses to run on anything else; the name is about where the last bit lands,
//!   not the first, and the arithmetic in `byte_extractor.rb` is unambiguous.
//!
//! Scope is 24 bit uncompressed BMP. wbStego also takes 4 and 8 bit bitmaps, but
//! there its capacity depends on how many palette entries the image actually uses
//! (fewer than 9, or fewer than 129, per `calc_avail_size`), which needs an index
//! histogram and a second traversal rule. That is a separate detector rather than
//! a flag on this one, and it is not written yet.
//!
//! # Tier: `Heuristic`, provisionally, and the measurement that says why
//!
//! ## What was measured
//!
//! Clean corpus: **2,000 photographs from the local ALASKA2 cover sample**,
//! decoded and written out as 24 bit uncompressed BMP, which is the carrier
//! format this detector reads. Photographs rather than synthetic noise, because
//! the low bits of a real photograph are not uniform and that is the thing that
//! could bite.
//!
//! | Measure | Count | Share |
//! |---|---|---|
//! | Plausible 24 bit size field alone | 38 of 2,000 | 1.90% |
//! | Full header match, so flagged | **0 of 2,000** | **0.000%** |
//!
//! The first row is the point of the exercise. The size field on its own is a
//! weak test and the measurement says so: one clean photograph in fifty-three
//! produces a 24 bit value that lands inside its own carrier's capacity, which is
//! close to the 1.6% the arithmetic predicts and would be an unusable detector by
//! itself. The `00 FF` marker and the cipher byte are what take that to zero.
//!
//! `tests/fingerprint_wbstego_fpr.rs` holds the walk and prints both rows. It
//! examines a smaller sample on an ordinary test run, because decoding two
//! thousand JPEGs takes over three minutes; the figures above are from the full
//! run on 2026-10-01, and that file documents how to repeat it. It skips itself
//! when the corpus is absent, so a fresh clone still passes.
//!
//! ## Why that is not enough for `Exact`
//!
//! A false-positive rate of zero on 2,000 clean files would support `Exact` on
//! the precision argument, and the arithmetic agrees: sixteen fixed bits, a size
//! field that has to land inside the carrier's capacity, and a cipher byte
//! confined to five of 256 values, which multiplies out to something around one
//! in a thousand million. That is the same shape of argument DeepSound's tier
//! rests on.
//!
//! It is held at `Heuristic` anyway, for a reason that has nothing to do with
//! precision: **the recall side is untested**. No file wbStego wrote has ever
//! been through this code. The traversal above is transcribed from a reader
//! rather than confirmed against a sample, and if any one of those three
//! traversal decisions is wrong, the detector is not a cautious detector, it is a
//! detector that never fires and whose zero false-positive rate means nothing.
//! `Exact` short-circuits the whole ensemble, so the bar for it is a signature
//! that has been seen working, not one that has been read carefully.
//!
//! **This tier is provisional.** What would settle it: one wbStego 4.x BMP, or a
//! run of zsteg's own committed wbStego samples through this code. Either turns
//! the recall side from an argument into a number, and then the tier is a
//! decision somebody can make on evidence.

use std::path::Path;

use crate::fingerprints::{read_capped, Tier, ToolFingerprint};

/// The two fixed bytes that mark a wbStego 4.x header, at offsets 3 and 4 of the
/// assembled stream.
pub const HEADER_MARKER: [u8; 2] = [0x00, 0xFF];

/// The ciphers wbStego 4.x names in the first byte of its inner header, indexed
/// by that byte. Index 0 is an unencrypted payload.
///
/// Transcribed from zsteg's `ENCRYPTIONS` table. A byte outside this range is
/// treated as no match rather than as a weaker one, the same way DeepSound's
/// mode byte is: a sixteen bit marker coincidence is already unlikely, and a
/// wbStego build using a cipher index nobody has recorded is a thing to find out
/// about rather than to guess at.
pub const CIPHERS: [&str; 5] = [
    "no encryption",
    "Blowfish",
    "Twofish",
    "CAST128",
    "Rijndael",
];

/// Longest inner header length accepted, in bytes.
///
/// A documented cap rather than trust in the field. zsteg reads whatever length
/// the byte claims; the real headers are a cipher byte and a short amount of key
/// material, so anything approaching 256 is a malformed or hostile file rather
/// than a wbStego one, and accepting it would only widen the false-positive
/// surface.
pub const MAX_INNER_HEADER_LEN: usize = 64;

/// Bytes assembled from the pixel array. The header is seven bytes; this reads a
/// little past it so the inner header length can be sanity checked against bytes
/// that actually exist.
const STREAM_BYTES: usize = 7 + MAX_INNER_HEADER_LEN;

/// Smallest bitmap worth looking at, in pixel-array bytes.
///
/// [`STREAM_BYTES`] bytes of stream need eight times that many carrier bytes. An
/// image smaller than this cannot hold the header at all, so it is declined
/// before any arithmetic rather than part way through it.
pub const MIN_PIXEL_ARRAY_BYTES: usize = STREAM_BYTES * 8;

/// Largest pixel array this detector will index into, in bytes.
///
/// The whole file is already bounded by [`crate::fingerprints::MAX_FILE_BYTES`].
/// This second cap exists because the dimensions in a BMP header are
/// attacker-supplied and multiply: a width and height that claim a petabyte of
/// pixels must be rejected by arithmetic that cannot overflow, not discovered by
/// a slice that panics.
pub const MAX_PIXEL_ARRAY_BYTES: u64 = 512 * 1024 * 1024;

/// A recognised wbStego 4.x header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Payload length the size field claims, in bytes.
    pub payload_bytes: u32,
    /// Length of the inner header that follows the marker.
    pub inner_header_len: u8,
    /// The cipher its first byte names, in words.
    pub cipher: &'static str,
}

/// A bitmap's pixel array and what it can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Carrier<'a> {
    /// The pixel array in file order, padding bytes included.
    pub pixel_array: &'a [u8],
    /// Bytes wbStego could store here: one bit per pixel-array byte.
    pub capacity_bytes: u64,
}

/// Look for wbStego 4.x in a 24 bit uncompressed BMP.
///
/// Returns `None` for any other file, which includes the palette bitmaps
/// wbStego also supports; see the module notes on why those are out of scope.
pub fn check(path: &Path) -> Option<ToolFingerprint> {
    let bytes = read_capped(path)?;
    let carrier = carrier_from_bmp(&bytes)?;
    let stream = assemble(carrier.pixel_array, STREAM_BYTES)?;
    let header = header_from_stream(&stream, carrier.capacity_bytes)?;
    Some(ToolFingerprint {
        tool: "wbStego".to_string(),
        tier: Tier::Heuristic,
        evidence: format!(
            "the low bits of the bitmap's pixel array assemble into wbStego 4's header: a \
             {} byte payload, the 00 FF marker, and an inner header of {} bytes naming {}. \
             The marker is sixteen fixed bits at a fixed place in the bit stream, so this is \
             unlikely to be a coincidence, but no file wbStego wrote has been through this \
             detector, so it corroborates rather than decides.",
            header.payload_bytes, header.inner_header_len, header.cipher
        ),
    })
}

/// Locate the pixel array of a 24 bit uncompressed BMP.
///
/// Every field read here comes from the file, so every one is bounds checked and
/// every multiplication is checked. Returns `None` for anything that is not the
/// one bitmap shape this detector handles, and for a file whose own headers do
/// not agree with its length.
pub fn carrier_from_bmp(bytes: &[u8]) -> Option<Carrier<'_>> {
    // BITMAPFILEHEADER is 14 bytes, BITMAPINFOHEADER another 40.
    if bytes.len() < 54 || !bytes.starts_with(b"BM") {
        return None;
    }
    let u32_at = |offset: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let offset_to_pixels = u32_at(10)? as usize;
    let dib_header_len = u32_at(14)?;
    // Smaller than a BITMAPINFOHEADER means a BITMAPCOREHEADER, which cannot
    // describe a compression mode, so the checks below have nothing to read.
    if dib_header_len < 40 {
        return None;
    }
    let width = i32::from_le_bytes(bytes.get(18..22)?.try_into().ok()?);
    let height = i32::from_le_bytes(bytes.get(22..26)?.try_into().ok()?);
    let bits_per_pixel = u16::from_le_bytes(bytes.get(28..30)?.try_into().ok()?);
    let compression = u32_at(30)?;
    if bits_per_pixel != 24 || compression != 0 || width <= 0 || height == 0 {
        return None;
    }

    // Rows are padded to a four byte boundary. A negative height means the rows
    // are stored top-down; either way they are read in file order, so only the
    // magnitude matters here.
    let stride = (u64::from(width as u32).checked_mul(3)?.checked_add(3)? / 4).checked_mul(4)?;
    let rows = u64::from(height.unsigned_abs());
    let array_len = stride.checked_mul(rows)?;
    if array_len > MAX_PIXEL_ARRAY_BYTES {
        return None;
    }
    let array_len = usize::try_from(array_len).ok()?;
    let end = offset_to_pixels.checked_add(array_len)?;
    if end > bytes.len() || array_len < MIN_PIXEL_ARRAY_BYTES {
        return None;
    }
    Some(Carrier {
        pixel_array: bytes.get(offset_to_pixels..end)?,
        // One bit per byte, so a byte of payload per eight carrier bytes. This
        // is zsteg's `calc_avail_size` for the 24 bit case.
        capacity_bytes: array_len as u64 / 8,
    })
}

/// Assemble `count` bytes from the low bits of `pixel_bytes`.
///
/// The first bit read lands in the most significant bit of the first byte; see
/// the module notes on where that comes from. Returns `None` when there are not
/// enough carrier bytes, rather than assembling a short stream that the header
/// check would then have to second-guess.
pub fn assemble(pixel_bytes: &[u8], count: usize) -> Option<Vec<u8>> {
    let needed = count.checked_mul(8)?;
    if pixel_bytes.len() < needed {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for chunk in pixel_bytes[..needed].chunks_exact(8) {
        let mut byte = 0u8;
        for (index, carrier) in chunk.iter().enumerate() {
            if carrier & 1 == 1 {
                byte |= 1 << (7 - index);
            }
        }
        out.push(byte);
    }
    Some(out)
}

/// Read a wbStego 4.x header out of an assembled bit stream.
///
/// `capacity_bytes` is what the carrier could hold, and it is what makes the
/// size field mean anything: in a clean image those 24 bits are effectively
/// random, so the odds of them landing inside a real capacity are the capacity
/// over sixteen million.
pub fn header_from_stream(stream: &[u8], capacity_bytes: u64) -> Option<Header> {
    // Three size bytes, three discriminator bytes, one cipher byte.
    if stream.len() < 7 {
        return None;
    }
    let payload_bytes = u32::from_le_bytes([stream[0], stream[1], stream[2], 0]);
    if payload_bytes == 0 || u64::from(payload_bytes) > capacity_bytes {
        return None;
    }
    if stream[3..5] != HEADER_MARKER {
        return None;
    }
    let inner_header_len = stream[5];
    if inner_header_len == 0 || usize::from(inner_header_len) > MAX_INNER_HEADER_LEN {
        return None;
    }
    let cipher = *CIPHERS.get(usize::from(stream[6]))?;
    // The header and the payload it describes both have to fit. A size field
    // that only just fits on its own but overruns once the header is counted is
    // an inconsistent file, not a wbStego one.
    let claimed = u64::from(payload_bytes)
        .checked_add(6)?
        .checked_add(u64::from(inner_header_len))?;
    if claimed > capacity_bytes {
        return None;
    }
    Some(Header {
        payload_bytes,
        inner_header_len,
        cipher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 24 bit BMP whose pixel array carries `stream` in its low bits, over a
    /// mid-grey base so the other seven bits of each byte are not all zero.
    fn bmp_carrying(stream: &[u8], pixel_array_bytes: usize) -> Vec<u8> {
        let mut pixels = vec![0x80u8; pixel_array_bytes];
        for (byte_index, byte) in stream.iter().enumerate() {
            for bit in 0..8usize {
                let at = byte_index * 8 + bit;
                if at >= pixels.len() {
                    break;
                }
                let value = (byte >> (7 - bit)) & 1;
                pixels[at] = (pixels[at] & 0xFE) | value;
            }
        }
        // One row, as wide as the array allows, so the stride arithmetic agrees
        // with the array length exactly.
        let width = (pixel_array_bytes / 3) as u32;
        let stride = (width as usize * 3).div_ceil(4) * 4;
        bmp_with(width, 1, stride, &pixels)
    }

    /// Assemble a BMP around a pixel array, padding each row to `stride`.
    fn bmp_with(width: u32, height: u32, stride: usize, pixels: &[u8]) -> Vec<u8> {
        let mut array = pixels.to_vec();
        array.resize(stride * height as usize, 0x80);
        let mut file = Vec::new();
        file.extend_from_slice(b"BM");
        file.extend_from_slice(&((54 + array.len()) as u32).to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes()); // reserved
        file.extend_from_slice(&54u32.to_le_bytes()); // offset to pixels
        file.extend_from_slice(&40u32.to_le_bytes()); // DIB header length
        file.extend_from_slice(&(width as i32).to_le_bytes());
        file.extend_from_slice(&(height as i32).to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes()); // planes
        file.extend_from_slice(&24u16.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes()); // BI_RGB
        file.extend_from_slice(&(array.len() as u32).to_le_bytes());
        file.extend_from_slice(&[0u8; 16]); // resolution, palette counts
        file.extend_from_slice(&array);
        file
    }

    /// A wbStego 4.x header stream.
    fn header_stream(payload_bytes: u32, inner_len: u8, cipher_byte: u8) -> Vec<u8> {
        let size = payload_bytes.to_le_bytes();
        let mut stream = vec![size[0], size[1], size[2]];
        stream.extend_from_slice(&HEADER_MARKER);
        stream.push(inner_len);
        stream.push(cipher_byte);
        stream.resize(STREAM_BYTES, 0x5A);
        stream
    }

    #[test]
    fn the_header_round_trips_through_the_bit_assembly() {
        let stream = header_stream(1_000, 8, 4);
        let assembled = assemble(&bmp_carrying(&stream, 8_192)[54..], STREAM_BYTES).unwrap();
        assert_eq!(assembled[..7], stream[..7]);
    }

    #[test]
    fn a_planted_header_is_recognised_in_a_real_bitmap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carrier.bmp");
        // 8,192 pixel-array bytes is 1,024 bytes of capacity.
        std::fs::write(&path, bmp_carrying(&header_stream(512, 8, 1), 8_192)).unwrap();
        let found = check(&path).expect("the header is there to be found");
        assert_eq!(found.tool, "wbStego");
        assert_eq!(found.tier, Tier::Heuristic);
        assert!(found.evidence.contains("512 byte payload"));
        assert!(found.evidence.contains("Blowfish"));
    }

    #[test]
    fn every_documented_cipher_index_is_read_and_named() {
        for (index, name) in CIPHERS.iter().enumerate() {
            let stream = header_stream(64, 4, index as u8);
            let header = header_from_stream(&stream, 1_024)
                .unwrap_or_else(|| panic!("cipher index {index} should parse"));
            assert_eq!(header.cipher, *name);
        }
    }

    #[test]
    fn a_cipher_index_nobody_has_recorded_is_not_claimed_as_a_match() {
        // Deliberate: see the note on `CIPHERS`.
        assert!(header_from_stream(&header_stream(64, 4, 5), 1_024).is_none());
        assert!(header_from_stream(&header_stream(64, 4, 0xFF), 1_024).is_none());
    }

    #[test]
    fn the_near_miss_cases_do_not_fire() {
        // The marker is the signature. One byte wrong in it and this is an
        // ordinary image, however plausible the rest of the stream looks.
        let mut almost = header_stream(64, 4, 0);
        almost[4] = 0xFE;
        assert!(header_from_stream(&almost, 1_024).is_none());

        // The 2.x/3.x control byte form, which is explicitly out of scope: a
        // high bit set in the first discriminator byte and no 00 FF marker.
        let mut old_version = header_stream(64, 4, 0);
        old_version[3] = 0xC0;
        old_version[4] = 0x11;
        assert!(header_from_stream(&old_version, 1_024).is_none());

        // The plain file-extension form, also out of scope.
        let mut with_extension = header_stream(64, 4, 0);
        with_extension[3..6].copy_from_slice(b"txt");
        assert!(header_from_stream(&with_extension, 1_024).is_none());
    }

    #[test]
    fn a_size_field_the_carrier_could_not_hold_does_not_fire() {
        // Zero, and larger than capacity, and large enough that it only
        // overruns once the header itself is counted.
        assert!(header_from_stream(&header_stream(0, 4, 0), 1_024).is_none());
        assert!(header_from_stream(&header_stream(2_048, 4, 0), 1_024).is_none());
        assert!(header_from_stream(&header_stream(1_020, 8, 0), 1_024).is_none());
        // One below that boundary does fire, so the check is not simply refusing
        // everything near the edge.
        assert!(header_from_stream(&header_stream(1_010, 8, 0), 1_024).is_some());
    }

    #[test]
    fn an_inner_header_length_outside_the_documented_cap_does_not_fire() {
        assert!(header_from_stream(&header_stream(64, 0, 0), 1_024).is_none());
        assert!(header_from_stream(&header_stream(64, 0xFF, 0), 1_024).is_none());
        assert!(
            header_from_stream(&header_stream(64, MAX_INNER_HEADER_LEN as u8, 0), 1_024).is_some()
        );
    }

    #[test]
    fn a_stream_too_short_to_hold_the_header_is_not_a_match() {
        assert!(header_from_stream(&[], 1_024).is_none());
        assert!(header_from_stream(&header_stream(64, 4, 0)[..6], 1_024).is_none());
    }

    #[test]
    fn a_carrier_that_ends_before_the_header_does_is_declined_not_part_read() {
        // The boundary case: the header straddles the end of what there is to
        // read. Assembly refuses rather than returning a short stream.
        let stream = header_stream(64, 4, 0);
        let array = bmp_carrying(&stream, 8_192);
        let pixels = &array[54..];
        assert!(assemble(pixels, STREAM_BYTES).is_some());
        assert!(assemble(&pixels[..STREAM_BYTES * 8 - 1], STREAM_BYTES).is_none());

        // And the same thing through the whole detector: a bitmap whose pixel
        // array is one byte short of what the header needs.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.bmp");
        std::fs::write(&path, bmp_carrying(&stream, MIN_PIXEL_ARRAY_BYTES - 3)).unwrap();
        assert!(check(&path).is_none());
    }

    #[test]
    fn a_clean_photograph_shaped_bitmap_is_not_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean.bmp");
        // Smoothly varying bytes, as a photograph's rows are, rather than
        // uniform grey.
        let pixels: Vec<u8> = (0..24_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8)
            .collect();
        let width = (pixels.len() / 3) as u32;
        let stride = pixels.len().div_ceil(4) * 4;
        std::fs::write(&path, bmp_with(width, 1, stride, &pixels)).unwrap();
        assert!(check(&path).is_none());
    }

    #[test]
    fn a_zero_byte_or_truncated_or_malformed_bitmap_is_declined_rather_than_crashing() {
        let dir = tempfile::tempdir().unwrap();
        let stream = header_stream(512, 8, 1);
        let good = bmp_carrying(&stream, 8_192);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty.bmp", Vec::new()),
            ("two.bmp", b"BM".to_vec()),
            ("header_only.bmp", good[..54].to_vec()),
            ("half.bmp", good[..good.len() / 2].to_vec()),
            (
                "not_a_bmp.bmp",
                vec![0x89, b'P', b'N', b'G', 13, 10, 26, 10],
            ),
            ("core_header.bmp", {
                let mut f = good.clone();
                f[14..18].copy_from_slice(&12u32.to_le_bytes()); // BITMAPCOREHEADER
                f
            }),
            ("eight_bit.bmp", {
                let mut f = good.clone();
                f[28..30].copy_from_slice(&8u16.to_le_bytes());
                f
            }),
            ("rle_compressed.bmp", {
                let mut f = good.clone();
                f[30..34].copy_from_slice(&1u32.to_le_bytes()); // BI_RLE8
                f
            }),
            ("zero_width.bmp", {
                let mut f = good.clone();
                f[18..22].copy_from_slice(&0i32.to_le_bytes());
                f
            }),
            ("zero_height.bmp", {
                let mut f = good.clone();
                f[22..26].copy_from_slice(&0i32.to_le_bytes());
                f
            }),
            ("absurd_dimensions.bmp", {
                let mut f = good.clone();
                f[18..22].copy_from_slice(&0x3FFF_FFFFi32.to_le_bytes());
                f[22..26].copy_from_slice(&0x3FFF_FFFFi32.to_le_bytes());
                f
            }),
            ("pixel_offset_past_end.bmp", {
                let mut f = good.clone();
                f[10..14].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
                f
            }),
        ];
        for (name, bytes) in cases {
            let path = dir.path().join(name);
            std::fs::write(&path, &bytes).unwrap();
            assert!(check(&path).is_none(), "{name} should have been declined");
        }
        assert!(check(Path::new("/nonexistent/carrier.bmp")).is_none());
    }

    #[test]
    fn a_top_down_bitmap_reads_the_same_header_as_a_bottom_up_one() {
        // A negative height stores the rows the other way up. The pixel array is
        // read in file order either way, so the header must still be found.
        let dir = tempfile::tempdir().unwrap();
        let stream = header_stream(512, 8, 2);
        let mut file = bmp_carrying(&stream, 8_192);
        let height = i32::from_le_bytes(file[22..26].try_into().unwrap());
        file[22..26].copy_from_slice(&(-height).to_le_bytes());
        let path = dir.path().join("topdown.bmp");
        std::fs::write(&path, &file).unwrap();
        assert!(check(&path).is_some());
    }

    #[test]
    fn assembly_refuses_a_count_that_cannot_be_multiplied_out() {
        assert!(assemble(&[0u8; 64], usize::MAX).is_none());
        assert_eq!(assemble(&[0u8; 8], 1), Some(vec![0u8]));
        assert_eq!(assemble(&[1u8; 8], 1), Some(vec![0xFFu8]));
        // The first bit read is the most significant one.
        assert_eq!(assemble(&[1, 0, 0, 0, 0, 0, 0, 0], 1), Some(vec![0x80u8]));
    }
}
