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

//! Steghide attribution: what is built, and the one piece that is not.
//!
//! # Read this before using anything here
//!
//! **Steghide attribution does not work yet, and this module says so in code
//! rather than only in a document.** [`TRAVERSAL_RECONSTRUCTED`] is `false`, no
//! [`crate::bruteforce::Probe`] over a real Steghide file is exported, and the
//! parts that *are* here are the parts that could be established rather than
//! guessed. Wiring a guessed traversal into the analyser would produce a
//! detector that reports "not Steghide" on every Steghide file in existence,
//! which is worse than reporting nothing, because the first is a claim and the
//! second is a gap.
//!
//! # Why Steghide is hard, in plain terms
//!
//! Most tools that leave a signature leave it somewhere you can just look. A
//! Steghide file does not: a Steghide JPEG still begins with the ordinary JPEG
//! start marker. Its signature, the three bytes `73 68 8D`, is written into the
//! hidden stream, and the hidden stream is spread through the carrier in an
//! order derived from the password. So the signature is genuinely present and
//! genuinely unreadable until you reproduce that order.
//!
//! Stegcore carried a check for years that compared the first three bytes of the
//! *file* to those three bytes. It could never fire, and it was removed in
//! 4.0.1. The catalogue entry at `private/plans/fingerprint-catalog.md` section
//! 3 records that history.
//!
//! # The published attack, and what it actually needs
//!
//! CVE-2021-27211 is the lever: Steghide reduces the password to a 32 bit value
//! before using it to order the samples, so the ordering has at most four
//! thousand million possibilities regardless of how long the password is. Try
//! each, read the first few bits in the order it implies, and look for the
//! signature.
//!
//! Three pieces are needed and only two of them could be built here:
//!
//! | Piece | State | Why |
//! |---|---|---|
//! | The sample space: which carrier values can carry a bit, in what order | **Built** ([`SampleSpace`]) for uncompressed BMP and PCM WAV | Determined by the carrier format, and testable against it |
//! | The confirmation: what a correct read looks like | **Built** ([`confirm`]) | Anchored on the signature, with the rest of the prefix treated as corroboration rather than asserted |
//! | The traversal: which sample carries bit *n* for seed *s* | **Not built** | Needs Steghide's own generator and permutation, which are in its source and could not be obtained or derived on this machine |
//!
//! The traversal is a trait, [`Traversal`], so the day the source is to hand the
//! gap is one implementation wide and everything around it is already tested.
//!
//! # The finding that changes how E1 has to be specified
//!
//! The signature is three bytes, 24 bits. A sweep of a 32 bit seed space makes
//! about 2^32 / 2^24, roughly **256 wrong seeds produce those three bytes by
//! chance**. So "exhaust the seed space and confirm the magic" as the deferred
//! item words it does not identify a file with certainty: it identifies about
//! 257 candidates, 256 of them noise. Confirmation has to extend past the
//! signature into fields whose values are constrained, which is what [`Prefix`]
//! and [`confirm`] are shaped for and why [`MIN_CONFIRMATION_BITS`] exists.

use std::path::Path;

use crate::errors::StegError;

/// Steghide's signature, the first three bytes of its hidden stream.
///
/// Often written as the text "shm", which is only two thirds true: the third
/// byte is `0x8D` and is not printable.
pub const MAGIC: [u8; 3] = [0x73, 0x68, 0x8D];

/// Whether the sample traversal has been reconstructed and checked against real
/// Steghide output.
///
/// `false`, deliberately and visibly. Nothing in this module may be used to
/// claim a file is or is not Steghide output while this is `false`; see the
/// module notes.
pub const TRAVERSAL_RECONSTRUCTED: bool = false;

/// Bits of agreement a confirmation needs before it may be called decisive.
///
/// The signature alone is 24, and a 32 bit sweep produces about 256 chance
/// matches at that width. 40 bits puts the expected number of chance matches
/// across a full sweep at about one in 256, which is the point at which a single
/// hit is worth reporting.
pub const MIN_CONFIRMATION_BITS: u32 = 40;

/// Largest carrier this module will read into a sample space, in samples.
/// Documented cap rather than trust in the file being reasonable.
pub const MAX_SAMPLES: usize = 400_000_000;

/// The values in a carrier that can each hold one bit of hidden data, in the
/// order the carrier itself lays them out.
///
/// Steghide hides a bit in the parity of a sample: an even value means zero, an
/// odd value means one. What counts as a sample depends on the format, which is
/// the part this type knows and the traversal does not.
#[derive(Debug, Clone)]
pub struct SampleSpace {
    parities: Vec<bool>,
    carrier: CarrierKind,
}

/// Which family of carrier a sample space came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    /// Uncompressed 24 bit BMP. Every colour byte of the pixel array is a
    /// sample, in the order the file stores them.
    Bmp24,
    /// PCM WAV. Every audio sample is one sample.
    PcmWav,
}

impl SampleSpace {
    /// Parse a carrier into its sample space.
    ///
    /// Only the two formats whose sample definition is fixed by the file format
    /// itself are supported. JPEG is the gap that matters most, and it is
    /// refused rather than approximated: Steghide's JPEG samples are quantised
    /// coefficients under its own inclusion rules, and getting those rules wrong
    /// looks identical to getting the traversal wrong, so guessing here would
    /// make the remaining gap impossible to diagnose.
    pub fn load(path: &Path) -> Result<Self, StegError> {
        if !path.exists() {
            return Err(StegError::FileNotFound(path.display().to_string()));
        }
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }

    /// Parse a carrier already held in memory.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StegError> {
        if bytes.starts_with(b"BM") {
            return Self::from_bmp(bytes);
        }
        if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
            return Self::from_wav(bytes);
        }
        if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Err(StegError::UnsupportedFormat(
                "Steghide attribution cannot read JPEG carriers yet. Only uncompressed BMP and \
                 PCM WAV are supported. See the notes in the brute-force module for why JPEG is \
                 refused rather than approximated."
                    .into(),
            ));
        }
        Err(StegError::UnsupportedFormat(
            "this file is not a format Steghide attribution can read. Supported: uncompressed \
             BMP and PCM WAV."
                .into(),
        ))
    }

    /// Read the pixel array of an uncompressed 24 bit BMP.
    fn from_bmp(bytes: &[u8]) -> Result<Self, StegError> {
        // A BITMAPFILEHEADER is 14 bytes; the pixel-array offset is at 10 and
        // the DIB header size at 14. Every field is bounds-checked, because the
        // whole point of this module is that its input is a suspect file.
        if bytes.len() < 54 {
            return Err(StegError::CorruptedFile);
        }
        let data_offset = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
        let bits_per_pixel = u16::from_le_bytes([bytes[28], bytes[29]]);
        let compression = u32::from_le_bytes([bytes[30], bytes[31], bytes[32], bytes[33]]);
        if bits_per_pixel != 24 {
            return Err(StegError::UnsupportedFormat(format!(
                "this BMP stores {bits_per_pixel} bits per pixel. Steghide attribution reads \
                 24 bit BMPs only."
            )));
        }
        if compression != 0 {
            return Err(StegError::UnsupportedFormat(
                "this BMP is compressed. Steghide attribution reads uncompressed BMPs only.".into(),
            ));
        }
        if data_offset >= bytes.len() {
            return Err(StegError::CorruptedFile);
        }
        let pixels = &bytes[data_offset..];
        if pixels.len() > MAX_SAMPLES {
            return Err(StegError::UnsupportedFormat(format!(
                "this carrier has {} samples, past the {MAX_SAMPLES} limit this search will hold.",
                pixels.len()
            )));
        }
        Ok(Self {
            parities: pixels.iter().map(|b| b & 1 == 1).collect(),
            carrier: CarrierKind::Bmp24,
        })
    }

    /// Read the PCM samples of a WAV file.
    fn from_wav(bytes: &[u8]) -> Result<Self, StegError> {
        let (bits_per_sample, data) = wav_data_chunk(bytes)?;
        let parities: Vec<bool> = match bits_per_sample {
            8 => data.iter().map(|b| b & 1 == 1).collect(),
            16 => data.chunks_exact(2).map(|s| s[0] & 1 == 1).collect(),
            other => {
                return Err(StegError::UnsupportedFormat(format!(
                    "this WAV stores {other} bits per sample. Steghide attribution reads 8 and \
                     16 bit PCM only."
                )))
            }
        };
        if parities.len() > MAX_SAMPLES {
            return Err(StegError::UnsupportedFormat(format!(
                "this carrier has {} samples, past the {MAX_SAMPLES} limit this search will hold.",
                parities.len()
            )));
        }
        Ok(Self {
            parities,
            carrier: CarrierKind::PcmWav,
        })
    }

    /// Build a sample space directly from parities, for tests and for a caller
    /// that has already decoded a carrier some other way.
    pub fn from_parities(parities: Vec<bool>, carrier: CarrierKind) -> Self {
        Self { parities, carrier }
    }

    /// How many samples the carrier has, which is the ceiling on how much could
    /// be hidden in it.
    pub fn len(&self) -> usize {
        self.parities.len()
    }

    /// Whether the carrier has no samples at all.
    pub fn is_empty(&self) -> bool {
        self.parities.is_empty()
    }

    /// Which carrier family this came from.
    pub fn carrier(&self) -> CarrierKind {
        self.carrier
    }

    /// The bit stored in sample `index`, or `None` past the end.
    pub fn bit(&self, index: usize) -> Option<bool> {
        self.parities.get(index).copied()
    }

    /// Read `count` bits in the order `traversal` dictates, most significant
    /// first within each byte.
    ///
    /// Returns `None` when the traversal runs past the end of the carrier, which
    /// is a property of the carrier rather than a failure.
    pub fn read_bits<T: Traversal>(&self, traversal: &mut T, count: usize) -> Option<Vec<bool>> {
        if count > self.parities.len() {
            return None;
        }
        let mut bits = Vec::with_capacity(count);
        for position in 0..count {
            let index = traversal.sample_for(position)?;
            bits.push(self.bit(index)?);
        }
        Some(bits)
    }
}

/// Locate the `data` chunk of a RIFF WAV file and the bit depth that describes
/// it, bounds-checking every length field on the way.
fn wav_data_chunk(bytes: &[u8]) -> Result<(u16, &[u8]), StegError> {
    let mut cursor = 12usize;
    let mut bits_per_sample = None;
    // Bounded by construction: every iteration advances `cursor` by at least
    // eight bytes, so the walk cannot revisit a chunk or spin on a zero length.
    while cursor + 8 <= bytes.len() {
        let id = &bytes[cursor..cursor + 4];
        let size = u32::from_le_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let body_start = cursor + 8;
        let body_end = body_start.saturating_add(size).min(bytes.len());
        if id == b"fmt " && size >= 16 && body_start + 16 <= bytes.len() {
            bits_per_sample = Some(u16::from_le_bytes([
                bytes[body_start + 14],
                bytes[body_start + 15],
            ]));
        }
        if id == b"data" {
            let bits = bits_per_sample.ok_or_else(|| {
                StegError::UnsupportedFormat(
                    "this WAV has audio data but no format chunk before it, so the sample size \
                     is unknown."
                        .into(),
                )
            })?;
            return Ok((bits, &bytes[body_start..body_end]));
        }
        // Chunks are word aligned, and the pad byte is not counted in the size.
        cursor = body_start.saturating_add(size).saturating_add(size & 1);
    }
    Err(StegError::UnsupportedFormat(
        "this WAV has no audio data chunk.".into(),
    ))
}

/// The order a candidate key implies for reading the hidden stream.
///
/// This is the one piece of Steghide attribution that is not built. An
/// implementation answers, for a given candidate key, which sample carries bit
/// `position` of the hidden stream. The trait exists now so that the sample
/// readers, the confirmation and the whole search harness around them are
/// written and tested against something; supplying a faithful implementation is
/// the entire remaining task.
pub trait Traversal {
    /// Which sample holds bit `position`, or `None` once the traversal has run
    /// out of carrier.
    ///
    /// Called with `position` strictly increasing from zero, so an
    /// implementation may keep state rather than recompute from scratch.
    fn sample_for(&mut self, position: usize) -> Option<usize>;
}

/// A traversal that reads samples in file order.
///
/// **Not Steghide's order.** Steghide permutes. This exists so the sample
/// readers and the confirmation can be tested, and so the shape of a real
/// implementation is on the page.
#[derive(Debug, Clone)]
pub struct SequentialTraversal {
    limit: usize,
}

impl SequentialTraversal {
    /// A sequential traversal over a carrier with `limit` samples.
    pub fn new(limit: usize) -> Self {
        Self { limit }
    }
}

impl Traversal for SequentialTraversal {
    fn sample_for(&mut self, position: usize) -> Option<usize> {
        (position < self.limit).then_some(position)
    }
}

/// How much of the hidden stream's leading structure a read agreed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    /// Whether the three signature bytes were present.
    pub magic_matched: bool,
    /// Bits of the read that are constrained, and so count as evidence. The
    /// signature contributes 24; corroborating fields contribute the rest.
    pub confirmed_bits: u32,
}

impl Prefix {
    /// Whether this is enough to report. See [`MIN_CONFIRMATION_BITS`] for why
    /// a signature match on its own is not.
    pub fn is_decisive(&self) -> bool {
        self.magic_matched && self.confirmed_bits >= MIN_CONFIRMATION_BITS
    }
}

/// Test a read of the hidden stream's opening bits against Steghide's structure.
///
/// `bits` is the stream as a traversal read it, most significant bit of each
/// byte first. The signature is checked exactly, because it is a published
/// constant. Everything after it is treated as corroboration and is deliberately
/// not asserted field by field: Steghide's post-signature layout could not be
/// established on this machine from a primary source, and inventing a layout
/// would hide the real gap behind a plausible-looking check.
///
/// Returns `None` when there are not even enough bits for the signature.
pub fn confirm(bits: &[bool]) -> Option<Prefix> {
    if bits.len() < 24 {
        return None;
    }
    let mut magic_matched = true;
    for (byte_index, expected) in MAGIC.iter().enumerate() {
        for bit_index in 0..8 {
            let read = bits[byte_index * 8 + bit_index];
            let want = (expected >> (7 - bit_index)) & 1 == 1;
            if read != want {
                magic_matched = false;
            }
        }
    }
    Some(Prefix {
        magic_matched,
        // Only the signature is constrained today. The moment the layout after
        // it is established from a primary source, this is where those bits are
        // added, and `is_decisive` starts returning true.
        confirmed_bits: if magic_matched { 24 } else { 0 },
    })
}

/// Pack a byte sequence into the bit order a traversal reads, for tests and for
/// building fixtures.
pub fn bits_of(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for index in 0..8 {
            bits.push((byte >> (7 - index)) & 1 == 1);
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bmp24(pixel_bytes: &[u8]) -> Vec<u8> {
        let mut file = vec![0u8; 54];
        file[0] = b'B';
        file[1] = b'M';
        file[10..14].copy_from_slice(&54u32.to_le_bytes());
        file[14..18].copy_from_slice(&40u32.to_le_bytes());
        file[28..30].copy_from_slice(&24u16.to_le_bytes());
        file[30..34].copy_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(pixel_bytes);
        file
    }

    fn wav(bits_per_sample: u16, data: &[u8]) -> Vec<u8> {
        let mut file = Vec::new();
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(b"WAVE");
        file.extend_from_slice(b"fmt ");
        file.extend_from_slice(&16u32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes()); // PCM
        file.extend_from_slice(&1u16.to_le_bytes()); // mono
        file.extend_from_slice(&44_100u32.to_le_bytes());
        file.extend_from_slice(&44_100u32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&bits_per_sample.to_le_bytes());
        file.extend_from_slice(b"data");
        file.extend_from_slice(&(data.len() as u32).to_le_bytes());
        file.extend_from_slice(data);
        file
    }

    /// Build a carrier whose parities spell `bytes` when read in file order.
    fn carrier_carrying(bytes: &[u8], total_samples: usize) -> SampleSpace {
        let wanted = bits_of(bytes);
        let mut parities = vec![false; total_samples];
        for (index, bit) in wanted.iter().enumerate() {
            if index < total_samples {
                parities[index] = *bit;
            }
        }
        SampleSpace::from_parities(parities, CarrierKind::Bmp24)
    }

    #[test]
    fn a_bmp_pixel_array_becomes_one_sample_per_byte() {
        let file = bmp24(&[0x00, 0x01, 0x02, 0x03, 0xFF]);
        let space = SampleSpace::from_bytes(&file).unwrap();
        assert_eq!(space.len(), 5);
        assert_eq!(space.carrier(), CarrierKind::Bmp24);
        assert_eq!(space.bit(0), Some(false));
        assert_eq!(space.bit(1), Some(true));
        assert_eq!(space.bit(2), Some(false));
        assert_eq!(space.bit(3), Some(true));
        assert_eq!(space.bit(4), Some(true));
        assert_eq!(space.bit(5), None);
        assert!(!space.is_empty());
    }

    #[test]
    fn a_sixteen_bit_wav_uses_the_low_byte_of_each_sample() {
        let file = wav(16, &[0x01, 0x00, 0x02, 0x00, 0x03, 0x00]);
        let space = SampleSpace::from_bytes(&file).unwrap();
        assert_eq!(space.len(), 3);
        assert_eq!(space.carrier(), CarrierKind::PcmWav);
        assert_eq!(space.bit(0), Some(true));
        assert_eq!(space.bit(1), Some(false));
        assert_eq!(space.bit(2), Some(true));
    }

    #[test]
    fn an_eight_bit_wav_uses_every_byte() {
        let file = wav(8, &[0x01, 0x02, 0x03]);
        let space = SampleSpace::from_bytes(&file).unwrap();
        assert_eq!(space.len(), 3);
    }

    #[test]
    fn a_wav_with_an_extra_chunk_before_the_data_is_still_read() {
        let mut file = Vec::new();
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(b"WAVE");
        file.extend_from_slice(b"fmt ");
        file.extend_from_slice(&16u32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&8_000u32.to_le_bytes());
        file.extend_from_slice(&8_000u32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&8u16.to_le_bytes());
        // An odd-sized chunk, which forces the word-alignment pad byte.
        file.extend_from_slice(b"LIST");
        file.extend_from_slice(&3u32.to_le_bytes());
        file.extend_from_slice(&[1, 2, 3, 0]);
        file.extend_from_slice(b"data");
        file.extend_from_slice(&2u32.to_le_bytes());
        file.extend_from_slice(&[0x01, 0x00]);
        let space = SampleSpace::from_bytes(&file).unwrap();
        assert_eq!(space.len(), 2);
    }

    #[test]
    fn jpeg_is_refused_with_the_reason_rather_than_approximated() {
        let err = SampleSpace::from_bytes(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0]).unwrap_err();
        assert!(err.to_string().contains("cannot read JPEG"));
    }

    #[test]
    fn an_unknown_format_is_refused() {
        let err = SampleSpace::from_bytes(b"not a carrier at all").unwrap_err();
        assert!(err.to_string().contains("not a format"));
    }

    #[test]
    fn a_truncated_bmp_is_corrupt_rather_than_a_crash() {
        assert!(matches!(
            SampleSpace::from_bytes(b"BM").unwrap_err(),
            StegError::CorruptedFile
        ));
        let mut file = bmp24(&[0u8; 4]);
        file[10..14].copy_from_slice(&9_999u32.to_le_bytes());
        assert!(matches!(
            SampleSpace::from_bytes(&file).unwrap_err(),
            StegError::CorruptedFile
        ));
    }

    #[test]
    fn a_non_24_bit_or_compressed_bmp_is_refused_with_a_reason() {
        let mut eight_bit = bmp24(&[0u8; 4]);
        eight_bit[28..30].copy_from_slice(&8u16.to_le_bytes());
        assert!(SampleSpace::from_bytes(&eight_bit)
            .unwrap_err()
            .to_string()
            .contains("bits per pixel"));

        let mut compressed = bmp24(&[0u8; 4]);
        compressed[30..34].copy_from_slice(&1u32.to_le_bytes());
        assert!(SampleSpace::from_bytes(&compressed)
            .unwrap_err()
            .to_string()
            .contains("compressed"));
    }

    #[test]
    fn a_wav_with_an_odd_bit_depth_is_refused_with_a_reason() {
        let file = wav(24, &[0u8; 6]);
        assert!(SampleSpace::from_bytes(&file)
            .unwrap_err()
            .to_string()
            .contains("bits per sample"));
    }

    #[test]
    fn a_wav_with_no_data_chunk_is_refused() {
        let mut file = Vec::new();
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(b"WAVE");
        assert!(SampleSpace::from_bytes(&file)
            .unwrap_err()
            .to_string()
            .contains("no audio data chunk"));
    }

    #[test]
    fn a_wav_whose_data_precedes_its_format_chunk_is_refused() {
        let mut file = Vec::new();
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(b"WAVE");
        file.extend_from_slice(b"data");
        file.extend_from_slice(&2u32.to_le_bytes());
        file.extend_from_slice(&[0, 0]);
        assert!(SampleSpace::from_bytes(&file)
            .unwrap_err()
            .to_string()
            .contains("no format chunk"));
    }

    #[test]
    fn a_wav_with_a_data_size_past_the_end_of_the_file_is_clamped() {
        let mut file = wav(8, &[1, 2, 3, 4]);
        let data_size_at = file.len() - 8;
        file[data_size_at..data_size_at + 4].copy_from_slice(&999_999u32.to_le_bytes());
        let space = SampleSpace::from_bytes(&file).unwrap();
        assert_eq!(space.len(), 4, "the declared size must not be trusted");
    }

    #[test]
    fn a_missing_carrier_file_names_itself() {
        assert!(matches!(
            SampleSpace::load(Path::new("/nonexistent/carrier.bmp")).unwrap_err(),
            StegError::FileNotFound(_)
        ));
    }

    #[test]
    fn the_signature_is_confirmed_when_a_traversal_reads_it() {
        let space = carrier_carrying(&MAGIC, 256);
        let mut traversal = SequentialTraversal::new(space.len());
        let bits = space.read_bits(&mut traversal, 24).unwrap();
        let prefix = confirm(&bits).unwrap();
        assert!(prefix.magic_matched);
        assert_eq!(prefix.confirmed_bits, 24);
    }

    #[test]
    fn a_signature_match_alone_is_not_yet_decisive() {
        // The arithmetic that makes this the right answer: 24 bits of agreement
        // leaves about 256 chance matches across a 32 bit sweep.
        let space = carrier_carrying(&MAGIC, 256);
        let mut traversal = SequentialTraversal::new(space.len());
        let bits = space.read_bits(&mut traversal, 24).unwrap();
        assert!(!confirm(&bits).unwrap().is_decisive());
    }

    #[test]
    fn a_wrong_read_does_not_confirm() {
        let space = carrier_carrying(&[0x00, 0x00, 0x00], 256);
        let mut traversal = SequentialTraversal::new(space.len());
        let bits = space.read_bits(&mut traversal, 24).unwrap();
        let prefix = confirm(&bits).unwrap();
        assert!(!prefix.magic_matched);
        assert_eq!(prefix.confirmed_bits, 0);
        assert!(!prefix.is_decisive());
    }

    #[test]
    fn too_few_bits_to_judge_returns_nothing_rather_than_a_verdict() {
        assert!(confirm(&[true; 23]).is_none());
        assert!(confirm(&[]).is_none());
    }

    #[test]
    fn a_traversal_past_the_end_of_the_carrier_reads_nothing() {
        let space = carrier_carrying(&MAGIC, 10);
        let mut traversal = SequentialTraversal::new(space.len());
        assert!(space.read_bits(&mut traversal, 24).is_none());
    }

    #[test]
    fn an_empty_carrier_is_empty() {
        let space = SampleSpace::from_parities(vec![], CarrierKind::Bmp24);
        assert!(space.is_empty());
        assert_eq!(space.bit(0), None);
    }

    #[test]
    fn bit_packing_round_trips() {
        assert_eq!(
            bits_of(&[0b1010_0001]),
            vec![true, false, true, false, false, false, false, true]
        );
        assert_eq!(bits_of(&[]), Vec::<bool>::new());
    }
}
