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

//! DeepSound: `DSCF` in the sample bits of lossless audio.
//!
//! # Why this one matters more than its priority suggests
//!
//! DeepSound is Windows freeware and it has been used by real intrusion sets to
//! carry stolen data out of a network inside audio files. It is the fingerprint
//! on this list most likely to appear in an actual case rather than a puzzle.
//!
//! # The signature
//!
//! DeepSound writes a small protocol header into the least significant bits of
//! the audio samples, starting at the first sample:
//!
//! ```text
//! "DSCF"   four bytes, 44 53 43 46, "DeepSound Create File"
//! mode     one byte: 02 low, 04 normal, 08 high quality
//! crypt    one byte: 00 none, 01 AES
//! ```
//!
//! and then, per hidden file, a content block starting `DSSF` with a 20 byte
//! name field and a four byte little-endian length.
//!
//! Four bytes is 32 bits, so a clean file matching `DSCF` by chance has a
//! probability of about one in four thousand million, and the two bytes after it
//! are constrained to three and two values respectively, which takes it to about
//! one in a hundred thousand million. That arithmetic is what justifies
//! [`Tier::Exact`]; it is not a feeling about how distinctive the letters look.
//!
//! # What is verified and what is not, stated plainly
//!
//! **This detector has not been run against a file DeepSound wrote.** DeepSound
//! is Windows only and is not installed on the machine this was built on, so
//! there was no way to produce one. The reader is pinned against planted
//! fixtures, which proves it is self-consistent and nothing more.
//!
//! The specification leaves two things open, and rather than pick one and hope,
//! the detector tries both:
//!
//! 1. **Bit order within a byte.** Whether the first bit read is the most or the
//!    least significant bit of `D` is not stated anywhere consulted. Both orders
//!    are tried, and the one that matched is named in the evidence string.
//! 2. **Where the bits come from in a multi-byte sample.** For 16 bit audio the
//!    low byte's bit 0 is the only sensible candidate and is what is used.
//!
//! One thing is inferred rather than read, and the inference is the same one
//! OpenStego's header forces: the header must be readable before the mode byte
//! is known, so the header itself has to sit at one bit per sample whatever the
//! quality setting later turns out to mean. If a real DeepSound file ever
//! contradicts that, this is the line to look at first.

use std::path::Path;

use crate::fingerprints::{read_capped, Tier, ToolFingerprint};

/// DeepSound's file-level start flag.
pub const START_FLAG: [u8; 4] = *b"DSCF";

/// DeepSound's per-file content flag.
pub const CONTENT_FLAG: [u8; 4] = *b"DSSF";

/// The quality modes DeepSound writes in the byte after the start flag.
pub const VALID_MODES: [u8; 3] = [0x02, 0x04, 0x08];

/// The encryption flags DeepSound writes in the byte after the mode.
pub const VALID_CRYPT: [u8; 2] = [0x00, 0x01];

/// Largest audio file this detector will decode.
///
/// Matches the limit the FLAC embed path already uses, so the two agree on what
/// counts as an unreasonable audio file.
pub const MAX_AUDIO_BYTES: u64 = 256 * 1024 * 1024;

/// Samples read from the front of the file. The header is 48 bits; reading a few
/// hundred covers the `DSSF` block that corroborates it without walking the
/// whole file, which keeps this cheap enough to run on every analysis.
const SAMPLES_TO_READ: usize = 2_048;

/// Which end of the byte the first bit read lands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitOrder {
    /// First bit read is the most significant bit of the byte.
    MostSignificantFirst,
    /// First bit read is the least significant bit of the byte.
    LeastSignificantFirst,
}

impl BitOrder {
    fn describe(&self) -> &'static str {
        match self {
            BitOrder::MostSignificantFirst => "most significant bit first",
            BitOrder::LeastSignificantFirst => "least significant bit first",
        }
    }
}

/// What a confirmed DeepSound header says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The quality mode byte.
    pub mode: u8,
    /// Whether the payload is AES encrypted.
    pub encrypted: bool,
    /// Whether a `DSSF` content block follows, which corroborates the match.
    pub content_flag_present: bool,
    /// Which bit order read it.
    pub bit_order: BitOrder,
}

impl Header {
    /// Plain-language description of the mode, since the raw byte means nothing
    /// to a reader.
    pub fn quality(&self) -> &'static str {
        match self.mode {
            0x02 => "low quality",
            0x04 => "normal quality",
            0x08 => "high quality",
            _ => "an unrecognised quality setting",
        }
    }
}

/// Look for DeepSound in a lossless audio file.
///
/// Returns `None` for anything that is not WAV or FLAC, and for a file whose
/// sample bits do not start with the flag.
pub fn check(path: &Path) -> Option<ToolFingerprint> {
    let samples = read_samples(path)?;
    let header = header_from_samples(&samples)?;
    Some(ToolFingerprint {
        tool: "DeepSound".to_string(),
        tier: Tier::Exact,
        evidence: format!(
            "the audio sample bits begin DSCF, DeepSound's own start flag, read {}, \
             followed by {} and {}{}",
            header.bit_order.describe(),
            header.quality(),
            if header.encrypted {
                "an AES encrypted payload"
            } else {
                "an unencrypted payload"
            },
            if header.content_flag_present {
                ", with a DSSF content block after it"
            } else {
                ""
            }
        ),
    })
}

/// Read the parity of the leading samples of a lossless audio file.
///
/// The parity is all a fingerprint needs, and reducing each sample to one bit
/// here is what keeps the rest of this module free of format knowledge.
fn read_samples(path: &Path) -> Option<Vec<bool>> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_AUDIO_BYTES {
        return None;
    }
    let bytes = read_capped(path)?;
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
        return wav_parities(&bytes);
    }
    if bytes.starts_with(b"fLaC") {
        return flac_parities(&bytes);
    }
    None
}

/// Parities of the leading PCM samples of a WAV file.
fn wav_parities(bytes: &[u8]) -> Option<Vec<bool>> {
    let (bits_per_sample, data) = wav_data(bytes)?;
    let parities: Vec<bool> = match bits_per_sample {
        8 => data
            .iter()
            .take(SAMPLES_TO_READ)
            .map(|b| b & 1 == 1)
            .collect(),
        16 => data
            .chunks_exact(2)
            .take(SAMPLES_TO_READ)
            .map(|s| s[0] & 1 == 1)
            .collect(),
        24 => data
            .chunks_exact(3)
            .take(SAMPLES_TO_READ)
            .map(|s| s[0] & 1 == 1)
            .collect(),
        32 => data
            .chunks_exact(4)
            .take(SAMPLES_TO_READ)
            .map(|s| s[0] & 1 == 1)
            .collect(),
        _ => return None,
    };
    Some(parities)
}

/// Walk a RIFF file to its `data` chunk, bounds-checking every length field.
///
/// Terminates by construction: the cursor advances by at least eight bytes each
/// time round, so a zero-length or self-referential chunk cannot make it spin.
fn wav_data(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let mut cursor = 12usize;
    let mut bits_per_sample = None;
    while cursor + 8 <= bytes.len() {
        let id = &bytes[cursor..cursor + 4];
        let size = u32::from_le_bytes([
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let body = cursor + 8;
        if id == b"fmt " && size >= 16 && body + 16 <= bytes.len() {
            bits_per_sample = Some(u16::from_le_bytes([bytes[body + 14], bytes[body + 15]]));
        }
        if id == b"data" {
            let end = body.saturating_add(size).min(bytes.len());
            return Some((bits_per_sample?, bytes.get(body..end)?));
        }
        cursor = body.saturating_add(size).saturating_add(size & 1);
    }
    None
}

/// Parities of the leading samples of a FLAC file, in the same interleaved order
/// the embed path uses, so the two agree on what "the first sample" means.
fn flac_parities(bytes: &[u8]) -> Option<Vec<bool>> {
    let audio = flac_io::decode(bytes).ok()?;
    let channels = audio.channels as usize;
    if channels == 0 || audio.samples.is_empty() {
        return None;
    }
    let frames = audio.samples_per_channel();
    let mut parities = Vec::with_capacity(SAMPLES_TO_READ.min(frames * channels));
    for frame in 0..frames {
        for channel in &audio.samples {
            if parities.len() >= SAMPLES_TO_READ {
                return Some(parities);
            }
            parities.push(channel.get(frame)? & 1 == 1);
        }
    }
    Some(parities)
}

/// Assemble bytes from sample parities in one bit order.
fn bytes_from_parities(parities: &[bool], order: BitOrder, count: usize) -> Option<Vec<u8>> {
    if parities.len() < count * 8 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for byte_index in 0..count {
        let mut value = 0u8;
        for bit in 0..8usize {
            if parities[byte_index * 8 + bit] {
                let shift = match order {
                    BitOrder::MostSignificantFirst => 7 - bit,
                    BitOrder::LeastSignificantFirst => bit,
                };
                value |= 1 << shift;
            }
        }
        out.push(value);
    }
    Some(out)
}

/// Look for the header in sample parities, trying both bit orders.
pub fn header_from_samples(parities: &[bool]) -> Option<Header> {
    for order in [
        BitOrder::MostSignificantFirst,
        BitOrder::LeastSignificantFirst,
    ] {
        // Six bytes is the file header; thirty takes in the start of the first
        // content block, which is what corroborates the match.
        let wanted = 30usize;
        let available = (parities.len() / 8).min(wanted);
        let Some(bytes) = bytes_from_parities(parities, order, available) else {
            continue;
        };
        if bytes.len() < 6 || bytes[..4] != START_FLAG {
            continue;
        }
        let mode = bytes[4];
        let crypt = bytes[5];
        if !VALID_MODES.contains(&mode) || !VALID_CRYPT.contains(&crypt) {
            // The flag matched and the fields did not. Reported as no match
            // rather than as a weaker one: a four byte coincidence is already
            // unlikely, and a DeepSound version writing fields we have never
            // seen is a thing to learn about rather than guess at.
            continue;
        }
        let content_flag_present = bytes
            .windows(4)
            .skip(6)
            .any(|window| window == CONTENT_FLAG);
        return Some(Header {
            mode,
            encrypted: crypt == 0x01,
            content_flag_present,
            bit_order: order,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build sample parities that spell `bytes` in the given order.
    fn parities_for(bytes: &[u8], order: BitOrder, total: usize) -> Vec<bool> {
        let mut parities = vec![false; total.max(bytes.len() * 8)];
        for (byte_index, byte) in bytes.iter().enumerate() {
            for bit in 0..8usize {
                let shift = match order {
                    BitOrder::MostSignificantFirst => 7 - bit,
                    BitOrder::LeastSignificantFirst => bit,
                };
                parities[byte_index * 8 + bit] = (byte >> shift) & 1 == 1;
            }
        }
        parities
    }

    fn deepsound_header(mode: u8, crypt: u8, with_content: bool) -> Vec<u8> {
        let mut bytes = START_FLAG.to_vec();
        bytes.push(mode);
        bytes.push(crypt);
        if with_content {
            bytes.extend_from_slice(&CONTENT_FLAG);
            bytes.extend_from_slice(&[b'n'; 20]);
            bytes.extend_from_slice(&64u32.to_le_bytes());
        }
        bytes
    }

    /// A 16 bit mono WAV whose sample low bytes carry `parities`.
    fn wav_with_parities(parities: &[bool]) -> Vec<u8> {
        let mut data = Vec::with_capacity(parities.len() * 2);
        for (index, bit) in parities.iter().enumerate() {
            let low = ((index % 120) as u8 & 0xFE) | u8::from(*bit);
            data.push(low);
            data.push(0x10);
        }
        let mut file = Vec::new();
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(b"WAVE");
        file.extend_from_slice(b"fmt ");
        file.extend_from_slice(&16u32.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&1u16.to_le_bytes());
        file.extend_from_slice(&44_100u32.to_le_bytes());
        file.extend_from_slice(&88_200u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&16u16.to_le_bytes());
        file.extend_from_slice(b"data");
        file.extend_from_slice(&(data.len() as u32).to_le_bytes());
        file.extend_from_slice(&data);
        file
    }

    #[test]
    fn the_header_is_recognised_in_both_bit_orders() {
        for order in [
            BitOrder::MostSignificantFirst,
            BitOrder::LeastSignificantFirst,
        ] {
            let parities = parities_for(&deepsound_header(0x04, 0x01, true), order, 400);
            let header = header_from_samples(&parities)
                .unwrap_or_else(|| panic!("{order:?} should have been read"));
            assert_eq!(header.mode, 0x04);
            assert_eq!(header.quality(), "normal quality");
            assert!(header.encrypted);
            assert!(header.content_flag_present);
            assert_eq!(header.bit_order, order);
        }
    }

    #[test]
    fn every_documented_mode_and_encryption_combination_is_accepted() {
        for mode in VALID_MODES {
            for crypt in VALID_CRYPT {
                let parities = parities_for(
                    &deepsound_header(mode, crypt, false),
                    BitOrder::MostSignificantFirst,
                    200,
                );
                let header = header_from_samples(&parities)
                    .unwrap_or_else(|| panic!("mode {mode:#x} crypt {crypt:#x}"));
                assert_eq!(header.mode, mode);
                assert_eq!(header.encrypted, crypt == 0x01);
                assert!(!header.content_flag_present);
            }
        }
    }

    #[test]
    fn a_flag_with_fields_we_have_never_seen_is_not_claimed_as_a_match() {
        // Reported as no match on purpose; see the note in `header_from_samples`.
        let parities = parities_for(
            &deepsound_header(0x77, 0x00, false),
            BitOrder::MostSignificantFirst,
            200,
        );
        assert!(header_from_samples(&parities).is_none());
        let bad_crypt = parities_for(
            &deepsound_header(0x02, 0x09, false),
            BitOrder::MostSignificantFirst,
            200,
        );
        assert!(header_from_samples(&bad_crypt).is_none());
    }

    #[test]
    fn an_unrecognised_mode_byte_still_describes_itself_in_words() {
        let header = Header {
            mode: 0x55,
            encrypted: false,
            content_flag_present: false,
            bit_order: BitOrder::MostSignificantFirst,
        };
        assert_eq!(header.quality(), "an unrecognised quality setting");
    }

    #[test]
    fn samples_carrying_nothing_are_not_a_match() {
        assert!(header_from_samples(&vec![false; 400]).is_none());
        assert!(header_from_samples(&vec![true; 400]).is_none());
    }

    #[test]
    fn too_few_samples_to_hold_a_header_is_not_a_match() {
        assert!(header_from_samples(&[]).is_none());
        assert!(header_from_samples(&[true; 40]).is_none());
    }

    #[test]
    fn a_real_wav_container_carrying_the_header_is_identified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carrier.wav");
        let parities = parities_for(
            &deepsound_header(0x08, 0x00, true),
            BitOrder::MostSignificantFirst,
            600,
        );
        std::fs::write(&path, wav_with_parities(&parities)).unwrap();
        let found = check(&path).expect("the header is there to be found");
        assert_eq!(found.tool, "DeepSound");
        assert_eq!(found.tier, Tier::Exact);
        assert!(found.evidence.contains("DSCF"));
        assert!(found.evidence.contains("high quality"));
        assert!(found.evidence.contains("unencrypted"));
        assert!(found.evidence.contains("DSSF"));
    }

    #[test]
    fn a_clean_wav_is_not_identified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean.wav");
        // A plausible waveform rather than silence, so the parities vary.
        let parities: Vec<bool> = (0..4000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761).rotate_left(7) >> 3) & 1 == 1)
            .collect();
        std::fs::write(&path, wav_with_parities(&parities)).unwrap();
        assert!(check(&path).is_none());
    }

    #[test]
    fn eight_and_twenty_four_and_thirty_two_bit_wavs_are_all_read() {
        for bits in [8u16, 24, 32] {
            let bytes_per_sample = (bits / 8) as usize;
            let parities = parities_for(
                &deepsound_header(0x02, 0x00, false),
                BitOrder::MostSignificantFirst,
                200,
            );
            let mut data = Vec::new();
            for bit in &parities {
                data.push(u8::from(*bit));
                // The remaining bytes of the sample carry no payload bit; only
                // the low byte does.
                data.extend(std::iter::repeat(0x20u8).take(bytes_per_sample - 1));
            }
            let mut file = Vec::new();
            file.extend_from_slice(b"RIFF");
            file.extend_from_slice(&0u32.to_le_bytes());
            file.extend_from_slice(b"WAVE");
            file.extend_from_slice(b"fmt ");
            file.extend_from_slice(&16u32.to_le_bytes());
            file.extend_from_slice(&1u16.to_le_bytes());
            file.extend_from_slice(&1u16.to_le_bytes());
            file.extend_from_slice(&44_100u32.to_le_bytes());
            file.extend_from_slice(&44_100u32.to_le_bytes());
            file.extend_from_slice(&1u16.to_le_bytes());
            file.extend_from_slice(&bits.to_le_bytes());
            file.extend_from_slice(b"data");
            file.extend_from_slice(&(data.len() as u32).to_le_bytes());
            file.extend_from_slice(&data);

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("carrier{bits}.wav"));
            std::fs::write(&path, &file).unwrap();
            assert!(check(&path).is_some(), "{bits} bit WAV was not read");
        }
    }

    #[test]
    fn a_flac_carrying_the_header_is_identified() {
        let parities = parities_for(
            &deepsound_header(0x04, 0x01, false),
            BitOrder::MostSignificantFirst,
            200,
        );
        // Mono so the interleaved order is the sample order.
        let samples: Vec<i32> = parities
            .iter()
            .enumerate()
            .map(|(i, bit)| ((i as i32 % 500) & !1) | i32::from(*bit))
            .collect();
        let audio = flac_io::FlacAudio {
            sample_rate: 44_100,
            channels: 1,
            bits_per_sample: 16,
            samples: vec![samples],
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("carrier.flac");
        std::fs::write(&path, flac_io::encode(&audio).unwrap()).unwrap();
        let found = check(&path).expect("the FLAC path must read the same header");
        assert_eq!(found.tool, "DeepSound");
        assert!(found.evidence.contains("AES encrypted"));
    }

    #[test]
    fn a_file_that_is_not_lossless_audio_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("photo.png");
        std::fs::write(&path, [0x89, b'P', b'N', b'G', 13, 10, 26, 10]).unwrap();
        assert!(check(&path).is_none());
        assert!(check(Path::new("/nonexistent/audio.wav")).is_none());
    }

    #[test]
    fn a_truncated_or_malformed_wav_is_skipped_rather_than_crashing() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("short.wav", b"RIFF".to_vec()),
            ("nodata.wav", b"RIFF\0\0\0\0WAVE".to_vec()),
            ("badbits.wav", {
                let mut f = wav_with_parities(&[true; 100]);
                // Claim an impossible sample size.
                f[34] = 7;
                f
            }),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, &bytes).unwrap();
            assert!(check(&path).is_none(), "{name} should be skipped");
        }
    }

    #[test]
    fn a_wav_whose_data_size_overruns_the_file_is_clamped_not_trusted() {
        let mut file = wav_with_parities(&parities_for(
            &deepsound_header(0x02, 0x00, false),
            BitOrder::MostSignificantFirst,
            200,
        ));
        let size_at = file.len() - (file.len() - 44);
        let _ = size_at;
        let data_size_offset = 40;
        file[data_size_offset..data_size_offset + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overrun.wav");
        std::fs::write(&path, &file).unwrap();
        // Still found, because clamping to the real end leaves the header intact.
        assert!(check(&path).is_some());
    }

    #[test]
    fn bit_order_names_are_plain_words() {
        assert_eq!(
            BitOrder::MostSignificantFirst.describe(),
            "most significant bit first"
        );
        assert_eq!(
            BitOrder::LeastSignificantFirst.describe(),
            "least significant bit first"
        );
    }
}
