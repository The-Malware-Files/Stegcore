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

//! Data sitting after the end of a WAV, which is how Xiao and Invisible Secrets
//! hide things.
//!
//! # The gap this fills
//!
//! `crate::analysis` already flags data appended past the end of a PNG, a JPEG or
//! a BMP. Audio carriers got nothing: the audio fingerprint path returned no
//! match for every file, whatever was stapled to the end of it. Xiao
//! Steganography and Invisible Secrets both take WAV carriers and both work by
//! appending, so an audio file was the one place this whole class of tool walked
//! straight through.
//!
//! # How a WAV says where it ends
//!
//! A WAV is a RIFF file, and RIFF puts its own length in the header:
//!
//! ```text
//! offset 0..4    "RIFF"
//! offset 4..8    size, 32 bit little endian: everything after this field
//! offset 8..12   "WAVE"
//! offset 12..    chunks, each a four byte id, a 32 bit little endian
//!                length, that many bytes, and a pad byte if the length is odd
//! ```
//!
//! So the file logically ends at `8 + size`, and anything past that is not part
//! of the audio. The chunk list is walked as well, and a file whose chunks do not
//! land exactly on that same end is declined rather than reported: a mismatch
//! there means either the file is malformed or the reading is wrong, and neither
//! is grounds for an accusation.
//!
//! The end is **parsed, not searched for**, which is the same reasoning the image
//! side records: an appended payload can contain anything, including bytes that
//! look like a chunk header, so a search can be led to a false end and miss the
//! very data it is looking for.
//!
//! FLAC is out of scope. A FLAC stream carries no total length anywhere in its
//! header; finding its end means decoding frames until they run out, and the
//! decoder in use reports the samples it found rather than the byte offset it
//! stopped at. Detecting an appended payload there needs a frame walker that does
//! not exist yet, and guessing at the end of a FLAC file would produce exactly
//! the false accusations this module is careful to avoid.
//!
//! # What is not flagged, and why that list exists
//!
//! Trailing bytes on an audio file are not automatically a payload. Tag writers
//! have put metadata after the audio for thirty years, and a detector that called
//! every tagged file suspicious would be useless. So a trailing region is skipped
//! when it is a recognised tag ([`BENIGN_TRAILERS`]) or when it is nothing but
//! zero padding, and the rest is reported with whatever the payload's own first
//! bytes identify it as, because "a ZIP archive is bolted to the end of this WAV"
//! is a far more useful sentence than "there are extra bytes".
//!
//! # Tier: `Heuristic`, provisionally
//!
//! Appended data is a fact about the file rather than a claim about a tool. It
//! cannot tell Xiao from Invisible Secrets from someone typing `cat`, so by the
//! attribution argument alone this could never be `Exact`, and the image-side
//! detector it mirrors is `Heuristic` for the same reason.
//!
//! The provisional part is the false-positive rate. **There is no clean WAV
//! corpus on the machine this was built on**, so unlike Snow and the palette
//! detector there is no measured number here, only the benign-trailer list above
//! and the reasoning behind it. The arithmetic is not available either: how often
//! a real WAV carries unrecognised trailing bytes is a property of the tools that
//! wrote it, not of probability.
//!
//! What would settle it: a few thousand WAV files from varied sources, counting
//! how many carry a trailing region this would report. The threshold to turn is
//! [`MIN_APPENDED_BYTES`], and the list to extend is [`BENIGN_TRAILERS`]. Until
//! then `Heuristic` is the honest tier, and it is also the safe one, because a
//! heuristic match floors a verdict at suspicious rather than settling it.

use std::path::Path;

use crate::fingerprints::{read_capped, Tier, ToolFingerprint};

/// Smallest trailing region reported, in bytes.
///
/// Below this it is padding or an alignment artefact rather than a payload.
/// Matches the figure the image-side detector in `crate::analysis` uses, so the
/// two surfaces agree on what counts as "something is there".
pub const MIN_APPENDED_BYTES: usize = 16;

/// Hard cap on chunks walked while finding the end of a RIFF file.
///
/// The chunk list comes from the file, so its length does too. The walk advances
/// by at least eight bytes a time and so terminates on its own, but a file full
/// of eight byte chunks would still cost a pass over the whole thing on every
/// analysis, and this bounds that.
pub const MAX_CHUNK_STEPS: usize = 100_000;

/// Trailing regions that are ordinary metadata rather than a hidden payload,
/// as a leading magic and the name to recognise it by.
///
/// ID3 tags after the audio data are the common case by a wide margin: ID3v2
/// starts `ID3`, and ID3v1 is a 128 byte block starting `TAG`.
pub const BENIGN_TRAILERS: [(&[u8], &str); 2] =
    [(b"ID3", "an ID3v2 tag"), (b"TAG", "an ID3v1 tag")];

/// Magics identifying what the appended payload is, as a leading signature and
/// a plain-language name.
///
/// Reported rather than acted on: naming the payload is what makes the finding
/// useful to somebody who then has to get it out.
pub const PAYLOAD_MAGICS: [(&[u8], &str); 9] = [
    (b"PK\x03\x04", "a ZIP archive"),
    (b"Rar!\x1a\x07", "a RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"),
    (b"\x1f\x8b", "a gzip stream"),
    (b"BZh", "a bzip2 stream"),
    (b"\xfd7zXZ\x00", "an xz stream"),
    (b"\xff\xd8\xff", "a JPEG image"),
    (b"\x89PNG\r\n\x1a\n", "a PNG image"),
    (b"-----BEGIN ", "a PEM encoded block"),
];

/// A trailing region found past the end of a WAV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trailer {
    /// Offset the audio file logically ended at.
    pub starts_at: usize,
    /// Size of the trailing region, in bytes.
    pub bytes: usize,
    /// What the region's own first bytes identify it as, when anything does.
    pub payload: Option<&'static str>,
}

/// Look for data appended past the end of a WAV.
pub fn check(path: &Path) -> Option<ToolFingerprint> {
    let bytes = read_capped(path)?;
    let trailer = trailer_of_wav(&bytes)?;
    Some(ToolFingerprint {
        tool: "appended data after EOF".to_string(),
        tier: Tier::Heuristic,
        evidence: format!(
            "the WAV header says the file ends at byte {}, and {} bytes sit after that{}. \
             Xiao Steganography and Invisible Secrets both hide payloads this way, as does \
             anyone concatenating two files, so this says data is hidden here and not which \
             program put it there.",
            trailer.starts_at,
            trailer.bytes,
            match trailer.payload {
                Some(what) => format!(", beginning with {what}"),
                None => String::new(),
            }
        ),
    })
}

/// Find the trailing region of a WAV, or `None` when there is not one to report.
///
/// `None` covers every uninteresting case together: not a WAV, a WAV whose own
/// headers do not agree, a trailing region too small to matter, and a trailing
/// region that is recognisable metadata. A fingerprint that cannot be taken is
/// an absent fingerprint.
pub fn trailer_of_wav(bytes: &[u8]) -> Option<Trailer> {
    let end = riff_end(bytes)?;
    let trailing = bytes.get(end..)?;
    if trailing.len() < MIN_APPENDED_BYTES {
        return None;
    }
    if is_benign(trailing) {
        return None;
    }
    Some(Trailer {
        starts_at: end,
        bytes: trailing.len(),
        payload: PAYLOAD_MAGICS
            .iter()
            .find(|(magic, _)| trailing.starts_with(magic))
            .map(|(_, name)| *name),
    })
}

/// Offset just past the logical end of a RIFF WAVE file.
///
/// Both the header's own size field and the chunk list have to agree. They
/// normally do; when they do not, this returns `None`, because a file that
/// disagrees with itself is one to be careful about rather than one to accuse.
fn riff_end(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 12 || !bytes.starts_with(b"RIFF") || &bytes[8..12] != b"WAVE" {
        return None;
    }
    let declared = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?) as usize;
    let end = declared.checked_add(8)?;
    if end > bytes.len() || end < 12 {
        return None;
    }
    // Walk the chunks. Each step moves the cursor forward by at least eight
    // bytes, so this terminates by construction; the step cap bounds the cost
    // rather than the termination.
    let mut cursor = 12usize;
    for _ in 0..MAX_CHUNK_STEPS {
        if cursor == end {
            return Some(end);
        }
        if cursor + 8 > end {
            return None; // a chunk header straddling the declared end
        }
        let size = u32::from_le_bytes(bytes.get(cursor + 4..cursor + 8)?.try_into().ok()?) as usize;
        // RIFF pads an odd-length chunk to an even boundary.
        cursor = cursor
            .checked_add(8)?
            .checked_add(size)?
            .checked_add(size & 1)?;
        if cursor > end {
            return None; // a chunk overrunning the declared end
        }
    }
    None
}

/// Whether a trailing region is recognisable metadata rather than a payload.
fn is_benign(trailing: &[u8]) -> bool {
    if trailing.iter().all(|b| *b == 0) {
        return true;
    }
    BENIGN_TRAILERS
        .iter()
        .any(|(magic, _)| trailing.starts_with(magic))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal 16 bit mono WAV with `audio_bytes` of sample data, optionally
    /// followed by `trailing`.
    fn wav(audio_bytes: usize, trailing: &[u8]) -> Vec<u8> {
        let data: Vec<u8> = (0..audio_bytes).map(|i| (i % 251) as u8).collect();
        let mut body = Vec::new();
        body.extend_from_slice(b"WAVE");
        body.extend_from_slice(b"fmt ");
        body.extend_from_slice(&16u32.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // PCM
        body.extend_from_slice(&1u16.to_le_bytes()); // mono
        body.extend_from_slice(&44_100u32.to_le_bytes());
        body.extend_from_slice(&88_200u32.to_le_bytes());
        body.extend_from_slice(&2u16.to_le_bytes());
        body.extend_from_slice(&16u16.to_le_bytes());
        body.extend_from_slice(b"data");
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        body.extend_from_slice(&data);
        if data.len() % 2 == 1 {
            body.push(0);
        }
        let mut file = Vec::new();
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend_from_slice(&body);
        file.extend_from_slice(trailing);
        file
    }

    #[test]
    fn a_payload_appended_past_the_declared_end_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xiao.wav");
        std::fs::write(&path, wav(2_048, &[0x42u8; 900])).unwrap();
        let found = check(&path).expect("900 trailing bytes is a finding");
        assert_eq!(found.tool, "appended data after EOF");
        assert_eq!(found.tier, Tier::Heuristic);
        assert!(found.evidence.contains("900 bytes"));
        assert!(found.evidence.contains("Xiao"));
    }

    #[test]
    fn the_appended_payload_is_named_when_its_own_magic_says_what_it_is() {
        for (magic, name) in PAYLOAD_MAGICS {
            let mut trailing = magic.to_vec();
            trailing.resize(512, 0x37);
            let trailer = trailer_of_wav(&wav(1_024, &trailing))
                .unwrap_or_else(|| panic!("{name} should have been reported"));
            assert_eq!(trailer.payload, Some(name));
        }
    }

    #[test]
    fn an_unrecognisable_payload_is_still_reported_just_not_named() {
        let trailer = trailer_of_wav(&wav(1_024, &[0x5Au8; 64])).unwrap();
        assert_eq!(trailer.bytes, 64);
        assert_eq!(trailer.payload, None);
    }

    #[test]
    fn a_clean_wav_with_nothing_after_it_is_not_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean.wav");
        std::fs::write(&path, wav(4_096, &[])).unwrap();
        assert!(check(&path).is_none());
    }

    #[test]
    fn an_ordinary_tag_after_the_audio_is_not_an_accusation() {
        // The near-miss that matters most: a tagged file is a normal file.
        for (magic, _) in BENIGN_TRAILERS {
            let mut trailing = magic.to_vec();
            trailing.resize(256, 0x20);
            assert!(
                trailer_of_wav(&wav(1_024, &trailing)).is_none(),
                "a trailer starting {magic:?} should be treated as metadata"
            );
        }
        // Zero padding likewise.
        assert!(trailer_of_wav(&wav(1_024, &[0u8; 512])).is_none());
    }

    #[test]
    fn a_trailing_region_below_the_threshold_is_not_reported() {
        assert!(trailer_of_wav(&wav(1_024, &[0x42u8; MIN_APPENDED_BYTES - 1])).is_none());
        assert!(trailer_of_wav(&wav(1_024, &[0x42u8; MIN_APPENDED_BYTES])).is_some());
    }

    #[test]
    fn a_zero_byte_or_truncated_or_malformed_wav_is_declined_rather_than_crashing() {
        let dir = tempfile::tempdir().unwrap();
        let good = wav(1_024, &[0x42u8; 64]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty.wav", Vec::new()),
            ("four.wav", b"RIFF".to_vec()),
            ("eleven.wav", b"RIFF\x00\x00\x00\x00WAV".to_vec()),
            ("not_wave.wav", b"RIFF\x04\x00\x00\x00AVI ".to_vec()),
            ("not_riff.wav", vec![0x89, b'P', b'N', b'G', 13, 10, 26, 10]),
            ("half.wav", good[..good.len() / 2].to_vec()),
            ("declared_past_end.wav", {
                let mut f = good.clone();
                f[4..8].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
                f
            }),
            ("chunk_overruns.wav", {
                // A chunk claiming more bytes than the declared end allows.
                let mut f = good.clone();
                f[16..20].copy_from_slice(&0x0010_0000u32.to_le_bytes());
                f
            }),
            ("chunk_header_straddles_end.wav", {
                // The declared end lands four bytes into a chunk header.
                let mut f = good.clone();
                let declared = u32::from_le_bytes(f[4..8].try_into().unwrap());
                f[4..8].copy_from_slice(&(declared - 4).to_le_bytes());
                f
            }),
        ];
        for (name, bytes) in cases {
            let path = dir.path().join(name);
            std::fs::write(&path, &bytes).unwrap();
            assert!(check(&path).is_none(), "{name} should have been declined");
        }
        assert!(check(Path::new("/nonexistent/carrier.wav")).is_none());
    }

    #[test]
    fn a_wav_with_an_extra_metadata_chunk_inside_it_still_parses_to_its_real_end() {
        // The chunk walk has to cope with more than fmt and data, including an
        // odd length chunk and the pad byte RIFF adds after it.
        let mut body = Vec::new();
        body.extend_from_slice(b"WAVE");
        body.extend_from_slice(b"LIST");
        body.extend_from_slice(&11u32.to_le_bytes());
        body.extend_from_slice(b"INFOIART\x00\x00\x00");
        body.push(0); // pad to an even length
        body.extend_from_slice(b"fmt ");
        body.extend_from_slice(&16u32.to_le_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(b"data");
        body.extend_from_slice(&64u32.to_le_bytes());
        body.extend_from_slice(&[0x11u8; 64]);
        let mut file = Vec::new();
        file.extend_from_slice(b"RIFF");
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend_from_slice(&body);
        assert!(trailer_of_wav(&file).is_none());
        file.extend_from_slice(&[0x42u8; 200]);
        let trailer = trailer_of_wav(&file).expect("the appended region is past every chunk");
        assert_eq!(trailer.bytes, 200);
    }

    #[test]
    fn the_boundary_where_the_payload_magic_straddles_the_end_is_not_named_wrongly() {
        // Only part of a ZIP magic fits before the file ends, so the region is
        // reported but not identified as a ZIP.
        let mut trailing = b"PK\x03".to_vec();
        trailing.resize(MIN_APPENDED_BYTES, 0x99);
        let trailer = trailer_of_wav(&wav(1_024, &trailing)).unwrap();
        assert_eq!(trailer.payload, None);
        // One more byte and it is a ZIP.
        let mut full = b"PK\x03\x04".to_vec();
        full.resize(MIN_APPENDED_BYTES, 0x99);
        assert_eq!(
            trailer_of_wav(&wav(1_024, &full)).unwrap().payload,
            Some("a ZIP archive")
        );
    }
}
