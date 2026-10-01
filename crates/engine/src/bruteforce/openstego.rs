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

//! OpenStego Random LSB attribution.
//!
//! # What OpenStego does
//!
//! OpenStego hides a file by writing its bits into the least significant bits
//! of an image's pixels. Its Random LSB mode picks which pixel, which colour
//! channel and which bit for every single payload bit by drawing from a random
//! number generator, and it seeds that generator from the password. Get the
//! seed right and you read the payload in the order it was written; get it
//! wrong and you read noise.
//!
//! What makes this attributable is that OpenStego writes a nine-byte header
//! stamp, the ASCII text `OPENSTEGO`, at the very front of the hidden stream.
//! Reading those nine bytes back is conclusive: the chance of a wrong seed
//! producing them is one in two to the seventy-second.
//!
//! # What already shipped, and the gap this fills
//!
//! Stegcore 4.1 already catches the sequential (Null LSB) case, where the
//! header sits in the first pixels in order and needs no key at all. Random LSB
//! was left open because the seed is derived from the password and could not be
//! predicted. This module closes that, and turns up one case that needs no
//! search whatsoever (see [`EMPTY_PASSWORD_SEED`]).
//!
//! # The algorithm, and how it was established
//!
//! Not from documentation or from reading about it. The constants and the draw
//! order below were read out of the bytecode of the shipped OpenStego 0.8.6 jar
//! (`RandomLSBInputStream`, `LSBDataHeader` and `StringUtil` in
//! `com.openstego.desktop`), and then checked end to end by embedding a file
//! with the real jar, with and without a password, and reading the stamp back.
//!
//! For each bit of each byte, in order:
//!
//! ```text
//! x       = random(0 .. image width)
//! y       = random(0 .. image height)
//! channel = random(0 .. 3)
//! bit     = random(0 .. channel bits in use)
//! if (x, y, channel, bit) has already been used, draw again
//! value   = (pixel ARGB at (x, y) >> (channel * 8 + bit)) & 1
//! ```
//!
//! and the eight bits become a byte most significant bit first.
//!
//! Three details that silently break a reimplementation if missed:
//!
//! 1. **The header is always read at one bit per channel.** The number of bits
//!    per channel is itself a header field, so it cannot be known while the
//!    header is being read. OpenStego reads the whole header with the value
//!    still at its initial 1, which means the fourth draw is always
//!    `random(0 .. 1)`. That draw returns zero every time, but it still
//!    advances the generator, so skipping it desynchronises everything after it.
//! 2. **Channel 0 is blue.** The pixel is taken as a packed ARGB integer, so
//!    shifting by `channel * 8` reaches blue first, then green, then red.
//! 3. **The already-used check changes the draw sequence**, because a repeat
//!    causes a redraw rather than being tolerated.
//!
//! # The honest limit on searching this
//!
//! The seed is the first fifteen hexadecimal digits of the MD5 of the password,
//! which is 60 bits. Sweeping that space is not possible at any throughput, so
//! a raw seed sweep is offered only for a range an investigator has independent
//! reason to try. The attack that works is a wordlist, and
//! [`WordlistProbe`] is the one to reach for.

use std::collections::HashSet;
use std::path::Path;

use crate::bruteforce::digest::md5;
use crate::bruteforce::java_random::JavaRandom;
use crate::bruteforce::Probe;
use crate::errors::StegError;

/// The header stamp OpenStego writes at the front of the hidden stream.
pub const DATA_STAMP: &[u8; 9] = b"OPENSTEGO";

/// The header version byte OpenStego 0.8.x writes after the stamp.
pub const HEADER_VERSION: u8 = 2;

/// The seed OpenStego uses when no password is given.
///
/// `StringUtil.passwordHash` short-circuits an empty or absent password to this
/// constant rather than hashing it, so a Random LSB embed with no password is
/// recoverable with no search at all: one candidate, decisive either way. Worth
/// stating plainly because it is a free detection the engine does not currently
/// make.
pub const EMPTY_PASSWORD_SEED: i64 = 98_234_782;

/// Largest carrier this module will decode, in pixels.
///
/// The probe holds the pixels in memory for the life of the search, at three
/// bytes each, so this is a 360 MB ceiling. A carrier past it is refused with a
/// reason rather than being allowed to exhaust the machine; baseline section 2.1
/// asks for a hard, documented limit on every parser and this is it.
pub const MAX_CARRIER_PIXELS: u64 = 120_000_000;

/// Longest wordlist this module will load, in entries.
pub const MAX_WORDLIST_ENTRIES: usize = 50_000_000;

/// Longest single wordlist entry, in bytes. Past this the line is a corrupt
/// file or a wrong file, not a password.
pub const MAX_WORD_LENGTH: usize = 1_024;

/// Redraw attempts allowed per bit before the carrier is declared too small.
///
/// A repeat forces a redraw, and on a carrier with very few usable positions
/// the generator can spend a long time colliding. OpenStego itself would spin
/// here; this bounds it, because an unbounded loop in a search worker is a hang
/// with no diagnostic.
const MAX_REDRAWS_PER_BIT: u32 = 10_000;

/// Bytes of the hidden stream read when testing a candidate.
///
/// The stamp alone decides it, but the ten bytes after it describe the payload
/// and cost nothing extra once the order is known, so a hit reports them.
const HEADER_BYTES: usize = 19;

/// A decoded carrier, ready to be read in any order.
///
/// Decoded once, before any search starts. Everything the search does afterwards
/// is arithmetic over this buffer, which is what keeps the image parser off the
/// hot path and out of the worker threads.
pub struct Carrier {
    width: u32,
    height: u32,
    /// Row-major RGB, three bytes per pixel.
    rgb: Vec<u8>,
}

/// Written by hand rather than derived so a diagnostic never dumps a hundred
/// megabytes of pixels into a log.
impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carrier")
            .field("width", &self.width)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

impl Carrier {
    /// Decode an image file into a carrier.
    pub fn load(path: &Path) -> Result<Self, StegError> {
        if !path.exists() {
            return Err(StegError::FileNotFound(path.display().to_string()));
        }
        let image = image::open(path)?;
        Self::from_image(&image)
    }

    /// Build a carrier from an already-decoded image.
    pub fn from_image(image: &image::DynamicImage) -> Result<Self, StegError> {
        Self::from_dimensions_and_rgb(image.width(), image.height(), image.to_rgb8().into_raw())
    }

    fn from_dimensions_and_rgb(width: u32, height: u32, rgb: Vec<u8>) -> Result<Self, StegError> {
        if width == 0 || height == 0 {
            return Err(StegError::UnsupportedFormat(
                "the image has no pixels, so nothing could have been hidden in it".into(),
            ));
        }
        let pixels = u64::from(width) * u64::from(height);
        if pixels > MAX_CARRIER_PIXELS {
            return Err(StegError::UnsupportedFormat(format!(
                "the image has {pixels} pixels, past the {MAX_CARRIER_PIXELS} pixel limit this \
                 search will hold in memory. Work on a smaller copy, or raise the limit \
                 deliberately."
            )));
        }
        let expected = pixels.saturating_mul(3);
        if rgb.len() as u64 != expected {
            return Err(StegError::CorruptedFile);
        }
        Ok(Self { width, height, rgb })
    }

    /// The packed ARGB value OpenStego would see at `(x, y)`, with the alpha
    /// byte at full opacity exactly as `BufferedImage.getRGB` reports it for an
    /// image with no alpha channel.
    fn argb(&self, x: u32, y: u32) -> Option<u32> {
        let index = (u64::from(y) * u64::from(self.width) + u64::from(x)).checked_mul(3)?;
        let index = usize::try_from(index).ok()?;
        let r = *self.rgb.get(index)?;
        let g = *self.rgb.get(index + 1)?;
        let b = *self.rgb.get(index + 2)?;
        Some(0xFF00_0000 | (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b))
    }

    /// Read the first `HEADER_BYTES` bytes of the hidden stream, as the seed
    /// implies they were written.
    ///
    /// Returns `None` when the carrier is too small to hold that many bits
    /// without exhausting the redraw budget, which is a property of the carrier
    /// rather than of the seed.
    fn read_header_bytes(&self, seed: i64) -> Option<[u8; HEADER_BYTES]> {
        let mut rng = JavaRandom::new(seed);
        // The header is read with one bit per channel in use; see the module
        // notes on why that draw still has to happen.
        let channel_bits_used = 1u32;
        let mut used: HashSet<u64> = HashSet::with_capacity(HEADER_BYTES * 8);
        let mut out = [0u8; HEADER_BYTES];

        for byte in out.iter_mut() {
            let mut value = 0u8;
            for bit_position in 0..8u8 {
                let mut drawn = None;
                for _ in 0..MAX_REDRAWS_PER_BIT {
                    let x = rng.next_int(self.width)?;
                    let y = rng.next_int(self.height)?;
                    let channel = rng.next_int(3)?;
                    let bit = rng.next_int(channel_bits_used)?;
                    let key = (u64::from(x) << 40)
                        | (u64::from(y) << 16)
                        | (u64::from(channel) << 8)
                        | u64::from(bit);
                    if used.insert(key) {
                        drawn = Some((x, y, channel, bit));
                        break;
                    }
                }
                let (x, y, channel, bit) = drawn?;
                let argb = self.argb(x, y)?;
                let shift = channel * 8 + bit;
                let pixel_bit = (argb >> shift) & 1;
                value |= (pixel_bit as u8) << (7 - bit_position);
            }
            *byte = value;
        }
        Some(out)
    }

    /// Read OpenStego's header with a candidate seed, returning it only when the
    /// stamp matches. A match is the attribution.
    pub fn header_for_seed(&self, seed: i64) -> Option<Header> {
        let bytes = self.read_header_bytes(seed)?;
        if &bytes[..9] != DATA_STAMP.as_slice() {
            return None;
        }
        Some(Header {
            seed,
            header_version: bytes[9],
            data_length: u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
            channel_bits_used: bytes[14],
            file_name_length: bytes[15],
            compressed: bytes[16] == 1,
            encrypted: bytes[17] == 1,
        })
    }
}

/// What a confirmed OpenStego file tells us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The seed that read the stamp. Recorded so the recovery is reproducible
    /// by the next custodian, which is what `AUP.md` section 3.1's seed-only
    /// mode exists for.
    pub seed: i64,
    /// Header version byte. OpenStego 0.8.x writes 2.
    pub header_version: u8,
    /// Length of the hidden payload in bytes, as the header declares it.
    pub data_length: u32,
    /// Bits per colour channel the payload itself was written with.
    pub channel_bits_used: u8,
    /// Length of the stored original file name.
    pub file_name_length: u8,
    /// Whether the payload was compressed before hiding.
    pub compressed: bool,
    /// Whether the payload was encrypted before hiding.
    pub encrypted: bool,
}

impl Header {
    /// Whether the header's own fields are internally plausible. A stamp match
    /// is already decisive, so this is reported rather than required: a
    /// mismatch here would mean a newer OpenStego, not a false positive.
    pub fn is_self_consistent(&self) -> bool {
        self.header_version == HEADER_VERSION
            && (1..=4).contains(&self.channel_bits_used)
            && self.data_length > 0
    }

    /// Plain-language description for a report.
    pub fn describe(&self) -> String {
        format!(
            "OpenStego Random LSB, {} bytes of payload at {} bit(s) per channel, {}, {}",
            self.data_length,
            self.channel_bits_used,
            if self.compressed {
                "compressed"
            } else {
                "not compressed"
            },
            if self.encrypted {
                "encrypted"
            } else {
                "not encrypted"
            },
        )
    }
}

/// OpenStego's own password-to-seed derivation.
///
/// MD5 the password, render it as 32 lowercase hexadecimal digits, take the
/// first fifteen and read them as a hexadecimal integer. An empty or absent
/// password short-circuits to [`EMPTY_PASSWORD_SEED`] without being hashed.
pub fn password_seed(password: &str) -> i64 {
    if password.is_empty() {
        return EMPTY_PASSWORD_SEED;
    }
    let digest = md5(password.as_bytes());
    // Fifteen hexadecimal digits is 60 bits, so the first seven and a half
    // bytes of the digest. The half byte is the high nibble of byte seven.
    let mut value: i64 = 0;
    for byte in &digest[..7] {
        value = (value << 8) | i64::from(*byte);
    }
    (value << 4) | i64::from(digest[7] >> 4)
}

/// Search a list of candidate passwords.
///
/// This is the probe that actually finds keys. A wordlist is read once, capped
/// in both entry count and entry length, and every entry becomes one candidate.
pub struct WordlistProbe<'a> {
    carrier: &'a Carrier,
    words: Vec<String>,
}

/// Written by hand so a diagnostic reports how many candidates were loaded
/// rather than printing every password in the list.
impl std::fmt::Debug for WordlistProbe<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WordlistProbe")
            .field("carrier", &self.carrier)
            .field("candidates", &self.words.len())
            .finish()
    }
}

impl<'a> WordlistProbe<'a> {
    /// Build from an in-memory list, used by callers that already hold one.
    pub fn new(carrier: &'a Carrier, words: Vec<String>) -> Self {
        Self { carrier, words }
    }

    /// Read a wordlist from disk, one candidate per line.
    ///
    /// Lines are trimmed of trailing carriage returns and newlines only; a
    /// password may legitimately start or end with a space. Blank lines are
    /// kept, because the empty password is a real case here. Invalid UTF-8 is
    /// skipped rather than rejected, since a large public wordlist usually has
    /// some, and refusing the whole file over one bad line would be the wrong
    /// trade.
    pub fn from_file(carrier: &'a Carrier, path: &Path) -> Result<Self, StegError> {
        use std::io::BufRead;
        if !path.exists() {
            return Err(StegError::FileNotFound(path.display().to_string()));
        }
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut words = Vec::new();
        let mut skipped_long = 0usize;
        let mut skipped_invalid = 0usize;
        for line in reader.split(b'\n') {
            let raw = line?;
            if words.len() >= MAX_WORDLIST_ENTRIES {
                return Err(StegError::UnsupportedFormat(format!(
                    "the wordlist has more than {MAX_WORDLIST_ENTRIES} entries, which is past \
                     what this search will load. Split it and run the parts in turn."
                )));
            }
            let trimmed = raw.strip_suffix(b"\r").unwrap_or(&raw);
            if trimmed.len() > MAX_WORD_LENGTH {
                skipped_long += 1;
                continue;
            }
            match std::str::from_utf8(trimmed) {
                Ok(word) => words.push(word.to_string()),
                Err(_) => skipped_invalid += 1,
            }
        }
        if words.is_empty() {
            return Err(StegError::UnsupportedFormat(format!(
                "no usable candidates were read from {}. Checked {} over-long and {} \
                 non-text lines.",
                path.display(),
                skipped_long,
                skipped_invalid
            )));
        }
        Ok(Self { carrier, words })
    }

    /// How many candidates were loaded.
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// Whether the list is empty. Present because clippy asks for it beside
    /// `len`; a probe built through either constructor never is.
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }
}

impl Probe for WordlistProbe<'_> {
    type Evidence = Header;

    fn tool(&self) -> &'static str {
        "OpenStego"
    }

    fn space_size(&self) -> u64 {
        self.words.len() as u64
    }

    fn try_candidate(&self, index: u64) -> Result<Option<Header>, StegError> {
        let Some(word) = usize::try_from(index).ok().and_then(|i| self.words.get(i)) else {
            return Ok(None);
        };
        Ok(self.carrier.header_for_seed(password_seed(word)))
    }

    fn label(&self, index: u64) -> String {
        match usize::try_from(index).ok().and_then(|i| self.words.get(i)) {
            Some(word) => format!("password {word:?}"),
            None => format!("entry {index} (past the end of the wordlist)"),
        }
    }
}

/// Search a range of raw seed values.
///
/// Useful in two narrow cases: confirming a seed an investigator already has,
/// and sweeping a small range they have independent reason to suspect. It is
/// **not** a way to break an unknown password: the derivation produces a 60 bit
/// seed, so the full space is around 1.15 quintillion values and no throughput
/// makes that finish. The command line says so before it starts.
#[derive(Debug)]
pub struct SeedRangeProbe<'a> {
    carrier: &'a Carrier,
    first: i64,
    count: u64,
}

impl<'a> SeedRangeProbe<'a> {
    /// A probe over `count` seeds starting at `first`.
    pub fn new(carrier: &'a Carrier, first: i64, count: u64) -> Self {
        Self {
            carrier,
            first,
            count,
        }
    }

    /// The single-candidate probe for the no-password case, which needs no
    /// search: one try, and the answer is decisive either way.
    pub fn empty_password(carrier: &'a Carrier) -> Self {
        Self::new(carrier, EMPTY_PASSWORD_SEED, 1)
    }

    fn seed_at(&self, index: u64) -> Option<i64> {
        let offset = i64::try_from(index).ok()?;
        self.first.checked_add(offset)
    }
}

impl Probe for SeedRangeProbe<'_> {
    type Evidence = Header;

    fn tool(&self) -> &'static str {
        "OpenStego"
    }

    fn space_size(&self) -> u64 {
        self.count
    }

    fn try_candidate(&self, index: u64) -> Result<Option<Header>, StegError> {
        if index >= self.count {
            return Ok(None);
        }
        let Some(seed) = self.seed_at(index) else {
            // Running off the end of the signed range is the end of the space,
            // not an error worth aborting a search for.
            return Ok(None);
        };
        Ok(self.carrier.header_for_seed(seed))
    }

    fn label(&self, index: u64) -> String {
        match self.seed_at(index) {
            Some(seed) => format!("seed {seed}"),
            None => format!("seed offset {index} (past the end of the range)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bruteforce::digest::hex;
    use image::{Rgb, RgbImage};

    /// Write `bytes` into a carrier the way OpenStego would for `seed`, so the
    /// reader can be tested without a Java runtime in the loop. This mirrors
    /// `read_header_bytes` exactly, which is the point: the pair round-trips,
    /// and the reader is separately pinned against the real jar by the
    /// integration test in `tests/bruteforce_openstego.rs`.
    fn plant(width: u32, height: u32, seed: i64, bytes: &[u8]) -> Carrier {
        let mut image = RgbImage::from_fn(width, height, |x, y| {
            Rgb([(x % 256) as u8, (y % 256) as u8, ((x + y) % 256) as u8])
        });
        let mut rng = JavaRandom::new(seed);
        let mut used: HashSet<u64> = HashSet::new();
        for byte in bytes {
            for bit_position in 0..8u8 {
                let (x, y, channel, bit) = loop {
                    let x = rng.next_int(width).unwrap();
                    let y = rng.next_int(height).unwrap();
                    let channel = rng.next_int(3).unwrap();
                    let bit = rng.next_int(1).unwrap();
                    let key = (u64::from(x) << 40)
                        | (u64::from(y) << 16)
                        | (u64::from(channel) << 8)
                        | u64::from(bit);
                    if used.insert(key) {
                        break (x, y, channel, bit);
                    }
                };
                let want = (byte >> (7 - bit_position)) & 1;
                // Channel 0 is blue in a packed ARGB word, so index from the
                // end of the RGB triple.
                let component = 2 - channel as usize;
                let pixel = image.get_pixel_mut(x, y);
                let mask = 1u8 << bit;
                if want == 1 {
                    pixel.0[component] |= mask;
                } else {
                    pixel.0[component] &= !mask;
                }
            }
        }
        Carrier::from_dimensions_and_rgb(width, height, image.into_raw()).unwrap()
    }

    fn full_header(data_length: u32) -> Vec<u8> {
        let mut bytes = DATA_STAMP.to_vec();
        bytes.push(HEADER_VERSION);
        bytes.extend_from_slice(&data_length.to_le_bytes());
        bytes.push(1); // channel bits used
        bytes.push(10); // file name length
        bytes.push(1); // compressed
        bytes.push(0); // encrypted
        bytes.push(0); // first byte of the cipher-name field, unread here
        bytes
    }

    #[test]
    fn empty_password_seed_matches_openstego_constant() {
        assert_eq!(password_seed(""), EMPTY_PASSWORD_SEED);
    }

    #[test]
    fn password_seed_takes_the_first_sixty_bits_of_the_md5() {
        // Worked through by hand from the digest so the shift arithmetic is
        // pinned rather than trusted.
        let digest = md5(b"hunter2");
        let expected = i64::from_str_radix(&hex(&digest)[..15], 16).unwrap();
        assert_eq!(password_seed("hunter2"), expected);
        assert!(password_seed("hunter2") < (1 << 60));
    }

    #[test]
    fn a_planted_header_is_read_back_and_described() {
        let seed = password_seed("correct horse");
        let carrier = plant(64, 64, seed, &full_header(1234));
        let header = carrier.header_for_seed(seed).expect("stamp should match");
        assert_eq!(header.seed, seed);
        assert_eq!(header.data_length, 1234);
        assert_eq!(header.channel_bits_used, 1);
        assert_eq!(header.file_name_length, 10);
        assert!(header.compressed);
        assert!(!header.encrypted);
        assert!(header.is_self_consistent());
        assert!(header.describe().contains("1234 bytes"));
    }

    #[test]
    fn the_wrong_seed_reads_nothing() {
        let seed = password_seed("correct horse");
        let carrier = plant(64, 64, seed, &full_header(1234));
        assert!(carrier.header_for_seed(seed ^ 1).is_none());
        assert!(carrier.header_for_seed(0).is_none());
    }

    #[test]
    fn a_clean_image_reads_nothing_for_any_seed_tried() {
        let image = RgbImage::from_fn(48, 48, |x, y| {
            Rgb([
                (x * 5 % 256) as u8,
                (y * 7 % 256) as u8,
                ((x ^ y) % 256) as u8,
            ])
        });
        let carrier = Carrier::from_dimensions_and_rgb(48, 48, image.into_raw()).unwrap();
        for seed in 0..500i64 {
            assert!(
                carrier.header_for_seed(seed).is_none(),
                "seed {seed} produced a stamp on a clean image"
            );
        }
    }

    #[test]
    fn the_wordlist_probe_finds_the_password_that_was_used() {
        let carrier = plant(64, 64, password_seed("swordfish"), &full_header(99));
        let probe = WordlistProbe::new(
            &carrier,
            vec!["letmein".into(), "swordfish".into(), "hunter2".into()],
        );
        assert_eq!(probe.space_size(), 3);
        assert!(probe.try_candidate(0).unwrap().is_none());
        let found = probe.try_candidate(1).unwrap().expect("should match");
        assert_eq!(found.data_length, 99);
        assert_eq!(probe.label(1), "password \"swordfish\"");
        assert_eq!(probe.tool(), "OpenStego");
    }

    #[test]
    fn a_wordlist_index_past_the_end_is_a_miss_not_an_error() {
        let carrier = plant(32, 32, 7, &full_header(1));
        let probe = WordlistProbe::new(&carrier, vec!["a".into()]);
        assert!(probe.try_candidate(99).unwrap().is_none());
        assert!(probe.label(99).contains("past the end"));
        assert!(!probe.is_empty());
        assert_eq!(probe.len(), 1);
    }

    #[test]
    fn the_seed_range_probe_finds_a_seed_inside_its_range() {
        let carrier = plant(64, 64, 4242, &full_header(7));
        let probe = SeedRangeProbe::new(&carrier, 4200, 100);
        assert_eq!(probe.space_size(), 100);
        assert!(probe.try_candidate(0).unwrap().is_none());
        assert!(probe.try_candidate(42).unwrap().is_some());
        assert_eq!(probe.label(42), "seed 4242");
        assert!(probe.try_candidate(100).unwrap().is_none());
    }

    #[test]
    fn the_no_password_probe_is_a_single_candidate() {
        let carrier = plant(64, 64, EMPTY_PASSWORD_SEED, &full_header(5));
        let probe = SeedRangeProbe::empty_password(&carrier);
        assert_eq!(probe.space_size(), 1);
        assert!(probe.try_candidate(0).unwrap().is_some());
    }

    #[test]
    fn a_seed_range_running_off_the_signed_end_stops_rather_than_wrapping() {
        let carrier = plant(32, 32, 1, &full_header(1));
        let probe = SeedRangeProbe::new(&carrier, i64::MAX - 1, 10);
        assert!(probe.try_candidate(5).unwrap().is_none());
        assert!(probe.label(5).contains("past the end"));
    }

    #[test]
    fn a_zero_sized_image_is_refused_with_a_reason() {
        let err = Carrier::from_dimensions_and_rgb(0, 10, vec![]).unwrap_err();
        assert!(err.to_string().contains("no pixels"));
    }

    #[test]
    fn an_over_large_image_is_refused_before_it_is_held() {
        let err = Carrier::from_dimensions_and_rgb(200_000, 200_000, vec![]).unwrap_err();
        assert!(err.to_string().contains("pixel limit"));
    }

    #[test]
    fn a_buffer_that_does_not_match_the_dimensions_is_corrupt() {
        let err = Carrier::from_dimensions_and_rgb(4, 4, vec![0u8; 10]).unwrap_err();
        assert!(matches!(err, StegError::CorruptedFile));
    }

    #[test]
    fn a_missing_carrier_file_names_itself() {
        let err = Carrier::load(Path::new("/nonexistent/carrier.png")).unwrap_err();
        assert!(matches!(err, StegError::FileNotFound(_)));
    }

    #[test]
    fn a_carrier_too_small_for_a_header_gives_up_rather_than_spinning() {
        // A 2 by 2 image has 12 distinct one-bit positions, far fewer than the
        // 152 a header needs, so the redraw budget must run out and the read
        // must return None instead of looping.
        let image = RgbImage::from_fn(2, 2, |_, _| Rgb([0, 0, 0]));
        let carrier = Carrier::from_dimensions_and_rgb(2, 2, image.into_raw()).unwrap();
        assert!(carrier.header_for_seed(1).is_none());
    }

    #[test]
    fn a_wordlist_file_is_read_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("words.txt");
        let over_long = "x".repeat(MAX_WORD_LENGTH + 1);
        std::fs::write(&path, format!("alpha\r\nbeta\n{over_long}\ngamma\n")).unwrap();
        let carrier = plant(32, 32, password_seed("beta"), &full_header(3));
        let probe = WordlistProbe::from_file(&carrier, &path).unwrap();
        // The over-long line is dropped; the trailing newline yields a final
        // empty entry, which is a legitimate candidate.
        assert!(probe.words.contains(&"alpha".to_string()));
        assert!(probe.words.contains(&"beta".to_string()));
        assert!(probe.words.contains(&"gamma".to_string()));
        assert!(!probe.words.iter().any(|w| w.len() > MAX_WORD_LENGTH));
        let index = probe
            .words
            .iter()
            .position(|w| w == "beta")
            .expect("beta should be loaded") as u64;
        assert!(probe.try_candidate(index).unwrap().is_some());
    }

    #[test]
    fn an_empty_wordlist_file_is_refused_with_a_reason() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "").unwrap();
        let carrier = plant(32, 32, 1, &full_header(1));
        let err = WordlistProbe::from_file(&carrier, &path).unwrap_err();
        assert!(err.to_string().contains("no usable candidates"));
    }

    #[test]
    fn a_missing_wordlist_file_names_itself() {
        let carrier = plant(32, 32, 1, &full_header(1));
        let err =
            WordlistProbe::from_file(&carrier, Path::new("/nonexistent/words.txt")).unwrap_err();
        assert!(matches!(err, StegError::FileNotFound(_)));
    }

    #[test]
    fn a_header_from_a_future_openstego_is_reported_but_not_rejected() {
        let mut bytes = full_header(10);
        bytes[9] = 99; // header version we have never seen
        let carrier = plant(64, 64, 11, &bytes);
        let header = carrier
            .header_for_seed(11)
            .expect("the stamp still matches");
        assert!(!header.is_self_consistent());
        assert_eq!(header.header_version, 99);
    }
}
