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

//! S-Tools: the tell it leaves in a palette.
//!
//! # The problem S-Tools had, and the trace it left solving it
//!
//! A palette image does not store colours in its pixels. It stores numbers that
//! point into a list of colours, the palette. So flipping the lowest bit of a
//! pixel does not nudge its colour slightly, it jumps to whatever colour happens
//! to sit at the next entry in the list, which could be anything. Hiding data in
//! the low bits of a palette image, naively, wrecks it visibly.
//!
//! S-Tools got around this by rebuilding the palette so that **entries come in
//! pairs whose colours are nearly identical**, differing only in their lowest
//! bits. Then flipping a pixel's low bit moves it to a colour nobody can tell
//! apart from the original, and the image survives.
//!
//! That rebuilt palette is the fingerprint. A photograph quantised to 256
//! colours by an ordinary encoder spreads those colours out, because spending two
//! of a scarce 256 slots on indistinguishable colours is exactly what a quantiser
//! is built to avoid. A palette full of near-duplicate pairs is a palette
//! somebody constructed on purpose.
//!
//! # The measurement, which changed the detector
//!
//! Clean corpus: 1,500 real photographs from the local ALASKA2 set, quantised to
//! 256 colours by an ordinary median-cut encoder, which is the nearest available
//! thing to "palette images somebody made without hiding anything". An 8 bit BMP
//! written from the same quantisation carries the same colour table, so one
//! measurement covers both formats.
//!
//! The first rule tried was the obvious one: count entries that have any
//! neighbour within one step per channel. It was unusable.
//!
//! | Rule | Clean median | Clean p99 | Clean max | Flagged at 0.90 |
//! |---|---|---|---|---|
//! | Any neighbour within one step | 0.094 | 0.852 | **1.000** | 4 of 1,500, 0.27% |
//! | A genuine low-bit flip, paired one to one | 0.031 | 0.453 | **0.570** | **0 of 1,500, 0.00%** |
//!
//! The first rule reached **1.000 on a photograph nobody had touched**, which
//! would have been a confident accusation against a clean file. Two changes fixed
//! it, and both are properties of what S-Tools actually builds rather than
//! arbitrary tightenings:
//!
//! 1. **A real low-bit flip, not merely a near neighbour.** 7 and 8 differ by one
//!    and differ in four bits; they are adjacent colours, not a flip. A flip is an
//!    even value and that value with its low bit set. Photographs are full of the
//!    former and not of the latter.
//! 2. **Paired one to one.** S-Tools rebuilds the palette into disjoint pairs. A
//!    photograph's palette has *clusters*, where one colour sits near several
//!    others, and a cluster of five counts five entries under the naive rule while
//!    contributing at most two pairs under this one.
//!
//! The clean maximum is 0.570 and the threshold is [`MIN_PAIRED_FRACTION`], which
//! leaves real margin rather than sitting a whisker above the worst clean file.
//!
//! # The tier
//!
//! `Heuristic`, and a 0.00% false-positive rate does not change that.
//!
//! The reason is not precision, it is attribution. An `Exact` match is a claim
//! about *which tool*, and this evidence cannot distinguish S-Tools from any other
//! program that pairs a palette to hide data in it: the catalogue says so
//! explicitly, and the artefact is a consequence of the technique rather than a
//! value S-Tools chose. So it corroborates, and the evidence string says what was
//! actually seen so a reader can judge the attribution themselves.
//!
//! # What is not verified
//!
//! **The recall side.** S-Tools v4 is a 1996 Windows program and was not available
//! on the machine this was built on, so no file it wrote has been tested. The
//! threshold was chosen from the clean distribution alone, which is the
//! conservative direction (it risks missing an S-Tools image, not accusing a clean
//! one), and the expectation that a real S-Tools palette sits near 1.0 rests on
//! the catalogue's description rather than on a measurement.

use std::path::Path;

use crate::fingerprints::{read_capped, Tier, ToolFingerprint};

/// Fraction of palette entries that must be paired before a match is called.
///
/// Set by the measurement in the module notes: the worst clean photograph of
/// 1,500 reached 0.570, and S-Tools rebuilds the whole palette, so this sits well
/// clear of the clean distribution rather than a whisker above it.
pub const MIN_PAIRED_FRACTION: f64 = 0.90;

/// Palette entries needed before the fraction means anything. A sixteen colour
/// image can reach a high fraction on a couple of coincidences.
pub const MIN_PALETTE_ENTRIES: usize = 64;

/// A colour table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    /// Entries as red, green, blue triples, in table order.
    pub entries: Vec<[u8; 3]>,
    /// Which format it came from, for the evidence string.
    pub source: PaletteSource,
}

/// Where a palette was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteSource {
    /// A GIF global colour table.
    GifGlobalColourTable,
    /// A BMP colour table, for an image of 8 bits per pixel or fewer.
    BmpColourTable,
}

impl PaletteSource {
    fn describe(&self) -> &'static str {
        match self {
            PaletteSource::GifGlobalColourTable => "the GIF colour table",
            PaletteSource::BmpColourTable => "the BMP colour table",
        }
    }
}

/// What a palette analysis found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairAnalysis {
    /// Entries in the palette.
    pub entries: usize,
    /// Entries that have at least one near-duplicate partner elsewhere in the
    /// table.
    pub paired_entries: usize,
    /// Entries that are byte-for-byte duplicates of another entry.
    pub exact_duplicates: usize,
}

impl PairAnalysis {
    /// Proportion of the palette that is paired, in 0.0 to 1.0.
    pub fn paired_fraction(&self) -> f64 {
        if self.entries == 0 {
            return 0.0;
        }
        self.paired_entries as f64 / self.entries as f64
    }

    /// Whether this palette looks built for hiding data.
    pub fn looks_doubled(&self) -> bool {
        self.entries >= MIN_PALETTE_ENTRIES && self.paired_fraction() >= MIN_PAIRED_FRACTION
    }
}

/// Look for a doubled palette in a GIF or a palette BMP.
pub fn check_stools(path: &Path) -> Option<ToolFingerprint> {
    let palette = read_palette(path)?;
    let analysis = analyse_pairs(&palette.entries);
    if !analysis.looks_doubled() {
        return None;
    }
    Some(ToolFingerprint {
        tool: "S-Tools".to_string(),
        tier: Tier::Heuristic,
        evidence: format!(
            "{} of {} colours in {} have a near twin differing by at most one in each \
             channel ({:.0} percent, {} of them identical). Rebuilding a palette into pairs \
             like that is how S-Tools hides data in a palette image without it showing; a \
             quantiser would not spend scarce colours that way.",
            analysis.paired_entries,
            analysis.entries,
            palette.source.describe(),
            analysis.paired_fraction() * 100.0,
            analysis.exact_duplicates,
        ),
    })
}

/// Read the colour table of a GIF or a palette BMP.
pub fn read_palette(path: &Path) -> Option<Palette> {
    let bytes = read_capped(path)?;
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return gif_palette(&bytes);
    }
    if bytes.starts_with(b"BM") {
        return bmp_palette(&bytes);
    }
    None
}

/// Read a GIF's global colour table.
///
/// Only the global table. A GIF may also carry a local table per frame, and
/// reaching those means walking the block structure, which is the sort of
/// format walking that belongs in one place rather than two. Recorded as a known
/// limit: an S-Tools GIF with only a local table would be missed.
fn gif_palette(bytes: &[u8]) -> Option<Palette> {
    // Header is six bytes, then the logical screen descriptor: width, height,
    // then the packed flags byte.
    let flags = *bytes.get(10)?;
    let has_global_table = flags & 0x80 != 0;
    if !has_global_table {
        return None;
    }
    let size_exponent = u32::from(flags & 0x07);
    let count = 1usize << (size_exponent + 1);
    let start = 13usize;
    let end = start.checked_add(count.checked_mul(3)?)?;
    let table = bytes.get(start..end)?;
    Some(Palette {
        entries: table.chunks_exact(3).map(|c| [c[0], c[1], c[2]]).collect(),
        source: PaletteSource::GifGlobalColourTable,
    })
}

/// Read a BMP's colour table, for an image of 8 bits per pixel or fewer.
fn bmp_palette(bytes: &[u8]) -> Option<Palette> {
    if bytes.len() < 54 {
        return None;
    }
    let dib_size = u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]) as usize;
    let bits_per_pixel = u16::from_le_bytes([bytes[28], bytes[29]]);
    if bits_per_pixel == 0 || bits_per_pixel > 8 {
        return None;
    }
    let declared = u32::from_le_bytes([bytes[46], bytes[47], bytes[48], bytes[49]]) as usize;
    let count = if declared == 0 {
        1usize << bits_per_pixel
    } else {
        declared.min(1usize << bits_per_pixel)
    };
    let start = 14usize.checked_add(dib_size)?;
    // BMP colour table entries are four bytes: blue, green, red, then a reserved
    // byte. The channel order is the trap here, and it would turn a pair check
    // into nonsense if read as red first.
    let end = start.checked_add(count.checked_mul(4)?)?;
    let table = bytes.get(start..end)?;
    Some(Palette {
        entries: table.chunks_exact(4).map(|c| [c[2], c[1], c[0]]).collect(),
        source: PaletteSource::BmpColourTable,
    })
}

/// Whether two palette entries differ by a genuine flip of low bits.
///
/// Each channel must either be equal or be an even value beside that value with
/// its low bit set, and at least one channel must differ. The even-value rule is
/// what the measurement turned on: 7 and 8 differ by one and differ in four bits,
/// so they are adjacent colours a quantiser would pick, not a bit flip a tool
/// would construct.
pub fn is_low_bit_flip(a: &[u8; 3], b: &[u8; 3]) -> bool {
    let mut differing = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        if x == y {
            continue;
        }
        let (low, high) = if x < y { (*x, *y) } else { (*y, *x) };
        if high - low != 1 || low % 2 != 0 {
            return false;
        }
        differing += 1;
    }
    differing > 0
}

/// Count how much of a palette is built out of disjoint low-bit pairs.
///
/// Pairing is one to one: an entry already spoken for cannot be somebody else's
/// partner. That is what separates S-Tools' construction, which is disjoint pairs,
/// from a photograph's palette, which has clusters of nearby colours. A cluster of
/// five contributes two pairs here and would contribute five matches to a rule
/// that only asked "does anything sit near this".
///
/// The scan is quadratic in the palette size. That is deliberate rather than
/// overlooked: a palette holds at most 256 entries, so the worst case is about
/// 32,000 comparisons of three bytes, and any index would cost more to build than
/// the scan costs to run.
///
/// Deterministic: entries are considered in table order, so the same palette
/// always yields the same matching.
pub fn analyse_pairs(entries: &[[u8; 3]]) -> PairAnalysis {
    let mut taken = vec![false; entries.len()];
    let mut paired = 0usize;
    let mut exact = 0usize;
    for index in 0..entries.len() {
        if taken[index] {
            continue;
        }
        for other in index + 1..entries.len() {
            if taken[other] {
                continue;
            }
            if !is_low_bit_flip(&entries[index], &entries[other]) {
                continue;
            }
            taken[index] = true;
            taken[other] = true;
            paired += 2;
            break;
        }
    }
    // Counted separately and reported rather than scored. An exactly repeated
    // colour is a palette oddity worth telling a reader about, but it is not part
    // of the pairing rule: S-Tools' pairs differ, they are not duplicates.
    for index in 0..entries.len() {
        if entries
            .iter()
            .enumerate()
            .any(|(other, value)| other != index && value == &entries[index])
        {
            exact += 1;
        }
    }
    PairAnalysis {
        entries: entries.len(),
        paired_entries: paired,
        exact_duplicates: exact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A palette rebuilt the way S-Tools rebuilds one: `pairs` distinct colours,
    /// each beside a twin one lower bit away.
    fn doubled_palette(pairs: usize) -> Vec<[u8; 3]> {
        let mut entries = Vec::with_capacity(pairs * 2);
        for i in 0..pairs {
            let base = [
                ((i * 7) % 128) as u8 * 2,
                ((i * 11) % 128) as u8 * 2,
                ((i * 13) % 128) as u8 * 2,
            ];
            entries.push(base);
            entries.push([base[0] | 1, base[1] | 1, base[2] | 1]);
        }
        entries
    }

    /// A palette with colours spread out, the way a quantiser leaves one.
    fn spread_palette(count: usize) -> Vec<[u8; 3]> {
        (0..count)
            .map(|i| {
                [
                    ((i * 37) % 256) as u8,
                    ((i * 61) % 256) as u8,
                    ((i * 97) % 256) as u8,
                ]
            })
            .collect()
    }

    fn gif_with_palette(entries: &[[u8; 3]]) -> Vec<u8> {
        // Only sizes that are a power of two from 2 to 256 are expressible.
        let exponent = (entries.len().trailing_zeros()).saturating_sub(1);
        let mut file = Vec::new();
        file.extend_from_slice(b"GIF89a");
        file.extend_from_slice(&16u16.to_le_bytes());
        file.extend_from_slice(&16u16.to_le_bytes());
        file.push(0x80 | (exponent as u8 & 0x07));
        file.push(0); // background colour index
        file.push(0); // pixel aspect ratio
        for entry in entries {
            file.extend_from_slice(entry);
        }
        file.push(0x3B); // trailer
        file
    }

    fn bmp_with_palette(entries: &[[u8; 3]]) -> Vec<u8> {
        let mut file = vec![0u8; 54];
        file[0] = b'B';
        file[1] = b'M';
        file[14..18].copy_from_slice(&40u32.to_le_bytes());
        file[28..30].copy_from_slice(&8u16.to_le_bytes());
        file[46..50].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        let offset = 54 + entries.len() * 4;
        file[10..14].copy_from_slice(&(offset as u32).to_le_bytes());
        for entry in entries {
            // Blue, green, red, reserved.
            file.extend_from_slice(&[entry[2], entry[1], entry[0], 0]);
        }
        file.extend_from_slice(&[0u8; 16]);
        file
    }

    #[test]
    fn a_doubled_palette_is_recognised() {
        let analysis = analyse_pairs(&doubled_palette(128));
        assert_eq!(analysis.entries, 256);
        assert_eq!(analysis.paired_entries, 256);
        assert_eq!(analysis.paired_fraction(), 1.0);
        assert!(analysis.looks_doubled());
    }

    #[test]
    fn a_spread_palette_is_not() {
        let analysis = analyse_pairs(&spread_palette(256));
        assert!(
            analysis.paired_fraction() < MIN_PAIRED_FRACTION,
            "a spread palette read as {:.2} paired",
            analysis.paired_fraction()
        );
        assert!(!analysis.looks_doubled());
    }

    #[test]
    fn exact_duplicates_are_reported_but_are_not_pairs() {
        // S-Tools builds pairs that differ. A repeated colour is a palette oddity
        // worth telling the reader about and is not evidence of pairing.
        let entries = vec![[10, 10, 10], [10, 10, 10], [200, 200, 200]];
        let analysis = analyse_pairs(&entries);
        assert_eq!(analysis.exact_duplicates, 2);
        assert_eq!(analysis.paired_entries, 0);
    }

    #[test]
    fn adjacent_colours_that_are_not_bit_flips_do_not_pair() {
        // The case the measurement turned on. 7 and 8 differ by one and differ in
        // four bits, so a quantiser picks them and a bit flip cannot produce them.
        // Counting them was what made a clean photograph read as fully paired.
        assert!(!is_low_bit_flip(&[7, 0, 0], &[8, 0, 0]));
        assert!(is_low_bit_flip(&[8, 0, 0], &[9, 0, 0]));
        assert!(
            !is_low_bit_flip(&[8, 0, 0], &[8, 0, 0]),
            "equal is not a flip"
        );
    }

    #[test]
    fn pairing_is_one_to_one_so_a_cluster_is_not_counted_as_many_pairs() {
        // A run of colours each a flip away from the next. Under a one-to-one
        // matching this is two pairs and a spare, not five matches.
        let entries = vec![[0, 0, 0], [1, 0, 0], [2, 0, 0], [3, 0, 0], [4, 0, 0]];
        assert_eq!(analyse_pairs(&entries).paired_entries, 4);
    }

    #[test]
    fn a_fully_paired_palette_of_flips_reaches_the_threshold_with_margin() {
        // The clean maximum measured was 0.570; a constructed palette is 1.0.
        let analysis = analyse_pairs(&doubled_palette(128));
        assert_eq!(analysis.paired_fraction(), 1.0);
        assert!(analysis.paired_fraction() > MIN_PAIRED_FRACTION);
    }

    #[test]
    fn a_small_palette_cannot_trip_the_detector_however_paired_it_is() {
        // The guard that stops a sixteen colour image matching on a coincidence.
        let analysis = analyse_pairs(&doubled_palette(8));
        assert_eq!(analysis.paired_fraction(), 1.0);
        assert!(
            !analysis.looks_doubled(),
            "sixteen entries is below the minimum palette size"
        );
    }

    #[test]
    fn a_difference_of_two_in_a_channel_is_not_a_pair() {
        let entries = vec![[10, 10, 10], [12, 10, 10]];
        assert_eq!(analyse_pairs(&entries).paired_entries, 0);
    }

    #[test]
    fn an_empty_palette_is_not_a_pair_analysis_divide_by_zero() {
        let analysis = analyse_pairs(&[]);
        assert_eq!(analysis.paired_fraction(), 0.0);
        assert!(!analysis.looks_doubled());
    }

    #[test]
    fn a_gif_colour_table_is_read_in_the_right_order() {
        let entries = doubled_palette(128);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doubled.gif");
        std::fs::write(&path, gif_with_palette(&entries)).unwrap();
        let palette = read_palette(&path).expect("the global table should be read");
        assert_eq!(palette.source, PaletteSource::GifGlobalColourTable);
        assert_eq!(palette.entries, entries);
    }

    #[test]
    fn a_bmp_colour_table_is_read_with_its_channels_the_right_way_round() {
        // The trap: BMP stores blue first. Read as red first, a pair check still
        // works by symmetry, so this test uses an asymmetric colour to catch it.
        let entries = vec![[1u8, 2, 3], [250, 251, 252]];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("small.bmp");
        std::fs::write(&path, bmp_with_palette(&entries)).unwrap();
        let palette = read_palette(&path).expect("the colour table should be read");
        assert_eq!(palette.source, PaletteSource::BmpColourTable);
        assert_eq!(palette.entries, entries);
    }

    #[test]
    fn a_doubled_gif_is_identified_as_a_heuristic_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doubled.gif");
        std::fs::write(&path, gif_with_palette(&doubled_palette(128))).unwrap();
        let found = check_stools(&path).expect("a fully doubled palette should match");
        assert_eq!(found.tool, "S-Tools");
        assert_eq!(
            found.tier,
            Tier::Heuristic,
            "the artefact cannot distinguish S-Tools from another palette LSB tool"
        );
        assert!(found.evidence.contains("GIF colour table"));
        assert!(found.evidence.contains("100 percent"));
    }

    #[test]
    fn a_doubled_bmp_palette_is_identified_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doubled.bmp");
        std::fs::write(&path, bmp_with_palette(&doubled_palette(128))).unwrap();
        let found = check_stools(&path).expect("a fully doubled BMP palette should match");
        assert!(found.evidence.contains("BMP colour table"));
    }

    #[test]
    fn a_spread_gif_is_not_identified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spread.gif");
        std::fs::write(&path, gif_with_palette(&spread_palette(256))).unwrap();
        assert!(check_stools(&path).is_none());
    }

    #[test]
    fn a_gif_with_no_global_colour_table_is_skipped() {
        let mut file = gif_with_palette(&spread_palette(256));
        file[10] &= 0x7F;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notable.gif");
        std::fs::write(&path, &file).unwrap();
        assert!(read_palette(&path).is_none());
    }

    #[test]
    fn a_truncated_colour_table_is_skipped_rather_than_read_short() {
        let mut file = gif_with_palette(&doubled_palette(128));
        file.truncate(100);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cut.gif");
        std::fs::write(&path, &file).unwrap();
        assert!(read_palette(&path).is_none());
    }

    #[test]
    fn a_true_colour_bmp_has_no_palette_to_read() {
        let mut file = bmp_with_palette(&spread_palette(256));
        file[28..30].copy_from_slice(&24u16.to_le_bytes());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("truecolour.bmp");
        std::fs::write(&path, &file).unwrap();
        assert!(read_palette(&path).is_none());
    }

    #[test]
    fn a_bmp_declaring_more_colours_than_its_depth_allows_is_clamped() {
        let mut file = bmp_with_palette(&spread_palette(256));
        file[46..50].copy_from_slice(&9_999u32.to_le_bytes());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("overclaim.bmp");
        std::fs::write(&path, &file).unwrap();
        let palette = read_palette(&path).expect("clamped to the depth, not refused");
        assert_eq!(palette.entries.len(), 256);
    }

    #[test]
    fn a_bmp_with_no_declared_colour_count_uses_its_depth() {
        let mut file = bmp_with_palette(&spread_palette(256));
        file[46..50].copy_from_slice(&0u32.to_le_bytes());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("undeclared.bmp");
        std::fs::write(&path, &file).unwrap();
        assert_eq!(read_palette(&path).unwrap().entries.len(), 256);
    }

    #[test]
    fn a_format_with_no_palette_at_all_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("photo.png");
        std::fs::write(&path, [0x89, b'P', b'N', b'G']).unwrap();
        assert!(read_palette(&path).is_none());
        assert!(check_stools(Path::new("/nonexistent/image.gif")).is_none());
    }

    #[test]
    fn palette_source_names_are_plain_words() {
        assert_eq!(
            PaletteSource::GifGlobalColourTable.describe(),
            "the GIF colour table"
        );
        assert_eq!(
            PaletteSource::BmpColourTable.describe(),
            "the BMP colour table"
        );
    }
}
