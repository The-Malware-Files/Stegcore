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

//! The false-positive measurement behind wbStego's tier.
//!
//! `CLAUDE.md` A3 requires a tier to rest on a measured false-positive rate on a
//! clean corpus rather than on how convincing the signature looks. wbStego's
//! signature is a header read out of the low bits of a bitmap's pixel array, and
//! the low bits of a real photograph are not random, which is exactly the
//! situation where an argument from probability can be wrong.
//!
//! So this walks a corpus of real photographs, turns each into the carrier format
//! the detector reads, and reports two numbers: how many clean images produce a
//! plausible size field, which is the weak half of the header, and how many
//! produce a full match, which is what would actually be reported.
//!
//! The corpus is the local ALASKA2 cover sample, the same clean distribution the
//! statistical detectors are calibrated against. It is not in a fresh clone, so
//! **this test skips itself when the corpus is absent** rather than failing; the
//! measurement it produced is recorded in the detector's own module notes, and
//! this file is how that number gets re-derived.

use std::path::{Path, PathBuf};

use stegcore_engine::fingerprints::wbstego;

/// Clean photographs examined on an ordinary test run.
///
/// Decoding a JPEG and writing it back out as a bitmap costs about a tenth of a
/// second, so the full 2,000 image measurement takes over three minutes, which is
/// too long to pay on every `cargo test`. The default here is the standing gate:
/// enough images that a detector which started firing on photographs would be
/// caught, cheap enough to leave switched on.
///
/// Set `STEGCORE_FPR_CORPUS_LIMIT` to re-run the full measurement, which is what
/// the figure recorded in the detector's notes came from:
///
/// ```text
/// STEGCORE_FPR_CORPUS_LIMIT=2000 cargo test -p stegcore-engine \
///     --test fingerprint_wbstego_fpr -- --nocapture
/// ```
const DEFAULT_CORPUS_LIMIT: usize = 200;

/// Fewest images the measurement will accept before it refuses to mean anything.
const MIN_CORPUS: usize = 100;

/// Where the clean corpus lives, relative to the workspace root.
const CORPUS: &str = "private/datasets/alaska2/cover-sample";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("the engine crate sits two levels below the workspace root")
}

/// Write an RGB image out as the carrier wbStego reads: a 24 bit uncompressed
/// BMP, rows bottom-up in BGR order, each padded to a four byte boundary.
fn bmp_bytes(rgb: &image::RgbImage) -> Vec<u8> {
    let (width, height) = rgb.dimensions();
    let stride = (width as usize * 3).div_ceil(4) * 4;
    let mut array = Vec::with_capacity(stride * height as usize);
    for y in (0..height).rev() {
        let row_start = array.len();
        for x in 0..width {
            let p = rgb.get_pixel(x, y).0;
            array.extend_from_slice(&[p[2], p[1], p[0]]);
        }
        array.resize(row_start + stride, 0);
    }
    let mut file = Vec::with_capacity(54 + array.len());
    file.extend_from_slice(b"BM");
    file.extend_from_slice(&((54 + array.len()) as u32).to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&54u32.to_le_bytes());
    file.extend_from_slice(&40u32.to_le_bytes());
    file.extend_from_slice(&(width as i32).to_le_bytes());
    file.extend_from_slice(&(height as i32).to_le_bytes());
    file.extend_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&24u16.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&(array.len() as u32).to_le_bytes());
    file.extend_from_slice(&[0u8; 16]);
    file.extend_from_slice(&array);
    file
}

#[test]
fn wbstego_does_not_fire_on_clean_photographs() {
    let corpus = workspace_root().join(CORPUS);
    let Ok(entries) = std::fs::read_dir(&corpus) else {
        println!(
            "\nwbStego false-positive measurement SKIPPED: no corpus at {}.\n\
             The recorded figures are 38 of 2,000 clean photographs producing a plausible\n\
             size field and 0 of 2,000 producing a full header match, measured 2026-10-01.\n",
            corpus.display()
        );
        return;
    };
    // Sorted, so two runs examine the same images in the same order.
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("jpg"))
        .collect();
    files.sort();
    let limit = std::env::var("STEGCORE_FPR_CORPUS_LIMIT")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_CORPUS_LIMIT);
    files.truncate(limit);

    assert!(
        files.len() >= MIN_CORPUS,
        "only {} images were found under {}, too few for the measurement to mean anything",
        files.len(),
        corpus.display()
    );

    let mut examined = 0usize;
    let mut plausible_size_field = 0usize;
    let mut flagged = Vec::new();

    for path in &files {
        let Ok(decoded) = image::open(path) else {
            continue;
        };
        let bmp = bmp_bytes(&decoded.to_rgb8());
        let Some(carrier) = wbstego::carrier_from_bmp(&bmp) else {
            continue;
        };
        // The same seven bytes the detector reads, so the weak half of the
        // header can be counted separately from the whole of it.
        let Some(stream) = wbstego::assemble(carrier.pixel_array, 7) else {
            continue;
        };
        examined += 1;
        let size = u32::from_le_bytes([stream[0], stream[1], stream[2], 0]);
        if size > 0 && u64::from(size) <= carrier.capacity_bytes {
            plausible_size_field += 1;
        }
        if wbstego::header_from_stream(&stream, carrier.capacity_bytes).is_some() {
            flagged.push(path.clone());
        }
    }

    println!(
        "\nwbStego false-positive measurement\n\
         Corpus: {} clean photographs from {}, written out as 24 bit BMP\n\
         Plausible 24 bit size field alone: {} ({:.2}%)\n\
         Full header match, so flagged: {} ({:.3}%)\n",
        examined,
        corpus.display(),
        plausible_size_field,
        100.0 * plausible_size_field as f64 / examined as f64,
        flagged.len(),
        100.0 * flagged.len() as f64 / examined as f64,
    );

    assert!(
        flagged.is_empty(),
        "wbStego flagged {} clean photographs, so its tier is no longer justified. \
         First few: {:?}",
        flagged.len(),
        flagged
            .iter()
            .take(5)
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn wbstego_still_fires_on_a_wbstego_shaped_header_so_the_checks_have_not_been_tightened_shut() {
    // The other half of the measurement. A false-positive rate of zero is easy
    // to reach by never matching anything, so the recall side is pinned too,
    // against a header built from the layout in the detector's notes.
    let mut stream = 4_096u32.to_le_bytes()[..3].to_vec();
    stream.extend_from_slice(&wbstego::HEADER_MARKER);
    stream.push(12); // inner header length
    stream.push(4); // Rijndael
    let header = wbstego::header_from_stream(&stream, 1 << 20)
        .expect("a header built to the documented layout must be recognised");
    assert_eq!(header.payload_bytes, 4_096);
    assert_eq!(header.inner_header_len, 12);
    assert_eq!(header.cipher, "Rijndael");
}
