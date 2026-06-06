// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Natural-image cover corpus acquisition.
//!
//! Procedural noise covers cannot give an honest false-positive rate: a random
//! LSB plane is indistinguishable from a fully embedded one, so the statistical
//! detectors fire on every clean sample. This fetches real photographs (seeded
//! and reproducible) from Lorem Picsum, which serves royalty-free Unsplash
//! images with no API key, and writes them as lossless PNG into the `clean`
//! split of a dataset the `audit`/`score`/`benchmark` chain consumes.
//!
//! The network fetch is delegated to the system `curl` (the same shell-out
//! pattern `score` uses for the engine) so no HTTP/TLS dependency is added; the
//! decode-and-re-encode step uses the already-vetted `image` crate.

use std::fs;
use std::io::Cursor;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use image::{DynamicImage, ImageFormat};

/// Outcome of a corpus fetch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CorpusOutcome {
    pub fetched: usize,
    pub failed: usize,
}

/// Decode encoded image bytes (e.g. JPEG from the source) and re-encode as a
/// lossless RGB8 PNG. The pixels are preserved exactly, so the cover keeps the
/// natural-image statistics that make it a meaningful clean sample.
pub fn decode_to_png(raw: &[u8]) -> Result<Vec<u8>, String> {
    let img = image::load_from_memory(raw).map_err(|e| format!("decode: {e}"))?;
    let rgb = img.to_rgb8();
    let mut buf = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(rgb)
        .write_to(&mut buf, ImageFormat::Png)
        .map_err(|e| format!("encode: {e}"))?;
    Ok(buf.into_inner())
}

/// Fetch one seeded image via the system `curl`, retrying on the flaky network.
/// `seed` selects a stable image; `size` is the square side in pixels.
pub fn curl_download(seed: &str, size: u32, retries: u32) -> Result<Vec<u8>, String> {
    let url = format!("https://picsum.photos/seed/{seed}/{size}/{size}");
    let mut last = String::from("no attempt made");
    for attempt in 1..=retries.max(1) {
        match Command::new("curl")
            .args(["-sS", "-L", "--max-time", "30", "-o", "-", &url])
            .output()
        {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => return Ok(o.stdout),
            Ok(o) => {
                last = String::from_utf8_lossy(&o.stderr)
                    .chars()
                    .take(120)
                    .collect()
            }
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_secs(u64::from(attempt) * 2));
    }
    Err(format!("curl failed after {retries} attempts: {last}"))
}

/// Fetch `count` covers into `clean_dir` as `NNNNN.png`, sourcing raw bytes
/// from `download(index)`. A failed or undecodable fetch is counted and skipped
/// rather than aborting the run. The downloader is injected so the fetch loop
/// is testable without touching the network.
pub fn run_fetch<F>(clean_dir: &Path, count: u32, download: F) -> std::io::Result<CorpusOutcome>
where
    F: Fn(u32) -> Result<Vec<u8>, String>,
{
    fs::create_dir_all(clean_dir)?;
    let mut outcome = CorpusOutcome::default();
    for i in 0..count {
        match download(i).and_then(|raw| decode_to_png(&raw)) {
            Ok(png) => {
                fs::write(clean_dir.join(format!("{i:05}.png")), png)?;
                outcome.fetched += 1;
            }
            Err(e) => {
                eprintln!("  cover {i} failed: {e}");
                outcome.failed += 1;
            }
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// A small in-memory JPEG, to stand in for a fetched cover.
    fn tiny_jpeg(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbImage::from_fn(w, h, |x, y| {
            image::Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        let mut buf = Cursor::new(Vec::new());
        DynamicImage::ImageRgb8(img)
            .write_to(&mut buf, ImageFormat::Jpeg)
            .unwrap();
        buf.into_inner()
    }

    #[test]
    fn decode_to_png_produces_valid_png() {
        let png = decode_to_png(&tiny_jpeg(48, 32)).unwrap();
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        // It must decode back at the same dimensions.
        let back = image::load_from_memory(&png).unwrap();
        assert_eq!((back.width(), back.height()), (48, 32));
    }

    #[test]
    fn decode_to_png_rejects_garbage() {
        assert!(decode_to_png(b"not an image").is_err());
    }

    #[test]
    fn run_fetch_counts_and_names_covers() {
        let tmp = TempDir::new().unwrap();
        let clean = tmp.path().join("clean");
        let jpeg = tiny_jpeg(32, 32);
        // Even indices succeed, odd ones fail.
        let outcome = run_fetch(&clean, 4, |i| {
            if i % 2 == 0 {
                Ok(jpeg.clone())
            } else {
                Err("network".into())
            }
        })
        .unwrap();
        assert_eq!(outcome.fetched, 2);
        assert_eq!(outcome.failed, 2);
        assert!(clean.join("00000.png").exists());
        assert!(!clean.join("00001.png").exists());
        assert!(clean.join("00002.png").exists());
    }

    #[test]
    fn run_fetch_skips_undecodable_bytes() {
        let tmp = TempDir::new().unwrap();
        let clean = tmp.path().join("clean");
        let outcome = run_fetch(&clean, 2, |_| Ok(b"junk".to_vec())).unwrap();
        assert_eq!(outcome.fetched, 0);
        assert_eq!(outcome.failed, 2);
    }
}
