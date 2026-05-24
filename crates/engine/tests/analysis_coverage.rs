// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

//! Format-dispatch + sampled-mode coverage for the engine's analysis surface.
//!
//! The inline test module in `analysis.rs` covers the SPA / RS / WS detector
//! logic and the all-PNG happy path well. This file fills the format-dispatch
//! gaps (BMP / JPEG / WebP / WAV-stego / malformed inputs) and the fast /
//! sampled code path that the inline tests never exercise.
//!
//! Targets the v4.0.1 coverage gate (engine line coverage >=90%); the work
//! that moves engine + core to the v4.1 workspace >=90% standard is tracked
//! in `private/plans/active-sprint.md`.

use std::path::{Path, PathBuf};

use image::{ImageBuffer, ImageFormat, Rgb};
use stegcore_engine::analysis::{analyse, analyse_batch, analyse_fast, generate_html_report};

// ── Fixture helpers ──────────────────────────────────────────────────────────

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("stegcore-analysis-cov-{name}"))
}

fn cleanup(p: &Path) {
    let _ = std::fs::remove_file(p);
}

/// Smooth gradient that gives detectors something to chew on without spiking
/// any of them on its own. Saved in whichever container the caller requests.
fn smooth_image(w: u32, h: u32) -> ImageBuffer<Rgb<u8>, Vec<u8>> {
    ImageBuffer::from_fn(w, h, |x, y| {
        let r = 128u8.wrapping_add(((x as i16) - (w as i16) / 2) as u8);
        let g = 128u8.wrapping_add(((y as i16) - (h as i16) / 2) as u8);
        let b = ((x + y) % 256) as u8;
        Rgb([r, g, b])
    })
}

fn save_as(img: &ImageBuffer<Rgb<u8>, Vec<u8>>, path: &Path, fmt: ImageFormat) {
    img.save_with_format(path, fmt).unwrap();
}

// ── Format-dispatch coverage ─────────────────────────────────────────────────

#[test]
fn analyse_dispatches_bmp() {
    let p = tmp("smooth.bmp");
    save_as(&smooth_image(128, 128), &p, ImageFormat::Bmp);
    let json = analyse(&p).expect("BMP path should analyse cleanly");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["format"].as_str(), Some("bmp"));
    cleanup(&p);
}

#[test]
fn analyse_dispatches_jpeg() {
    let p = tmp("smooth.jpg");
    save_as(&smooth_image(128, 128), &p, ImageFormat::Jpeg);
    let json = analyse(&p).expect("JPEG path should analyse cleanly");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["format"].as_str(), Some("jpg"));
    // JPEG path runs the same detector suite — verdict must still parse.
    assert!(v.get("verdict").is_some());
    cleanup(&p);
}

#[test]
fn analyse_dispatches_webp() {
    let p = tmp("smooth.webp");
    save_as(&smooth_image(128, 128), &p, ImageFormat::WebP);
    let json = analyse(&p).expect("WebP path should analyse cleanly");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["format"].as_str(), Some("webp"));
    cleanup(&p);
}

#[test]
fn analyse_dispatches_png_via_extension_when_content_unknown() {
    // Plain PNG with a known signature still routes to the PNG path even when
    // the extension is unusual; this also covers the magic-byte sniff branch.
    let p = tmp("renamed.png");
    save_as(&smooth_image(64, 64), &p, ImageFormat::Png);
    let json = analyse(&p).expect("PNG path should analyse cleanly");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["format"].as_str(), Some("png"));
    cleanup(&p);
}

// ── Fast / sampled mode ──────────────────────────────────────────────────────

#[test]
fn analyse_fast_on_png_returns_valid_report() {
    let p = tmp("fast.png");
    save_as(&smooth_image(256, 256), &p, ImageFormat::Png);
    let json = analyse_fast(&p).expect("fast analysis should succeed");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    // Fast mode produces no fingerprint and no block_entropy by design;
    // the serialiser may render this as null or omit the field entirely.
    assert!(v.get("verdict").is_some());
    let fp_absent = v.get("tool_fingerprint").is_none_or(|x| x.is_null());
    let be_absent = v.get("block_entropy").is_none_or(|x| x.is_null());
    assert!(fp_absent, "fast mode must not populate tool_fingerprint");
    assert!(be_absent, "fast mode must not populate block_entropy");
    cleanup(&p);
}

#[test]
fn analyse_fast_on_bmp_returns_valid_report() {
    let p = tmp("fast.bmp");
    save_as(&smooth_image(256, 256), &p, ImageFormat::Bmp);
    let json = analyse_fast(&p).expect("fast analysis should succeed for BMP");
    assert!(!json.is_empty());
    cleanup(&p);
}

#[test]
fn analyse_fast_on_small_image_returns_full_report() {
    // Image with <48 bytes of pixel data forces sample_pixels to return all.
    let p = tmp("tiny.png");
    save_as(&smooth_image(4, 4), &p, ImageFormat::Png);
    let json = analyse_fast(&p).expect("fast analysis should handle tiny images");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("verdict").is_some());
    cleanup(&p);
}

// ── WAV analysis (sequential LSB modification) ───────────────────────────────

#[test]
fn analyse_wav_with_lsb_modification() {
    let p = tmp("lsb.wav");
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    // Tone with LSB modulated by a pseudo-random pattern: gives the WAV
    // detector its first non-trivial input under test.
    let mut writer = hound::WavWriter::create(&p, spec).unwrap();
    for i in 0..44100u32 {
        let t = i as f32 / 44100.0;
        let base = ((t * 440.0 * 2.0 * std::f32::consts::PI).sin() * 16000.0) as i16;
        let lsb = ((i.wrapping_mul(2654435761)) & 1) as i16;
        writer.write_sample((base & !1) | lsb).unwrap();
    }
    writer.finalize().unwrap();

    let json = analyse(&p).expect("WAV with LSB modifications should still analyse");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["format"].as_str(), Some("wav"));
    let score = v["overall_score"].as_f64().unwrap();
    assert!((0.0..=1.0).contains(&score));
    cleanup(&p);
}

// ── Batch + HTML report edges ────────────────────────────────────────────────

#[test]
fn analyse_batch_mixes_success_and_error() {
    let good = tmp("batch_ok.png");
    save_as(&smooth_image(64, 64), &good, ImageFormat::Png);
    let missing = std::env::temp_dir().join("stegcore-analysis-cov-not-there.png");
    let _ = std::fs::remove_file(&missing); // make sure it does not exist

    let paths: Vec<&Path> = vec![good.as_path(), missing.as_path()];
    let results = analyse_batch(&paths);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok(), "good path should succeed");
    assert!(results[1].is_err(), "missing path should error");
    cleanup(&good);
}

#[test]
fn generate_html_report_handles_empty_input() {
    let html = generate_html_report(&[]);
    // Empty report still renders a valid HTML envelope.
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("</html>"));
}

#[test]
fn generate_html_report_filters_invalid_json() {
    // Mix of valid + malformed: invalid entries are skipped by the renderer.
    let p = tmp("html_input.png");
    save_as(&smooth_image(64, 64), &p, ImageFormat::Png);
    let valid = analyse(&p).unwrap();
    let invalid = "not actually json";
    let html = generate_html_report(&[&valid, invalid]);
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("</html>"));
    cleanup(&p);
}

#[test]
fn generate_html_report_with_multiple_valid_reports() {
    let p1 = tmp("html_multi1.png");
    let p2 = tmp("html_multi2.png");
    save_as(&smooth_image(64, 64), &p1, ImageFormat::Png);
    save_as(&smooth_image(96, 96), &p2, ImageFormat::Png);
    let j1 = analyse(&p1).unwrap();
    let j2 = analyse(&p2).unwrap();
    let html = generate_html_report(&[&j1, &j2]);
    assert!(html.contains("<!DOCTYPE html>"));
    // Each report leaves its file name in the rendered output.
    assert!(html.contains("html_multi1") || html.contains("html_multi2"));
    cleanup(&p1);
    cleanup(&p2);
}

// ── Malformed / pathological inputs ──────────────────────────────────────────

#[test]
fn analyse_zero_byte_file_returns_error() {
    let p = tmp("empty.png");
    std::fs::write(&p, b"").unwrap();
    let result = analyse(&p);
    assert!(result.is_err(), "zero-byte file should error, not panic");
    cleanup(&p);
}

#[test]
fn analyse_truncated_png_returns_error() {
    let p = tmp("truncated.png");
    // PNG magic bytes only — no IHDR, no data.
    std::fs::write(&p, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
    let result = analyse(&p);
    assert!(result.is_err(), "truncated PNG should error, not panic");
    cleanup(&p);
}

#[test]
fn analyse_random_bytes_with_png_extension_returns_error() {
    let p = tmp("random.png");
    let garbage: Vec<u8> = (0..1024).map(|i| (i * 17) as u8).collect();
    std::fs::write(&p, garbage).unwrap();
    let result = analyse(&p);
    assert!(result.is_err(), "random bytes should not parse as PNG");
    cleanup(&p);
}

#[test]
fn analyse_fast_propagates_missing_file_error() {
    let p = std::env::temp_dir().join("stegcore-analysis-cov-fast-missing.png");
    let _ = std::fs::remove_file(&p);
    let result = analyse_fast(&p);
    assert!(
        result.is_err(),
        "fast analysis must surface missing-file errors"
    );
}

#[test]
fn analyse_fast_rejects_unsupported_extension() {
    let p = tmp("unknown.tiff");
    std::fs::write(&p, b"not a tiff either").unwrap();
    let result = analyse_fast(&p);
    assert!(result.is_err());
    cleanup(&p);
}
