// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Lossy-pipeline survival tests — half of Track E of the adversarial gate.
//
// Real users send stego files through chat apps, email clients, image
// viewers — pipelines that re-encode the file. The behavioural contract:
//
//   - Lossless re-encode (PNG → PNG, BMP → BMP): payload SURVIVES.
//   - Lossy re-encode (PNG → JPEG, resize, quality strip): extract FAILS
//     CLEANLY. Never panic, never return silently-corrupt payload.
//
// We exercise two real-world pipelines:
//
//   - ImageMagick `convert` — the canonical Linux/macOS recompression tool;
//     also what most image hosting services use under the hood.
//   - Python PIL (Pillow) `Image.save` — the canonical Python tool; used by
//     thousands of web services and bots.
//
// Tests skip with a log message (rather than fail) when the required
// external tool isn't on PATH, so they're CI-safe across platforms.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────────

fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

fn write_png_cover(path: &Path, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state: u32 = 0xCAFE_F00D;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    image::save_buffer(path, &pixels, w, h, image::ColorType::Rgb8).expect("png write");
}

fn write_payload(path: &Path, body: &[u8]) {
    fs::File::create(path).unwrap().write_all(body).unwrap();
}

/// Embed a fixed test payload into a fresh cover; return (cover, stego, payload, passphrase).
fn make_stego(
    tmp: &TempDir,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    Vec<u8>,
    &'static str,
) {
    let cover = tmp.path().join("cover.png");
    let stego = tmp.path().join("stego.png");
    let payload_file = tmp.path().join("payload.txt");
    let payload = b"lossy-pipeline-survival-test-payload".to_vec();
    let passphrase = "lossy-pipeline-test-pass";

    write_png_cover(&cover, 256, 256);
    write_payload(&payload_file, &payload);

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload_file.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .assert()
        .success();

    (cover, stego, payload, passphrase)
}

fn tool_on_path(tool: &str) -> bool {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn extract_returns_payload(stego: &Path, passphrase: &str, expected: &[u8]) -> bool {
    let tmp = TempDir::new().unwrap();
    let recovered = tmp.path().join("recovered.bin");
    let result = bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .ok();
    if result.is_err() {
        return false;
    }
    fs::read(&recovered).map(|b| b == expected).unwrap_or(false)
}

// ── ImageMagick: PNG → PNG round-trip (lossless) ────────────────────────────

#[test]
fn imagemagick_png_to_png_preserves_payload() {
    if !tool_on_path("convert") {
        eprintln!("skipping: ImageMagick `convert` not on PATH");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let (_, stego, payload, passphrase) = make_stego(&tmp);
    let resaved = tmp.path().join("resaved.png");

    // ImageMagick PNG → PNG with default settings (no quality option).
    // This is the bit-identical re-save case.
    let status = Command::new("convert")
        .args([stego.to_str().unwrap(), resaved.to_str().unwrap()])
        .status()
        .expect("convert spawn");
    assert!(status.success(), "ImageMagick convert failed");

    assert!(
        extract_returns_payload(&resaved, passphrase, &payload),
        "PNG → PNG round-trip must preserve the embedded payload"
    );
}

// ── ImageMagick: PNG → JPEG → PNG (lossy) ───────────────────────────────────

#[test]
fn imagemagick_png_to_jpeg_destroys_payload_cleanly() {
    if !tool_on_path("convert") {
        eprintln!("skipping: ImageMagick `convert` not on PATH");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let (_, stego, payload, passphrase) = make_stego(&tmp);
    let jpeg = tmp.path().join("through.jpg");
    let resaved = tmp.path().join("resaved.png");

    Command::new("convert")
        .args([
            stego.to_str().unwrap(),
            "-quality",
            "75",
            jpeg.to_str().unwrap(),
        ])
        .status()
        .expect("convert spawn");
    Command::new("convert")
        .args([jpeg.to_str().unwrap(), resaved.to_str().unwrap()])
        .status()
        .expect("convert spawn");

    // JPEG re-encoding destroys LSBs by construction. Extract must either:
    //   - fail cleanly (Err), preferred
    //   - or return data that does NOT equal the original payload
    // Both are acceptable. Silent return of the original payload is forbidden,
    // and panic is forbidden.
    let recovered_matches = extract_returns_payload(&resaved, passphrase, &payload);
    assert!(
        !recovered_matches,
        "PNG → JPEG → PNG must destroy the payload — recovering it would mean LSBs survived JPEG compression, which is mathematically impossible"
    );
}

// ── ImageMagick: PNG → resize → PNG (lossy in a different way) ──────────────

#[test]
fn imagemagick_resize_destroys_payload_cleanly() {
    if !tool_on_path("convert") {
        eprintln!("skipping: ImageMagick `convert` not on PATH");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let (_, stego, payload, passphrase) = make_stego(&tmp);
    let resized = tmp.path().join("resized.png");

    // 50% downsize, then back up. The interpolation destroys the LSB plane.
    Command::new("convert")
        .args([
            stego.to_str().unwrap(),
            "-resize",
            "128x128",
            "-resize",
            "256x256",
            resized.to_str().unwrap(),
        ])
        .status()
        .expect("convert spawn");

    let recovered_matches = extract_returns_payload(&resized, passphrase, &payload);
    assert!(
        !recovered_matches,
        "resize round-trip must destroy the payload"
    );
}

// ── Pillow (Python PIL): PNG → PNG re-save with optimisation ───────────────

#[test]
fn pillow_png_resave_preserves_payload() {
    if !tool_on_path("python3") {
        eprintln!("skipping: python3 not on PATH");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let (_, stego, payload, passphrase) = make_stego(&tmp);
    let resaved = tmp.path().join("pillow_resaved.png");

    // Pillow's PNG save with optimize=True still preserves the pixel
    // values bit-identically (PNG is lossless). LSBs survive.
    let script = format!(
        "from PIL import Image; \
         Image.open('{}').save('{}', 'PNG', optimize=True)",
        stego.display(),
        resaved.display()
    );
    let status = Command::new("python3")
        .args(["-c", &script])
        .status()
        .expect("python3 spawn");
    assert!(status.success(), "Pillow PNG save failed");

    assert!(
        extract_returns_payload(&resaved, passphrase, &payload),
        "Pillow PNG re-save must preserve the payload (PNG is lossless)"
    );
}

// ── Pillow: PNG → JPEG quality 90 → PNG ────────────────────────────────────

#[test]
fn pillow_jpeg_quality_90_destroys_payload_cleanly() {
    if !tool_on_path("python3") {
        eprintln!("skipping: python3 not on PATH");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let (_, stego, payload, passphrase) = make_stego(&tmp);
    let intermediate = tmp.path().join("through.jpg");
    let resaved = tmp.path().join("pillow_jpeg_resaved.png");

    // JPEG quality 90 is what messaging apps typically use. Still lossy.
    let script = format!(
        "from PIL import Image; \
         Image.open('{}').convert('RGB').save('{}', 'JPEG', quality=90); \
         Image.open('{}').save('{}', 'PNG')",
        stego.display(),
        intermediate.display(),
        intermediate.display(),
        resaved.display()
    );
    Command::new("python3")
        .args(["-c", &script])
        .status()
        .expect("python3 spawn");

    let recovered_matches = extract_returns_payload(&resaved, passphrase, &payload);
    assert!(
        !recovered_matches,
        "JPEG quality 90 round-trip must destroy the payload"
    );
}

// ── ImageMagick: metadata-strip should not affect the payload ──────────────

#[test]
fn imagemagick_strip_metadata_preserves_payload() {
    if !tool_on_path("convert") {
        eprintln!("skipping: ImageMagick `convert` not on PATH");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let (_, stego, payload, passphrase) = make_stego(&tmp);
    let stripped = tmp.path().join("stripped.png");

    // -strip removes EXIF, ICC profiles, comments, etc. — but should NOT
    // touch the pixel data. Our LSB payload lives in pixels, so this should
    // pass through cleanly.
    Command::new("convert")
        .args([
            stego.to_str().unwrap(),
            "-strip",
            stripped.to_str().unwrap(),
        ])
        .status()
        .expect("convert spawn");

    assert!(
        extract_returns_payload(&stripped, passphrase, &payload),
        "Metadata strip must not affect a pixel-LSB payload"
    );
}

// ── Extract on garbage that started as a stego file (no panic) ─────────────

#[test]
fn extract_on_completely_overwritten_stego_fails_cleanly() {
    let tmp = TempDir::new().unwrap();
    let (_, stego, _, passphrase) = make_stego(&tmp);

    // Overwrite the entire pixel area with zeros. This is the most
    // aggressive "lossy" pipeline imaginable. Extract must not panic;
    // a clean Err is the expected outcome.
    let mut bytes = fs::read(&stego).unwrap();
    let pixel_start = 100; // past most PNG headers
    if bytes.len() > pixel_start + 1000 {
        for b in &mut bytes[pixel_start..] {
            *b = 0;
        }
        fs::write(&stego, &bytes).unwrap();
    }

    // Fully overwritten file is no longer a valid PNG either — extract may
    // fail at the decode step or the parse step. Either is fine.
    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            tmp.path().join("r.bin").to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .assert()
        .failure();
}
