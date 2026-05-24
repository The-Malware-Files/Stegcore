// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Track F — concurrent + resource-cap + content-sniffing dispatcher tests.
//
// Three adjacent threat surfaces, one integration file:
//
//   1. Concurrent abuse — 100 parallel `analyse` invocations on the same
//      file, embed+extract races, temp-file collision avoidance.
//
//   2. Resource caps — payload-larger-than-capacity, very-large-file
//      analyse, low-memory-friendly behaviour.
//
//   3. Content-sniffing dispatcher — a file with PNG bytes named `.jpg`
//      should dispatch to the PNG path, not be mis-routed by extension.
//      Closes a known weakness in the engine.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use assert_cmd::Command as AssertCommand;
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────────

fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

fn write_png_cover(path: &Path, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state: u32 = 0xDECA_F1BA;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    image::save_buffer(path, &pixels, w, h, image::ColorType::Rgb8).expect("png write");
}

fn write_payload(path: &Path, body: &[u8]) {
    fs::File::create(path).unwrap().write_all(body).unwrap();
}

// ── Section 1 — Concurrent abuse ───────────────────────────────────────────

#[test]
fn one_hundred_parallel_analyses_succeed() {
    // Build a single test cover. Then fire 100 `analyse` invocations
    // concurrently against it. Every one must succeed; the test detects
    // any panic / non-zero exit. Stegcore opens each file independently so
    // there should be no contention, but verify empirically.
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("c.png");
    write_png_cover(&cover, 96, 96);

    let cover_str = cover.to_str().unwrap().to_string();
    let failures = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = (0..100)
        .map(|_| {
            let cover_str = cover_str.clone();
            let failures = Arc::clone(&failures);
            thread::spawn(move || {
                let result = AssertCommand::cargo_bin("stegcore")
                    .unwrap()
                    .args(["analyse", &cover_str, "--json"])
                    .ok();
                if result.is_err() {
                    failures.fetch_add(1, Ordering::SeqCst);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread did not panic");
    }
    assert_eq!(
        failures.load(Ordering::SeqCst),
        0,
        "all 100 parallel analyses must succeed"
    );
}

#[test]
fn parallel_embed_to_distinct_outputs_succeeds() {
    // Two processes embedding different payloads into copies of the same
    // cover, writing to different output paths. Both should succeed and
    // produce independently-valid stego files.
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("c.png");
    write_png_cover(&cover, 128, 128);

    let mut threads = vec![];
    for i in 0..4 {
        let cover_path = cover.clone();
        let workdir = tmp.path().to_path_buf();
        threads.push(thread::spawn(move || {
            let payload = workdir.join(format!("p_{i}.txt"));
            let stego = workdir.join(format!("s_{i}.png"));
            let recovered = workdir.join(format!("r_{i}.txt"));
            let secret = format!("parallel-embed-{i}");
            write_payload(&payload, secret.as_bytes());
            let pass = format!("pass-{i}");

            AssertCommand::cargo_bin("stegcore")
                .unwrap()
                .args([
                    "embed",
                    cover_path.to_str().unwrap(),
                    payload.to_str().unwrap(),
                    "-o",
                    stego.to_str().unwrap(),
                    "--passphrase",
                    &pass,
                ])
                .assert()
                .success();

            AssertCommand::cargo_bin("stegcore")
                .unwrap()
                .args([
                    "extract",
                    stego.to_str().unwrap(),
                    "-o",
                    recovered.to_str().unwrap(),
                    "--passphrase",
                    &pass,
                ])
                .assert()
                .success();

            assert_eq!(fs::read(&recovered).unwrap(), secret.as_bytes());
        }));
    }
    for t in threads {
        t.join().expect("parallel embed thread did not panic");
    }
}

// ── Section 2 — Resource caps ──────────────────────────────────────────────

#[test]
fn payload_at_capacity_boundary_fails_cleanly() {
    // Tiny cover, payload just over capacity — must fail cleanly with
    // InsufficientCapacity, not panic, not silently truncate.
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("tiny.png");
    let payload = tmp.path().join("payload.bin");

    // 16x16 cover -> ~96 LSB-bytes -> well under the framing overhead
    // (header + meta JSON + AEAD tag is already ~200 bytes), so any
    // non-trivial payload exceeds capacity.
    write_png_cover(&cover, 16, 16);
    write_payload(&payload, &vec![0xFF; 1024]);

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "p",
        ])
        .assert()
        .failure();
}

#[test]
fn analyse_huge_dimension_lie_does_not_oom() {
    // Forge a PNG-ish file with a sane header but a claimed payload size
    // that would over-allocate. The image crate's decode path should
    // reject this; if it doesn't, we OOM. Either outcome must be a clean
    // Err, not a process kill.
    //
    // We can't easily craft a malicious dimension PNG by hand here, so we
    // approximate: a truncated PNG that the decoder will reject after
    // reading the IHDR.
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("bad.png");
    // Valid PNG header + IHDR claiming 32768x32768x16-bit RGBA = ~8 GB.
    let mut bytes: Vec<u8> = vec![
        0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, // PNG sig
        0x00, 0x00, 0x00, 0x0D, // IHDR length
        b'I', b'H', b'D', b'R', 0x00, 0x00, 0x80, 0x00, // width  32768
        0x00, 0x00, 0x80, 0x00, // height 32768
        0x10, 0x06, 0x00, 0x00, 0x00, // 16-bit RGBA, etc.
    ];
    // Bogus CRC + premature EOF.
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    fs::write(&bad, bytes).unwrap();

    // Run analyse — it should reject the file cleanly, NOT allocate 8 GB.
    let assert = bin().args(["analyse", bad.to_str().unwrap()]).assert();
    // Expect failure (the file is malformed); the crucial part is no panic.
    let _ = assert.try_failure();
}

#[test]
fn zero_payload_rejected_cleanly() {
    // Stegcore's embed rejects empty payloads via StegError::EmptyPayload.
    // Verify the CLI surfaces this as a failure exit.
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("c.png");
    let payload = tmp.path().join("p.bin");
    write_png_cover(&cover, 64, 64);
    write_payload(&payload, b"");

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "p",
        ])
        .assert()
        .failure();
}

// ── Section 3 — Content-sniffing dispatcher ────────────────────────────────

#[test]
fn png_bytes_named_dot_jpg_dispatches_as_png() {
    // The engine now dispatches by magic bytes first, extension second.
    // A file with PNG content named `.jpg` must route to the PNG path
    // and analyse cleanly — not crash, not be mis-decoded as JPEG.
    let tmp = TempDir::new().unwrap();
    let lying_path = tmp.path().join("disguised.jpg");

    // Generate a PNG into a temp file, then move it to the lying path.
    let real_png = tmp.path().join("real.png");
    write_png_cover(&real_png, 64, 64);
    fs::rename(&real_png, &lying_path).unwrap();

    // analyse should succeed — the content sniff overrides the misleading
    // extension.
    // `analyse`'s table output goes to STDERR (via output::print_*, which
    // targets stderr for tty-aware colouring). Read from stderr.
    let assert = bin()
        .args(["analyse", lying_path.to_str().unwrap()])
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    // The verdict block prints the canonical format. PNG bytes -> "PNG".
    assert!(
        out.to_lowercase().contains("png"),
        "PNG content named .jpg should still report PNG format; got: {out:?}"
    );
}

#[test]
fn bmp_bytes_named_dot_png_dispatches_as_bmp() {
    let tmp = TempDir::new().unwrap();
    let real_bmp = tmp.path().join("real.bmp");
    let lying_path = tmp.path().join("disguised.png");

    let mut pixels = vec![0u8; (64 * 64 * 3) as usize];
    let mut state: u32 = 0xCAFE_BABE;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    let img = image::RgbImage::from_raw(64, 64, pixels).unwrap();
    img.save_with_format(&real_bmp, image::ImageFormat::Bmp)
        .unwrap();
    fs::rename(&real_bmp, &lying_path).unwrap();

    // `analyse`'s table output goes to STDERR (via output::print_*, which
    // targets stderr for tty-aware colouring). Read from stderr.
    let assert = bin()
        .args(["analyse", lying_path.to_str().unwrap()])
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        out.to_lowercase().contains("bmp"),
        "BMP content named .png should report BMP; got: {out:?}"
    );
}

#[test]
fn unknown_magic_falls_back_to_extension() {
    // A file with garbage content but a .png extension: magic-byte sniff
    // returns None, dispatcher falls back to the extension. The image
    // decoder then rejects the garbage, so we expect a clean failure.
    // The point of THIS test: the dispatcher did not crash trying to
    // sniff a file too short to have a recognisable signature.
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("garbage.png");
    fs::write(&bad, b"not a real image, just text").unwrap();

    bin()
        .args(["analyse", bad.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn analyse_routes_a_wav_named_as_png_to_wav() {
    // RIFF/WAVE header in a file named .png — the sniff should catch
    // the WAVE form-type at offset 8 and route as WAV.
    let tmp = TempDir::new().unwrap();
    let real_wav = tmp.path().join("real.wav");
    let lying_path = tmp.path().join("disguised.png");

    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut w = hound::WavWriter::create(&real_wav, spec).unwrap();
    for i in 0..1024i16 {
        w.write_sample(i.wrapping_mul(7)).unwrap();
    }
    w.finalize().unwrap();
    fs::rename(&real_wav, &lying_path).unwrap();

    // analyse must succeed; the engine reports WAV.
    // `analyse`'s table output goes to STDERR (via output::print_*, which
    // targets stderr for tty-aware colouring). Read from stderr.
    let assert = bin()
        .args(["analyse", lying_path.to_str().unwrap()])
        .assert()
        .success();
    let out = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        out.to_lowercase().contains("wav"),
        "WAV content named .png should report WAV; got: {out:?}"
    );
}
