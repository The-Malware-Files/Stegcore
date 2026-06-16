// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// Integration tests for the post-v4.0.1 audit fixes:
//   F3 overwrite protection (--force)
//   F4 embeddable-format pre-flight (clean FLAC rejection)
//   F6 extract output flags are mutually exclusive
//   F8 `analyse --report json` prints to stdout when no -o is given

use std::fs;
use std::io::Write;
use std::path::Path;

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;

fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

/// Deterministic noisy PNG cover with ample capacity.
fn write_png_cover(path: &Path, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state: u32 = 0xDEAD_BEEF;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    image::save_buffer(path, &pixels, w, h, image::ColorType::Rgb8).expect("write PNG cover");
}

fn write_payload(path: &Path, body: &[u8]) {
    let mut f = fs::File::create(path).expect("payload create");
    f.write_all(body).expect("payload write");
}

// ── F3: overwrite protection ────────────────────────────────────────────────

#[test]
fn embed_refuses_to_overwrite_existing_output_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("p.txt");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 64, 64);
    write_payload(&payload, b"hello");
    fs::write(&out, b"EXISTING IMPORTANT DATA").unwrap();

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "pw",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    // The existing file must be untouched.
    assert_eq!(fs::read(&out).unwrap(), b"EXISTING IMPORTANT DATA");
}

#[test]
fn embed_overwrites_existing_output_with_force() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("p.txt");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 64, 64);
    write_payload(&payload, b"hello");
    fs::write(&out, b"OLD").unwrap();

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "pw",
            "-o",
            out.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();

    // The file was replaced with a real stego image (much larger than "OLD").
    assert!(fs::read(&out).unwrap().len() > 100);
}

// ── F4: malformed-cover pre-flight ──────────────────────────────────────────

#[test]
fn embed_rejects_malformed_flac_cover_with_clear_message() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("audio.flac");
    let payload = dir.path().join("p.txt");
    // FLAC is an embed target now, so a cover that merely carries the fLaC
    // magic but is not a decodable stream must be rejected by the decoder with
    // a clear, FLAC-specific message rather than producing a broken output.
    fs::write(&cover, b"fLaC\0\0\0\0\0\0\0\0\0\0\0\0").unwrap();
    write_payload(&payload, b"hello");

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "pw",
            "-o",
            dir.path().join("out.flac").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("flac"));
}

// ── F6: extract output flags are mutually exclusive ─────────────────────────

#[test]
fn extract_stdout_and_raw_are_mutually_exclusive() {
    // The clap conflict fires at parse time, before any file is touched.
    bin()
        .args([
            "extract",
            "anything.png",
            "--passphrase",
            "pw",
            "--stdout",
            "--raw",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn extract_output_and_raw_are_mutually_exclusive() {
    bin()
        .args([
            "extract",
            "anything.png",
            "--passphrase",
            "pw",
            "-o",
            "out.txt",
            "--raw",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

// ── F8: analyse --report json prints to stdout when no -o ───────────────────

#[test]
fn analyse_report_json_without_output_prints_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    write_png_cover(&cover, 64, 64);

    bin()
        .current_dir(dir.path())
        .args(["analyse", cover.to_str().unwrap(), "--report", "json"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("["));

    // It must NOT have written a report.json file to the working directory.
    assert!(
        !dir.path().join("report.json").exists(),
        "json report should go to stdout, not a file, when no -o is given"
    );
}
