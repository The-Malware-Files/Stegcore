// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Coverage-fill integration tests for the embed / extract command modules.
//!
//! The existing suites exercise the failure and edge branches well; these
//! target the success emission paths that were still uncovered: structured
//! JSON success output, the deniable-embed success path, and the
//! stdout / raw extraction sinks. Driving the real binary means
//! cargo-llvm-cov attributes the coverage to the command modules.

use std::fs;
use std::path::Path;

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use tempfile::TempDir;

fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

/// Deterministic noise PNG cover (varied texture so it scores as usable).
fn write_png_cover(path: &Path, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state: u32 = 0xDEAD_BEEF;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    image::save_buffer(path, &pixels, w, h, image::ColorType::Rgb8)
        .expect("failed to write PNG cover");
}

/// Embed a payload and return the stego path.
fn embed(tmp: &Path, payload: &[u8], passphrase: &str) -> std::path::PathBuf {
    let cover = tmp.join("cover.png");
    let payload_path = tmp.join("payload.bin");
    let stego = tmp.join("stego.png");
    write_png_cover(&cover, 128, 128);
    fs::write(&payload_path, payload).unwrap();
    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload_path.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .assert()
        .success();
    stego
}

// ── embed: success emission paths ──────────────────────────────────────────

#[test]
fn embed_json_success_emits_structured_output() {
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("cover.png");
    let payload = tmp.path().join("payload.bin");
    let stego = tmp.path().join("stego.png");
    write_png_cover(&cover, 128, 128);
    fs::write(&payload, b"structured json embed payload").unwrap();

    bin()
        .args([
            "--json",
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "pw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"success\"").or(predicate::str::contains("stego")));
    assert!(stego.exists());
}

#[test]
fn embed_json_missing_cover_emits_failure() {
    let tmp = TempDir::new().unwrap();
    let payload = tmp.path().join("payload.bin");
    let stego = tmp.path().join("stego.png");
    fs::write(&payload, b"x").unwrap();

    bin()
        .args([
            "--json",
            "embed",
            "/tmp/this-cover-does-not-exist.png",
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "pw",
        ])
        .assert()
        .failure();
}

#[test]
fn embed_deniable_success_exports_both_key_files() {
    // The deniable partition half is randomised, so plain extraction of a
    // half is non-deterministic; this test covers the deniable embed success
    // emission and asserts both key files are exported (the deterministic,
    // observable outcome).
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("cover.png");
    let real = tmp.path().join("real.bin");
    let decoy = tmp.path().join("decoy.bin");
    let stego = tmp.path().join("stego.png");
    write_png_cover(&cover, 160, 160);
    fs::write(&real, b"the real deniable message").unwrap();
    fs::write(&decoy, b"a harmless decoy").unwrap();

    bin()
        .args([
            "--json",
            "embed",
            cover.to_str().unwrap(),
            real.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "real-pw",
            "--deniable",
            "--decoy",
            decoy.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-pw",
            "--export-key",
        ])
        .assert()
        .success();
    assert!(stego.exists());

    // Deniable + export writes a .real.json and a .decoy.json key file.
    let exported: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".json"))
        .collect();
    assert!(
        exported.iter().any(|n| n.contains("real")),
        "real key file exported, got {exported:?}"
    );
    assert!(
        exported.iter().any(|n| n.contains("decoy")),
        "decoy key file exported, got {exported:?}"
    );
}

// ── extract: success sinks ──────────────────────────────────────────────────

#[test]
fn extract_json_success_emits_structured_output() {
    let tmp = TempDir::new().unwrap();
    let stego = embed(tmp.path(), b"json extract payload", "pw");
    let out = tmp.path().join("out.bin");

    bin()
        .args([
            "--json",
            "extract",
            stego.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--passphrase",
            "pw",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&out).unwrap(), b"json extract payload");
}

#[test]
fn extract_stdout_prints_text_payload() {
    let tmp = TempDir::new().unwrap();
    let stego = embed(tmp.path(), b"hello from stdout", "pw");

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--stdout",
            "--passphrase",
            "pw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello from stdout"));
}

#[test]
fn extract_raw_writes_bytes_to_stdout() {
    let tmp = TempDir::new().unwrap();
    let stego = embed(tmp.path(), b"raw-bytes-payload", "pw");

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--raw",
            "--passphrase",
            "pw",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("raw-bytes-payload"));
}

#[test]
fn extract_json_wrong_passphrase_emits_failure() {
    let tmp = TempDir::new().unwrap();
    let stego = embed(tmp.path(), b"secret", "right-pw");
    let out = tmp.path().join("out.bin");

    bin()
        .args([
            "--json",
            "extract",
            stego.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--passphrase",
            "wrong-pw",
        ])
        .assert()
        .failure();
    assert!(!out.exists(), "no output on a failed extract");
}

#[test]
fn extract_missing_key_file_fails_cleanly() {
    let tmp = TempDir::new().unwrap();
    let stego = embed(tmp.path(), b"secret", "pw");
    let out = tmp.path().join("out.bin");

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--key-file",
            "/tmp/no-such-key-file.json",
            "-o",
            out.to_str().unwrap(),
            "--passphrase",
            "pw",
        ])
        .assert()
        .failure()
        .code(3); // FileNotFound
}
