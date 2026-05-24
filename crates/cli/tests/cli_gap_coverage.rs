// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Gap-fill integration tests for the v4.0.1 coverage gate.
//!
//! `cli_integration.rs` covers happy-path round-trips and the obvious error
//! shapes. This file fills in the branches that file did not exercise:
//! deniable embed flows, `--export-key`, JSON output shapes for each
//! command, `extract --stdout` / `--raw` / `--key-file`, and the info /
//! score success paths that need an embedded fixture to run against.
//!
//! Conventions match `cli_integration.rs` — small covers (64×64 PNG /
//! 128 KB BMP) to keep Argon2 KDF cycles cheap, one passphrase per test,
//! every assertion documented with what it proves.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use tempfile::TempDir;

/// Parse the JSON envelope emitted by the CLI. `emit_json` writes the only
/// stdout content on the JSON path (status prints go to stderr), so the
/// whole stdout, trimmed, is a single JSON document (pretty-printed or
/// not). Find the first `{` to skip any incidental BOM or leading whitespace.
fn parse_json_envelope(stdout: &str) -> serde_json::Value {
    let start = stdout
        .find('{')
        .expect("stdout should contain a JSON object opening brace");
    let trimmed = stdout[start..].trim_end();
    serde_json::from_str(trimmed).expect("JSON envelope should parse")
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

/// Deterministic noise PNG cover.
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

/// Embed a fixture file so the extract / info / score variants below have
/// something to chew on. Returns the path to the stego file.
fn embed_fixture(tmp: &Path, payload: &[u8], passphrase: &str) -> PathBuf {
    let cover = tmp.join("fixture_cover.png");
    let payload_path = tmp.join("fixture_payload.bin");
    let stego = tmp.join("fixture_stego.png");
    write_png_cover(&cover, 128, 128);
    fs::write(&payload_path, payload).expect("write fixture payload");
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

// ── embed: deniable flows ──────────────────────────────────────────────────

#[test]
fn embed_deniable_without_decoy_flag_rejected_by_clap() {
    // clap's `requires = "deniable"` on `--decoy` doesn't fire here — the
    // missing piece is `--deniable` without `--decoy`. Our hand-rolled check
    // returns "--deniable requires --decoy <file>".
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let payload = tmp.path().join("payload.txt");
    write_png_cover(&cover, 64, 64);
    fs::write(&payload, b"top secret").unwrap();

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "pw",
            "--deniable",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires --decoy"));
}

#[test]
fn embed_deniable_with_missing_decoy_file_fails_cleanly() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let payload = tmp.path().join("payload.txt");
    write_png_cover(&cover, 64, 64);
    fs::write(&payload, b"real message").unwrap();

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "real-pw",
            "--deniable",
            "--decoy",
            "/tmp/does-not-exist.txt",
            "--decoy-passphrase",
            "decoy-pw",
        ])
        .assert()
        .failure()
        .code(3); // FileNotFound exits with 3
}

#[test]
fn embed_deniable_succeeds_with_both_payloads() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let real = tmp.path().join("real.txt");
    let decoy = tmp.path().join("decoy.txt");
    let stego = tmp.path().join("stego.png");
    write_png_cover(&cover, 256, 256);
    fs::write(&real, b"the launch codes are 0000").unwrap();
    fs::write(&decoy, b"recipe for jam tarts").unwrap();

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            real.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "real-pass",
            "--deniable",
            "--decoy",
            decoy.to_str().unwrap(),
            "--decoy-passphrase",
            "decoy-pass",
            "--export-key",
        ])
        .assert()
        .success();

    // Stego file present; key files written because --export-key was set.
    assert!(stego.exists(), "stego file should have been written");
    let real_kf = stego.with_extension("real.json");
    let decoy_kf = stego.with_extension("decoy.json");
    assert!(real_kf.exists(), "real key file should be present");
    assert!(decoy_kf.exists(), "decoy key file should be present");

    // Deniable extracts need the corresponding key file: each key file
    // points to a different slot. Real key + real pass → real payload.
    let recovered_real = tmp.path().join("recovered_real.txt");
    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--key-file",
            real_kf.to_str().unwrap(),
            "-o",
            recovered_real.to_str().unwrap(),
            "--passphrase",
            "real-pass",
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(&recovered_real).unwrap(),
        b"the launch codes are 0000"
    );

    // Decoy key + decoy pass → decoy payload.
    let recovered_decoy = tmp.path().join("recovered_decoy.txt");
    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--key-file",
            decoy_kf.to_str().unwrap(),
            "-o",
            recovered_decoy.to_str().unwrap(),
            "--passphrase",
            "decoy-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&recovered_decoy).unwrap(), b"recipe for jam tarts");
}

#[test]
fn embed_deniable_empty_decoy_file_rejected() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let real = tmp.path().join("real.txt");
    let decoy = tmp.path().join("decoy.txt"); // intentionally empty
    write_png_cover(&cover, 64, 64);
    fs::write(&real, b"real").unwrap();
    fs::write(&decoy, b"").unwrap();

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            real.to_str().unwrap(),
            "--passphrase",
            "pw",
            "--deniable",
            "--decoy",
            decoy.to_str().unwrap(),
            "--decoy-passphrase",
            "dp",
        ])
        .assert()
        .failure();
}

#[test]
fn embed_with_export_key_writes_key_file() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let payload = tmp.path().join("payload.txt");
    let stego = tmp.path().join("stego.png");
    write_png_cover(&cover, 128, 128);
    fs::write(&payload, b"hello").unwrap();

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "kf-test",
            "--export-key",
            "--mode",
            "sequential",
        ])
        .assert()
        .success();

    // Sequential mode emits a key file alongside the stego output.
    let kf = stego.with_extension("json");
    assert!(kf.exists(), "key file expected at {}", kf.display());
}

#[test]
fn embed_json_success_emits_machine_readable_output() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let payload = tmp.path().join("payload.txt");
    let stego = tmp.path().join("stego.png");
    write_png_cover(&cover, 128, 128);
    fs::write(&payload, b"json embed").unwrap();

    let out = bin()
        .args([
            "--json",
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "json-pass",
        ])
        .output()
        .expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["ok"], serde_json::json!(true));
    assert!(v["data"]["output"].as_str().unwrap().ends_with("stego.png"));
}

#[test]
fn embed_json_failure_for_missing_cover_emits_error_envelope() {
    let out = bin()
        .args([
            "--json",
            "embed",
            "/tmp/stegcore-cli-gap-missing.png",
            "/tmp/stegcore-cli-gap-missing-payload.txt",
            "--passphrase",
            "p",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["ok"], serde_json::json!(false));
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("not found")
            || v["error"]
                .as_str()
                .unwrap()
                .to_lowercase()
                .contains("missing")
    );
}

#[test]
fn embed_payload_from_stdin_dash_works() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let stego = tmp.path().join("stego.png");
    let recovered = tmp.path().join("recovered.bin");
    write_png_cover(&cover, 128, 128);

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            "-", // payload from stdin
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "stdin-pass",
        ])
        .write_stdin("piped secret bytes\n")
        .assert()
        .success();

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            "stdin-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&recovered).unwrap(), b"piped secret bytes\n");
}

// ── extract: alternative output modes ──────────────────────────────────────

#[test]
fn extract_stdout_with_utf8_payload_prints_text() {
    let tmp = TempDir::new().expect("tmp");
    let stego = embed_fixture(tmp.path(), b"plain utf8 text", "stdout-test");

    let out = bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--stdout",
            "--passphrase",
            "stdout-test",
        ])
        .output()
        .expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("plain utf8 text"));
}

#[test]
fn extract_stdout_with_binary_payload_warns_and_exits_one() {
    let tmp = TempDir::new().expect("tmp");
    // Non-UTF-8 bytes — invalid lone continuation byte.
    let bin_payload: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x80, 0x90];
    let stego = embed_fixture(tmp.path(), &bin_payload, "bin-test");

    let out = bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--stdout",
            "--passphrase",
            "bin-test",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("not valid UTF-8") || stderr.contains("binary"));
}

#[test]
fn extract_raw_writes_bytes_to_stdout() {
    let tmp = TempDir::new().expect("tmp");
    let payload = b"\xDE\xAD\xBE\xEF\x00\x01\x02\x03raw bytes";
    let stego = embed_fixture(tmp.path(), payload, "raw-test");

    let out = bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--raw",
            "--passphrase",
            "raw-test",
        ])
        .output()
        .expect("run");
    assert!(out.status.success());
    assert_eq!(out.stdout, payload);
}

#[test]
fn extract_json_success_envelope() {
    let tmp = TempDir::new().expect("tmp");
    let stego = embed_fixture(tmp.path(), b"json extract test", "json-extract");
    let recovered = tmp.path().join("recovered.txt");

    let out = bin()
        .args([
            "--json",
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            "json-extract",
        ])
        .output()
        .expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["ok"], serde_json::json!(true));
    assert_eq!(v["data"]["bytes"], serde_json::json!(17));
}

#[test]
fn extract_with_missing_key_file_fails_with_three() {
    let tmp = TempDir::new().expect("tmp");
    let stego = embed_fixture(tmp.path(), b"x", "kf-missing");

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--key-file",
            "/tmp/stegcore-cli-gap-no-keyfile.json",
            "--passphrase",
            "kf-missing",
        ])
        .assert()
        .failure()
        .code(3);
}

#[test]
fn extract_with_invalid_key_file_json_fails() {
    let tmp = TempDir::new().expect("tmp");
    let stego = embed_fixture(tmp.path(), b"x", "kf-bad");
    let bad_kf = tmp.path().join("bad.json");
    fs::write(&bad_kf, b"{not even close to a key file}").unwrap();

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "--key-file",
            bad_kf.to_str().unwrap(),
            "--passphrase",
            "kf-bad",
        ])
        .assert()
        .failure();
}

// ── info: success + JSON + error ───────────────────────────────────────────

#[test]
fn info_on_embedded_file_succeeds() {
    let tmp = TempDir::new().expect("tmp");
    let stego = embed_fixture(tmp.path(), b"meta", "info-test");

    bin()
        .args(["info", stego.to_str().unwrap(), "--passphrase", "info-test"])
        .assert()
        .success();
}

#[test]
fn info_json_success_envelope() {
    let tmp = TempDir::new().expect("tmp");
    let stego = embed_fixture(tmp.path(), b"meta-json", "info-json");

    let out = bin()
        .args([
            "--json",
            "info",
            stego.to_str().unwrap(),
            "--passphrase",
            "info-json",
        ])
        .output()
        .expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["ok"], serde_json::json!(true));
}

#[test]
fn info_missing_file_fails_with_three() {
    bin()
        .args([
            "info",
            "/tmp/stegcore-cli-gap-info-missing.png",
            "--passphrase",
            "x",
        ])
        .assert()
        .failure()
        .code(3);
}

#[test]
fn info_with_wrong_passphrase_fails() {
    let tmp = TempDir::new().expect("tmp");
    let stego = embed_fixture(tmp.path(), b"meta", "info-right");

    bin()
        .args([
            "info",
            stego.to_str().unwrap(),
            "--passphrase",
            "info-wrong",
        ])
        .assert()
        .failure();
}

// ── score: JSON + error paths ──────────────────────────────────────────────

#[test]
fn score_json_emits_envelope_with_percent_and_label() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    write_png_cover(&cover, 128, 128);

    let out = bin()
        .args(["--json", "score", cover.to_str().unwrap()])
        .output()
        .expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["ok"], serde_json::json!(true));
    // Score range + label invariants.
    let pct = v["data"]["percent"].as_u64().unwrap();
    assert!(pct <= 100);
    assert!(v["data"]["label"].is_string());
}

#[test]
fn score_missing_file_fails_with_three() {
    bin()
        .args(["score", "/tmp/stegcore-cli-gap-score-missing.png"])
        .assert()
        .failure()
        .code(3);
}

#[test]
fn score_unsupported_format_fails_cleanly() {
    let tmp = TempDir::new().expect("tmp");
    let p = tmp.path().join("not_an_image.txt");
    fs::write(&p, b"this is plain text, not a cover").unwrap();
    bin()
        .args(["score", p.to_str().unwrap()])
        .assert()
        .failure();
}

// ── verse / completions / doctor / benchmark: bare invocations ─────────────

#[test]
fn verse_default_prints_text() {
    bin().args(["verse"]).assert().success();
}

#[test]
fn verse_json_emits_text_and_reference() {
    let out = bin().args(["--json", "verse"]).output().expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(v["text"].is_string());
    assert!(v["reference"].is_string());
}

#[test]
fn completions_for_zsh_emit_completion_script() {
    bin()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("#compdef"));
}

#[test]
fn completions_for_fish_emit_completion_script() {
    bin()
        .args(["completions", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete -c stegcore"));
}

#[test]
fn completions_for_powershell_emit_completion_script() {
    bin().args(["completions", "powershell"]).assert().success();
}
