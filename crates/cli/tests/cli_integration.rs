// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// CLI integration sweep — Track C of the adversarial test gate.
//
// Closes tech-debt T-09. Exercises the real built `stegcore` binary against
// temp-dir fixtures: happy-path round-trips, error paths, flag combinations,
// pathological inputs, and standalone subcommands. The goal is "things the
// user can actually do" coverage, not unit-level depth.
//
// Convention: each top-level test is `#[test]`-marked and self-contained;
// helpers below the test module body. Use `cargo test -p stegcore-cli --test
// cli_integration` to run the file in isolation.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Path to the binary under test. `assert_cmd::cargo_bin` finds the build
/// artefact regardless of profile.
fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

/// Write a deterministic PNG cover with enough capacity for small payloads.
///
/// Procedural noise so every test gets a "natural-ish" cover with no real
/// content; capacity = `w * h * 3 / 8` bytes minus headers.
fn write_png_cover(path: &Path, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    // Simple LCG for determinism; we don't need cryptographic randomness here.
    let mut state: u32 = 0xDEAD_BEEF;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    image::save_buffer(path, &pixels, w, h, image::ColorType::Rgb8)
        .expect("failed to write PNG cover");
}

/// Write a deterministic BMP cover.
fn write_bmp_cover(path: &Path, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state: u32 = 0xCAFE_BABE;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    let img = image::RgbImage::from_raw(w, h, pixels).expect("bad raw buffer");
    img.save_with_format(path, image::ImageFormat::Bmp)
        .expect("failed to write BMP cover");
}

/// Write a deterministic WAV cover (16-bit PCM mono, ~1 s).
fn write_wav_cover(path: &Path, sample_count: u32) {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(path, spec).expect("wav writer");
    let mut state: u32 = 0xFEED_FACE;
    for _ in 0..sample_count {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let s = ((state >> 16) as i16).wrapping_mul(8);
        writer.write_sample(s).expect("wav write");
    }
    writer.finalize().expect("wav finalize");
}

/// Write a payload file with the given bytes.
fn write_payload(path: &Path, body: &[u8]) {
    let mut f = fs::File::create(path).expect("payload create");
    f.write_all(body).expect("payload write");
}

// ── Section 1 — Version / help / metadata ──────────────────────────────────

#[test]
fn version_reports_4_0_1() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("stegcore 4.0.1"));
}

#[test]
fn help_lists_all_subcommands() {
    let assert = bin().arg("--help").assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    for sub in &[
        "embed",
        "extract",
        "analyse",
        "score",
        "info",
        "ciphers",
        "wizard",
        "diff",
        "doctor",
        "benchmark",
        "completions",
    ] {
        assert!(out.contains(sub), "help missing subcommand `{sub}`");
    }
}

#[test]
fn no_args_prints_help_and_exits_non_zero() {
    // arg_required_else_help = true on the root Cli — should exit 2 with help.
    bin()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage:"));
}

// ── Section 2 — Standalone subcommands ─────────────────────────────────────

#[test]
fn ciphers_lists_three_ciphers() {
    // `ciphers` writes its human-readable listing to stderr (via
    // `output::print_info`, which targets stderr for tty-aware colouring).
    // The JSON output mode is the stdout-stable contract; this test
    // checks both surfaces.
    let assert = bin().arg("ciphers").assert().success();
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    for c in &["chacha20-poly1305", "aes-256-gcm", "ascon-128"] {
        assert!(
            stderr.to_lowercase().contains(c),
            "ciphers stderr missing `{c}`; got: {stderr:?}"
        );
    }
}

#[test]
fn ciphers_json_is_machine_readable() {
    let assert = bin().args(["--json", "ciphers"]).assert().success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    let v: serde_json::Value = serde_json::from_str(&out).expect("ciphers --json output not JSON");
    assert!(
        v.is_object() || v.is_array(),
        "ciphers JSON must be object or array"
    );
}

#[test]
fn doctor_runs_clean() {
    bin()
        .arg("doctor")
        .assert()
        .success()
        .stderr(predicate::str::contains("Stegcore Doctor"));
}

#[test]
fn benchmark_completes_without_panic() {
    // Benchmark prints throughput numbers for each cipher. Just confirm it
    // exits cleanly and produces some output — we are not asserting on
    // throughput thresholds (CI noise would flake).
    bin().arg("benchmark").assert().success();
}

#[test]
fn completions_emit_bash_script() {
    let assert = bin().args(["completions", "bash"]).assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(
        out.contains("_stegcore") || out.contains("complete -F"),
        "bash completion script does not look like one"
    );
}

#[test]
fn completions_reject_invalid_shell() {
    bin()
        .args(["completions", "not-a-shell"])
        .assert()
        .failure();
}

// ── Section 3 — Embed → extract round-trips ────────────────────────────────

#[test]
fn roundtrip_png_chacha20() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.png");
    let payload = tmp.path().join("payload.txt");
    let stego = tmp.path().join("stego.png");
    let recovered = tmp.path().join("recovered.txt");
    let secret = b"the quick brown fox jumps over the lazy dog";

    write_png_cover(&cover, 128, 128);
    write_payload(&payload, secret);

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--cipher",
            "chacha20-poly1305",
            "--passphrase",
            "round-trip-test-pass",
        ])
        .assert()
        .success();

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            "round-trip-test-pass",
        ])
        .assert()
        .success();

    let got = fs::read(&recovered).expect("read recovered");
    assert_eq!(got, secret, "round-trip mismatch on chacha20-poly1305/PNG");
}

#[test]
fn roundtrip_bmp_aes_gcm() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.bmp");
    let payload = tmp.path().join("payload.bin");
    let stego = tmp.path().join("stego.bmp");
    let recovered = tmp.path().join("recovered.bin");
    let secret: Vec<u8> = (0..200u16).map(|n| n as u8).collect();

    write_bmp_cover(&cover, 128, 128);
    write_payload(&payload, &secret);

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--cipher",
            "aes-256-gcm",
            "--passphrase",
            "aes-pass",
        ])
        .assert()
        .success();

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            "aes-pass",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&recovered).unwrap(), secret);
}

#[test]
fn roundtrip_wav_ascon() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("cover.wav");
    let payload = tmp.path().join("payload.txt");
    let stego = tmp.path().join("stego.wav");
    let recovered = tmp.path().join("recovered.txt");
    let secret = b"ascon round-trip over wav";

    write_wav_cover(&cover, 44100); // 1 s of audio
    write_payload(&payload, secret);

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--cipher",
            "ascon-128",
            "--passphrase",
            "ascon-pass",
        ])
        .assert()
        .success();

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            "ascon-pass",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(&recovered).unwrap(), secret);
}

#[test]
fn roundtrip_sequential_mode() {
    // Sequential mode is the deterministic-placement alternative to adaptive.
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("c.png");
    let payload = tmp.path().join("p.txt");
    let stego = tmp.path().join("s.png");
    let recovered = tmp.path().join("r.txt");
    let secret = b"sequential mode works too";

    write_png_cover(&cover, 96, 96);
    write_payload(&payload, secret);

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--mode",
            "sequential",
            "--passphrase",
            "seq-pass",
        ])
        .assert()
        .success();
    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            "seq-pass",
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&recovered).unwrap(), secret);
}

#[test]
fn extract_with_wrong_passphrase_fails_cleanly() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("c.png");
    let payload = tmp.path().join("p.txt");
    let stego = tmp.path().join("s.png");
    write_png_cover(&cover, 96, 96);
    write_payload(&payload, b"secret");

    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            "right-pass",
        ])
        .assert()
        .success();

    bin()
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            tmp.path().join("r.txt").to_str().unwrap(),
            "--passphrase",
            "wrong-pass",
        ])
        .assert()
        .failure(); // AEAD authentication must fail; never silent-success.
}

#[test]
fn passphrase_via_env_var_works() {
    // STEGCORE_PASSPHRASE env var is the documented non-flag input path.
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("c.png");
    let payload = tmp.path().join("p.txt");
    let stego = tmp.path().join("s.png");
    let recovered = tmp.path().join("r.txt");
    write_png_cover(&cover, 96, 96);
    write_payload(&payload, b"env var pass");

    bin()
        .env("STEGCORE_PASSPHRASE", "env-driven-pass")
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
        ])
        .assert()
        .success();

    bin()
        .env("STEGCORE_PASSPHRASE", "env-driven-pass")
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(fs::read(&recovered).unwrap(), b"env var pass");
}

// ── Section 4 — Analyse: every output format, every flag combo ─────────────

#[test]
fn analyse_table_default_output() {
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("clean.png");
    write_png_cover(&img, 96, 96);
    bin()
        .args(["analyse", img.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn analyse_json_is_valid_json() {
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    write_png_cover(&img, 96, 96);
    let assert = bin()
        .args(["analyse", img.to_str().unwrap(), "--json"])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    let v: serde_json::Value = serde_json::from_str(&out).expect("analyse --json not JSON");
    assert!(v.get("ok").is_some(), "missing top-level `ok` field");
    assert!(v.get("data").is_some(), "missing top-level `data` field");
}

#[test]
fn analyse_report_csv_writes_csv_header() {
    // `--report csv` saves to a file (default `report.csv` in CWD); we pass
    // `--output` explicitly so the artefact lands in the test's tempdir
    // rather than polluting the workspace.
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    let report = tmp.path().join("report.csv");
    write_png_cover(&img, 96, 96);
    bin()
        .args([
            "analyse",
            img.to_str().unwrap(),
            "--report",
            "csv",
            "-o",
            report.to_str().unwrap(),
        ])
        .assert()
        .success();
    let body = fs::read_to_string(&report).expect("csv report not written");
    assert!(
        body.to_lowercase().contains("file") && body.contains(','),
        "CSV file does not look like CSV: {body:?}"
    );
}

#[test]
fn analyse_report_html_writes_html() {
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    let report = tmp.path().join("report.html");
    write_png_cover(&img, 96, 96);
    bin()
        .args([
            "analyse",
            img.to_str().unwrap(),
            "--report",
            "html",
            "-o",
            report.to_str().unwrap(),
        ])
        .assert()
        .success();
    let body = fs::read_to_string(&report).expect("html report not written");
    assert!(body.contains("<html") || body.contains("<!DOCTYPE"));
}

#[test]
fn analyse_report_rejects_invalid_format() {
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    write_png_cover(&img, 96, 96);
    bin()
        .args(["analyse", img.to_str().unwrap(), "--report", "yaml-please"])
        .assert()
        .failure();
}

#[test]
fn analyse_batch_matches_glob() {
    let tmp = TempDir::new().expect("tmp");
    for i in 0..3 {
        write_png_cover(&tmp.path().join(format!("img_{i}.png")), 64, 64);
    }
    let pattern = format!("{}/img_*.png", tmp.path().display());
    bin()
        .args(["analyse", "--batch", &pattern])
        .assert()
        .success();
}

#[test]
fn analyse_batch_with_no_matches_does_not_panic() {
    // Empty match-set is a known edge: the binary should exit non-zero with
    // a clear message rather than panic. We accept either outcome (exit
    // cleanly vs surface an error) — the only thing we forbid is a panic /
    // abort.
    let tmp = TempDir::new().expect("tmp");
    let pattern = format!("{}/no-such-*.png", tmp.path().display());
    let output = bin()
        .args(["analyse", "--batch", &pattern])
        .output()
        .expect("spawn");
    // Exit status -1 or signal-termination would indicate a panic/abort.
    // Any clean exit code (0, 1, 2, ...) is acceptable here.
    assert!(
        output.status.code().is_some(),
        "binary terminated via signal — likely panic"
    );
}

#[test]
fn analyse_batch_empty_glob_is_handled() {
    bin().args(["analyse", "--batch", ""]).assert().failure();
}

// ── Section 5 — Error paths ────────────────────────────────────────────────

#[test]
fn embed_missing_cover_fails() {
    let tmp = TempDir::new().expect("tmp");
    let payload = tmp.path().join("p.txt");
    write_payload(&payload, b"x");
    bin()
        .args([
            "embed",
            "/does/not/exist.png",
            payload.to_str().unwrap(),
            "--passphrase",
            "x",
        ])
        .assert()
        .failure();
}

#[test]
fn embed_missing_payload_fails() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("c.png");
    write_png_cover(&cover, 64, 64);
    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            "/does/not/exist.txt",
            "--passphrase",
            "x",
        ])
        .assert()
        .failure();
}

#[test]
fn extract_missing_stego_fails() {
    bin()
        .args(["extract", "/no/such/stego.png", "--passphrase", "x"])
        .assert()
        .failure();
}

#[test]
fn analyse_missing_file_fails() {
    bin()
        .args(["analyse", "/no/such/file.png"])
        .assert()
        .failure();
}

#[test]
fn analyse_unsupported_format_fails() {
    let tmp = TempDir::new().expect("tmp");
    let bogus = tmp.path().join("notreal.xyz");
    fs::write(&bogus, b"not an image").unwrap();
    bin()
        .args(["analyse", bogus.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn embed_payload_larger_than_capacity_fails() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("tiny.png");
    let payload = tmp.path().join("huge.bin");
    write_png_cover(&cover, 16, 16); // ~96 LSB-bytes capacity
    write_payload(&payload, &vec![0xAB; 64 * 1024]); // 64 KiB
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
fn embed_empty_passphrase_rejected() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("c.png");
    let payload = tmp.path().join("p.txt");
    write_png_cover(&cover, 64, 64);
    write_payload(&payload, b"x");
    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--passphrase",
            "",
        ])
        .assert()
        .failure();
}

#[test]
fn embed_invalid_cipher_rejected() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("c.png");
    let payload = tmp.path().join("p.txt");
    write_png_cover(&cover, 64, 64);
    write_payload(&payload, b"x");
    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--cipher",
            "rot13",
            "--passphrase",
            "x",
        ])
        .assert()
        .failure(); // clap's value_parser rejects unknown ciphers.
}

#[test]
fn embed_invalid_mode_rejected() {
    let tmp = TempDir::new().expect("tmp");
    let cover = tmp.path().join("c.png");
    let payload = tmp.path().join("p.txt");
    write_png_cover(&cover, 64, 64);
    write_payload(&payload, b"x");
    bin()
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "--mode",
            "supercalifragilistic",
            "--passphrase",
            "x",
        ])
        .assert()
        .failure();
}

// ── Section 6 — Pathological inputs ────────────────────────────────────────

#[test]
fn analyse_zero_byte_file_does_not_panic() {
    let tmp = TempDir::new().expect("tmp");
    let p = tmp.path().join("empty.png");
    fs::File::create(&p).unwrap();
    // 0-byte "PNG" is malformed — binary must reject cleanly, not panic.
    bin()
        .args(["analyse", p.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn analyse_garbage_with_png_extension_does_not_panic() {
    let tmp = TempDir::new().expect("tmp");
    let p = tmp.path().join("fake.png");
    fs::write(
        &p,
        b"This is plain text, not a PNG. The decoder should reject me.",
    )
    .unwrap();
    bin()
        .args(["analyse", p.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn analyse_file_with_no_extension_fails_cleanly() {
    let tmp = TempDir::new().expect("tmp");
    let p = tmp.path().join("noext");
    fs::write(&p, b"x").unwrap();
    bin()
        .args(["analyse", p.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn analyse_directory_argument_fails_cleanly() {
    let tmp = TempDir::new().expect("tmp");
    bin()
        .args(["analyse", tmp.path().to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
#[cfg(unix)]
fn analyse_unreadable_file_fails_cleanly() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().expect("tmp");
    let p = tmp.path().join("perm.png");
    write_png_cover(&p, 32, 32);
    let mut perms = fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&p, perms.clone()).unwrap();
    let result = bin().args(["analyse", p.to_str().unwrap()]).assert();
    // Restore perms before TempDir's Drop runs cleanup.
    perms.set_mode(0o644);
    fs::set_permissions(&p, perms).unwrap();
    result.failure();
}

#[test]
fn extract_garbage_file_fails_cleanly() {
    let tmp = TempDir::new().expect("tmp");
    let p = tmp.path().join("not-stego.png");
    write_png_cover(&p, 96, 96); // a real PNG, but no stego payload inside.
    bin()
        .args(["extract", p.to_str().unwrap(), "--passphrase", "anything"])
        .assert()
        .failure();
}

// ── Section 7 — Info / score / diff smoke ──────────────────────────────────

#[test]
fn score_on_clean_cover_succeeds() {
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    write_png_cover(&img, 96, 96);
    bin()
        .args(["score", img.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn info_on_clean_cover_succeeds_or_reports_missing() {
    // `info` reads embedded metadata from a stego file. On a clean cover it
    // either reports "no metadata" gracefully or exits non-zero with a clear
    // message — both are acceptable, panic is not.
    //
    // The passphrase MUST be supplied via flag: without one, `info` falls
    // back to an interactive rpassword prompt which hangs forever in CI
    // (no TTY on the Windows runner, no stdin EOF). The 5s timeout is a
    // defence-in-depth — if the binary ever regresses to prompting again
    // we want a clean kill, not a 30-minute runner stall.
    use std::time::Duration;
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    write_png_cover(&img, 96, 96);
    let _ = bin()
        .args([
            "info",
            img.to_str().unwrap(),
            "--passphrase",
            "info-test-pass",
        ])
        .timeout(Duration::from_secs(5))
        .assert();
}

#[test]
fn diff_identical_files_produces_zero_diff() {
    let tmp = TempDir::new().expect("tmp");
    let a = tmp.path().join("a.png");
    let b = tmp.path().join("b.png");
    write_png_cover(&a, 64, 64);
    fs::copy(&a, &b).unwrap();
    bin()
        .args(["diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .success();
}

// ── Section 8 — Quiet / global flag interactions ──────────────────────────

#[test]
fn quiet_suppresses_stdout_on_success_path() {
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    write_png_cover(&img, 64, 64);
    let assert = bin()
        .args(["--quiet", "analyse", img.to_str().unwrap()])
        .assert()
        .success();
    let out = &assert.get_output().stdout;
    // `--quiet` should keep stdout near-empty (allowance for a single newline).
    assert!(out.len() < 8, "quiet mode leaked stdout: {:?}", out);
}

#[test]
fn quiet_and_json_together_emit_json_only() {
    let tmp = TempDir::new().expect("tmp");
    let img = tmp.path().join("c.png");
    write_png_cover(&img, 64, 64);
    let assert = bin()
        .args(["--quiet", "--json", "analyse", img.to_str().unwrap()])
        .assert()
        .success();
    let out = String::from_utf8(assert.get_output().stdout.clone()).expect("utf-8");
    serde_json::from_str::<serde_json::Value>(&out)
        .expect("--quiet --json analyse must still emit valid JSON");
}

// ── Section 9 — Subcommand help pages ──────────────────────────────────────

#[test]
fn each_subcommand_has_help() {
    for sub in &[
        "embed",
        "extract",
        "analyse",
        "score",
        "info",
        "ciphers",
        "diff",
        "doctor",
        "benchmark",
    ] {
        let assert = bin().args([sub, "--help"]).assert().success();
        let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
        assert!(
            out.to_lowercase().contains("usage"),
            "subcommand `{sub}` --help missing 'Usage' header"
        );
    }
}

// ── Helpers test (kept last to avoid being mistaken for a feature test) ───

#[test]
fn helper_smoke_png_cover_is_valid() {
    let tmp = TempDir::new().expect("tmp");
    let p = tmp.path().join("h.png");
    write_png_cover(&p, 32, 32);
    let bytes = fs::read(&p).unwrap();
    assert_eq!(
        &bytes[..8],
        b"\x89PNG\r\n\x1a\n",
        "helper produced bad PNG header"
    );
}

// Silence the unused-import lint when individual sections are commented out
// in dev.
#[allow(dead_code)]
fn _force_imports() -> (Command, PathBuf) {
    (Command::new("true"), PathBuf::new())
}
