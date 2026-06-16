// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Watermark subcommand integration sweep.
//
// Drives the real built `stegcore watermark` binary end to end: the consent
// gate (refused without authorisation, granted once and then persistent and
// shared), the write/verify round-trip, and the ungated read-back path.
//
// Every invocation points STEGCORE_CONFIG_DIR at a per-test temp directory so
// the consent marker never touches the real `~/.config/stegcore` and tests stay
// order-independent.

use std::path::Path;

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use tempfile::TempDir;

fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

/// Deterministic noisy PNG cover with capacity for a small mark.
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

const PASS: &str = "watermark-integration-pass";

#[test]
fn watermark_refused_without_authorisation() {
    let cfg = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let cover = work.path().join("cover.png");
    write_png_cover(&cover, 96, 96);

    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", PASS)
        .arg("watermark")
        .arg(&cover)
        .arg("--text")
        .arg("owner: Acme")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("--i-am-authorised"));

    // No marker was written, so consent was not silently granted.
    assert!(!cfg.path().join(".watermarking_consent").exists());
}

#[test]
fn watermark_granted_then_persists_and_round_trips() {
    let cfg = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let cover = work.path().join("cover.png");
    write_png_cover(&cover, 128, 128);
    let marked = work.path().join("marked.png");

    // First write must carry --i-am-authorised; it records consent.
    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", PASS)
        .arg("watermark")
        .arg(&cover)
        .arg("--text")
        .arg("owner: Acme Corp")
        .arg("--output")
        .arg(&marked)
        .arg("--i-am-authorised")
        .assert()
        .success();
    assert!(marked.exists());
    assert!(cfg.path().join(".watermarking_consent").exists());

    // Verify reads the mark back without needing the flag.
    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", PASS)
        .arg("watermark")
        .arg(&marked)
        .arg("--verify")
        .assert()
        .success()
        .stdout(predicate::str::contains("owner: Acme Corp"));

    // A second write needs no flag now that consent is recorded.
    let marked2 = work.path().join("marked2.png");
    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", PASS)
        .arg("watermark")
        .arg(&cover)
        .arg("--text")
        .arg("ref: INV-2026-002")
        .arg("--output")
        .arg(&marked2)
        .assert()
        .success();
    assert!(marked2.exists());
}

#[test]
fn verify_with_wrong_passphrase_fails() {
    let cfg = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let cover = work.path().join("cover.png");
    write_png_cover(&cover, 96, 96);
    let marked = work.path().join("marked.png");

    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", PASS)
        .arg("watermark")
        .arg(&cover)
        .arg("--text")
        .arg("mark")
        .arg("--output")
        .arg(&marked)
        .arg("--i-am-authorised")
        .assert()
        .success();

    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", "definitely-wrong")
        .arg("watermark")
        .arg(&marked)
        .arg("--verify")
        .assert()
        .failure();
}

#[test]
fn watermark_missing_file_reports_not_found() {
    let cfg = TempDir::new().unwrap();
    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", PASS)
        .arg("watermark")
        .arg("/tmp/stegcore-no-such-cover-xyz.png")
        .arg("--text")
        .arg("mark")
        .arg("--i-am-authorised")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("No such")));
}

#[test]
fn json_output_on_successful_watermark() {
    let cfg = TempDir::new().unwrap();
    let work = TempDir::new().unwrap();
    let cover = work.path().join("cover.png");
    write_png_cover(&cover, 96, 96);
    let marked = work.path().join("marked.png");

    bin()
        .env("STEGCORE_CONFIG_DIR", cfg.path())
        .env("STEGCORE_PASSPHRASE", PASS)
        .arg("--json")
        .arg("watermark")
        .arg(&cover)
        .arg("--text")
        .arg("mark")
        .arg("--output")
        .arg(&marked)
        .arg("--i-am-authorised")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"output\""));
}
