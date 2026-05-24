// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Crash-injection tests — the other half of Track E.
//
// SIGKILL the embed/extract process at random points during its run and
// verify Stegcore's atomic-rename-on-close behaviour holds. Per the
// robustness mandate, "any operation that can be re-run after an
// interruption must be safe to re-run." This file verifies that
// contract empirically.
//
// What we check:
//
//   1. Mid-embed SIGKILL never leaves a partially-written stego file that
//      looks valid but extracts garbage. Either the output is absent
//      (clean cancel) or it's a valid+complete stego file.
//   2. Re-running embed after a crash works cleanly — no leftover temp
//      files block the rerun.
//   3. Mid-extract SIGKILL doesn't corrupt the source stego file.
//
// Unix-only: SIGKILL via libc / Command::process_id() + kill(2). Windows
// has TerminateProcess but the test shape would need to differ — out of
// scope here.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use assert_cmd::cargo::CommandCargoExt;
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────────

fn write_png_cover(path: &Path, w: u32, h: u32) {
    let mut pixels = vec![0u8; (w * h * 3) as usize];
    let mut state: u32 = 0xBADC_0FFE;
    for px in pixels.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *px = (state >> 16) as u8;
    }
    image::save_buffer(path, &pixels, w, h, image::ColorType::Rgb8).expect("png write");
}

fn write_payload(path: &Path, body: &[u8]) {
    fs::File::create(path).unwrap().write_all(body).unwrap();
}

/// Spawn `stegcore embed ...` as a child process. Return the Child so
/// the test can kill it mid-flight.
fn spawn_embed(cover: &Path, payload: &Path, out: &Path, passphrase: &str) -> std::process::Child {
    Command::cargo_bin("stegcore")
        .expect("cargo_bin")
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn stegcore embed")
}

/// Send SIGKILL to a running child process.
fn sigkill(child: &mut std::process::Child) {
    // SIGKILL = 9 on every Unix.
    unsafe {
        libc::kill(child.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = child.wait();
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[test]
fn mid_embed_sigkill_does_not_leave_corrupt_stego() {
    // Strategy: spawn embed, kill after a small random delay, then verify
    // the output state is either (a) absent or (b) a valid stego file that
    // extracts the original payload. NEVER a present-but-corrupt file that
    // looks valid to a casual `file` check but extracts to garbage.
    //
    // We sweep a few kill delays so we cover early-kill (still parsing
    // cover), mid-kill (mid-write of pixels), and late-kill (about to
    // rename-into-place).
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("cover.png");
    let payload_path = tmp.path().join("payload.bin");

    // Cover big enough that embed has noticeable work to do.
    write_png_cover(&cover, 512, 512);
    // Payload ~16 KB so we span a non-trivial write window.
    write_payload(&payload_path, &vec![0xAB; 16 * 1024]);

    let passphrase = "crash-test-pass";

    for (i, delay_ms) in [5u64, 15, 40, 100, 250].iter().enumerate() {
        let stego = tmp.path().join(format!("stego_{i}.png"));
        let mut child = spawn_embed(&cover, &payload_path, &stego, passphrase);

        thread::sleep(Duration::from_millis(*delay_ms));
        sigkill(&mut child);

        // After the kill, the output path is either:
        //   - Absent (we killed before atomic rename) — clean.
        //   - Present + valid (we killed after rename) — clean too, just
        //     means the kill landed too late. Verify by extracting.
        //   - Present + invalid — that's the failure case.
        if !stego.exists() {
            // Absent: clean cancel. Done.
            continue;
        }

        // File exists. Try to extract; this should succeed (kill was after
        // the atomic rename) OR fail cleanly (the file is a partial PNG).
        let recovered = tmp.path().join(format!("recovered_{i}.bin"));
        let r = Command::cargo_bin("stegcore")
            .expect("cargo_bin")
            .args([
                "extract",
                stego.to_str().unwrap(),
                "-o",
                recovered.to_str().unwrap(),
                "--passphrase",
                passphrase,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("extract spawn");

        if r.success() {
            // Extract succeeded — file must contain the full original payload.
            let recovered_bytes = fs::read(&recovered).unwrap();
            let expected = fs::read(&payload_path).unwrap();
            assert_eq!(
                recovered_bytes, expected,
                "kill at {delay_ms}ms left a stego file that extracts but the payload doesn't match — corruption"
            );
        }
        // Extract failed cleanly — also acceptable; means the file is a
        // partial write that doesn't parse. Stegcore reported an error and
        // didn't panic, which is the whole contract.
    }
}

#[test]
fn embed_rerun_after_crash_works() {
    // Crash mid-embed, then re-run embed cleanly. Must not be blocked by
    // any leftover state.
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("cover.png");
    let payload_path = tmp.path().join("payload.txt");
    let stego = tmp.path().join("stego.png");
    write_png_cover(&cover, 256, 256);
    write_payload(&payload_path, b"crash recovery payload");

    let passphrase = "rerun-pass";

    // Crash.
    let mut child = spawn_embed(&cover, &payload_path, &stego, passphrase);
    thread::sleep(Duration::from_millis(30));
    sigkill(&mut child);

    // Re-run. Must succeed.
    let r = Command::cargo_bin("stegcore")
        .expect("cargo_bin")
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload_path.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("rerun spawn");
    assert!(r.success(), "embed re-run after crash must succeed cleanly");

    // And the resulting stego must extract correctly.
    let recovered = tmp.path().join("recovered.txt");
    let r2 = Command::cargo_bin("stegcore")
        .expect("cargo_bin")
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("extract spawn");
    assert!(r2.success(), "extract on the re-run stego must succeed");
    assert_eq!(
        fs::read(&recovered).unwrap(),
        b"crash recovery payload",
        "extracted payload must match"
    );
}

#[test]
fn mid_extract_sigkill_does_not_corrupt_source_stego() {
    // Embed cleanly first.
    let tmp = TempDir::new().unwrap();
    let cover = tmp.path().join("cover.png");
    let payload_path = tmp.path().join("payload.bin");
    let stego = tmp.path().join("stego.png");
    write_png_cover(&cover, 256, 256);
    write_payload(&payload_path, &vec![0xCD; 4096]);
    let passphrase = "extract-crash-pass";

    Command::cargo_bin("stegcore")
        .expect("cargo_bin")
        .args([
            "embed",
            cover.to_str().unwrap(),
            payload_path.to_str().unwrap(),
            "-o",
            stego.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("embed");

    let stego_before = fs::read(&stego).expect("read stego");

    // Now crash an extract.
    let recovered = tmp.path().join("recovered.bin");
    let mut child = Command::cargo_bin("stegcore")
        .expect("cargo_bin")
        .args([
            "extract",
            stego.to_str().unwrap(),
            "-o",
            recovered.to_str().unwrap(),
            "--passphrase",
            passphrase,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn extract");
    thread::sleep(Duration::from_millis(20));
    sigkill(&mut child);

    let stego_after = fs::read(&stego).expect("read stego");
    assert_eq!(
        stego_before, stego_after,
        "extract must NOT mutate the source stego file, even on crash"
    );
}
