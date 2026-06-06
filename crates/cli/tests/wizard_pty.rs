// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Pseudo-terminal harness for the interactive `stegcore wizard`.
//!
//! `run_embed` / `run_extract` read passphrases through rpassword (which
//! opens /dev/tty directly), print to the terminal, and `process::exit` out
//! of every step, so they cannot be driven from an in-process unit test. We
//! drive the real built binary through a pty instead and script the prompts.
//! With DISPLAY / WAYLAND_DISPLAY unset, the wizard's file picker falls back
//! to a typed-path stdin prompt (it announces "type the path manually"),
//! which the pty answers. cargo-llvm-cov captures the spawned binary's
//! coverage, so this is what closes the wizard.rs exclusion.
//!
//! Unix only: the pty is provided by rexpect (nix under the hood).

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use rexpect::session::spawn_command;

const PASS: &str = "wizard pty correct horse";
const PAYLOAD: &[u8] = b"the secret carried through the wizard pty";
const TIMEOUT_MS: u64 = 60_000;

/// A high-entropy PNG so the cover scores well above the wizard's
/// "poor cover, continue anyway?" threshold (which would add a prompt).
fn write_noisy_png(path: &Path, w: u32, h: u32) {
    let hash = |x: u32, y: u32, salt: u32| -> u8 {
        let mut v = x.wrapping_mul(0x9E37_79B1)
            ^ y.wrapping_mul(0x85EB_CA77)
            ^ salt.wrapping_mul(0xC2B2_AE3D);
        v ^= v >> 15;
        v = v.wrapping_mul(0x2545_F491);
        v ^= v >> 13;
        (v & 0xff) as u8
    };
    let img = image::ImageBuffer::from_fn(w, h, |x, y| {
        image::Rgb([hash(x, y, 1), hash(x, y, 2), hash(x, y, 3)])
    });
    img.save(path).expect("write noisy png cover");
}

/// `stegcore wizard` with the graphical picker disabled so the file steps
/// fall back to a typed-path prompt the pty can answer.
fn wizard_command() -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin("stegcore"));
    cmd.arg("wizard");
    cmd.env_remove("DISPLAY");
    cmd.env_remove("WAYLAND_DISPLAY");
    cmd
}

#[test]
fn wizard_embed_then_extract_round_trips_over_a_pty() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("secret.bin");
    let stego = dir.path().join("stego.png");
    let recovered = dir.path().join("recovered.bin");
    write_noisy_png(&cover, 128, 128);
    std::fs::write(&payload, PAYLOAD).unwrap();

    // ── Embed ──────────────────────────────────────────────────────────────
    let mut p = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    p.exp_string("What would you like to do").unwrap();
    p.send_line("1").unwrap(); // Embed

    p.exp_string("type the path manually").unwrap(); // message-file picker fallback
    p.send_line(payload.to_str().unwrap()).unwrap();

    p.exp_string("type the path manually").unwrap(); // cover-file picker fallback
    p.send_line(cover.to_str().unwrap()).unwrap();

    p.exp_string("Cipher").unwrap();
    p.send_line("1").unwrap(); // ChaCha20-Poly1305

    p.exp_string("Mode").unwrap();
    p.send_line("1").unwrap(); // Adaptive

    p.exp_string("Passphrase: ").unwrap(); // rpassword (no echo)
    p.send_line(PASS).unwrap();
    p.exp_string("Confirm").unwrap();
    p.send_line(PASS).unwrap();

    p.exp_string("deniable mode").unwrap();
    p.send_line("n").unwrap();

    p.exp_string("Export a key file").unwrap();
    p.send_line("n").unwrap();

    p.exp_string("Output file").unwrap();
    p.send_line(stego.to_str().unwrap()).unwrap();

    p.exp_string("Proceed with embedding").unwrap();
    p.send_line("y").unwrap();

    p.exp_string("Embedded successfully").unwrap();
    p.exp_eof().unwrap();
    assert!(stego.exists(), "stego file should be written");

    // ── Extract ────────────────────────────────────────────────────────────
    let mut e = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    e.exp_string("What would you like to do").unwrap();
    e.send_line("2").unwrap(); // Extract

    e.exp_string("type the path manually").unwrap(); // stego-file picker fallback
    e.send_line(stego.to_str().unwrap()).unwrap();

    e.exp_string("Do you have a key file").unwrap();
    e.send_line("n").unwrap();

    e.exp_string("Passphrase: ").unwrap();
    e.send_line(PASS).unwrap();

    e.exp_string("Output file").unwrap();
    e.send_line(recovered.to_str().unwrap()).unwrap();

    e.exp_string("Proceed with extraction").unwrap();
    e.send_line("y").unwrap();

    e.exp_string("Saved").unwrap();
    e.exp_eof().unwrap();

    assert_eq!(
        std::fs::read(&recovered).unwrap(),
        PAYLOAD,
        "round-tripped payload must match"
    );
}

#[test]
fn wizard_extract_with_wrong_passphrase_reports_no_payload() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("secret.bin");
    let stego = dir.path().join("stego.png");
    let recovered = dir.path().join("recovered.bin");
    write_noisy_png(&cover, 128, 128);
    std::fs::write(&payload, PAYLOAD).unwrap();

    // Embed (standard/sequential mode this time, to cover that branch too).
    let mut p = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    p.exp_string("What would you like to do").unwrap();
    p.send_line("1").unwrap();
    p.exp_string("type the path manually").unwrap();
    p.send_line(payload.to_str().unwrap()).unwrap();
    p.exp_string("type the path manually").unwrap();
    p.send_line(cover.to_str().unwrap()).unwrap();
    p.exp_string("Cipher").unwrap();
    p.send_line("1").unwrap();
    p.exp_string("Mode").unwrap();
    p.send_line("2").unwrap(); // Standard (higher capacity)
    p.exp_string("Passphrase: ").unwrap();
    p.send_line(PASS).unwrap();
    p.exp_string("Confirm").unwrap();
    p.send_line(PASS).unwrap();
    p.exp_string("deniable mode").unwrap();
    p.send_line("n").unwrap();
    p.exp_string("Export a key file").unwrap();
    p.send_line("n").unwrap();
    p.exp_string("Output file").unwrap();
    p.send_line(stego.to_str().unwrap()).unwrap();
    p.exp_string("Proceed with embedding").unwrap();
    p.send_line("y").unwrap();
    p.exp_string("Embedded successfully").unwrap();
    p.exp_eof().unwrap();

    // Extract with the wrong passphrase: the oracle-resistant path reports
    // no payload and exits non-zero, without writing an output file.
    let mut e = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    e.exp_string("What would you like to do").unwrap();
    e.send_line("2").unwrap();
    e.exp_string("type the path manually").unwrap();
    e.send_line(stego.to_str().unwrap()).unwrap();
    e.exp_string("Do you have a key file").unwrap();
    e.send_line("n").unwrap();
    e.exp_string("Passphrase: ").unwrap();
    e.send_line("the wrong passphrase entirely").unwrap();
    e.exp_string("Output file").unwrap();
    e.send_line(recovered.to_str().unwrap()).unwrap();
    e.exp_string("Proceed with extraction").unwrap();
    e.send_line("y").unwrap();
    e.exp_eof().unwrap();

    assert!(
        !recovered.exists(),
        "no output should be written on a failed extract"
    );
}

#[test]
fn wizard_deniable_embed_with_key_export_then_keyfile_extract() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let real = dir.path().join("real.bin");
    let decoy = dir.path().join("decoy.bin");
    let stego = dir.path().join("stego.png");
    let recovered = dir.path().join("recovered.bin");
    write_noisy_png(&cover, 160, 160);
    std::fs::write(&real, PAYLOAD).unwrap();
    std::fs::write(&decoy, b"a perfectly innocent decoy message").unwrap();

    // ── Deniable embed, exporting key files ─────────────────────────────────
    let mut p = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    p.exp_string("What would you like to do").unwrap();
    p.send_line("1").unwrap();
    p.exp_string("type the path manually").unwrap();
    p.send_line(real.to_str().unwrap()).unwrap();
    p.exp_string("type the path manually").unwrap();
    p.send_line(cover.to_str().unwrap()).unwrap();
    p.exp_string("Cipher").unwrap();
    p.send_line("1").unwrap();
    p.exp_string("Mode").unwrap();
    p.send_line("1").unwrap();
    p.exp_string("Passphrase: ").unwrap();
    p.send_line(PASS).unwrap();
    p.exp_string("Confirm").unwrap();
    p.send_line(PASS).unwrap();

    p.exp_string("deniable mode").unwrap();
    p.send_line("y").unwrap(); // enable deniable
    p.exp_string("type the path manually").unwrap(); // decoy file picker
    p.send_line(decoy.to_str().unwrap()).unwrap();
    p.exp_string("Decoy passphrase: ").unwrap();
    p.send_line("a different decoy passphrase").unwrap();
    p.exp_string("Confirm").unwrap();
    p.send_line("a different decoy passphrase").unwrap();

    p.exp_string("Export a key file").unwrap();
    p.send_line("y").unwrap(); // export keys
    p.exp_string("Output file").unwrap();
    p.send_line(stego.to_str().unwrap()).unwrap();
    p.exp_string("Proceed with embedding").unwrap();
    p.send_line("y").unwrap();
    p.exp_string("Embedded successfully").unwrap();
    p.exp_eof().unwrap();

    // Deniable + export writes <stem>.real.json and <stem>.decoy.json.
    let real_kf = dir.path().join("stego.real.json");
    assert!(real_kf.exists(), "real key file should be exported");
    assert!(
        dir.path().join("stego.decoy.json").exists(),
        "decoy key file should be exported"
    );

    // ── Extract the real half via its key file ──────────────────────────────
    let mut e = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    e.exp_string("What would you like to do").unwrap();
    e.send_line("2").unwrap();
    e.exp_string("type the path manually").unwrap();
    e.send_line(stego.to_str().unwrap()).unwrap();
    e.exp_string("Do you have a key file").unwrap();
    e.send_line("y").unwrap(); // yes, provide a key file
    e.exp_string("type the path manually").unwrap();
    e.send_line(real_kf.to_str().unwrap()).unwrap();
    e.exp_string("Key file loaded").unwrap();
    e.exp_string("Passphrase: ").unwrap();
    e.send_line(PASS).unwrap();
    e.exp_string("Output file").unwrap();
    e.send_line(recovered.to_str().unwrap()).unwrap();
    e.exp_string("Proceed with extraction").unwrap();
    e.send_line("y").unwrap();
    e.exp_string("Saved").unwrap();
    e.exp_eof().unwrap();

    assert_eq!(std::fs::read(&recovered).unwrap(), PAYLOAD);
}

#[test]
fn wizard_embed_handles_retries_overwrite_and_decline() {
    let dir = tempfile::tempdir().unwrap();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("secret.bin");
    let missing = dir.path().join("does-not-exist.bin");
    let stego = dir.path().join("stego.png");
    write_noisy_png(&cover, 128, 128);
    std::fs::write(&payload, PAYLOAD).unwrap();

    let mut p = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    p.exp_string("What would you like to do").unwrap();
    p.send_line("1").unwrap();

    // Message file: a non-existent path first (re-prompts), then the real one.
    p.exp_string("type the path manually").unwrap();
    p.send_line(missing.to_str().unwrap()).unwrap();
    p.exp_string("File not found").unwrap();
    p.exp_string("type the path manually").unwrap();
    p.send_line(payload.to_str().unwrap()).unwrap();

    p.exp_string("type the path manually").unwrap();
    p.send_line(cover.to_str().unwrap()).unwrap();
    p.exp_string("Cipher").unwrap();
    p.send_line("1").unwrap();
    p.exp_string("Mode").unwrap();
    p.send_line("1").unwrap();
    p.exp_string("Passphrase: ").unwrap();
    p.send_line(PASS).unwrap();
    p.exp_string("Confirm").unwrap();
    p.send_line(PASS).unwrap();
    p.exp_string("deniable mode").unwrap();
    p.send_line("n").unwrap();
    p.exp_string("Export a key file").unwrap();
    p.send_line("n").unwrap();

    // Output path: an existing file first (overwrite? -> no, re-prompts), then new.
    p.exp_string("Output file").unwrap();
    p.send_line(cover.to_str().unwrap()).unwrap(); // already exists
    p.exp_string("already exists").unwrap();
    p.exp_string("Overwrite").unwrap();
    p.send_line("n").unwrap();
    p.exp_string("Output file").unwrap();
    p.send_line(stego.to_str().unwrap()).unwrap();

    // Decline at the final confirmation: nothing is written.
    p.exp_string("Proceed with embedding").unwrap();
    p.send_line("n").unwrap();
    p.exp_string("no files were written").unwrap();
    p.exp_eof().unwrap();

    assert!(!stego.exists(), "declining the confirmation writes nothing");
}

#[test]
fn wizard_cancels_cleanly_on_eof_at_the_menu() {
    let mut p = spawn_command(wizard_command(), Some(TIMEOUT_MS)).expect("spawn wizard");
    p.exp_string("What would you like to do").unwrap();
    p.send_control('d').unwrap(); // EOF -> menu returns None -> cancel
    p.exp_string("Cancelled").unwrap();
    p.exp_eof().unwrap();
}
