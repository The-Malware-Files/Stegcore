// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! End-to-end CLI tests that drive the built `stegcore-ops` binary, covering
//! the command glue (argument resolution, summary output, exit codes) that the
//! in-crate unit tests cannot reach.

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_stegcore-ops"))
}

fn write_png(path: &Path, body: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = PNG_MAGIC.to_vec();
    bytes.extend_from_slice(body);
    fs::write(path, bytes).unwrap();
}

#[test]
fn missing_root_fails_cleanly() {
    let out = bin()
        .args(["audit", "--root", "/no/such/dataset"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dataset root not found"),
        "stderr: {stderr}"
    );
}

#[test]
fn clean_dataset_succeeds_and_writes_default_jsonl() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("image_dataset");
    write_png(&root.join("train/train/clean/1.png"), b"a");
    write_png(&root.join("train/train/clean/2.png"), b"b");
    write_png(&root.join("train/train/stego/image_1_steghide_0.png"), b"c");

    let out = bin().args(["audit", "--root"]).arg(&root).output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("=== AUDIT SUMMARY ==="));
    assert!(stdout.contains("Accepted:             3"));

    // With no --out, a dated JSONL lands beside the dataset root.
    let beside: Vec<_> = fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with("audit-") && n.ends_with(".jsonl")
        })
        .collect();
    assert_eq!(beside.len(), 1, "expected exactly one dated audit JSONL");
}

#[test]
fn drop_rate_over_ceiling_exits_two() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("image_dataset");
    // One good sample, one magic-mismatch drop → 50% drop rate.
    write_png(&root.join("test/test/clean/1.png"), b"ok");
    fs::write(root.join("test/test/clean/2.png"), b"not-a-png").unwrap();

    let out_path = tmp.path().join("audit.jsonl");
    let out = bin()
        .args(["audit", "--root"])
        .arg(&root)
        .args(["--out"])
        .arg(&out_path)
        .args(["--max-drop-rate", "10"])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(2),
        "expected the review-halt exit code"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("exceeds"), "stderr: {stderr}");
    assert!(
        out_path.exists(),
        "JSONL is written even when the gate trips"
    );
}
