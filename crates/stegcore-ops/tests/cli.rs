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

#[test]
fn score_missing_binary_fails_cleanly() {
    let tmp = TempDir::new().unwrap();
    let audit = tmp.path().join("audit.jsonl");
    fs::write(&audit, "").unwrap();
    let out = bin()
        .args(["score", "--audit"])
        .arg(&audit)
        .args(["--out"])
        .arg(tmp.path().join("scores.jsonl"))
        .args(["--bin", "/no/such/engine", "--path-root"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("engine binary not found"));
}

#[cfg(unix)]
#[test]
fn score_runs_over_audit_with_a_stub_engine() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();

    // A stub engine that emits a minimal analyse payload.
    let engine = root.join("stub-engine");
    let json = r#"{"data":[{"verdict":"clean","overall_score":0.01,"tests":[{"name":"Chi-Squared","score":0.02}]}]}"#;
    fs::write(&engine, format!("#!/bin/sh\ncat <<'JSON'\n{json}\nJSON\n")).unwrap();
    fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();

    write_png(&root.join("5.png"), b"body");
    let audit = root.join("audit.jsonl");
    fs::write(
        &audit,
        "{\"path\":\"5.png\",\"split\":\"test\",\"claimed_label\":\"clean\",\"variant\":null,\"sha256\":\"deadbeef\",\"claimed_tool\":null,\"magic_ok\":true,\"verdict\":\"accept\",\"reason\":null}\n",
    )
    .unwrap();
    let scores = root.join("scores.jsonl");

    let out = bin()
        .args(["score", "--audit"])
        .arg(&audit)
        .args(["--out"])
        .arg(&scores)
        .args(["--bin"])
        .arg(&engine)
        .args(["--path-root"])
        .arg(root)
        .args(["--jobs", "1"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 scored"));
    let body = fs::read_to_string(&scores).unwrap();
    assert_eq!(body.lines().count(), 1);
    assert!(body.contains("\"chi\":0.02"));
}

#[test]
fn benchmark_missing_scores_fails_cleanly() {
    let out = bin()
        .args(["benchmark", "--scores", "/no/such/scores.jsonl", "--out"])
        .arg(TempDir::new().unwrap().path().join("report.json"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("scores JSONL not found"));
}

#[test]
fn benchmark_produces_a_report() {
    let tmp = TempDir::new().unwrap();
    let scores = tmp.path().join("scores.jsonl");
    // Two clean + two stego, perfectly separated by the ensemble score.
    let lines = [
        r#"{"path":"a","sha256":"1","label":"clean","overall_score":0.02,"chi":0.03}"#,
        r#"{"path":"b","sha256":"2","label":"clean","overall_score":0.10,"chi":0.08}"#,
        r#"{"path":"c","sha256":"3","label":"stego","overall_score":0.80,"chi":0.90}"#,
        r#"{"path":"d","sha256":"4","label":"stego","overall_score":0.95,"chi":0.93}"#,
    ];
    fs::write(&scores, lines.join("\n")).unwrap();
    let report = tmp.path().join("report.json");

    let out = bin()
        .args(["benchmark", "--scores"])
        .arg(&scores)
        .args(["--out"])
        .arg(&report)
        .args(["--threshold", "0.5"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("DETECTION BENCHMARK"));

    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    assert_eq!(parsed["n_samples"], 4);
    assert_eq!(parsed["ensemble"]["tp"], 2);
}
