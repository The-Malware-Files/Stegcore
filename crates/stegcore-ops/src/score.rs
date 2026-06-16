// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Score collection: run `stegcore analyse --json` over every accepted audit
//! sample and record the five detector scores, the ensemble verdict and any
//! tool fingerprint as one JSON line per sample.
//!
//! Work is parallelised across a configurable worker pool. The output is
//! opened in append mode and a resume pass skips any sample whose hash is
//! already present, so an interrupted run continues where it stopped. A
//! heartbeat reports throughput periodically. This is the Rust port of the
//! former `score.py`, emitting the same per-sample schema (absent fields are
//! omitted rather than written as null, which downstream readers treat the
//! same way).

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::audit::AuditRecord;

const HEARTBEAT_EVERY: usize = 500;
/// Cap on captured child stderr stored in an error record.
const ERR_SNIPPET: usize = 200;

/// One scored sample. Score fields are absent (omitted from JSON) when the
/// analyse run did not report them or when the sample errored.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScoreRecord {
    pub path: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chi: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spa: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overall_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Aggregated outcome of a score run.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScoreOutcome {
    pub scored: usize,
    pub errors: usize,
    pub skipped: usize,
}

/// Read accepted samples (verdict `accept` with a hash) from an audit JSONL.
/// Malformed lines are skipped rather than aborting the load.
pub fn load_accepted(audit: &Path) -> std::io::Result<Vec<AuditRecord>> {
    let file = File::open(audit)?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<AuditRecord>(&line) {
            if rec.verdict == "accept" && rec.sha256.is_some() {
                out.push(rec);
            }
        }
    }
    Ok(out)
}

/// Hashes already present in an existing scores file, so a resumed run skips
/// them. A missing file yields an empty set.
pub fn load_done(out_path: &Path) -> HashSet<String> {
    let mut done = HashSet::new();
    let Ok(file) = File::open(out_path) else {
        return done;
    };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if let Ok(v) = serde_json::from_str::<Value>(&line) {
            if let Some(sha) = v.get("sha256").and_then(Value::as_str) {
                done.insert(sha.to_string());
            }
        }
    }
    done
}

/// Pull the five detector scores, ensemble fields and fingerprint out of an
/// `analyse --json` payload into `rec`.
fn fill_scores(stdout: &str, rec: &mut ScoreRecord) -> Result<(), String> {
    let v: Value = serde_json::from_str(stdout).map_err(|e| format!("parse: {e}"))?;
    let d = v
        .get("data")
        .and_then(|d| d.get(0))
        .ok_or_else(|| "parse: missing data[0]".to_string())?;

    let mut by_name = std::collections::HashMap::new();
    if let Some(tests) = d.get("tests").and_then(Value::as_array) {
        for t in tests {
            if let (Some(name), Some(score)) = (
                t.get("name").and_then(Value::as_str),
                t.get("score").and_then(Value::as_f64),
            ) {
                by_name.insert(name.to_string(), score);
            }
        }
    }
    rec.chi = by_name.get("Chi-Squared").copied();
    rec.spa = by_name.get("Sample Pair Analysis").copied();
    rec.rs = by_name.get("RS Analysis").copied();
    rec.entropy = by_name.get("LSB Entropy").copied();
    rec.ws = by_name.get("Weighted Stego").copied();
    rec.overall_score = d.get("overall_score").and_then(Value::as_f64);
    rec.verdict = d.get("verdict").and_then(Value::as_str).map(str::to_string);
    rec.fingerprint = d
        .get("tool_fingerprint")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(())
}

/// Run `bin analyse <path> --json`, killing the child if it outruns `timeout`.
/// analyse emits a small JSON document (well under the pipe buffer), so reading
/// the captured output after the process exits cannot deadlock.
fn analyse_with_timeout(bin: &Path, path: &Path, timeout: Duration) -> Result<String, String> {
    let spawn = || {
        Command::new(bin)
            .arg("analyse")
            .arg(path)
            .arg("--json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    };
    // Retry the transient ETXTBSY (os error 26) that can occur when the engine
    // binary was just written by a concurrent process; see embedders::run.
    let mut attempt = 0u32;
    let mut child = loop {
        match spawn() {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(26) && attempt < 4 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(20 * u64::from(attempt)));
            }
            Err(e) => return Err(format!("spawn: {e}")),
        }
    };

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("timeout after {}s", timeout.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("wait: {e}")),
        }
    };

    let mut stdout = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut stdout);
    }
    if !status.success() {
        let mut stderr = String::new();
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut stderr);
        }
        let snippet: String = stderr.chars().take(ERR_SNIPPET).collect();
        return Err(if snippet.is_empty() {
            format!("exit {status}")
        } else {
            snippet
        });
    }
    Ok(stdout)
}

/// Score one accepted sample, carrying its labels through and recording any
/// failure in the `error` field rather than propagating it.
fn score_one(rec: &AuditRecord, bin: &Path, path_root: &Path, timeout: Duration) -> ScoreRecord {
    let mut out = ScoreRecord {
        path: rec.path.clone(),
        sha256: rec.sha256.clone().unwrap_or_default(),
        split: Some(rec.split.clone()),
        label: Some(rec.claimed_label.clone()),
        variant: rec.variant.clone(),
        tool: rec.claimed_tool.clone(),
        ..Default::default()
    };
    let full = path_root.join(&rec.path);
    match analyse_with_timeout(bin, &full, timeout) {
        Ok(stdout) => {
            if let Err(e) = fill_scores(&stdout, &mut out) {
                out.error = Some(e);
            }
        }
        Err(e) => out.error = Some(e),
    }
    out
}

/// Default worker count: one fewer than the available parallelism, floored at
/// one, so the machine stays responsive during a long run.
pub fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(1).max(1))
        .unwrap_or(1)
}

/// Score every accepted sample in `audit`, appending results to `out_path`.
/// Skips samples already present in `out_path` (resume) and returns the run
/// outcome. `path_root` is the directory the audit's relative paths resolve
/// against.
#[allow(clippy::too_many_arguments)]
pub fn run_score(
    audit: &Path,
    out_path: &Path,
    bin: &Path,
    path_root: &Path,
    jobs: usize,
    timeout: Duration,
) -> std::io::Result<ScoreOutcome> {
    let done = load_done(out_path);
    let accepted = load_accepted(audit)?;
    let todo: Vec<AuditRecord> = accepted
        .into_iter()
        .filter(|r| {
            r.sha256
                .as_ref()
                .map(|s| !done.contains(s))
                .unwrap_or(false)
        })
        .collect();

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(out_path)?;
    let writer = Mutex::new(BufWriter::new(file));
    let count = AtomicUsize::new(done.len());
    let errors = AtomicUsize::new(0);
    let start = Instant::now();
    let total = todo.len() + done.len();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.max(1))
        .build()
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    pool.install(|| {
        todo.par_iter().for_each(|rec| {
            let scored = score_one(rec, bin, path_root, timeout);
            let is_err = scored.error.is_some();
            let line = serde_json::to_string(&scored).unwrap_or_default();
            let done_so_far = {
                let mut w = writer.lock().expect("score writer poisoned");
                let _ = writeln!(w, "{line}");
                let c = count.fetch_add(1, Ordering::Relaxed) + 1;
                if c % HEARTBEAT_EVERY == 0 {
                    let _ = w.flush();
                }
                c
            };
            if is_err {
                errors.fetch_add(1, Ordering::Relaxed);
            }
            if done_so_far % HEARTBEAT_EVERY == 0 {
                let elapsed = start.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 {
                    done_so_far as f64 / elapsed
                } else {
                    0.0
                };
                eprintln!(
                    "  {done_so_far} / {total}  rate={rate:.1}/s  errors={}  elapsed={elapsed:.0}s",
                    errors.load(Ordering::Relaxed)
                );
            }
        });
    });

    writer.lock().expect("score writer poisoned").flush()?;

    Ok(ScoreOutcome {
        scored: todo.len(),
        errors: errors.load(Ordering::Relaxed),
        skipped: done.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const SAMPLE_JSON: &str = r#"{
        "ok": true,
        "data": [{
            "verdict": "likely_stego",
            "overall_score": 0.95,
            "tool_fingerprint": "OpenStego (exact signature)",
            "tests": [
                {"name": "Chi-Squared", "score": 0.9},
                {"name": "Sample Pair Analysis", "score": 0.1},
                {"name": "RS Analysis", "score": 0.2},
                {"name": "LSB Entropy", "score": 0.3},
                {"name": "Weighted Stego", "score": 0.4}
            ]
        }]
    }"#;

    #[test]
    fn fill_scores_extracts_all_fields() {
        let mut rec = ScoreRecord::default();
        fill_scores(SAMPLE_JSON, &mut rec).unwrap();
        assert_eq!(rec.chi, Some(0.9));
        assert_eq!(rec.spa, Some(0.1));
        assert_eq!(rec.rs, Some(0.2));
        assert_eq!(rec.entropy, Some(0.3));
        assert_eq!(rec.ws, Some(0.4));
        assert_eq!(rec.overall_score, Some(0.95));
        assert_eq!(rec.verdict.as_deref(), Some("likely_stego"));
        assert_eq!(
            rec.fingerprint.as_deref(),
            Some("OpenStego (exact signature)")
        );
    }

    #[test]
    fn fill_scores_rejects_malformed_and_missing_data() {
        let mut rec = ScoreRecord::default();
        assert!(fill_scores("not json", &mut rec).is_err());
        assert!(fill_scores(r#"{"ok":true}"#, &mut rec).is_err());
    }

    #[test]
    fn load_accepted_filters_drops_and_missing_hashes() {
        let tmp = TempDir::new().unwrap();
        let audit = tmp.path().join("audit.jsonl");
        let lines = [
            r#"{"path":"a.png","split":"test","claimed_label":"clean","variant":null,"sha256":"h1","claimed_tool":null,"magic_ok":true,"verdict":"accept","reason":null}"#,
            r#"{"path":"b.png","split":"test","claimed_label":"clean","variant":null,"sha256":null,"claimed_tool":null,"magic_ok":false,"verdict":"drop","reason":"zero-byte"}"#,
            "",
            "garbage-not-json",
        ];
        fs::write(&audit, lines.join("\n")).unwrap();
        let accepted = load_accepted(&audit).unwrap();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].path, "a.png");
    }

    #[test]
    fn load_done_collects_present_hashes() {
        let tmp = TempDir::new().unwrap();
        let scores = tmp.path().join("scores.jsonl");
        assert!(load_done(&scores).is_empty()); // missing file -> empty
        fs::write(
            &scores,
            "{\"path\":\"a\",\"sha256\":\"h1\"}\nbad\n{\"path\":\"b\",\"sha256\":\"h2\"}\n",
        )
        .unwrap();
        let done = load_done(&scores);
        assert_eq!(done.len(), 2);
        assert!(done.contains("h1") && done.contains("h2"));
    }

    // Hermetic end-to-end: a fake "analyse" binary emits canned JSON so the
    // orchestration (parallel run, append, resume) is covered without the
    // engine. Unix-only because it relies on an executable shell stub.
    #[cfg(unix)]
    fn fake_bin(dir: &Path, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("fake-stegcore");
        fs::write(&p, format!("#!/bin/sh\ncat <<'JSON'\n{body}\nJSON\n")).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[cfg(unix)]
    fn audit_line(path: &str, sha: &str, label: &str, tool: Option<&str>) -> String {
        let rec = AuditRecord {
            path: path.into(),
            split: "test".into(),
            claimed_label: label.into(),
            variant: None,
            sha256: Some(sha.into()),
            claimed_tool: tool.map(str::to_string),
            magic_ok: true,
            verdict: "accept".into(),
            reason: None,
        };
        serde_json::to_string(&rec).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn run_score_writes_resumes_and_records_errors() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Two "samples"; the files need only exist for path resolution.
        fs::write(root.join("a.png"), b"x").unwrap();
        fs::write(root.join("b.png"), b"y").unwrap();
        let audit = root.join("audit.jsonl");
        fs::write(
            &audit,
            format!(
                "{}\n{}\n",
                audit_line("a.png", "h1", "stego", Some("openstego")),
                audit_line("b.png", "h2", "clean", None),
            ),
        )
        .unwrap();
        let bin = fake_bin(root, SAMPLE_JSON);
        let out = root.join("scores.jsonl");

        let r1 = run_score(&audit, &out, &bin, root, 2, Duration::from_secs(5)).unwrap();
        assert_eq!(r1.scored, 2);
        assert_eq!(r1.errors, 0);
        assert_eq!(r1.skipped, 0);
        let body = fs::read_to_string(&out).unwrap();
        assert_eq!(body.lines().count(), 2);
        let first: ScoreRecord = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(first.overall_score, Some(0.95));

        // Re-run: both hashes are already present, so nothing new is scored.
        let r2 = run_score(&audit, &out, &bin, root, 2, Duration::from_secs(5)).unwrap();
        assert_eq!(r2.scored, 0);
        assert_eq!(r2.skipped, 2);
        assert_eq!(fs::read_to_string(&out).unwrap().lines().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn run_score_marks_failing_binary_as_error() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::write(root.join("a.png"), b"x").unwrap();
        let audit = root.join("audit.jsonl");
        fs::write(
            &audit,
            format!("{}\n", audit_line("a.png", "h1", "clean", None)),
        )
        .unwrap();
        // A stub that exits non-zero.
        use std::os::unix::fs::PermissionsExt;
        let bin = root.join("boom");
        fs::write(&bin, "#!/bin/sh\necho 'kaboom' >&2\nexit 3\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let out = root.join("scores.jsonl");

        let r = run_score(&audit, &out, &bin, root, 1, Duration::from_secs(5)).unwrap();
        assert_eq!(r.scored, 1);
        assert_eq!(r.errors, 1);
        let rec: ScoreRecord =
            serde_json::from_str(fs::read_to_string(&out).unwrap().trim()).unwrap();
        assert!(rec.error.is_some());
    }
}
