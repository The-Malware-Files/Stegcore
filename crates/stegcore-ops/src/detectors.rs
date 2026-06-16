// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Comparator detectors for the head-to-head benchmark.
//!
//! Each detector takes one image and returns a binary verdict (stego or not),
//! so a confusion matrix can be built over a labelled corpus. Together with the
//! embedder split this produces the detectability heatmap: rows are embedders,
//! columns are detectors, each cell the detection rate.
//!
//! The tools run dockerised, driven by shell-out like the embedders. Their
//! output formats differ, so each verdict is parsed by a small pure function
//! that is unit-tested against captured output; the [`Detector`] trait keeps the
//! corpus runner testable with a stub.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use serde_json::Value;

use crate::metrics::Confusion;

/// A single comparator detector.
pub trait Detector {
    /// Short identifier, used as the heatmap column label.
    fn id(&self) -> &str;
    /// Classify one image: `true` means flagged as stego.
    fn detect(&self, image: &Path) -> Result<bool, String>;
}

/// Outcome of running a detector over a labelled corpus.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DetectOutcome {
    pub confusion: Confusion,
    pub errors: usize,
}

/// Run `detector` over each `(image, is_stego)` pair and tally a confusion
/// matrix. A detector error on one image is counted and skipped, never fatal.
pub fn detect_corpus(
    detector: &dyn Detector,
    labelled: &[(std::path::PathBuf, bool)],
) -> DetectOutcome {
    let mut labels = Vec::new();
    let mut preds = Vec::new();
    let mut errors = 0;
    for (image, is_stego) in labelled {
        match detector.detect(image) {
            Ok(flagged) => {
                labels.push(*is_stego);
                preds.push(flagged);
            }
            Err(e) => {
                eprintln!("  {} error on {}: {e}", detector.id(), image.display());
                errors += 1;
            }
        }
    }
    DetectOutcome {
        confusion: Confusion::tally(&labels, &preds),
        errors,
    }
}

/// Sorted PNG files directly under `dir` (empty if the directory is absent).
fn sorted_pngs(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "png"))
        .collect();
    out.sort();
    Ok(out)
}

/// Parse the embedder tool from a stego filename `image_<digits>_<tool>_<n>.png`.
fn tool_of(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".png")?.strip_prefix("image_")?;
    let parts: Vec<&str> = stem.split('_').collect();
    let lower = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase());
    if parts.len() == 3 && lower(parts[1]) {
        Some(parts[1].to_string())
    } else {
        None
    }
}

/// Clean covers, plus stego images grouped by embedder name.
pub type CorpusGroups = (Vec<PathBuf>, BTreeMap<String, Vec<PathBuf>>);

/// Gather a dataset's clean covers and its stego images grouped by embedder.
/// Layout is the audit grammar: `<root>/test/test/{clean,stego}`.
pub fn gather_groups(root: &Path) -> std::io::Result<CorpusGroups> {
    let inner = root.join("test").join("test");
    let clean = sorted_pngs(&inner.join("clean"))?;
    let mut groups: BTreeMap<String, Vec<PathBuf>> = BTreeMap::new();
    for p in sorted_pngs(&inner.join("stego"))? {
        if let Some(tool) = tool_of(&p) {
            groups.entry(tool).or_default().push(p);
        }
    }
    Ok((clean, groups))
}

/// Retry the transient ETXTBSY (os error 26) when exec'ing a freshly-written
/// program (a stub in tests, a just-updated binary in the wild); see
/// `embedders::run`.
fn output_retrying(cmd: &mut Command) -> std::io::Result<Output> {
    let mut attempt = 0u32;
    loop {
        match cmd.output() {
            Err(e) if e.raw_os_error() == Some(26) && attempt < 4 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(20 * u64::from(attempt)));
            }
            other => return other,
        }
    }
}

/// Stage `image` into a temp dir bind-mounted at `/data` and run the docker
/// `image_tag` with `args` (the container entrypoint supplies the tool). The
/// staged file is always named `sample.png`. Returns stdout and stderr joined,
/// since the tools split their output inconsistently.
fn docker_capture(
    docker_bin: &Path,
    image_tag: &str,
    image: &Path,
    args: &[&str],
) -> Result<String, String> {
    let work = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    fs::copy(image, work.path().join("sample.png")).map_err(|e| format!("stage: {e}"))?;
    let mut cmd = Command::new(docker_bin);
    cmd.args(["run", "--rm", "-v"])
        .arg(format!("{}:/data", work.path().display()))
        .arg(image_tag)
        .args(args);
    let out = output_retrying(&mut cmd).map_err(|e| format!("docker: {e}"))?;
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

// ── Parsers (pure, unit-tested against captured output) ───────────────────────

/// StegExpose prints one line per *suspicious* file and nothing for clean ones.
pub fn stegexpose_flagged(output: &str) -> bool {
    output.to_lowercase().contains("suspicious")
}

/// zsteg is an extraction tool, not a classifier: it always emits candidate
/// `text:`/`file:` findings, mostly noise. A real hit is a *coherent* string,
/// so we flag when any `text:` finding carries a long run of alphabetic
/// characters (clean-image noise is short gibberish or whitespace escapes).
pub fn zsteg_flagged(output: &str) -> bool {
    const MIN_ALPHA: usize = 12;
    for finding in text_findings(output) {
        if finding.chars().filter(|c| c.is_ascii_alphabetic()).count() >= MIN_ALPHA {
            return true;
        }
    }
    false
}

/// Aletheia's classical attacks print `Hidden data found in channel X <est>`
/// per channel, where `<est>` is the estimated embedding rate. Return the
/// largest channel estimate. Note the tool's own 0.05 threshold flags clean
/// natural images, so the caller applies its own (higher) decision threshold.
pub fn aletheia_estimate(output: &str) -> Option<f64> {
    let mut max: Option<f64> = None;
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix("Hidden data found in channel ") {
            if let Some(val) = rest
                .split_whitespace()
                .last()
                .and_then(|t| t.parse::<f64>().ok())
            {
                max = Some(max.map_or(val, |m| m.max(val)));
            }
        }
    }
    max
}

/// Extract the quoted strings from zsteg `text: "..."` findings.
fn text_findings(output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in output.lines() {
        let mut rest = line;
        while let Some(pos) = rest.find("text: \"") {
            let after = &rest[pos + 7..];
            match after.find('"') {
                Some(end) => {
                    out.push(after[..end].to_string());
                    rest = &after[end + 1..];
                }
                None => break,
            }
        }
    }
    out
}

// ── Dockerised detectors ──────────────────────────────────────────────────────

/// Stegcore itself, as a detector: run the engine's analyse and threshold its
/// ensemble score. This is the subject of the head-to-head.
pub struct StegcoreDetector {
    pub bin: PathBuf,
    pub threshold: f64,
}

impl Detector for StegcoreDetector {
    fn id(&self) -> &str {
        "stegcore"
    }
    fn detect(&self, image: &Path) -> Result<bool, String> {
        let mut cmd = Command::new(&self.bin);
        cmd.arg("analyse").arg(image).arg("--json");
        let out = output_retrying(&mut cmd).map_err(|e| format!("stegcore: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "stegcore: {}",
                String::from_utf8_lossy(&out.stderr)
                    .chars()
                    .take(120)
                    .collect::<String>()
            ));
        }
        let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("parse: {e}"))?;
        let score = v
            .get("data")
            .and_then(|d| d.get(0))
            .and_then(|d| d.get("overall_score"))
            .and_then(Value::as_f64)
            .ok_or_else(|| "stegcore: no overall_score".to_string())?;
        Ok(score >= self.threshold)
    }
}

/// StegExpose (b3dk7), a Java LSB-detection ensemble. Scans a directory; we
/// stage one image and read its verdict.
pub struct StegExposeDetector {
    pub image: String,
    pub docker_bin: PathBuf,
}

impl Detector for StegExposeDetector {
    fn id(&self) -> &str {
        "stegexpose"
    }
    fn detect(&self, image: &Path) -> Result<bool, String> {
        // StegExpose takes the directory; the container sees it as /data.
        let out = docker_capture(&self.docker_bin, &self.image, image, &["/data"])?;
        Ok(stegexpose_flagged(&out))
    }
}

/// zsteg (zed-0xff), a PNG/BMP bit-plane scanner.
pub struct ZstegDetector {
    pub image: String,
    pub docker_bin: PathBuf,
}

impl Detector for ZstegDetector {
    fn id(&self) -> &str {
        "zsteg"
    }
    fn detect(&self, image: &Path) -> Result<bool, String> {
        let out = docker_capture(&self.docker_bin, &self.image, image, &["/data/sample.png"])?;
        Ok(zsteg_flagged(&out))
    }
}

/// Aletheia (daniellerch), the parity reference. Runs a classical attack
/// (`spa`/`rs`/`ws`) and flags when the estimated embedding rate exceeds a
/// configurable threshold (the tool's own 0.05 default over-flags natural
/// covers, so we set a higher decision point).
pub struct AletheiaDetector {
    pub image: String,
    pub docker_bin: PathBuf,
    pub attack: String,
    pub threshold: f64,
}

impl Detector for AletheiaDetector {
    fn id(&self) -> &str {
        "aletheia"
    }
    fn detect(&self, image: &Path) -> Result<bool, String> {
        let out = docker_capture(
            &self.docker_bin,
            &self.image,
            image,
            &[&self.attack, "/data/sample.png"],
        )?;
        Ok(aletheia_estimate(&out).is_some_and(|e| e >= self.threshold))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct AlwaysStego;
    impl Detector for AlwaysStego {
        fn id(&self) -> &str {
            "always"
        }
        fn detect(&self, _: &Path) -> Result<bool, String> {
            Ok(true)
        }
    }

    struct Errs;
    impl Detector for Errs {
        fn id(&self) -> &str {
            "errs"
        }
        fn detect(&self, _: &Path) -> Result<bool, String> {
            Err("boom".into())
        }
    }

    #[test]
    fn detect_corpus_builds_confusion() {
        let labelled = vec![
            (PathBuf::from("a"), true),  // stego, flagged → tp
            (PathBuf::from("b"), false), // clean, flagged → fp
        ];
        let o = detect_corpus(&AlwaysStego, &labelled);
        assert_eq!((o.confusion.tp, o.confusion.fp), (1, 1));
        assert_eq!(o.errors, 0);
    }

    #[test]
    fn detect_corpus_counts_errors() {
        let o = detect_corpus(&Errs, &[(PathBuf::from("a"), true)]);
        assert_eq!(o.errors, 1);
        assert_eq!(o.confusion, Confusion::default());
    }

    #[test]
    fn stegexpose_parser() {
        assert!(stegexpose_flagged(
            "sample.png is suspicious. Approximate amount of hidden data is 19017 bytes."
        ));
        assert!(!stegexpose_flagged("")); // clean → no line
        assert!(!stegexpose_flagged("sample.png\n"));
    }

    #[test]
    fn zsteg_parser_discriminates_payload_from_noise() {
        // The real payload: a long coherent string → flagged.
        let stego = r#"b1,bgr,lsb,xy       .. text: "Stegcore benchmark payload.""#;
        assert!(zsteg_flagged(stego));
        // Clean-image noise: short gibberish and whitespace escapes → not flagged.
        let clean = "b1,r,lsb,xy .. text: \"V%`i78i:\"\nb2 .. text: \"\\t\\t\\n\"";
        assert!(!zsteg_flagged(clean));
        assert!(!zsteg_flagged("imagedata .. file: shared library"));
    }

    #[test]
    fn gather_groups_splits_clean_and_embedders() {
        let tmp = tempfile::TempDir::new().unwrap();
        let inner = tmp.path().join("test/test");
        for d in ["clean", "stego"] {
            fs::create_dir_all(inner.join(d)).unwrap();
        }
        fs::write(inner.join("clean/00000.png"), b"x").unwrap();
        fs::write(inner.join("clean/00001.png"), b"x").unwrap();
        fs::write(inner.join("stego/image_00000_lsbsteg_0.png"), b"x").unwrap();
        fs::write(inner.join("stego/image_00001_openstego_0.png"), b"x").unwrap();
        fs::write(inner.join("stego/image_00002_lsbsteg_0.png"), b"x").unwrap();
        fs::write(inner.join("stego/junk.png"), b"x").unwrap(); // not the grammar

        let (clean, groups) = gather_groups(tmp.path()).unwrap();
        assert_eq!(clean.len(), 2);
        assert_eq!(groups.get("lsbsteg").map(Vec::len), Some(2));
        assert_eq!(groups.get("openstego").map(Vec::len), Some(1));
        assert!(!groups.contains_key("junk"));
    }

    #[cfg(unix)]
    fn write_exec(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stegexpose_detector_drives_a_stub_docker() {
        let tmp = tempfile::TempDir::new().unwrap();
        let img = tmp.path().join("x.png");
        fs::write(&img, b"png").unwrap();
        let docker = tmp.path().join("docker.sh");
        write_exec(
            &docker,
            "#!/bin/sh\necho 'sample.png is suspicious. 1234 bytes'\n",
        );
        let d = StegExposeDetector {
            image: "stub".into(),
            docker_bin: docker,
        };
        assert!(d.detect(&img).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn zsteg_detector_drives_a_stub_docker() {
        let tmp = tempfile::TempDir::new().unwrap();
        let img = tmp.path().join("x.png");
        fs::write(&img, b"png").unwrap();
        let docker = tmp.path().join("docker.sh");
        write_exec(
            &docker,
            "#!/bin/sh\nprintf 'b1,bgr,lsb,xy .. text: \"Stegcore benchmark payload.\"\\n'\n",
        );
        let d = ZstegDetector {
            image: "stub".into(),
            docker_bin: docker,
        };
        assert!(d.detect(&img).unwrap());
    }

    #[test]
    fn aletheia_estimate_takes_the_max_channel() {
        let stego = "Using threshold: 0.05\nHidden data found in channel R 0.254\nHidden data found in channel G 0.131\nHidden data found in channel B 0.518";
        assert_eq!(aletheia_estimate(stego), Some(0.518));
        // Clean natural image: the tool still prints lines, but the estimates
        // are low, so a higher decision threshold separates it.
        let clean = "Hidden data found in channel R 0.114\nHidden data found in channel G 0.058\nHidden data found in channel B 0.14";
        let est = aletheia_estimate(clean).unwrap();
        assert!(est < 0.2 && est > 0.13);
        assert_eq!(aletheia_estimate("No hidden data found"), None);
    }

    #[cfg(unix)]
    #[test]
    fn aletheia_detector_drives_a_stub_docker() {
        let tmp = tempfile::TempDir::new().unwrap();
        let img = tmp.path().join("x.png");
        fs::write(&img, b"png").unwrap();
        let docker = tmp.path().join("docker.sh");
        write_exec(
            &docker,
            "#!/bin/sh\necho 'Hidden data found in channel R 0.518'\n",
        );
        let flag = AletheiaDetector {
            image: "stub".into(),
            docker_bin: docker.clone(),
            attack: "spa".into(),
            threshold: 0.2,
        };
        assert!(flag.detect(&img).unwrap());
        let strict = AletheiaDetector {
            image: "stub".into(),
            docker_bin: docker,
            attack: "spa".into(),
            threshold: 0.9,
        };
        assert!(!strict.detect(&img).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn stegcore_detector_thresholds_the_ensemble_score() {
        let tmp = tempfile::TempDir::new().unwrap();
        let img = tmp.path().join("x.png");
        fs::write(&img, b"png").unwrap();
        let bin = tmp.path().join("engine.sh");
        write_exec(
            &bin,
            "#!/bin/sh\ncat <<'JSON'\n{\"data\":[{\"overall_score\":0.80}]}\nJSON\n",
        );
        let above = StegcoreDetector {
            bin: bin.clone(),
            threshold: 0.55,
        };
        assert!(above.detect(&img).unwrap());
        let below = StegcoreDetector {
            bin,
            threshold: 0.95,
        };
        assert!(!below.detect(&img).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn stegcore_detector_reports_engine_failure() {
        let tmp = tempfile::TempDir::new().unwrap();
        let img = tmp.path().join("x.png");
        fs::write(&img, b"png").unwrap();
        let bin = tmp.path().join("boom.sh");
        write_exec(&bin, "#!/bin/sh\necho 'engine error' >&2\nexit 2\n");
        let d = StegcoreDetector {
            bin,
            threshold: 0.5,
        };
        assert!(d.detect(&img).is_err());
    }

    #[test]
    fn docker_capture_surfaces_a_missing_docker() {
        // A non-existent docker binary makes the spawn fail, not panic.
        let tmp = tempfile::TempDir::new().unwrap();
        let img = tmp.path().join("x.png");
        fs::write(&img, b"png").unwrap();
        let d = StegExposeDetector {
            image: "x".into(),
            docker_bin: "/no/such/docker".into(),
        };
        assert!(d.detect(&img).is_err());
    }
}
