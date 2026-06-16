// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Dataset audit: re-derive byte truth for a labelled image dataset.
//!
//! Labels on disk are treated as a suggestion, never as ground truth. Every
//! file is re-hashed from its bytes, its PNG magic is validated, its filename
//! is parsed for the claimed tool, and any sample whose hash collides across
//! labels is dropped (a cross-folder duplicate is a labelling error). Each
//! verdict is written as one JSON line; the run halts for review if the drop
//! rate climbs past a configured ceiling.
//!
//! This is the Rust port of the former `audit.py`; it produces the same JSONL
//! schema so existing downstream tooling reads it unchanged.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The 8-byte PNG signature every accepted sample must start with.
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Reason a duplicate hash spanning labels is dropped. Kept as a constant so
/// the summary and the per-record reason never drift apart.
const DUP_REASON: &str = "duplicate-sha256-across-labels";

/// One audit verdict, serialised as a single JSONL line. Field order and names
/// match the original `audit.py` schema so downstream readers are unaffected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub path: String,
    pub split: String,
    pub claimed_label: String,
    pub variant: Option<String>,
    pub sha256: Option<String>,
    pub claimed_tool: Option<String>,
    pub magic_ok: bool,
    pub verdict: String,
    pub reason: Option<String>,
}

impl AuditRecord {
    fn dropped(
        path: String,
        split: String,
        claimed_label: String,
        variant: Option<String>,
        reason: &str,
        magic_ok: bool,
        claimed_tool: Option<String>,
    ) -> Self {
        Self {
            path,
            split,
            claimed_label,
            variant,
            sha256: None,
            claimed_tool,
            magic_ok,
            verdict: "drop".into(),
            reason: Some(reason.into()),
        }
    }
}

/// Aggregated outcome of an audit run, returned to the caller for reporting
/// and the exit-code decision.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AuditSummary {
    pub accepted: usize,
    pub dropped: usize,
    pub drop_reasons: BTreeMap<String, usize>,
    /// Counts keyed by `(split, label, variant)`; variant is "-" for clean.
    pub by_split_label_variant: BTreeMap<(String, String, String), usize>,
    pub by_tool: BTreeMap<String, usize>,
    pub duplicate_hashes: usize,
    pub duplicate_files: usize,
}

impl AuditSummary {
    pub fn total(&self) -> usize {
        self.accepted + self.dropped
    }

    /// Drop rate as a percentage; zero when nothing was scanned.
    pub fn drop_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            self.dropped as f64 / total as f64 * 100.0
        }
    }
}

/// `^\d+\.png$` — a clean sample is a plain numeric index plus `.png`.
fn is_clean_name(name: &str) -> bool {
    match name.strip_suffix(".png") {
        Some(stem) => !stem.is_empty() && stem.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// `^image_\d+_(?P<tool>[a-z]+)_\d+\.png$` — returns the claimed tool on match.
/// The tool segment is lowercase ASCII with no underscore, so a plain split on
/// `_` recovers exactly the three expected fields.
fn stego_tool_of(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".png")?.strip_prefix("image_")?;
    let parts: Vec<&str> = stem.split('_').collect();
    if parts.len() != 3 {
        return None;
    }
    let [index, tool, variant] = [parts[0], parts[1], parts[2]];
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let lower = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase());
    if digits(index) && lower(tool) && digits(variant) {
        Some(tool)
    } else {
        None
    }
}

/// Stream a file through SHA-256 in 64 KiB chunks so memory stays flat
/// regardless of file size.
fn sha256_of(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Audit a single file. `rel` is the path as it should appear in the record
/// (relative to the dataset parent). Never panics: I/O failures become a
/// `drop` verdict with a diagnostic reason rather than aborting the run.
pub fn audit_file(
    path: &Path,
    rel: String,
    split: &str,
    claimed_label: &str,
    variant: Option<&str>,
) -> AuditRecord {
    let split = split.to_string();
    let label = claimed_label.to_string();
    let variant = variant.map(str::to_string);

    let mut head = [0u8; 8];
    let read_head = File::open(path).and_then(|mut f| f.read(&mut head));
    let magic_ok = matches!(read_head, Ok(8) if head == PNG_MAGIC);

    // Zero-byte files are dropped before anything else trusts their contents.
    match path.metadata() {
        Ok(meta) if meta.len() == 0 => {
            return AuditRecord::dropped(rel, split, label, variant, "zero-byte", false, None);
        }
        Err(e) => {
            return AuditRecord::dropped(
                rel,
                split,
                label,
                variant,
                &format!("io-error: {e}"),
                false,
                None,
            );
        }
        Ok(_) => {}
    }

    let claimed_tool;
    let filename_ok;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if claimed_label == "clean" {
        claimed_tool = None;
        filename_ok = is_clean_name(name);
    } else {
        match stego_tool_of(name) {
            Some(tool) => {
                claimed_tool = Some(tool.to_string());
                filename_ok = true;
            }
            None => {
                claimed_tool = None;
                filename_ok = false;
            }
        }
    }

    if !filename_ok {
        return AuditRecord::dropped(
            rel,
            split,
            label,
            variant,
            "filename-ambiguous",
            magic_ok,
            None,
        );
    }
    if !magic_ok {
        return AuditRecord::dropped(
            rel,
            split,
            label,
            variant,
            "magic-mismatch",
            false,
            claimed_tool,
        );
    }

    match sha256_of(path) {
        Ok(sha) => AuditRecord {
            path: rel,
            split,
            claimed_label: label,
            variant,
            sha256: Some(sha),
            claimed_tool,
            magic_ok: true,
            verdict: "accept".into(),
            reason: None,
        },
        Err(e) => AuditRecord::dropped(
            rel,
            split,
            label,
            variant,
            &format!("io-error: {e}"),
            magic_ok,
            claimed_tool,
        ),
    }
}

/// The four sample folders within a split and the (label, variant) each maps
/// to. `stego_b64`/`stego_zip` carry encoded payloads and appear in `test`.
fn folder_label_variant(folder: &str) -> Option<(&'static str, Option<&'static str>)> {
    match folder {
        "clean" => Some(("clean", None)),
        "stego" => Some(("stego", Some("raw"))),
        "stego_b64" => Some(("stego", Some("b64"))),
        "stego_zip" => Some(("stego", Some("zip"))),
        _ => None,
    }
}

/// Run the full audit over a dataset rooted at `root` (which holds the
/// `train`/`val`/`test` splits). Writes one JSON line per file to `out` and
/// returns the aggregated summary. The dataset-parent is used to build the
/// relative paths recorded in each line.
pub fn run_audit(root: &Path, out: &Path) -> std::io::Result<AuditSummary> {
    let parent = root.parent().unwrap_or(root);
    let file = File::create(out)?;
    let mut writer = BufWriter::new(file);

    // Held to resolve cross-label duplicates after the walk. Memory is O(number
    // of accepted samples); beyond ~10^7 samples this should spill to an
    // external sort, but the current corpora are well under that.
    let mut accepted: Vec<AuditRecord> = Vec::new();
    let mut hash_to_paths: HashMap<String, Vec<String>> = HashMap::new();
    let mut summary = AuditSummary::default();

    for split in ["train", "val", "test"] {
        let inner = root.join(split).join(split);
        if !inner.is_dir() {
            continue;
        }
        for folder in ["clean", "stego", "stego_b64", "stego_zip"] {
            let Some((label, variant)) = folder_label_variant(folder) else {
                continue;
            };
            let dir = inner.join(folder);
            if !dir.is_dir() {
                continue;
            }
            // Sort for reproducible iteration order (§ reproducibility).
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                .collect();
            entries.sort();
            for path in entries {
                let rel = path
                    .strip_prefix(parent)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                let rec = audit_file(&path, rel, split, label, variant);
                writeln!(writer, "{}", serde_json::to_string(&rec)?)?;
                if rec.verdict == "accept" {
                    if let Some(sha) = &rec.sha256 {
                        hash_to_paths
                            .entry(sha.clone())
                            .or_default()
                            .push(rec.path.clone());
                    }
                    accepted.push(rec);
                } else {
                    summary.dropped += 1;
                    *summary
                        .drop_reasons
                        .entry(rec.reason.unwrap_or_else(|| "unknown".into()))
                        .or_default() += 1;
                }
            }
        }
    }
    writer.flush()?;

    // Any hash appearing under more than one path spans labels: drop them all.
    let dup_paths: std::collections::HashSet<&String> = hash_to_paths
        .values()
        .filter(|paths| paths.len() > 1)
        .flatten()
        .collect();
    summary.duplicate_hashes = hash_to_paths.values().filter(|p| p.len() > 1).count();
    summary.duplicate_files = dup_paths.len();

    for rec in &accepted {
        if dup_paths.contains(&rec.path) {
            summary.dropped += 1;
            *summary.drop_reasons.entry(DUP_REASON.into()).or_default() += 1;
            continue;
        }
        summary.accepted += 1;
        let variant = rec.variant.clone().unwrap_or_else(|| "-".into());
        *summary
            .by_split_label_variant
            .entry((rec.split.clone(), rec.claimed_label.clone(), variant))
            .or_default() += 1;
        if let Some(tool) = &rec.claimed_tool {
            *summary.by_tool.entry(tool.clone()).or_default() += 1;
        }
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn png(extra: &[u8]) -> Vec<u8> {
        let mut v = PNG_MAGIC.to_vec();
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn filename_matchers() {
        assert!(is_clean_name("00042.png"));
        assert!(!is_clean_name("abc.png"));
        assert!(!is_clean_name(".png"));
        assert!(!is_clean_name("12.bmp"));
        assert_eq!(stego_tool_of("image_17_steghide_3.png"), Some("steghide"));
        assert_eq!(stego_tool_of("image_1_openstego_0.png"), Some("openstego"));
        assert_eq!(stego_tool_of("image_1_Steg_0.png"), None); // uppercase tool
        assert_eq!(stego_tool_of("image_x_tool_0.png"), None); // non-numeric index
        assert_eq!(stego_tool_of("17_steghide_3.png"), None); // missing prefix
        assert_eq!(stego_tool_of("image_17_steghide.png"), None); // too few fields
    }

    #[test]
    fn accepts_valid_clean_and_stego() {
        let tmp = TempDir::new().unwrap();
        let clean = tmp.path().join("5.png");
        write(&clean, &png(b"clean-body"));
        let rec = audit_file(&clean, "5.png".into(), "test", "clean", None);
        assert_eq!(rec.verdict, "accept");
        assert!(rec.sha256.is_some());
        assert!(rec.claimed_tool.is_none());

        let stego = tmp.path().join("image_9_lsbsteg_0.png");
        write(&stego, &png(b"stego-body"));
        let rec = audit_file(&stego, "x".into(), "test", "stego", Some("raw"));
        assert_eq!(rec.verdict, "accept");
        assert_eq!(rec.claimed_tool.as_deref(), Some("lsbsteg"));
    }

    #[test]
    fn drops_magic_mismatch_zero_byte_and_ambiguous() {
        let tmp = TempDir::new().unwrap();

        let bad_magic = tmp.path().join("7.png");
        write(&bad_magic, b"not-a-png-at-all");
        let r = audit_file(&bad_magic, "7.png".into(), "test", "clean", None);
        assert_eq!(r.verdict, "drop");
        assert_eq!(r.reason.as_deref(), Some("magic-mismatch"));

        let zero = tmp.path().join("8.png");
        write(&zero, b"");
        let r = audit_file(&zero, "8.png".into(), "test", "clean", None);
        assert_eq!(r.reason.as_deref(), Some("zero-byte"));

        let ambiguous = tmp.path().join("weird-name.png");
        write(&ambiguous, &png(b"x"));
        let r = audit_file(&ambiguous, "w".into(), "test", "stego", Some("raw"));
        assert_eq!(r.reason.as_deref(), Some("filename-ambiguous"));
    }

    #[test]
    fn io_error_on_missing_file_is_dropped_not_panicked() {
        let missing = Path::new("/nonexistent/dir/3.png");
        let r = audit_file(missing, "3.png".into(), "test", "clean", None);
        assert_eq!(r.verdict, "drop");
        assert!(r.reason.unwrap().starts_with("io-error"));
    }

    #[test]
    fn run_audit_aggregates_and_dedupes_across_labels() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("image_dataset");

        // train/clean: two distinct clean images.
        write(&root.join("train/train/clean/1.png"), &png(b"a"));
        write(&root.join("train/train/clean/2.png"), &png(b"b"));
        // train/stego: one valid stego + one magic-mismatch drop.
        write(
            &root.join("train/train/stego/image_1_steghide_0.png"),
            &png(b"c"),
        );
        write(
            &root.join("train/train/stego/image_2_steghide_0.png"),
            b"bad",
        );
        // test/stego_b64: a duplicate of a clean image (same bytes) → both drop.
        write(&root.join("test/test/clean/9.png"), &png(b"dup"));
        write(
            &root.join("test/test/stego_b64/image_9_outguess_0.png"),
            &png(b"dup"),
        );

        let out = tmp.path().join("audit.jsonl");
        let s = run_audit(&root, &out).unwrap();

        // Accepted: 1.png, 2.png, image_1_steghide_0.png = 3.
        assert_eq!(s.accepted, 3);
        // Dropped: bad magic (1) + the two cross-label duplicates (2) = 3.
        assert_eq!(s.dropped, 3);
        assert_eq!(s.drop_reasons.get("magic-mismatch"), Some(&1));
        assert_eq!(s.drop_reasons.get(DUP_REASON), Some(&2));
        assert_eq!(s.duplicate_hashes, 1);
        assert_eq!(s.duplicate_files, 2);
        assert_eq!(s.by_tool.get("steghide"), Some(&1));
        assert!((s.drop_rate() - 50.0).abs() < 1e-9);

        // The JSONL is one valid record per scanned file (6 total).
        let body = fs::read_to_string(&out).unwrap();
        assert_eq!(body.lines().count(), 6);
        for line in body.lines() {
            let _: AuditRecord = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn empty_dataset_has_zero_drop_rate() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("image_dataset");
        fs::create_dir_all(&root).unwrap();
        let out = tmp.path().join("audit.jsonl");
        let s = run_audit(&root, &out).unwrap();
        assert_eq!(s.total(), 0);
        assert_eq!(s.drop_rate(), 0.0);
    }
}
