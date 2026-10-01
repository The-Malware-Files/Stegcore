// Author:  Daniel Iwugo
// Comment: Christ is King
// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! The false-positive measurement behind Snow's tier.
//!
//! `CLAUDE.md` A3 requires a fingerprint's tier to be justified by a measured
//! false-positive rate on a clean corpus rather than by how convincing the
//! signature looks. Snow is the detector where that rule earns its keep: its
//! signature is whitespace at the ends of lines, and real text is full of
//! whitespace at the ends of lines.
//!
//! So rather than quoting a figure in a comment, this walks a clean corpus at test
//! time and fails if anything in it trips the detector. The corpus is this
//! repository's own text: Rust, TypeScript, Markdown, TOML, YAML and shell,
//! written and edited by hand over months. It is convenient, and it is also
//! representative of the files somebody would actually point `analyse` at.
//!
//! Two things this is and is not:
//!
//! - It **is** a standing regression gate. If a file lands in this tree that the
//!   detector flags, this fails and somebody has to decide whether the file is odd
//!   or the threshold is wrong.
//! - It is **not** a general claim about text. A codebase is text that tooling has
//!   stripped trailing whitespace from. Prose that has been through a word
//!   processor, or email, or anything exported from a spreadsheet, has not been
//!   measured. That limit is recorded in the detector's own notes too.

use std::path::{Path, PathBuf};

use stegcore_engine::fingerprints::snow;

/// Extensions treated as the clean text corpus.
const TEXT_EXTENSIONS: &[&str] = &[
    "rs", "toml", "md", "ts", "tsx", "js", "jsx", "json", "yml", "yaml", "sh", "css", "html",
    "txt", "cff", "py",
];

/// Directories skipped: build output, dependencies, and anything not written by a
/// person. `private` is skipped because it is not present in a fresh clone, so
/// including it would make the measurement depend on the machine.
const SKIP_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    "dist",
    "vendor",
    "private",
    "gen",
];

/// Walk a directory tree, bounded in depth so a symlink loop cannot hang the test.
fn collect_text_files(root: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    if depth > 12 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        // `symlink_metadata` rather than `metadata`, so a link out of the tree is
        // not followed.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) || name.starts_with('.') {
                continue;
            }
            collect_text_files(&path, depth + 1, out);
            continue;
        }
        let is_text = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| TEXT_EXTENSIONS.contains(&e))
            .unwrap_or(false);
        if is_text {
            out.push(path);
        }
    }
}

fn repository_root() -> PathBuf {
    // From crates/engine up to the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .expect("the engine crate sits two levels below the workspace root")
}

#[test]
fn snow_does_not_fire_on_this_repository_s_own_text() {
    let root = repository_root();
    let mut files = Vec::new();
    collect_text_files(&root, 0, &mut files);
    // Sorted so the report is the same on two runs regardless of directory order.
    files.sort();

    assert!(
        files.len() > 100,
        "only {} text files were found under {}, which is too few for the measurement \
         to mean anything. Has the corpus moved?",
        files.len(),
        root.display()
    );

    let mut flagged = Vec::new();
    let mut with_any_trailing_whitespace = 0usize;
    let mut worst_mixed_lines = 0usize;

    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let scan = snow::scan_text(text);
        if scan.lines_with_trailing_whitespace > 0 {
            with_any_trailing_whitespace += 1;
        }
        worst_mixed_lines = worst_mixed_lines.max(scan.lines_with_mixed_runs);
        if scan.is_match() {
            flagged.push((path.clone(), scan));
        }
    }

    println!(
        "\nSnow false-positive measurement\n\
         Corpus: {} text files under {}\n\
         Files with any trailing whitespace at all: {}\n\
         Worst file by mixed tab and space runs: {} lines (the threshold is {})\n\
         Flagged: {} ({:.3}%)\n",
        files.len(),
        root.display(),
        with_any_trailing_whitespace,
        worst_mixed_lines,
        snow::MIN_MIXED_RUN_LINES,
        flagged.len(),
        100.0 * flagged.len() as f64 / files.len() as f64,
    );

    assert!(
        flagged.is_empty(),
        "Snow flagged {} clean files, so its tier is no longer justified. First few: {:?}",
        flagged.len(),
        flagged
            .iter()
            .take(5)
            .map(|(p, s)| (p.display().to_string(), s.lines_with_mixed_runs))
            .collect::<Vec<_>>()
    );
}

#[test]
fn snow_still_fires_on_snow_shaped_text_so_the_threshold_has_not_been_raised_into_uselessness() {
    // The other half of the measurement. A false-positive rate of zero is easy to
    // reach by never matching anything, so the recall side is pinned too.
    let planted = (0..20)
        .map(|i| format!("Minutes of the meeting, item {i}.  \t \t  \t"))
        .collect::<Vec<_>>()
        .join("\n");
    let scan = snow::scan_text(&planted);
    assert!(scan.is_match());
    assert_eq!(scan.lines_with_mixed_runs, 20);
}
