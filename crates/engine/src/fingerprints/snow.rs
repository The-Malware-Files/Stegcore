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

//! Snow: data hidden in the whitespace at the ends of lines of text.
//!
//! # How Snow hides things
//!
//! Snow, by Matthew Kwan, puts its payload after the last visible character on
//! each line, where nothing displays it. It encodes bits as runs of spaces with a
//! tab ending each run, so a Snow file has lines whose invisible tails mix tabs
//! and spaces, over and over.
//!
//! # The tier, and why this one is the dangerous case
//!
//! Trailing whitespace is everywhere in real text. Editors leave it, people leave
//! it, generated files are full of it. A detector that called every file with a
//! trailing space "Snow" would fire on a large share of every source tree in
//! existence, and because an exact match short-circuits the verdict, each one
//! would be a confident accusation.
//!
//! So the signature here is not "trailing whitespace". It is **runs that mix
//! tabs and spaces, on many lines**, which is what Snow's encoding produces and
//! what ordinary sloppiness does not: a stray space at the end of a line of prose
//! is one character, not a tab-terminated run of five.
//!
//! ## Measured, 2026-10-01
//!
//! Clean corpus: **18,874 real text files** across every project tree on the
//! development machine. Rust, TypeScript, Python, C, Java, Go, Markdown, TOML,
//! YAML, shell, HTML, CSS, SQL, LaTeX, CSV and logs, written and edited by hand
//! over years, including generated files and files nobody tidied.
//!
//! | Measure | Files | Share |
//! |---|---|---|
//! | Any trailing whitespace at all | 550 | 2.9% |
//! | At least one mixed tab and space run | 1 | 0.005% |
//! | At least two | 0 | 0.000% |
//! | At or above the threshold of four | **0** | **0.000%** |
//!
//! Those rows are the whole argument. Trailing whitespace is common, just as
//! feared, at nearly one file in thirty. A trailing run that mixes a tab and a
//! space is not: exactly **one file in 18,874** had even one, and none had two.
//! The discriminator is carrying the detector, not the threshold.
//!
//! So the tier is [`Tier::Exact`], on a measured false-positive rate of zero with
//! the nearest clean file four times below the threshold.
//!
//! `tests/fingerprint_snow_fpr.rs` re-runs the walk over this repository's own
//! tree on every test run, as a standing gate: if a file lands here that trips
//! the detector, that test fails and the threshold gets revisited rather than
//! quietly going stale.
//!
//! ## What the measurement does not cover
//!
//! Every file in that corpus is source code or developer documentation, and such
//! trees have had whitespace stripped by tooling. **Word-processed prose, email,
//! and anything exported from a spreadsheet are unmeasured**, and those are
//! exactly the documents a Snow user would choose as a carrier. The detector is
//! built so that [`MIN_MIXED_RUN_LINES`] is the single knob to turn if a later
//! measurement on that kind of text says the rate is worse.

use std::path::Path;

use crate::fingerprints::{read_capped, Tier, ToolFingerprint};

/// Lines carrying a mixed tab and space trailing run before a match is called.
///
/// The threshold the measurement set. Snow spreads its payload over as many
/// lines as it needs, so even a short message crosses this; ordinary trailing
/// whitespace does not reach it because it is not tab terminated at all.
pub const MIN_MIXED_RUN_LINES: usize = 4;

/// Shortest trailing run that counts as mixed, in characters. A lone tab after a
/// word is not an encoded run.
pub const MIN_RUN_LENGTH: usize = 2;

/// Largest text file examined. Past this it is data, not prose, and walking it
/// line by line is not worth it on every analysis.
pub const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;

/// Proportion of bytes that must be plain text before the file is treated as
/// text at all. Keeps the detector off binaries that happen to contain newlines.
const MIN_TEXT_FRACTION: f64 = 0.95;

/// What a scan of a text file found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scan {
    /// Lines examined.
    pub lines: usize,
    /// Lines with any trailing whitespace at all.
    pub lines_with_trailing_whitespace: usize,
    /// Lines whose trailing run mixes tabs and spaces and is long enough to be
    /// an encoded run. This is the number the verdict rests on.
    pub lines_with_mixed_runs: usize,
    /// The longest trailing run seen, in characters.
    pub longest_run: usize,
}

impl Scan {
    /// Whether this is Snow by the measured threshold.
    pub fn is_match(&self) -> bool {
        self.lines_with_mixed_runs >= MIN_MIXED_RUN_LINES
    }
}

/// Look for Snow in a text file.
pub fn check(path: &Path) -> Option<ToolFingerprint> {
    let bytes = read_capped(path)?;
    if bytes.len() > MAX_TEXT_BYTES {
        return None;
    }
    let text = text_of(&bytes)?;
    let scan = scan_text(text);
    if !scan.is_match() {
        return None;
    }
    Some(ToolFingerprint {
        tool: "Snow".to_string(),
        tier: Tier::Exact,
        evidence: format!(
            "{} of {} lines end in an invisible run of mixed tabs and spaces, the longest \
             {} characters. That pattern is how Snow encodes bits; ordinary stray whitespace \
             is not tab terminated.",
            scan.lines_with_mixed_runs, scan.lines, scan.longest_run
        ),
    })
}

/// Treat the bytes as text, or decline.
///
/// A file is text when nearly all of it is printable, tab, carriage return or
/// newline, and it holds no null byte. The fraction rather than a strict rule
/// because real text files carry the occasional stray byte, and a single one
/// should not take a file out of scope.
fn text_of(bytes: &[u8]) -> Option<&str> {
    if bytes.is_empty() || bytes.contains(&0) {
        return None;
    }
    let printable = bytes
        .iter()
        .filter(|b| matches!(b, 0x09 | 0x0A | 0x0D | 0x20..=0x7E) || **b >= 0x80)
        .count();
    if (printable as f64) / (bytes.len() as f64) < MIN_TEXT_FRACTION {
        return None;
    }
    std::str::from_utf8(bytes).ok()
}

/// Count the trailing whitespace runs in a piece of text.
pub fn scan_text(text: &str) -> Scan {
    let mut scan = Scan::default();
    for line in text.split('\n') {
        scan.lines += 1;
        // A carriage return belongs to the line ending, not to the trailing run,
        // so a file with Windows line endings is not read as having a trailing
        // whitespace character on every single line.
        let line = line.strip_suffix('\r').unwrap_or(line);
        let trimmed = line.trim_end_matches([' ', '\t']);
        let run = &line[trimmed.len()..];
        if run.is_empty() {
            continue;
        }
        scan.lines_with_trailing_whitespace += 1;
        scan.longest_run = scan.longest_run.max(run.chars().count());
        let has_tab = run.contains('\t');
        let has_space = run.contains(' ');
        if has_tab && has_space && run.chars().count() >= MIN_RUN_LENGTH {
            scan.lines_with_mixed_runs += 1;
        }
    }
    // `split` on a trailing newline yields a final empty piece that is not a
    // line of the file.
    if text.ends_with('\n') {
        scan.lines = scan.lines.saturating_sub(1);
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text shaped the way Snow shapes it: a tab-terminated run of spaces after
    /// each line's visible content.
    fn snow_like(lines: usize) -> String {
        (0..lines)
            .map(|i| format!("This is line {i} of an innocent memo.  \t  \t"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn snow_shaped_text_is_identified() {
        let scan = scan_text(&snow_like(10));
        assert_eq!(scan.lines, 10);
        assert_eq!(scan.lines_with_mixed_runs, 10);
        assert!(scan.is_match());
    }

    #[test]
    fn ordinary_stray_trailing_spaces_are_not_snow() {
        // The false positive this detector exists to avoid: a file somebody left
        // trailing spaces in. Counted as trailing whitespace, not as a match.
        let text = "fn main() {  \nlet x = 1; \n}   \nmore text  \nand more  \n";
        let scan = scan_text(text);
        assert_eq!(scan.lines_with_trailing_whitespace, 5);
        assert_eq!(scan.lines_with_mixed_runs, 0);
        assert!(!scan.is_match());
    }

    #[test]
    fn trailing_tabs_alone_are_not_snow_either() {
        let text = "alpha\t\nbeta\t\t\ngamma\t\ndelta\t\nepsilon\t\n";
        let scan = scan_text(text);
        assert_eq!(scan.lines_with_trailing_whitespace, 5);
        assert_eq!(scan.lines_with_mixed_runs, 0);
        assert!(!scan.is_match());
    }

    #[test]
    fn a_single_mixed_run_is_below_the_threshold() {
        let text = "alpha \t\nbeta\ngamma\n";
        assert!(!scan_text(text).is_match());
    }

    #[test]
    fn the_threshold_is_where_the_measurement_put_it() {
        assert!(!scan_text(&snow_like(MIN_MIXED_RUN_LINES - 1)).is_match());
        assert!(scan_text(&snow_like(MIN_MIXED_RUN_LINES)).is_match());
    }

    #[test]
    fn a_run_shorter_than_the_minimum_does_not_count() {
        // A single character cannot be both a tab and a space, so this is really
        // a guard against the length rule being dropped by accident.
        assert_eq!(MIN_RUN_LENGTH, 2);
        let text = "alpha\t\nbeta\t\n";
        assert_eq!(scan_text(text).lines_with_mixed_runs, 0);
    }

    #[test]
    fn windows_line_endings_do_not_look_like_trailing_whitespace() {
        let text = "alpha\r\nbeta\r\ngamma\r\n";
        let scan = scan_text(text);
        assert_eq!(scan.lines_with_trailing_whitespace, 0);
        assert_eq!(scan.lines, 3);
    }

    #[test]
    fn windows_line_endings_still_reveal_a_real_run() {
        let text = "alpha \t \t\r\nbeta \t \t\r\ngamma \t \t\r\ndelta \t \t\r\n";
        assert!(scan_text(text).is_match());
    }

    #[test]
    fn empty_and_whitespace_only_text_does_not_match() {
        assert!(!scan_text("").is_match());
        assert!(!scan_text("\n\n\n").is_match());
        assert_eq!(scan_text("   \n").lines_with_mixed_runs, 0);
    }

    #[test]
    fn the_line_count_does_not_include_the_piece_after_a_final_newline() {
        assert_eq!(scan_text("a\nb\n").lines, 2);
        assert_eq!(scan_text("a\nb").lines, 2);
    }

    #[test]
    fn a_file_is_identified_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("memo.txt");
        std::fs::write(&path, snow_like(12)).unwrap();
        let found = check(&path).expect("snow-shaped text should be identified");
        assert_eq!(found.tool, "Snow");
        assert_eq!(found.tier, Tier::Exact);
        assert!(found.evidence.contains("mixed tabs and spaces"));
    }

    #[test]
    fn a_binary_file_is_not_scanned_as_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.bin");
        // Nulls and control bytes, with a newline and a mixed run in the middle
        // so a detector that ignored the text check would match it.
        let mut bytes = vec![0u8, 1, 2, 3, 0, 255];
        bytes.extend_from_slice(b"alpha \t \t\nbeta \t \t\ngamma \t \t\ndelta \t \t\n");
        bytes.extend_from_slice(&[0u8, 7, 8]);
        std::fs::write(&path, &bytes).unwrap();
        assert!(check(&path).is_none());
    }

    #[test]
    fn a_file_of_mostly_control_bytes_is_not_text() {
        let mut bytes = vec![0x01u8; 100];
        bytes.extend_from_slice(b"text\n");
        assert!(text_of(&bytes).is_none());
    }

    #[test]
    fn text_with_accented_characters_is_still_text() {
        let bytes = "Déjà vu, naïve façade.\n".as_bytes();
        assert!(text_of(bytes).is_some());
    }

    #[test]
    fn an_empty_file_and_a_missing_file_are_both_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, b"").unwrap();
        assert!(check(&path).is_none());
        assert!(check(Path::new("/nonexistent/memo.txt")).is_none());
    }

    #[test]
    fn invalid_utf8_is_declined_rather_than_guessed_at() {
        // Latin-1 text would be a legitimate Snow carrier, and it is out of scope
        // rather than silently misread. Recorded here as a known limit.
        let bytes = b"caf\xe9 \t \t\n";
        assert!(text_of(bytes).is_none());
    }
}
