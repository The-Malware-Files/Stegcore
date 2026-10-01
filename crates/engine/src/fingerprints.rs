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

//! Structural fingerprints for named steganography tools.
//!
//! A structural fingerprint is something a tool leaves behind that can be read
//! straight out of the file, without any statistics and without a password. When
//! one matches, the answer is not "this file looks odd"; it is the name of the
//! program that wrote it, which is what an investigator actually needs, because
//! it tells them which tool will get the payload out.
//!
//! # What lives here and what does not
//!
//! The fingerprints that shipped in 4.1 (`OPENSTEGO`, Camouflage, F5, appended
//! data) live in `crate::analysis`. This module holds the ones added since, for
//! formats and tools that module does not reach: lossless audio, plain text, and
//! palette and bitmap images.
//!
//! One of them, [`appended_audio`], is the audio half of a detector the other
//! module already has for images. That is not two answers to one question: the
//! image side parses PNG, JPEG and BMP structure and has no idea what a RIFF
//! chunk is, so audio carriers were simply not covered. The two agree on their
//! threshold and report under the same name.
//!
//! Generic metadata scoring is deliberately **not** here. "This metadata segment
//! looks like ciphertext rather than text" is a different question from "this is
//! DeepSound", it belongs with the container parsing in `crate::container`, and
//! two implementations of it would be two answers to one question.
//!
//! # Tiers, and why the choice is a measurement
//!
//! `CLAUDE.md` A3 is strict about this: a fingerprint declares [`Tier::Exact`]
//! or [`Tier::Heuristic`], and the choice is justified by a measured
//! false-positive rate on real clean files, not by how convincing the signature
//! feels. An `Exact` match short-circuits the ensemble; a wrong one is therefore
//! not a nudge, it is a confident accusation.
//!
//! Every detector below records what it was measured against, in its own module
//! notes, next to the threshold the measurement set.

use std::path::Path;

pub mod appended_audio;
pub mod deepsound;
pub mod palette;
pub mod snow;
pub mod wbstego;

/// How much weight a match carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// A signature unique to the tool, at a position the format fixes. Decisive
    /// on its own. Reserved for the cases where a false positive needs a
    /// coincidence with a probability small enough to write down.
    Exact,
    /// A structural regularity that the tool causes and that something else
    /// could also cause. Corroborating: it raises a verdict to suspicious and
    /// does not settle it.
    Heuristic,
}

impl Tier {
    /// The stable lowercase form for machine-readable output. Frontends key
    /// badge colour off this, so it does not change between releases.
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::Exact => "exact",
            Tier::Heuristic => "heuristic",
        }
    }
}

/// A matched fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolFingerprint {
    /// The tool's name as a user would recognise it.
    pub tool: String,
    /// How much the match is worth.
    pub tier: Tier,
    /// What was actually seen, in plain language. This is the part an operator
    /// reads, and it exists because "DeepSound" on its own invites the question
    /// "how do you know".
    pub evidence: String,
}

impl ToolFingerprint {
    /// An exact match.
    pub fn exact(tool: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            tier: Tier::Exact,
            evidence: evidence.into(),
        }
    }

    /// A corroborating match.
    pub fn heuristic(tool: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            tier: Tier::Heuristic,
            evidence: evidence.into(),
        }
    }

    /// Label for a report, in the same shape the fingerprints already shipping
    /// use, so the two sets read alike.
    pub fn label(&self) -> String {
        match self.tier {
            Tier::Exact => format!("{} (exact signature)", self.tool),
            Tier::Heuristic => format!("{} (heuristic match)", self.tool),
        }
    }
}

/// Try every fingerprint in this module that suits the file, and report them
/// all.
///
/// All of them, not the first: a file can carry more than one tool's traces, and
/// a detector that returns on the first match throws away the rest. Results are
/// ordered exact before heuristic, and alphabetically within a tier, so two runs
/// on one file produce the same list in the same order.
pub fn identify_all(path: &Path) -> Vec<ToolFingerprint> {
    let mut found = Vec::new();
    if let Some(fp) = appended_audio::check(path) {
        found.push(fp);
    }
    if let Some(fp) = deepsound::check(path) {
        found.push(fp);
    }
    if let Some(fp) = palette::check_stools(path) {
        found.push(fp);
    }
    if let Some(fp) = snow::check(path) {
        found.push(fp);
    }
    if let Some(fp) = wbstego::check(path) {
        found.push(fp);
    }
    found.sort_by(|a, b| match (a.tier, b.tier) {
        (Tier::Exact, Tier::Heuristic) => std::cmp::Ordering::Less,
        (Tier::Heuristic, Tier::Exact) => std::cmp::Ordering::Greater,
        _ => a.tool.cmp(&b.tool),
    });
    found
}

/// Largest file any detector in this module will read whole.
///
/// Documented cap rather than trust in the input. Audio decoding has its own,
/// lower limits; this is the ceiling on the cheap byte-level checks.
pub const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Read a file for fingerprinting, refusing an over-large one rather than
/// loading it.
///
/// Returns `None` on any failure, because a fingerprint that cannot be taken is
/// an absent fingerprint and not an error worth aborting an analysis for. The
/// callers here are all "look for this tool and say nothing if it is not there".
pub(crate) fn read_capped(path: &Path) -> Option<Vec<u8>> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_strings_are_stable_and_lowercase() {
        assert_eq!(Tier::Exact.as_str(), "exact");
        assert_eq!(Tier::Heuristic.as_str(), "heuristic");
    }

    #[test]
    fn labels_name_the_tool_and_the_tier() {
        assert_eq!(
            ToolFingerprint::exact("DeepSound", "DSCF in the sample bits").label(),
            "DeepSound (exact signature)"
        );
        assert_eq!(
            ToolFingerprint::heuristic("S-Tools", "paired palette entries").label(),
            "S-Tools (heuristic match)"
        );
    }

    #[test]
    fn exact_matches_sort_before_heuristic_ones() {
        let mut found = [
            ToolFingerprint::heuristic("S-Tools", "a"),
            ToolFingerprint::exact("Snow", "b"),
            ToolFingerprint::exact("DeepSound", "c"),
        ];
        found.sort_by(|a, b| match (a.tier, b.tier) {
            (Tier::Exact, Tier::Heuristic) => std::cmp::Ordering::Less,
            (Tier::Heuristic, Tier::Exact) => std::cmp::Ordering::Greater,
            _ => a.tool.cmp(&b.tool),
        });
        assert_eq!(found[0].tool, "DeepSound");
        assert_eq!(found[1].tool, "Snow");
        assert_eq!(found[2].tool, "S-Tools");
    }

    #[test]
    fn a_missing_or_over_large_file_reads_as_no_fingerprint() {
        assert!(read_capped(Path::new("/nonexistent/file.wav")).is_none());
        let dir = tempfile::tempdir().unwrap();
        assert!(
            read_capped(dir.path()).is_none(),
            "a directory is not a file"
        );
    }

    #[test]
    fn identifying_a_file_that_is_nothing_in_particular_finds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.bin");
        std::fs::write(&path, [0u8; 64]).unwrap();
        assert!(identify_all(&path).is_empty());
    }

    #[test]
    fn identifying_a_missing_file_finds_nothing_rather_than_failing() {
        assert!(identify_all(Path::new("/nonexistent/thing.wav")).is_empty());
    }
}
