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

//! The starter templates, embedded in the binary and versioned.
//!
//! Three, because three distinct jobs turned up repeatedly and a fourth would be
//! a variation on one of them:
//!
//! | template | the job | what it optimises for |
//! |---|---|---|
//! | `triage` | a pile of files, which ones deserve attention | throughput, and never missing one |
//! | `forensics` | one file, documented to a standard someone will question | a complete record |
//! | `ctf` | a puzzle, under time pressure | trying everything quickly |
//!
//! # Why they are embedded rather than downloaded
//!
//! A template fetched at run time is a supply-chain surface: whoever controls
//! the host controls what a pipeline does on every machine that ran
//! `stegcore init`. Embedded templates are reviewed in the same pull request as
//! the code and shipped in the same binary, so `stegcore init` needs no network
//! and cannot be made to write something a reviewer has not seen.
//!
//! # Why the version is on the template and not just the binary
//!
//! A template that a user has edited and a template the binary ships are
//! different files with the same name. The `# stegcore-template:` line lets the
//! tool say "this is version 1 of triage, and this build ships version 2, here
//! is what changed" instead of overwriting the user's edits or refusing to say
//! anything.
//!
//! Every template here is run through the full validator by the test suite, so a
//! starter template that does not validate cannot ship. That is the gate: a
//! curated set is only worth having if curation is enforced by something other
//! than care.

use crate::errors::StegError;
use crate::workflow::dsl::PipelineFile;

/// Version of the curated set, bumped when any template changes.
pub const TEMPLATE_VERSION: u32 = 1;

/// A starter template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Template {
    /// Name, as `stegcore init <name>` takes it.
    pub name: &'static str,
    /// One line for the help text.
    pub summary: &'static str,
    /// The TOML.
    pub body: &'static str,
}

impl Template {
    /// Parse and validate. Returns the pipeline file so a caller can show what
    /// it is about to write.
    pub fn parse(&self) -> Result<PipelineFile, StegError> {
        PipelineFile::parse_runnable(self.body)
    }
}

/// Triage: many files in, a ranked answer out.
///
/// Every detector that counts toward a verdict, plus the structural and
/// container checks, because those find things the statistical detectors cannot
/// see at all: the container scan was added after measuring that a payload in a
/// JPEG comment moved all five spatial detector scores by exactly zero.
///
/// A manifest for every file, not only the interesting ones. The clean results
/// are what make a false-positive rate measurable later, and they cost a
/// kilobyte each.
const TRIAGE: &str = r#"# stegcore-template: triage v1
#
# Watch a directory, analyse everything that lands in it, and write a record for
# every file. Extraction is attempted only on the strong hits, because a
# wordlist run costs real time per file.

[pipeline.triage]
input = "watch:./inbox"
steps = [
  { analyse = { detectors = ["spa", "rs", "ws", "fingerprint", "container", "chi_squared", "entropy"] } },
  { manifest = { out = "./records/{{sha256}}.stegcore-manifest.json" } },
  { report = { format = "csv", out = "./records/{{sha256}}.csv" } },
  { if = "verdict >= 0.7", then = { extract = { trial-passphrases = "wordlist:./passphrases.txt", out = "./recovered/{{sha256}}.bin" } } },
]
"#;

/// Forensics: one file, recorded completely.
///
/// Every detector, including the two excluded from the verdict, because an
/// examiner is asked what was run and "we skipped two" is a worse answer than a
/// number with a caveat attached. A manifest unconditionally, and no extraction:
/// recovering a payload is a separate, deliberate act with its own authorisation,
/// not something a pipeline does on the way past.
const FORENSICS: &str = r#"# stegcore-template: forensics v1
#
# One file at a time, measured exhaustively, with a manifest that records what
# was run and what it found. Nothing here attempts extraction: that is a separate
# decision with its own authorisation, and a pipeline is the wrong place to make
# it quietly.
#
# Point `input` at the file. Keep the manifest with the exhibit.

[pipeline.forensics]
input = "path:./exhibit.png"
steps = [
  { analyse = { detectors = ["spa", "rs", "ws", "chi_squared", "entropy", "audio_spa", "fingerprint", "container", "dct"] } },
  { manifest = { out = "./{{filename}}.stegcore-manifest.json" } },
  { report = { format = "json", out = "./{{stem}}-analysis.json" } },
  { report = { format = "text", out = "./{{stem}}-analysis.txt" } },
]
"#;

/// CTF: a directory of puzzle files, and not much patience.
///
/// The structural checks first, because a competition file is far more likely to
/// have been made by a named tool than by a careful adversary, and a fingerprint
/// answers the question outright. Extraction on a low threshold, because a false
/// positive costs seconds and a missed flag costs the round.
const CTF: &str = r#"# stegcore-template: ctf v1
#
# Everything in a directory, fast, with extraction tried on anything that looks
# remotely interesting. The threshold is deliberately low: in a competition a
# wasted wordlist run costs seconds and a missed file costs the round.

[pipeline.ctf]
input = "glob:./challenge/*"
steps = [
  { analyse = { detectors = ["fingerprint", "container", "spa", "rs", "ws", "dct", "entropy"] } },
  { report = { format = "text", out = "./results/{{stem}}.txt" } },
  { if = "verdict > 0.25", then = { extract = { trial-passphrases = "wordlist:./rockyou-short.txt", out = "./loot/{{stem}}.bin" } } },
]
"#;

/// The curated set.
pub const TEMPLATES: &[Template] = &[
    Template {
        name: "triage",
        summary: "watch a directory and record every file, extracting only the strong hits",
        body: TRIAGE,
    },
    Template {
        name: "forensics",
        summary: "measure one exhibit exhaustively and keep a manifest with it",
        body: FORENSICS,
    },
    Template {
        name: "ctf",
        summary: "sweep a directory of puzzle files quickly, trying extraction readily",
        body: CTF,
    },
];

/// Look a template up by name.
pub fn template(name: &str) -> Result<&'static Template, StegError> {
    TEMPLATES.iter().find(|t| t.name == name).ok_or_else(|| {
        StegError::UnsupportedFormat(format!(
            "there is no starter template called {name:?}. The templates are: {}",
            TEMPLATES
                .iter()
                .map(|t| t.name)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::dsl::Detector;

    /// The gate: a shipped template that does not validate cannot ship.
    #[test]
    fn every_shipped_template_parses_and_validates() {
        for template in TEMPLATES {
            let file = template
                .parse()
                .unwrap_or_else(|e| panic!("{}: {e}", template.name));
            assert_eq!(file.pipelines.len(), 1, "{}", template.name);
            assert!(
                file.pipelines.contains_key(template.name),
                "{} does not define a pipeline of its own name",
                template.name
            );
        }
    }

    #[test]
    fn every_template_carries_its_version_line() {
        for template in TEMPLATES {
            let first = template.body.lines().next().unwrap_or_default();
            assert!(
                first.starts_with("# stegcore-template: "),
                "{} opens with {first:?}",
                template.name
            );
            assert!(
                first.ends_with(&format!("v{TEMPLATE_VERSION}")),
                "{} is not at v{TEMPLATE_VERSION}: {first:?}",
                template.name
            );
            assert!(
                first.contains(template.name),
                "{} does not name itself in its version line",
                template.name
            );
        }
    }

    #[test]
    fn every_template_has_a_summary_and_a_unique_name() {
        let mut names: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "two templates share a name");
        for template in TEMPLATES {
            assert!(!template.summary.is_empty(), "{}", template.name);
            assert!(
                template.summary.len() < 100,
                "{} summary is a paragraph",
                template.name
            );
        }
    }

    #[test]
    fn the_three_templates_the_roadmap_names_are_the_three_that_exist() {
        let names: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        assert_eq!(names, ["triage", "forensics", "ctf"]);
    }

    #[test]
    fn templates_are_found_by_name() {
        for expected in TEMPLATES {
            assert_eq!(template(expected.name).expect("found"), expected);
        }
    }

    #[test]
    fn an_unknown_template_name_lists_the_real_ones() {
        let err = template("triaage").expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("triaage"), "{message}");
        assert!(message.contains("triage, forensics, ctf"), "{message}");
    }

    /// Forensics claims to measure exhaustively, so the claim is checked rather
    /// than trusted: if a detector is added to the engine and not to this
    /// template, the suite says so.
    #[test]
    fn the_forensics_template_names_every_detector_except_the_network_one() {
        let file = template("forensics")
            .expect("found")
            .parse()
            .expect("valid");
        let step = &file.pipelines["forensics"].steps[0];
        let crate::workflow::dsl::Step::Analyse { detectors } = step else {
            panic!("the first step of forensics should be an analysis, got {step:?}");
        };
        for detector in Detector::ALL {
            // `covert` reads a packet capture, not a media file, so it has no
            // place in a pipeline pointed at an exhibit image.
            if *detector == Detector::Covert {
                continue;
            }
            assert!(
                detectors.contains(detector),
                "the forensics template omits {}, which claims to be exhaustive",
                detector.slug()
            );
        }
    }

    #[test]
    fn the_forensics_template_never_attempts_extraction() {
        let file = template("forensics")
            .expect("found")
            .parse()
            .expect("valid");
        for step in &file.pipelines["forensics"].steps {
            assert_ne!(
                step.kind(),
                "extract",
                "forensics documents, it does not recover"
            );
        }
    }

    #[test]
    fn the_triage_template_records_every_file_and_not_only_the_hits() {
        let file = template("triage").expect("found").parse().expect("valid");
        let steps = &file.pipelines["triage"].steps;
        let manifest = steps
            .iter()
            .find(|s| s.kind() == "manifest")
            .expect("triage writes a manifest");
        assert!(
            !matches!(manifest, crate::workflow::dsl::Step::Conditional { .. }),
            "the manifest is conditional, so clean files would leave no record"
        );
    }

    #[test]
    fn the_triage_and_ctf_templates_both_gate_extraction_on_a_condition() {
        for name in ["triage", "ctf"] {
            let file = template(name).expect("found").parse().expect("valid");
            let gated = file.pipelines[name].steps.iter().any(|step| {
                matches!(step, crate::workflow::dsl::Step::Conditional { then, .. }
                    if then.kind() == "extract")
            });
            assert!(gated, "{name} extracts unconditionally");
        }
    }

    #[test]
    fn the_ctf_template_puts_the_structural_checks_first() {
        let file = template("ctf").expect("found").parse().expect("valid");
        let crate::workflow::dsl::Step::Analyse { detectors } = &file.pipelines["ctf"].steps[0]
        else {
            panic!("ctf should start by analysing");
        };
        assert_eq!(detectors[0], Detector::Fingerprint);
        assert_eq!(detectors[1], Detector::Container);
    }
}
