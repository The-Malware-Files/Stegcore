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

//! The pipeline file: declarative TOML for an analysis run.
//!
//! # The shape
//!
//! ```toml
//! [pipeline.triage]
//! input = "watch:./inbox"
//! steps = [
//!   { analyse = { detectors = ["spa", "rs", "ws", "fingerprint"] } },
//!   { if = "verdict > 0.7", then = { extract = { trial-passphrases = "wordlist:./pw" } } },
//!   { report = { format = "json", out = "./reports/{{filename}}.json" } },
//! ]
//! ```
//!
//! # The one rule that makes this worth having
//!
//! **The whole pipeline is validated before any step runs.** A typo in step four
//! fails before step one writes a byte. That is the difference between a
//! declarative pipeline and a shell script, and it is the reason to prefer one:
//! a shell script discovers its own mistakes halfway through, having already
//! written files it will not clean up.
//!
//! [`Pipeline::validate`] therefore returns **every** problem rather than the
//! first. A contributor fixing a file wants the list, not one round trip per
//! typo, and each problem carries the path to the thing that caused it, in the
//! shape `pipeline.triage.steps[3].report.out`.
//!
//! Validation is pure: it reads no file, creates no directory and touches no
//! network. What it cannot check without running (does `./pw` exist, is
//! `./reports` writable) is deliberately out of scope here and belongs to the
//! runner's own pre-flight, so that validating a file someone sent you has no
//! side effects at all.
//!
//! # What is not in the language
//!
//! No loops, no variables, no shell-out, no `include`. A step cannot run a
//! command. The condition language is one comparison; see
//! [`crate::workflow::condition`] for why.
//!
//! Output paths carry placeholders, and a placeholder is the one place a hostile
//! file name reaches a path. [`OutputTemplate`] handles that at the boundary:
//! a name is reduced to its final component before it is substituted, so a
//! recursive watch over a directory holding `../../etc/passwd` cannot escape the
//! declared output directory.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::errors::StegError;
use crate::workflow::condition::Condition;

/// Largest pipeline file read from disk.
///
/// A readable pipeline is under a kilobyte. This is three orders of magnitude of
/// headroom and still bounds the TOML parser's input.
pub const MAX_PIPELINE_BYTES: u64 = 1024 * 1024;

/// Most pipelines in one file.
pub const MAX_PIPELINES: usize = 64;

/// Most steps in one pipeline.
pub const MAX_STEPS: usize = 64;

/// Deepest a conditional may nest.
///
/// A conditional holds a step, and that step may itself be a conditional, so the
/// structure is recursive and needs a bound before a hostile file can recurse the
/// validator into a stack overflow. Two levels is past anything readable.
pub const MAX_NESTING: usize = 4;

/// Longest output template accepted.
pub const MAX_TEMPLATE_BYTES: usize = 512;

/// Longest input specification accepted.
pub const MAX_INPUT_BYTES: usize = 512;

/// A detector a pipeline may name.
///
/// The slug is the pipeline's contract and the display name is what the report
/// shows. Both live here so the DSL has one table: the CLI already notes that
/// deciding "does this count toward the verdict" in two places is a drift risk,
/// and adding a third would make it worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    /// Chi-squared test of the LSB plane.
    ChiSquared,
    /// Sample Pair Analysis.
    Spa,
    /// RS analysis.
    Rs,
    /// Weighted Stego.
    Ws,
    /// LSB-plane entropy.
    Entropy,
    /// Sample Pair Analysis over audio samples.
    AudioSpa,
    /// Structural tool fingerprints.
    Fingerprint,
    /// Payloads parked in container metadata.
    Container,
    /// JPEG DCT-domain features.
    Dct,
    /// Covert-channel statistics over a capture.
    Covert,
}

impl Detector {
    /// Every slug, in the order the variants are declared, which is the order a
    /// report lists them.
    pub const SLUGS: &'static [&'static str] = &[
        "chi_squared",
        "spa",
        "rs",
        "ws",
        "entropy",
        "audio_spa",
        "fingerprint",
        "container",
        "dct",
        "covert",
    ];

    /// All variants.
    pub const ALL: &'static [Detector] = &[
        Detector::ChiSquared,
        Detector::Spa,
        Detector::Rs,
        Detector::Ws,
        Detector::Entropy,
        Detector::AudioSpa,
        Detector::Fingerprint,
        Detector::Container,
        Detector::Dct,
        Detector::Covert,
    ];

    /// The slug written in a pipeline file.
    ///
    /// An explicit match rather than an index into [`Self::SLUGS`], so adding a
    /// variant is a compile error here instead of a silent fallback to the wrong
    /// slug.
    pub fn slug(self) -> &'static str {
        match self {
            Self::ChiSquared => "chi_squared",
            Self::Spa => "spa",
            Self::Rs => "rs",
            Self::Ws => "ws",
            Self::Entropy => "entropy",
            Self::AudioSpa => "audio_spa",
            Self::Fingerprint => "fingerprint",
            Self::Container => "container",
            Self::Dct => "dct",
            Self::Covert => "covert",
        }
    }

    /// Resolve a slug, or `None` if nothing matches.
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::SLUGS
            .iter()
            .position(|s| *s == slug)
            .map(|at| Self::ALL[at])
    }

    /// Whether this detector's score is allowed to move a verdict.
    ///
    /// Chi-squared and LSB entropy are excluded on measured evidence, not habit:
    /// both fire on ordinary photographic texture. They stay in the report
    /// because they are informative to a human reading it.
    pub fn counts_toward_verdict(self) -> bool {
        !matches!(self, Self::ChiSquared | Self::Entropy)
    }

    /// Whether this detector runs at all on a recording.
    ///
    /// Recorded here now, before anything executes a pipeline, because the
    /// obvious runner gets this wrong in a way that is invisible: it filters the
    /// detector list against whatever the carrier produced, finds nothing for a
    /// detector that cannot run, and reports a pipeline that did less than it
    /// was asked to as a pipeline that succeeded. A selection that silently
    /// means nothing is worse than a refusal, because the operator reads the
    /// absence of a complaint as a result.
    ///
    /// Chi-squared and LSB entropy left the audio path on measured grounds
    /// rather than tidiness: neither counts toward a verdict for any carrier, so
    /// computing them meant decoding the whole stream a second time to produce
    /// two numbers nobody could act on. Removing them took analysis of a
    /// thirteen-minute stereo recording from 3.29 s to 1.81 s.
    ///
    /// The image-domain pair statistic is a separate detector from the audio one
    /// and keeps its own name, because the image threshold is calibrated on
    /// images and means nothing on a waveform; a clean white-noise recording
    /// reads 0.599, which is above the image threshold of 0.377.
    pub fn runs_on_audio(self) -> bool {
        match self {
            // Measured on real recordings, and the one detector here with a
            // number behind it rather than an absence.
            Self::AudioSpa => true,
            // Structural, so they read the container rather than the samples and
            // work on any carrier.
            Self::Fingerprint | Self::Container => true,
            // Image-domain, or in the covert case packet-domain. None of them has
            // a meaning on a waveform.
            Self::ChiSquared
            | Self::Spa
            | Self::Rs
            | Self::Ws
            | Self::Entropy
            | Self::Dct
            | Self::Covert => false,
        }
    }
}

/// Where a pipeline's files come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputSource {
    /// One file.
    Path(String),
    /// A shell-style glob, expanded by the runner.
    Glob(String),
    /// A file holding one path per line.
    List(String),
    /// A directory watched for new files.
    Watch(String),
}

impl InputSource {
    /// Parse the `scheme:value` form.
    pub fn parse(text: &str) -> Result<Self, StegError> {
        if text.len() > MAX_INPUT_BYTES {
            return Err(problem(format!(
                "an input of {} characters, past the {MAX_INPUT_BYTES} limit",
                text.len()
            )));
        }
        let Some((scheme, value)) = text.split_once(':') else {
            return Err(problem(format!(
                "{text:?} does not say what kind of input it is. Write one of \
                 path:, glob:, list: or watch: in front of it, as in \
                 \"watch:./inbox\""
            )));
        };
        let value = value.trim();
        if value.is_empty() {
            return Err(problem(format!(
                "{text:?} names no location after the {scheme}:"
            )));
        }
        match scheme {
            "path" => Ok(Self::Path(value.to_string())),
            "glob" => Ok(Self::Glob(value.to_string())),
            "list" => Ok(Self::List(value.to_string())),
            "watch" => Ok(Self::Watch(value.to_string())),
            other => Err(problem(format!(
                "{other:?} is not a kind of input. The kinds are path, glob, list and watch"
            ))),
        }
    }

    /// The location, whatever the kind.
    pub fn location(&self) -> &str {
        match self {
            Self::Path(v) | Self::Glob(v) | Self::List(v) | Self::Watch(v) => v,
        }
    }

    /// Whether this source never finishes, which changes what a runner may do
    /// after the last step.
    pub fn is_continuous(&self) -> bool {
        matches!(self, Self::Watch(_))
    }
}

/// What a report is written as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    /// Machine-readable.
    Json,
    /// One row per input.
    Csv,
    /// The table a human reads in a terminal.
    Text,
}

/// Placeholders an output template may use.
///
/// An allowlist, so `{{filenam}}` is a validation failure rather than a literal
/// brace in a file name nobody notices for a month.
pub const PLACEHOLDERS: &[&str] = &["filename", "stem", "ext", "sha256", "verdict"];

/// An output path with placeholders in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputTemplate(pub String);

impl OutputTemplate {
    /// Check the template's shape. Does not touch the filesystem.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let text = &self.0;

        if text.is_empty() {
            problems.push("the output path is empty".to_string());
            return problems;
        }
        if text.len() > MAX_TEMPLATE_BYTES {
            problems.push(format!(
                "the output path is {} characters, past the {MAX_TEMPLATE_BYTES} limit",
                text.len()
            ));
            return problems;
        }

        let mut rest = text.as_str();
        let mut used = Vec::new();
        while let Some(open) = rest.find("{{") {
            let after = &rest[open + 2..];
            let Some(close) = after.find("}}") else {
                problems.push(format!(
                    "{text:?} opens a placeholder with {{{{ and never closes it with }}}}"
                ));
                break;
            };
            let name = after[..close].trim();
            if PLACEHOLDERS.contains(&name) {
                used.push(name.to_string());
            } else {
                problems.push(format!(
                    "{text:?} uses the placeholder {{{{{name}}}}}, which does not exist. \
                     The placeholders are: {}",
                    PLACEHOLDERS.join(", ")
                ));
            }
            rest = &after[close + 2..];
        }

        // A template with no placeholder writes every input to one path, so the
        // last file silently overwrites the rest. Worth a word, because the
        // failure is invisible: the run succeeds and the evidence is gone.
        if used.is_empty() && !problems.iter().any(|p| p.contains("placeholder")) {
            problems.push(format!(
                "{text:?} has no placeholder in it, so every input would be written \
                 to the same file and only the last one would survive. Add \
                 {{{{filename}}}} or {{{{sha256}}}}."
            ));
        }

        problems
    }

    /// Substitute values, keeping the result inside the template's own directory.
    ///
    /// Every substituted value is reduced to its last path component first. A
    /// file name is attacker-controlled in the one mode that matters, a watched
    /// directory, and a value of `../../etc/cron.d/x` would otherwise write
    /// wherever the operator's privileges reach. Stripping to the final
    /// component is the containment, and it happens here rather than at each
    /// call site so there is one place to get it right.
    pub fn expand(&self, values: &BTreeMap<&str, String>) -> String {
        let mut out = self.0.clone();
        for name in PLACEHOLDERS {
            let needle = format!("{{{{{name}}}}}");
            if !out.contains(&needle) {
                continue;
            }
            let raw = values.get(name).map(String::as_str).unwrap_or("unknown");
            out = out.replace(&needle, &safe_component(raw));
        }
        out
    }
}

/// Reduce a value to something that cannot change which directory it lands in.
fn safe_component(value: &str) -> String {
    let last = value.rsplit(['/', '\\']).next().unwrap_or(value);
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && *c != ':')
        .collect();
    let trimmed = cleaned.trim_matches('.').trim();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

/// One step of a pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Step {
    /// Run detectors over the input.
    Analyse {
        /// Which detectors, in the order given.
        detectors: Vec<Detector>,
    },
    /// Try to recover a payload.
    Extract {
        /// A `wordlist:` source of trial passphrases, when one was given.
        trial_passphrases: Option<String>,
        /// Where a recovered payload is written.
        out: Option<OutputTemplate>,
    },
    /// Write the analysis out.
    Report {
        /// Serialisation.
        format: ReportFormat,
        /// Destination.
        out: OutputTemplate,
    },
    /// Write a reproducibility manifest.
    Manifest {
        /// Destination.
        out: OutputTemplate,
    },
    /// Run a step only if a condition holds.
    Conditional {
        /// The comparison.
        condition: Condition,
        /// What to run when it holds.
        then: Box<Step>,
    },
}

impl Step {
    /// The step's name, for an error path.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Analyse { .. } => "analyse",
            Self::Extract { .. } => "extract",
            Self::Report { .. } => "report",
            Self::Manifest { .. } => "manifest",
            Self::Conditional { .. } => "if",
        }
    }

    /// Whether this step, or anything inside it, reads the analysis.
    fn needs_analysis(&self) -> bool {
        match self {
            Self::Analyse { .. } => false,
            Self::Report { .. } | Self::Manifest { .. } => true,
            Self::Extract { .. } => false,
            Self::Conditional { .. } => true,
        }
    }

    fn validate_into(&self, path: &str, depth: usize, problems: &mut Vec<Problem>) {
        if depth > MAX_NESTING {
            problems.push(Problem::new(
                path,
                format!("conditionals nest more than {MAX_NESTING} deep"),
            ));
            return;
        }

        match self {
            Self::Analyse { detectors } => {
                if detectors.is_empty() {
                    problems.push(Problem::new(
                        &format!("{path}.analyse.detectors"),
                        "no detectors, so the step would measure nothing".to_string(),
                    ));
                }
                let mut sorted = detectors.clone();
                sorted.sort();
                let before = sorted.len();
                sorted.dedup();
                if sorted.len() != before {
                    problems.push(Problem::new(
                        &format!("{path}.analyse.detectors"),
                        "the same detector is named twice, which would run it twice".to_string(),
                    ));
                }
                if detectors.iter().all(|d| !d.counts_toward_verdict()) {
                    problems.push(Problem::new(
                        &format!("{path}.analyse.detectors"),
                        "every detector named here is excluded from the verdict, so \
                         a later condition on `verdict` would always read zero"
                            .to_string(),
                    ));
                }
            }
            Self::Extract {
                trial_passphrases,
                out,
            } => {
                if let Some(source) = trial_passphrases {
                    match source.split_once(':') {
                        Some(("wordlist", value)) if !value.trim().is_empty() => {}
                        _ => problems.push(Problem::new(
                            &format!("{path}.extract.trial-passphrases"),
                            format!(
                                "{source:?} is not a passphrase source. Write \
                                 \"wordlist:<path>\""
                            ),
                        )),
                    }
                }
                if let Some(template) = out {
                    for reason in template.validate() {
                        problems.push(Problem::new(&format!("{path}.extract.out"), reason));
                    }
                }
            }
            Self::Report { out, .. } => {
                for reason in out.validate() {
                    problems.push(Problem::new(&format!("{path}.report.out"), reason));
                }
            }
            Self::Manifest { out } => {
                for reason in out.validate() {
                    problems.push(Problem::new(&format!("{path}.manifest.out"), reason));
                }
            }
            Self::Conditional { condition, then } => {
                if let Err(e) = condition.validate() {
                    problems.push(Problem::new(&format!("{path}.if"), e.to_string()));
                }
                if matches!(**then, Self::Conditional { .. }) {
                    problems.push(Problem::new(
                        &format!("{path}.then"),
                        "a conditional directly inside a conditional. Two steps with \
                         one condition each read better and behave the same"
                            .to_string(),
                    ));
                }
                then.validate_into(&format!("{path}.then"), depth + 1, problems);
            }
        }
    }
}

/// A problem found during validation, with the path to what caused it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Where in the file, as a dotted path.
    pub at: String,
    /// What is wrong, in plain words.
    pub reason: String,
}

impl Problem {
    fn new(at: &str, reason: String) -> Self {
        Self {
            at: at.to_string(),
            reason,
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.at, self.reason)
    }
}

/// One named pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pipeline {
    /// Name, as it appears in `[pipeline.<name>]`.
    pub name: String,
    /// Where the files come from.
    pub input: InputSource,
    /// What to do with each one, in order.
    pub steps: Vec<Step>,
}

/// A whole pipeline file, which may hold several pipelines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PipelineFile {
    /// Pipelines by name, ordered so two reads of one file agree.
    pub pipelines: BTreeMap<String, Pipeline>,
}

impl Pipeline {
    /// Every problem with this pipeline. Empty means it is runnable.
    pub fn validate(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        let path = format!("pipeline.{}", self.name);

        if self.name.is_empty() {
            problems.push(Problem::new(
                "pipeline",
                "a pipeline with no name".to_string(),
            ));
        }
        if self.steps.is_empty() {
            problems.push(Problem::new(
                &format!("{path}.steps"),
                "no steps, so running it would do nothing".to_string(),
            ));
        }
        if self.steps.len() > MAX_STEPS {
            problems.push(Problem::new(
                &format!("{path}.steps"),
                format!("{} steps, past the {MAX_STEPS} limit", self.steps.len()),
            ));
        }

        // Ordering: a step that reads the analysis before anything produced one
        // is the mistake the whole-pipeline check exists to catch, and it is
        // invisible when each step is read on its own.
        let mut analysed = false;
        for (index, step) in self.steps.iter().enumerate() {
            let step_path = format!("{path}.steps[{index}]");
            if step.needs_analysis() && !analysed {
                problems.push(Problem::new(
                    &format!("{step_path}.{}", step.kind()),
                    "this step reads the analysis, and no `analyse` step has run yet".to_string(),
                ));
            }
            if matches!(step, Step::Analyse { .. }) {
                analysed = true;
            }
            step.validate_into(&step_path, 0, &mut problems);
        }

        // A pipeline that measures and then throws the result away is almost
        // certainly an unfinished file, and saying so costs nothing.
        if analysed
            && !self.steps.iter().any(|s| {
                matches!(s, Step::Report { .. } | Step::Manifest { .. })
                    || matches!(s, Step::Conditional { then, .. } if matches!(**then, Step::Report { .. } | Step::Manifest { .. }))
            })
        {
            problems.push(Problem::new(
                &format!("{path}.steps"),
                "the analysis is never written anywhere: there is no `report` or \
                 `manifest` step"
                    .to_string(),
            ));
        }

        problems
    }
}

impl PipelineFile {
    /// Parse a pipeline file. Shape only; call [`Self::validate`] next.
    pub fn parse(text: &str) -> Result<Self, StegError> {
        let raw: raw::File = toml::from_str(text)
            .map_err(|e| problem(format!("this is not a readable pipeline file: {e}")))?;

        if raw.pipeline.is_empty() {
            return Err(problem(
                "the file defines no pipelines. A pipeline looks like \
                 [pipeline.triage], with an input and some steps"
                    .to_string(),
            ));
        }
        if raw.pipeline.len() > MAX_PIPELINES {
            return Err(problem(format!(
                "{} pipelines in one file, past the {MAX_PIPELINES} limit",
                raw.pipeline.len()
            )));
        }

        let mut pipelines = BTreeMap::new();
        for (name, body) in raw.pipeline {
            let input = InputSource::parse(&body.input)
                .map_err(|e| problem(format!("pipeline.{name}.input: {}", bare_reason(e))))?;
            let mut steps = Vec::with_capacity(body.steps.len());
            for (index, step) in body.steps.into_iter().enumerate() {
                steps.push(
                    step.into_step(0)
                        .map_err(|e| problem(format!("pipeline.{name}.steps[{index}]: {e}")))?,
                );
            }
            pipelines.insert(name.clone(), Pipeline { name, input, steps });
        }
        Ok(Self { pipelines })
    }

    /// Read a pipeline file from disk, bounded.
    pub fn read(path: &std::path::Path) -> Result<Self, StegError> {
        let meta = std::fs::metadata(path)
            .map_err(|_| StegError::FileNotFound(path.display().to_string()))?;
        if meta.len() > MAX_PIPELINE_BYTES {
            return Err(StegError::UnsupportedFormat(format!(
                "{} is {} bytes, past the {MAX_PIPELINE_BYTES} byte pipeline limit",
                path.display(),
                meta.len()
            )));
        }
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Every problem across every pipeline in the file.
    pub fn validate(&self) -> Vec<Problem> {
        self.pipelines.values().flat_map(|p| p.validate()).collect()
    }

    /// Parse and validate, refusing anything that has a problem.
    ///
    /// The only constructor a runner should use, so there is no path by which an
    /// unvalidated pipeline reaches execution.
    pub fn parse_runnable(text: &str) -> Result<Self, StegError> {
        let file = Self::parse(text)?;
        let problems = file.validate();
        if problems.is_empty() {
            return Ok(file);
        }
        let listed = problems
            .iter()
            .map(|p| format!("  {p}"))
            .collect::<Vec<_>>()
            .join("\n");
        Err(problem(format!(
            "{} problem(s) found, and nothing has been run:\n{listed}",
            problems.len()
        )))
    }
}

/// The TOML shapes, kept separate from the validated types.
///
/// Two layers rather than one because the written form is forgiving (a detector
/// is a string, a condition is a string, keys are hyphenated) and the validated
/// form is not (a detector is an enum, a condition is parsed). Collapsing them
/// would mean every consumer of a `Step` handles the possibility that its
/// contents were never checked.
mod raw {
    use super::*;

    #[derive(Deserialize)]
    pub struct File {
        #[serde(default)]
        pub pipeline: BTreeMap<String, Body>,
    }

    #[derive(Deserialize)]
    pub struct Body {
        pub input: String,
        #[serde(default)]
        pub steps: Vec<Entry>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Entry {
        #[serde(default)]
        pub analyse: Option<Analyse>,
        #[serde(default)]
        pub extract: Option<Extract>,
        #[serde(default)]
        pub report: Option<Report>,
        #[serde(default)]
        pub manifest: Option<ManifestStep>,
        #[serde(default, rename = "if")]
        pub condition: Option<String>,
        #[serde(default)]
        pub then: Option<Box<Entry>>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Analyse {
        pub detectors: Vec<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "kebab-case")]
    pub struct Extract {
        #[serde(default)]
        pub trial_passphrases: Option<String>,
        #[serde(default)]
        pub out: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Report {
        pub format: String,
        pub out: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ManifestStep {
        pub out: String,
    }

    impl Entry {
        /// Bare reasons rather than a `StegError`, so the one call site wraps the
        /// message once instead of nesting two copies of the same prefix.
        pub fn into_step(self, depth: usize) -> Result<Step, String> {
            if depth > MAX_NESTING {
                return Err(format!("steps nest more than {MAX_NESTING} deep"));
            }

            let named = [
                self.analyse.is_some(),
                self.extract.is_some(),
                self.report.is_some(),
                self.manifest.is_some(),
                self.condition.is_some(),
            ]
            .iter()
            .filter(|present| **present)
            .count();

            // Checked before the does-nothing case, because a step holding only
            // a `then` has no action either and "you wrote a then with no if" is
            // the message that names the actual mistake.
            if self.condition.is_none() && self.then.is_some() {
                return Err("a `then` with no `if` in front of it".to_string());
            }
            if named == 0 {
                return Err(
                    "a step that does nothing. A step is one of analyse, extract, \
                     report, manifest, or an `if` with a `then`"
                        .to_string(),
                );
            }
            if named > 1 && !(self.condition.is_some() && named == 2 && self.then.is_some()) {
                return Err(
                    "a step that does more than one thing. Write them as separate \
                     steps so the order is on the page"
                        .to_string(),
                );
            }

            if let Some(text) = self.condition {
                let condition = Condition::parse(&text).map_err(bare_reason)?;
                let Some(then) = self.then else {
                    return Err(format!(
                        "the condition {text:?} has no `then`, so nothing would happen \
                         when it held"
                    ));
                };
                return Ok(Step::Conditional {
                    condition,
                    then: Box::new(then.into_step(depth + 1)?),
                });
            }

            if let Some(analyse) = self.analyse {
                let mut detectors = Vec::with_capacity(analyse.detectors.len());
                for slug in &analyse.detectors {
                    let Some(detector) = Detector::from_slug(slug) else {
                        return Err(format!(
                            "{slug:?} is not a detector. The detectors are: {}",
                            Detector::SLUGS.join(", ")
                        ));
                    };
                    detectors.push(detector);
                }
                return Ok(Step::Analyse { detectors });
            }

            if let Some(extract) = self.extract {
                return Ok(Step::Extract {
                    trial_passphrases: extract.trial_passphrases,
                    out: extract.out.map(OutputTemplate),
                });
            }

            if let Some(report) = self.report {
                let format = match report.format.as_str() {
                    "json" => ReportFormat::Json,
                    "csv" => ReportFormat::Csv,
                    "text" => ReportFormat::Text,
                    other => {
                        return Err(format!(
                            "{other:?} is not a report format. The formats are json, csv and text"
                        ))
                    }
                };
                return Ok(Step::Report {
                    format,
                    out: OutputTemplate(report.out),
                });
            }

            let manifest = self
                .manifest
                .ok_or_else(|| "a step with no recognised action".to_string())?;
            Ok(Step::Manifest {
                out: OutputTemplate(manifest.out),
            })
        }
    }
}

/// Prefix every refusal from this module carries, so a reader always knows
/// nothing was run.
const REFUSAL: &str = "this pipeline cannot be run: ";

/// A pipeline file we will not accept.
///
/// `UnsupportedFormat` rather than `Internal`: a file the user wrote and we
/// cannot use is a statement about that file, and `Internal` is documented as
/// the opposite of that. Carried through to the CLI it also decides an exit
/// code, and `Internal` mapped onto the same number as "your pipeline has a
/// mistake in it", which is the one distinction a continuous-integration job
/// reading these codes needs. It also told the user "the file itself may well be
/// fine" about a file that definitively is not.
fn problem(reason: String) -> StegError {
    StegError::UnsupportedFormat(format!("{REFUSAL}{reason}"))
}

/// The reason inside an error raised by this module or by the condition parser,
/// without the prefix, for a caller that is about to add its own location and
/// would otherwise print the prefix twice.
fn bare_reason(error: StegError) -> String {
    let text = error.to_string();
    match text.split_once(REFUSAL) {
        Some((_, reason)) => reason.to_string(),
        None => text,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The roadmap's own worked example, with a report added, since the roadmap
    /// snippet writes one and the validator insists on it.
    const ROADMAP_EXAMPLE: &str = r#"
[pipeline.triage]
input = "watch:./inbox"
steps = [
  { analyse = { detectors = ["spa", "rs", "ws", "fingerprint"] } },
  { if = "verdict > 0.7", then = { extract = { trial-passphrases = "wordlist:./pw", out = "./out/{{stem}}.bin" } } },
  { report = { format = "json", out = "./reports/{{filename}}.json" } },
]
"#;

    #[test]
    fn the_roadmaps_worked_example_parses_and_validates() {
        let file = PipelineFile::parse_runnable(ROADMAP_EXAMPLE).expect("runnable");
        let pipeline = &file.pipelines["triage"];
        assert_eq!(pipeline.input, InputSource::Watch("./inbox".to_string()));
        assert!(pipeline.input.is_continuous());
        assert_eq!(pipeline.steps.len(), 3);
        assert_eq!(pipeline.steps[0].kind(), "analyse");
        assert_eq!(pipeline.steps[1].kind(), "if");
        assert_eq!(pipeline.steps[2].kind(), "report");
    }

    #[test]
    fn a_detector_slug_round_trips_and_every_variant_has_one() {
        assert_eq!(Detector::ALL.len(), Detector::SLUGS.len());
        for detector in Detector::ALL {
            assert_eq!(Detector::from_slug(detector.slug()), Some(*detector));
        }
        assert_eq!(Detector::from_slug("nonsense"), None);
    }

    /// `SLUGS` and `ALL` are two parallel tables, and `from_slug` indexes one by
    /// a position found in the other, so they have to agree pairwise and not
    /// merely in length.
    #[test]
    fn the_two_detector_tables_agree_pairwise() {
        for (slug, detector) in Detector::SLUGS.iter().zip(Detector::ALL.iter()) {
            assert_eq!(*slug, detector.slug(), "{slug} is paired with {detector:?}");
        }
    }

    #[test]
    fn the_two_detectors_excluded_from_the_verdict_are_the_measured_ones() {
        assert!(!Detector::ChiSquared.counts_toward_verdict());
        assert!(!Detector::Entropy.counts_toward_verdict());
        for detector in Detector::ALL {
            if !matches!(detector, Detector::ChiSquared | Detector::Entropy) {
                assert!(detector.counts_toward_verdict(), "{detector:?}");
            }
        }
    }

    #[test]
    fn every_input_kind_parses() {
        for (text, expected) in [
            ("path:./x.png", InputSource::Path("./x.png".to_string())),
            ("glob:./*.png", InputSource::Glob("./*.png".to_string())),
            (
                "list:./files.txt",
                InputSource::List("./files.txt".to_string()),
            ),
            ("watch:./inbox", InputSource::Watch("./inbox".to_string())),
        ] {
            let parsed = InputSource::parse(text).expect(text);
            assert_eq!(parsed, expected);
            assert_eq!(parsed.location(), expected.location());
        }
        assert!(!InputSource::Path("x".to_string()).is_continuous());
    }

    #[test]
    fn an_input_with_no_scheme_says_what_the_schemes_are() {
        let err = InputSource::parse("./inbox").expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("watch:./inbox"), "{message}");
    }

    #[test]
    fn an_unknown_input_scheme_is_refused() {
        let err = InputSource::parse("http://example.invalid/x.png").expect_err("must refuse");
        assert!(err.to_string().contains("not a kind of input"), "{err}");
    }

    #[test]
    fn an_input_with_an_empty_location_is_refused() {
        assert!(InputSource::parse("watch:").is_err());
        assert!(InputSource::parse("watch:   ").is_err());
    }

    #[test]
    fn an_over_long_input_is_refused() {
        let long = format!("watch:{}", "a".repeat(MAX_INPUT_BYTES));
        assert!(InputSource::parse(&long).is_err());
    }

    /// The headline property: a mistake in the last step stops the first one.
    #[test]
    fn a_typo_in_the_last_step_refuses_the_whole_pipeline() {
        let text = r#"
[pipeline.triage]
input = "watch:./inbox"
steps = [
  { analyse = { detectors = ["spa"] } },
  { report = { format = "json", out = "./reports/{{filenam}}.json" } },
]
"#;
        let err = PipelineFile::parse_runnable(text).expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("nothing has been run"), "{message}");
        assert!(message.contains("steps[1].report.out"), "{message}");
        assert!(message.contains("filenam"), "{message}");
    }

    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let text = r#"
[pipeline.a]
input = "watch:./in"
steps = [
  { analyse = { detectors = ["spa"] } },
  { report = { format = "json", out = "./r/{{nope}}.json" } },
  { manifest = { out = "./m/{{alsonope}}.json" } },
]
"#;
        let file = PipelineFile::parse(text).expect("parses");
        let problems = file.validate();
        assert!(problems.len() >= 2, "{problems:?}");
        assert!(problems.iter().any(|p| p.reason.contains("nope")));
        assert!(problems.iter().any(|p| p.reason.contains("alsonope")));
    }

    #[test]
    fn a_report_before_any_analysis_is_refused() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { report = { format = "json", out = "./r/{{filename}}.json" } },
  { analyse = { detectors = ["spa"] } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(
            problems
                .iter()
                .any(|p| p.reason.contains("no `analyse` step has run yet")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_condition_before_any_analysis_is_refused_too() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { if = "verdict > 0.7", then = { extract = { } } },
  { analyse = { detectors = ["spa"] } },
  { manifest = { out = "./m/{{filename}}.json" } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(
            problems.iter().any(|p| p.reason.contains("no `analyse`")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_analysis_that_is_never_written_anywhere_is_flagged() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [ { analyse = { detectors = ["spa"] } } ]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(
            problems.iter().any(|p| p.reason.contains("never written")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_conditional_report_counts_as_writing_the_analysis() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { if = "verdict > 0.7", then = { report = { format = "json", out = "./r/{{stem}}.json" } } },
]
"#;
        PipelineFile::parse_runnable(text).expect("runnable");
    }

    #[test]
    fn a_pipeline_with_no_steps_is_refused() {
        let text = "[pipeline.a]\ninput = \"path:./x.png\"\nsteps = []\n";
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(problems.iter().any(|p| p.reason.contains("no steps")));
    }

    #[test]
    fn an_analyse_step_with_no_detectors_is_refused() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = [] } },
  { manifest = { out = "./m/{{filename}}.json" } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(problems
            .iter()
            .any(|p| p.reason.contains("measure nothing")));
    }

    #[test]
    fn naming_the_same_detector_twice_is_flagged() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa", "spa"] } },
  { manifest = { out = "./m/{{filename}}.json" } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(problems.iter().any(|p| p.reason.contains("twice")));
    }

    /// Naming only the two non-verdict detectors and then reading `verdict` is
    /// the subtle mistake the whole-file check is for: every step is individually
    /// legal and the pipeline can never fire.
    #[test]
    fn naming_only_excluded_detectors_is_flagged() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["chi_squared", "entropy"] } },
  { if = "verdict > 0.7", then = { report = { format = "json", out = "./r/{{stem}}.json" } } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(
            problems
                .iter()
                .any(|p| p.reason.contains("excluded from the verdict")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_unknown_detector_slug_lists_the_real_ones() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [ { analyse = { detectors = ["spaa"] } } ]
"#;
        let err = PipelineFile::parse(text).expect_err("must refuse");
        let message = err.to_string();
        assert!(message.contains("spaa"), "{message}");
        assert!(message.contains("chi_squared"), "{message}");
    }

    #[test]
    fn an_unknown_report_format_lists_the_real_ones() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [ { report = { format = "yaml", out = "./r/{{stem}}.yaml" } } ]
"#;
        let err = PipelineFile::parse(text).expect_err("must refuse");
        assert!(err.to_string().contains("json, csv and text"), "{err}");
    }

    #[test]
    fn every_report_format_parses() {
        for (written, expected) in [
            ("json", ReportFormat::Json),
            ("csv", ReportFormat::Csv),
            ("text", ReportFormat::Text),
        ] {
            let text = format!(
                r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  {{ analyse = {{ detectors = ["spa"] }} }},
  {{ report = {{ format = "{written}", out = "./r/{{{{stem}}}}.out" }} }},
]
"#
            );
            let file = PipelineFile::parse_runnable(&text).expect(written);
            match &file.pipelines["a"].steps[1] {
                Step::Report { format, .. } => assert_eq!(*format, expected),
                other => panic!("expected a report step, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_step_that_does_nothing_is_refused() {
        let text = "[pipeline.a]\ninput = \"path:./x.png\"\nsteps = [ {} ]\n";
        let err = PipelineFile::parse(text).expect_err("must refuse");
        assert!(err.to_string().contains("does nothing"), "{err}");
    }

    #[test]
    fn a_step_that_does_two_things_is_refused() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [ { analyse = { detectors = ["spa"] }, manifest = { out = "./m/{{stem}}.json" } } ]
"#;
        let err = PipelineFile::parse(text).expect_err("must refuse");
        assert!(err.to_string().contains("more than one thing"), "{err}");
    }

    #[test]
    fn an_if_without_a_then_is_refused() {
        let text =
            "[pipeline.a]\ninput = \"path:./x.png\"\nsteps = [ { if = \"verdict > 0.7\" } ]\n";
        let err = PipelineFile::parse(text).expect_err("must refuse");
        assert!(err.to_string().contains("no `then`"), "{err}");
    }

    #[test]
    fn a_then_without_an_if_is_refused() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [ { then = { analyse = { detectors = ["spa"] } } } ]
"#;
        let err = PipelineFile::parse(text).expect_err("must refuse");
        assert!(err.to_string().contains("no `if`"), "{err}");
    }

    #[test]
    fn a_conditional_inside_a_conditional_is_flagged_rather_than_silently_allowed() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { if = "verdict > 0.5", then = { if = "spa > 0.4", then = { manifest = { out = "./m/{{stem}}.json" } } } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(
            problems.iter().any(|p| p
                .reason
                .contains("conditional directly inside a conditional")),
            "{problems:?}"
        );
    }

    #[test]
    fn deeply_nested_conditionals_are_refused_rather_than_recursed_into() {
        let mut inner = "{ manifest = { out = \"./m/{{stem}}.json\" } }".to_string();
        for _ in 0..MAX_NESTING + 3 {
            inner = format!("{{ if = \"verdict > 0.5\", then = {inner} }}");
        }
        let text = format!(
            "[pipeline.a]\ninput = \"path:./x.png\"\nsteps = [ {{ analyse = {{ detectors = [\"spa\"] }} }}, {inner} ]\n"
        );
        assert!(PipelineFile::parse_runnable(&text).is_err());
    }

    #[test]
    fn an_unknown_key_in_a_step_is_refused_rather_than_ignored() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [ { analyze = { detectors = ["spa"] } } ]
"#;
        assert!(PipelineFile::parse(text).is_err());
    }

    #[test]
    fn an_unknown_key_inside_an_action_is_refused() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [ { report = { format = "json", out = "./r/{{stem}}.json", colour = true } } ]
"#;
        assert!(PipelineFile::parse(text).is_err());
    }

    #[test]
    fn a_bad_passphrase_source_is_flagged() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { extract = { trial-passphrases = "./pw" } },
  { manifest = { out = "./m/{{stem}}.json" } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(
            problems.iter().any(|p| p.reason.contains("wordlist:")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_wordlist_with_no_path_is_flagged() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { extract = { trial-passphrases = "wordlist:" } },
  { manifest = { out = "./m/{{stem}}.json" } },
]
"#;
        let problems = PipelineFile::parse(text).expect("parses").validate();
        assert!(!problems.is_empty());
    }

    #[test]
    fn an_extract_step_may_omit_everything() {
        let text = r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { extract = { } },
  { manifest = { out = "./m/{{stem}}.json" } },
]
"#;
        PipelineFile::parse_runnable(text).expect("runnable");
    }

    #[test]
    fn a_file_with_no_pipelines_is_refused() {
        let err = PipelineFile::parse("").expect_err("must refuse");
        assert!(err.to_string().contains("[pipeline.triage]"), "{err}");
    }

    #[test]
    fn unreadable_toml_is_refused() {
        assert!(PipelineFile::parse("[pipeline.a").is_err());
    }

    #[test]
    fn a_pipeline_with_a_bad_input_is_refused_with_its_name() {
        let text = "[pipeline.triage]\ninput = \"./inbox\"\nsteps = []\n";
        let err = PipelineFile::parse(text).expect_err("must refuse");
        assert!(err.to_string().contains("pipeline.triage.input"), "{err}");
    }

    #[test]
    fn two_pipelines_in_one_file_are_both_validated() {
        let text = r#"
[pipeline.good]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { manifest = { out = "./m/{{stem}}.json" } },
]

[pipeline.bad]
input = "path:./x.png"
steps = [ { analyse = { detectors = ["spa"] } } ]
"#;
        let file = PipelineFile::parse(text).expect("parses");
        assert_eq!(file.pipelines.len(), 2);
        let problems = file.validate();
        assert!(
            problems.iter().all(|p| p.at.contains("pipeline.bad")),
            "{problems:?}"
        );
    }

    // ── Output templates ────────────────────────────────────────────────────

    #[test]
    fn a_template_with_a_known_placeholder_validates() {
        for name in PLACEHOLDERS {
            let template = OutputTemplate(format!("./out/{{{{{name}}}}}.json"));
            assert!(template.validate().is_empty(), "{name}");
        }
    }

    #[test]
    fn a_template_with_no_placeholder_warns_about_overwriting() {
        let problems = OutputTemplate("./out/report.json".to_string()).validate();
        assert!(
            problems
                .iter()
                .any(|p| p.contains("only the last one would survive")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_unclosed_placeholder_is_flagged() {
        let problems = OutputTemplate("./out/{{filename.json".to_string()).validate();
        assert!(
            problems.iter().any(|p| p.contains("never closes")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_empty_template_is_flagged() {
        assert!(!OutputTemplate(String::new()).validate().is_empty());
    }

    #[test]
    fn an_over_long_template_is_flagged() {
        let problems = OutputTemplate("a".repeat(MAX_TEMPLATE_BYTES + 1)).validate();
        assert!(
            problems.iter().any(|p| p.contains("past the")),
            "{problems:?}"
        );
    }

    #[test]
    fn expanding_a_template_substitutes_every_placeholder() {
        let template = OutputTemplate("./out/{{stem}}-{{sha256}}.{{ext}}".to_string());
        let values = BTreeMap::from([
            ("stem", "cover".to_string()),
            ("sha256", "abc123".to_string()),
            ("ext", "json".to_string()),
        ]);
        assert_eq!(template.expand(&values), "./out/cover-abc123.json");
    }

    #[test]
    fn a_missing_value_expands_to_unknown_rather_than_leaving_a_brace() {
        let template = OutputTemplate("./out/{{verdict}}.json".to_string());
        assert_eq!(template.expand(&BTreeMap::new()), "./out/unknown.json");
    }

    /// The containment the module docs promise, tested with the attack it exists
    /// for: a watched directory holding a file whose name is a traversal.
    #[test]
    fn a_traversing_file_name_cannot_escape_the_output_directory() {
        let template = OutputTemplate("./reports/{{filename}}.json".to_string());
        for hostile in [
            "../../etc/cron.d/x",
            "/etc/shadow",
            r"..\..\windows\system32\x",
            "../../../..//passwd",
        ] {
            let values = BTreeMap::from([("filename", hostile.to_string())]);
            let expanded = template.expand(&values);
            assert!(
                expanded.starts_with("./reports/"),
                "{hostile} expanded to {expanded}"
            );
            assert!(!expanded.contains(".."), "{hostile} expanded to {expanded}");
        }
    }

    #[test]
    fn a_file_name_that_is_only_separators_expands_to_a_usable_name() {
        let template = OutputTemplate("./reports/{{filename}}.json".to_string());
        for hostile in ["///", "..", "...", "   ", ""] {
            let values = BTreeMap::from([("filename", hostile.to_string())]);
            assert_eq!(
                template.expand(&values),
                "./reports/unnamed.json",
                "{hostile:?}"
            );
        }
    }

    #[test]
    fn control_characters_and_colons_are_stripped_from_a_substituted_name() {
        let template = OutputTemplate("./reports/{{filename}}.json".to_string());
        let values = BTreeMap::from([("filename", "co\u{0}ver:1".to_string())]);
        assert_eq!(template.expand(&values), "./reports/cover1.json");
    }

    // ── Reading from disk ───────────────────────────────────────────────────

    #[test]
    fn a_pipeline_file_reads_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("triage.toml");
        std::fs::write(&path, ROADMAP_EXAMPLE).expect("write");
        let file = PipelineFile::read(&path).expect("read");
        assert!(file.validate().is_empty());
    }

    #[test]
    fn a_missing_pipeline_file_names_the_path() {
        let err = PipelineFile::read(std::path::Path::new("/nonexistent/triage.toml"))
            .expect_err("must fail");
        assert!(err.to_string().contains("triage.toml"), "{err}");
    }

    #[test]
    fn an_over_large_pipeline_file_is_refused_before_it_is_parsed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge.toml");
        std::fs::write(&path, vec![b'#'; MAX_PIPELINE_BYTES as usize + 1]).expect("write");
        let err = PipelineFile::read(&path).expect_err("must refuse");
        assert!(err.to_string().contains("pipeline limit"), "{err}");
    }

    #[test]
    fn too_many_pipelines_in_one_file_is_refused() {
        let mut text = String::new();
        for i in 0..=MAX_PIPELINES {
            text.push_str(&format!(
                "[pipeline.p{i}]\ninput = \"path:./x.png\"\nsteps = [ {{ analyse = {{ detectors = [\"spa\"] }} }} ]\n"
            ));
        }
        let err = PipelineFile::parse(&text).expect_err("must refuse");
        assert!(err.to_string().contains("past the"), "{err}");
    }

    #[test]
    fn too_many_steps_in_one_pipeline_is_flagged() {
        let step = "{ analyse = { detectors = [\"spa\"] } }";
        let steps = vec![step; MAX_STEPS + 1].join(", ");
        let text = format!("[pipeline.a]\ninput = \"path:./x.png\"\nsteps = [ {steps} ]\n");
        let problems = PipelineFile::parse(&text).expect("parses").validate();
        assert!(
            problems.iter().any(|p| p.reason.contains("past the")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_problem_prints_its_path_and_its_reason() {
        let problem = Problem::new("pipeline.a.steps[0]", "something".to_string());
        assert_eq!(problem.to_string(), "pipeline.a.steps[0]: something");
    }

    #[test]
    fn a_validated_pipeline_round_trips_through_json() {
        let file = PipelineFile::parse_runnable(ROADMAP_EXAMPLE).expect("runnable");
        let text = serde_json::to_string(&file).expect("json");
        let back: PipelineFile = serde_json::from_str(&text).expect("read");
        assert_eq!(back, file);
    }
}

#[cfg(test)]
mod carrier_tests {
    use super::*;
    use crate::workflow::templates::TEMPLATES;

    #[test]
    fn every_detector_states_whether_it_runs_on_audio() {
        // An exhaustive match means a new variant is a compile error rather than
        // a default, so this only has to prove the answers are not all the same,
        // which would mean somebody stubbed it.
        let on_audio = Detector::ALL.iter().filter(|d| d.runs_on_audio()).count();
        assert!(
            on_audio > 0 && on_audio < Detector::ALL.len(),
            "runs_on_audio looks stubbed: {on_audio} of {}",
            Detector::ALL.len()
        );
    }

    #[test]
    fn the_two_audio_pair_statistics_are_separate_detectors() {
        // They share an algorithm and not a calibration. Collapsing them would
        // apply the image threshold of 0.377 to a waveform, where a clean
        // white-noise recording reads 0.599.
        assert_ne!(Detector::Spa, Detector::AudioSpa);
        assert!(Detector::AudioSpa.runs_on_audio());
        assert!(!Detector::Spa.runs_on_audio());
    }

    #[test]
    fn the_audio_templates_only_name_detectors_that_run_on_audio() {
        // The forensics template names chi_squared and entropy, which no longer
        // run on a recording. That is correct for an image-first template and
        // would be a silent no-op if a template meant for audio did it, so this
        // pins which templates are allowed to carry them.
        for template in TEMPLATES {
            let file = PipelineFile::parse(template.body).expect("template parses");
            for pipeline in file.pipelines.values() {
                for step in &pipeline.steps {
                    let Step::Analyse { detectors } = step else {
                        continue;
                    };
                    assert!(
                        detectors.iter().any(|d| d.runs_on_audio()),
                        "{} selects nothing at all on a recording",
                        template.name
                    );
                }
            }
        }
    }
}
