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

//! `stegcore brute-force`: recover the key a steganography tool used, so a file
//! can be named as that tool's output.
//!
//! # Why this command is gated and the others are not
//!
//! Every other subcommand either works on a file the operator supplied a
//! passphrase for, or reports statistics. This one takes a file the operator may
//! have no right to and tries to open it. That is useful in an investigation and
//! it is the same operation as reading somebody's private message, so it runs
//! only behind `--i-am-authorised` and it writes down who ran it.
//!
//! The gate follows the pattern the `watermark` command established rather than
//! inventing a second one: the same refusal exit code, the same shape of
//! message. It differs in one deliberate way. Watermarking records consent
//! **once per machine** and never asks again, because the operator is marking
//! their own documents and asking every time would be noise. Key recovery
//! records it **every single run**, into the report for that run, because the
//! thing being recorded is not "this person has read the terms" but "this
//! person ran this search against this file at this time". `AUP.md` section 3.1
//! asks for the second, and a once-per-machine marker cannot provide it.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use stegcore_engine::bruteforce::authorisation::Record;
use stegcore_engine::bruteforce::{
    authorisation, openstego, search, steghide, SearchLimits, SearchReport, StopReason,
    DEFAULT_MAX_ATTEMPTS,
};

use crate::output::{self, JsonOut};

/// Checked when this file is compiled, not when it is run: if somebody finishes
/// the Steghide traversal and forgets that this command still refuses to search
/// for it, the build stops here and makes them look.
const _: () = assert!(!steghide::TRAVERSAL_RECONSTRUCTED);

/// Exit code when the command refuses for lack of authorisation. The same code
/// `watermark` uses, because it is the same refusal.
const EXIT_CONSENT_REQUIRED: i32 = 2;

/// Exit code when the search ran correctly and found nothing. Distinct from a
/// refusal and from an error: the command worked, and the answer is no.
const EXIT_NOT_FOUND: i32 = 1;

/// How often to print a progress line.
const HEARTBEAT: Duration = Duration::from_secs(30);

#[derive(Debug, clap::Args)]
#[command(
    about = "Recover the key a steganography tool used, to confirm which tool wrote a file",
    long_about = "Recover the key a steganography tool used to hide data in a file, so the file \
can be named as that tool's output.

Some tools write their own name into the data they hide. Because the hidden data \
is scattered through the file in an order only the password knows, that name \
cannot be read until the order is reproduced. This command tries candidate keys \
until one reads it.

A match is conclusive: it is the tool's own signature, in its own bytes. A miss \
proves nothing, because the search stops at a limit long before it has tried \
everything, and the command always tells you how much of the space it covered.

What it can do today:

  OpenStego  Random LSB, both the password-protected case and the default with \
no password. A wordlist is what finds a password; a sweep of raw seed values \
cannot, because the key space is 60 bits wide.

  Steghide   Not yet. The sample readers are built and the traversal is not, so \
the command refuses rather than reporting a file as clean when it has not \
actually looked.

This command is gated. It requires --i-am-authorised, and every run records your \
account name, this machine's name, the time, and a checksum of the file.",
    after_long_help = "\x1b[36mExamples:\x1b[0m
  stegcore brute-force suspect.png --openstego --wordlist rockyou.txt --i-am-authorised
  stegcore brute-force suspect.png --openstego --seed-only --i-am-authorised
  stegcore brute-force suspect.png --any --wordlist words.txt --max-attempts 5000000 --i-am-authorised
"
)]
pub struct BruteForceArgs {
    /// File to examine
    pub file: PathBuf,

    /// Look for Steghide only
    #[arg(long)]
    pub steghide: bool,

    /// Look for OpenStego only
    #[arg(long)]
    pub openstego: bool,

    /// Look for every tool this command supports
    #[arg(long)]
    pub any: bool,

    /// Candidate passwords, one per line. This is what actually finds a
    /// password; without it only the no-password cases can be identified.
    #[arg(long, value_name = "PATH")]
    pub wordlist: Option<PathBuf>,

    /// Candidates to try before giving up. The default keeps the run short
    /// because a longer one is rarely more likely to succeed; see --help.
    #[arg(long, default_value_t = DEFAULT_MAX_ATTEMPTS, value_name = "N")]
    pub max_attempts: u64,

    /// Start from this candidate, to carry on a search that was stopped. The
    /// number to use is printed when a search stops early.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub resume_from: u64,

    /// Stop after this many seconds, however many candidates are left
    #[arg(long, value_name = "SECONDS")]
    pub time_limit: Option<u64>,

    /// Report the recovered key and nothing else, leaving the hidden data
    /// untouched. The preferred mode for evidence work: the next person can
    /// repeat the recovery from the key without this tool having opened the
    /// payload.
    #[arg(long)]
    pub seed_only: bool,

    /// Worker threads. The default asks the machine.
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub threads: usize,

    /// A signed engagement manifest, when policy requires one
    #[arg(long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,

    /// File holding the key that signs the manifest
    #[arg(long, value_name = "PATH", requires = "manifest")]
    pub manifest_key: Option<PathBuf>,

    /// Confirm you are permitted to recover keys from this file. Required, and
    /// recorded in the report for this run.
    #[arg(long)]
    pub i_am_authorised: bool,
}

/// Which tools a run will look for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Targets {
    pub steghide: bool,
    pub openstego: bool,
}

impl Targets {
    /// Work out the targets from the flags.
    ///
    /// Naming no tool is the same as `--any` rather than an error: an operator
    /// who points this at a file without saying what to look for wants it
    /// looked at, and refusing would be pedantry. `--any` with a specific flag
    /// is also accepted, widening rather than conflicting.
    pub fn from_flags(steghide: bool, openstego: bool, any: bool) -> Self {
        if any || (!steghide && !openstego) {
            return Self {
                steghide: true,
                openstego: true,
            };
        }
        Self {
            steghide,
            openstego,
        }
    }
}

/// What one run produced, in the shape the JSON output takes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Outcome {
    /// The authorisation record, which `AUP.md` section 3.1 requires in the
    /// report rather than only in a log.
    pub authorisation: Record,
    /// One entry per tool looked for.
    pub attempts: Vec<ToolOutcome>,
    /// The tool the file was attributed to, if any.
    pub identified_tool: Option<String>,
    /// Whether anything in this run licenses the reader to conclude the file is
    /// not any of these tools' output.
    pub absence_is_meaningful: bool,
}

/// What one tool's search produced.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ToolOutcome {
    pub tool: String,
    pub found: bool,
    /// The recovered key, described. Omitted entirely when nothing was found,
    /// rather than reported as an empty string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// What the match revealed about the hidden payload. Suppressed under
    /// `--seed-only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    pub candidates_tried: u64,
    pub candidate_space: u64,
    pub stopped_because: String,
    pub resume_from: u64,
    pub candidates_per_second: f64,
    /// Why a tool was skipped, when it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

/// Render a stop reason for a report.
fn describe_stop(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::Found => "a candidate matched",
        StopReason::Exhausted => "every candidate was tried",
        StopReason::CapReached => "the attempt limit was reached",
        StopReason::DeadlineReached => "the time limit was reached",
        StopReason::Cancelled => "you stopped it",
    }
}

/// Turn one search report into its reportable outcome.
fn tool_outcome<E>(
    report: &SearchReport<E>,
    seed_only: bool,
    describe_payload: impl Fn(&E) -> String,
) -> ToolOutcome {
    ToolOutcome {
        tool: report.tool.to_string(),
        found: report.hit.is_some(),
        key: report.hit.as_ref().map(|h| h.label.clone()),
        payload: match (&report.hit, seed_only) {
            (Some(hit), false) => Some(describe_payload(&hit.evidence)),
            _ => None,
        },
        candidates_tried: report.attempted,
        candidate_space: report.space_size,
        stopped_because: describe_stop(&report.stop_reason).to_string(),
        resume_from: report.resume_from,
        candidates_per_second: report.rate_per_second,
        skipped: None,
    }
}

/// An outcome for a tool that was not searched at all.
fn skipped(tool: &str, why: &str) -> ToolOutcome {
    ToolOutcome {
        tool: tool.to_string(),
        found: false,
        key: None,
        payload: None,
        candidates_tried: 0,
        candidate_space: 0,
        stopped_because: "not searched".to_string(),
        resume_from: 0,
        candidates_per_second: 0.0,
        skipped: Some(why.to_string()),
    }
}

/// Build the search limits from the flags.
fn limits_from(args: &BruteForceArgs) -> SearchLimits {
    SearchLimits {
        max_attempts: args.max_attempts,
        resume_from: args.resume_from,
        threads: args.threads,
        heartbeat: HEARTBEAT,
        deadline: args.time_limit.map(Duration::from_secs),
        ..Default::default()
    }
}

/// Read the manifest and its key, when both were given.
fn load_manifest(
    args: &BruteForceArgs,
) -> Result<Option<(authorisation::Manifest, Vec<u8>)>, String> {
    let Some(path) = &args.manifest else {
        return Ok(None);
    };
    let manifest = authorisation::Manifest::load(path).map_err(|e| e.to_string())?;
    let key_path = args.manifest_key.as_ref().ok_or_else(|| {
        "a manifest was given with no key to check it against. Pass --manifest-key as well."
            .to_string()
    })?;
    let key = std::fs::read(key_path).map_err(|e| {
        format!(
            "the manifest signing key at {} could not be read: {e}",
            key_path.display()
        )
    })?;
    if key.is_empty() {
        return Err(format!(
            "the manifest signing key at {} is empty.",
            key_path.display()
        ));
    }
    Ok(Some((manifest, key)))
}

/// The command line as it was typed, for the record. Reconstructed from the
/// process arguments rather than from the parsed flags, so what is recorded is
/// what was actually run.
fn invocation() -> String {
    std::env::args().collect::<Vec<_>>().join(" ")
}

pub fn run(
    args: &BruteForceArgs,
    verbose: bool,
    json: bool,
    quiet: bool,
    interrupted: Arc<AtomicBool>,
) -> ! {
    if !args.file.exists() {
        let e = stegcore_core::errors::StegError::FileNotFound(args.file.display().to_string());
        if json {
            output::emit_json(&JsonOut::<()>::failure(&e.to_string()), output::exit_code(&e));
        }
        output::die(&e, verbose);
    }

    let manifest = match load_manifest(args) {
        Ok(manifest) => manifest,
        Err(message) => {
            if json {
                output::emit_json(&JsonOut::<()>::failure(&message), EXIT_CONSENT_REQUIRED);
            }
            output::print_error(&message, None);
            std::process::exit(EXIT_CONSENT_REQUIRED);
        }
    };

    // The policy file is looked for beside the file being examined and upwards
    // from there, not beside the binary: the policy belongs to the material, so
    // a shared case directory can carry one that applies to everything in it.
    let policy_root = args
        .file
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let request = authorisation::Request {
        confirmed: args.i_am_authorised,
        manifest,
        invocation: invocation(),
    };

    let mut record = match authorisation::authorise(&request, &args.file, &policy_root) {
        Ok(record) => record,
        Err(refusal) => {
            let message = refusal.message();
            if json {
                output::emit_json(&JsonOut::<()>::failure(&message), EXIT_CONSENT_REQUIRED);
            }
            output::print_error(&message, None);
            std::process::exit(EXIT_CONSENT_REQUIRED);
        }
    };

    let targets = Targets::from_flags(args.steghide, args.openstego, args.any);
    let limits = limits_from(args);
    let mut attempts: Vec<ToolOutcome> = Vec::new();

    if !quiet && !json {
        output::print_info(&format!(
            "Authorisation recorded for {} on {}. Checksum of the file: {}.",
            record.operator, record.hostname, record.input_sha256
        ));
    }

    if targets.openstego {
        attempts.push(run_openstego(args, &limits, &interrupted, quiet && !json, json));
    }
    if targets.steghide {
        attempts.push(run_steghide(args));
    }

    let identified = attempts
        .iter()
        .find(|a| a.found)
        .map(|a| a.tool.clone());
    // A negative only means something when every tool searched exhausted its
    // space and none was skipped. Anything else and the report says plainly that
    // nothing was ruled out.
    let absence_is_meaningful = identified.is_none()
        && !attempts.is_empty()
        && attempts
            .iter()
            .all(|a| a.skipped.is_none() && a.stopped_because == "every candidate was tried");

    record.outcome = match attempts.iter().find(|a| a.found).and_then(|a| a.key.clone()) {
        Some(key) => key,
        None => authorisation::NOTHING_RECOVERED.to_string(),
    };

    let outcome = Outcome {
        authorisation: record,
        attempts,
        identified_tool: identified.clone(),
        absence_is_meaningful,
    };

    if json {
        let code = if identified.is_some() {
            0
        } else {
            EXIT_NOT_FOUND
        };
        output::emit_json(&JsonOut::success(outcome), code);
    }

    print_human(&outcome, quiet);
    std::process::exit(if identified.is_some() {
        0
    } else {
        EXIT_NOT_FOUND
    });
}

fn run_openstego(
    args: &BruteForceArgs,
    limits: &SearchLimits,
    interrupted: &Arc<AtomicBool>,
    quiet: bool,
    json: bool,
) -> ToolOutcome {
    let carrier = match openstego::Carrier::load(&args.file) {
        Ok(carrier) => carrier,
        Err(e) => return skipped("OpenStego", &format!("the file could not be read as an image: {e}")),
    };

    // The free check first, and it is genuinely free: OpenStego reduces an
    // absent password to a fixed constant, so one candidate settles the default
    // no-password case before any search starts.
    let known = openstego::SeedRangeProbe::empty_password(&carrier);
    match search(&known, &SearchLimits::default(), interrupted, |_| {}) {
        Ok(report) if report.hit.is_some() => {
            return tool_outcome(&report, args.seed_only, |h| h.describe())
        }
        Ok(_) => {}
        Err(e) => return skipped("OpenStego", &format!("the no-password check failed: {e}")),
    }

    let heartbeat = |progress: &stegcore_engine::bruteforce::Progress| {
        if quiet || json {
            return;
        }
        output::print_info(&format!(
            "Still searching: {} of {} candidates, {:.0} per second, {:.0} percent done.",
            progress.attempted,
            progress.planned,
            progress.rate_per_second,
            progress.fraction() * 100.0
        ));
    };

    match &args.wordlist {
        Some(path) => {
            let probe = match openstego::WordlistProbe::from_file(&carrier, path) {
                Ok(probe) => probe,
                Err(e) => return skipped("OpenStego", &format!("the wordlist could not be read: {e}")),
            };
            match search(&probe, limits, interrupted, heartbeat) {
                Ok(report) => tool_outcome(&report, args.seed_only, |h| h.describe()),
                Err(e) => skipped("OpenStego", &format!("the search failed: {e}")),
            }
        }
        None => skipped(
            "OpenStego",
            "no password was recovered and no wordlist was given. OpenStego derives its key \
             from the password, and the key space is 60 bits wide, so sweeping it is not \
             possible. Pass --wordlist to try candidate passwords.",
        ),
    }
}

fn run_steghide(_args: &BruteForceArgs) -> ToolOutcome {
    // Refusing is the honest answer. The sample readers are built and tested;
    // the traversal that says which sample holds which bit is not, so a search
    // would report every Steghide file in existence as clean. Saying "not
    // searched" is a gap; saying "clean" would be a claim.
    skipped(
        "Steghide",
        "Steghide attribution is not finished. The carrier readers are built, the part that \
         reproduces Steghide's own ordering is not, so this file has not been checked for \
         Steghide at all. Treat that as unknown rather than as clean.",
    )
}

fn print_human(outcome: &Outcome, quiet: bool) {
    match &outcome.identified_tool {
        Some(tool) => {
            let found = outcome.attempts.iter().find(|a| a.found);
            output::print_success(&format!("This file was written by {tool}."));
            if let Some(entry) = found {
                if let Some(key) = &entry.key {
                    output::print_info(&format!("Recovered: {key}"));
                }
                if let Some(payload) = &entry.payload {
                    output::print_info(payload);
                }
                output::print_info(&format!(
                    "Found after {} of {} candidates.",
                    entry.candidates_tried, entry.candidate_space
                ));
            }
        }
        None if outcome.absence_is_meaningful => {
            output::print_success(
                "No match. Every candidate was tried for every tool checked, so this file is \
                 not one of them.",
            );
        }
        None => {
            output::print_warn("No match, and nothing has been ruled out.");
        }
    }

    if quiet {
        return;
    }

    for entry in &outcome.attempts {
        match &entry.skipped {
            Some(why) => output::print_info(&format!("{}: not checked. {why}", entry.tool)),
            None if !entry.found => output::print_info(&format!(
                "{}: {} of {} candidates tried, {}. Carry on from {} with --resume-from.",
                entry.tool,
                entry.candidates_tried,
                entry.candidate_space,
                entry.stopped_because,
                entry.resume_from
            )),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The clap command this subcommand would present, for inspecting what the
    /// flag surface actually is rather than what it was meant to be.
    fn command() -> clap::Command {
        use clap::CommandFactory;
        #[derive(clap::Parser)]
        struct Wrapper {
            #[command(flatten)]
            inner: BruteForceArgs,
        }
        Wrapper::command()
    }

    fn authorisation_flag() -> clap::Arg {
        command()
            .get_arguments()
            .find(|a| a.get_id() == "i_am_authorised")
            .cloned()
            .expect("the authorisation flag must exist")
    }

    #[test]
    fn no_environment_variable_can_set_the_authorisation_flag() {
        // This crate enables clap's `env` feature, and other commands do bind
        // flags to variables (`--passphrase` reads STEGCORE_PASSPHRASE). So the
        // absence of a binding here has to be asserted rather than assumed: one
        // added later would let a script authorise itself by exporting a
        // variable, with nothing on the command line to show it happened.
        assert!(
            authorisation_flag().get_env().is_none(),
            "the authorisation flag must not be settable from the environment"
        );
    }

    #[test]
    fn the_authorisation_flag_has_no_alias_and_no_short_form() {
        // An alias is a second spelling that does the same thing, which is
        // exactly how a gate quietly acquires an undocumented way through.
        let flag = authorisation_flag();
        assert_eq!(flag.get_long(), Some("i-am-authorised"));
        assert!(flag.get_short().is_none(), "no short form");
        assert_eq!(
            flag.get_all_aliases().map(|a| a.len()).unwrap_or(0),
            0,
            "no long aliases"
        );
        assert_eq!(
            flag.get_all_short_aliases().map(|a| a.len()).unwrap_or(0),
            0,
            "no short aliases"
        );
        assert!(
            !flag.is_hide_set(),
            "the gate must appear in the help text, not be hidden from it"
        );
    }

    #[test]
    fn no_other_flag_on_this_command_reads_from_the_environment() {
        // The gate reads the file beside the carrier and the manifest beside
        // that. None of this command's inputs should arrive invisibly.
        let bound: Vec<String> = command()
            .get_arguments()
            .filter(|a| a.get_env().is_some())
            .map(|a| a.get_id().to_string())
            .collect();
        assert!(
            bound.is_empty(),
            "these flags can be set from the environment, which hides them from the \
             recorded invocation: {bound:?}"
        );
    }

    #[test]
    fn naming_no_tool_searches_for_every_tool() {
        let targets = Targets::from_flags(false, false, false);
        assert!(targets.steghide);
        assert!(targets.openstego);
    }

    #[test]
    fn any_searches_for_every_tool_even_beside_a_specific_flag() {
        assert_eq!(
            Targets::from_flags(true, false, true),
            Targets {
                steghide: true,
                openstego: true
            }
        );
    }

    #[test]
    fn a_single_flag_narrows_the_search() {
        assert_eq!(
            Targets::from_flags(false, true, false),
            Targets {
                steghide: false,
                openstego: true
            }
        );
        assert_eq!(
            Targets::from_flags(true, false, false),
            Targets {
                steghide: true,
                openstego: false
            }
        );
    }

    #[test]
    fn every_stop_reason_has_plain_words() {
        for reason in [
            StopReason::Found,
            StopReason::Exhausted,
            StopReason::CapReached,
            StopReason::DeadlineReached,
            StopReason::Cancelled,
        ] {
            let text = describe_stop(&reason);
            assert!(!text.is_empty());
            assert!(
                !text.contains('-'),
                "user-facing text must not carry hyphens: {text:?}"
            );
        }
    }

    #[test]
    fn a_skipped_tool_carries_its_reason_and_claims_nothing() {
        let entry = skipped("Steghide", "not finished");
        assert!(!entry.found);
        assert_eq!(entry.skipped.as_deref(), Some("not finished"));
        assert_eq!(entry.candidates_tried, 0);
        assert!(entry.key.is_none());
    }

    #[test]
    fn steghide_is_reported_as_unchecked_rather_than_clean() {
        let entry = run_steghide(&args_for("x.png"));
        assert!(!entry.found);
        let why = entry.skipped.expect("must carry a reason");
        assert!(why.contains("not been checked"));
        assert!(why.contains("unknown rather than as clean"));
    }

    fn args_for(file: &str) -> BruteForceArgs {
        BruteForceArgs {
            file: PathBuf::from(file),
            steghide: false,
            openstego: false,
            any: false,
            wordlist: None,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            resume_from: 0,
            time_limit: None,
            seed_only: false,
            threads: 0,
            manifest: None,
            manifest_key: None,
            i_am_authorised: false,
        }
    }

    #[test]
    fn limits_follow_the_flags() {
        let mut args = args_for("x.png");
        args.max_attempts = 4242;
        args.resume_from = 99;
        args.threads = 3;
        args.time_limit = Some(7);
        let limits = limits_from(&args);
        assert_eq!(limits.max_attempts, 4242);
        assert_eq!(limits.resume_from, 99);
        assert_eq!(limits.threads, 3);
        assert_eq!(limits.deadline, Some(Duration::from_secs(7)));
        assert_eq!(limits.heartbeat, HEARTBEAT);
    }

    #[test]
    fn no_time_limit_means_no_deadline_but_still_a_cap() {
        let limits = limits_from(&args_for("x.png"));
        assert!(limits.deadline.is_none());
        assert_eq!(limits.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert!(limits.max_attempts > 0, "the cap is never unbounded");
    }

    #[test]
    fn a_manifest_without_its_key_is_refused_with_a_reason() {
        let mut args = args_for("x.png");
        args.manifest = Some(PathBuf::from("/nonexistent/job.manifest"));
        let err = load_manifest(&args).unwrap_err();
        assert!(err.contains("job.manifest"));
    }

    #[test]
    fn no_manifest_is_not_an_error() {
        assert!(load_manifest(&args_for("x.png")).unwrap().is_none());
    }

    #[test]
    fn a_manifest_with_a_missing_key_file_names_the_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("job.manifest");
        std::fs::write(&manifest, "client = Acme\nsignature = 00\n").unwrap();
        let mut args = args_for("x.png");
        args.manifest = Some(manifest);
        args.manifest_key = Some(PathBuf::from("/nonexistent/key"));
        let err = load_manifest(&args).unwrap_err();
        assert!(err.contains("signing key"));
    }

    #[test]
    fn an_empty_manifest_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("job.manifest");
        std::fs::write(&manifest, "client = Acme\nsignature = 00\n").unwrap();
        let key = dir.path().join("key");
        std::fs::write(&key, b"").unwrap();
        let mut args = args_for("x.png");
        args.manifest = Some(manifest);
        args.manifest_key = Some(key);
        assert!(load_manifest(&args).unwrap_err().contains("is empty"));
    }

    #[test]
    fn the_invocation_recorded_is_not_empty() {
        assert!(!invocation().is_empty());
    }

    #[test]
    fn an_outcome_serialises_without_leaking_an_absent_key() {
        let outcome = Outcome {
            authorisation: Record {
                invocation: "stegcore brute-force".into(),
                operator: "tester".into(),
                hostname: "host".into(),
                timestamp_unix: 1_700_000_000,
                input_sha256: "ab".into(),
                manifest_verified: false,
                manifest_sha256: None,
                outcome: authorisation::NOTHING_RECOVERED.into(),
            },
            attempts: vec![skipped("Steghide", "not finished")],
            identified_tool: None,
            absence_is_meaningful: false,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        assert!(!json.contains("\"key\""));
        assert!(json.contains("not recovered"));
        assert!(json.contains("\"absence_is_meaningful\":false"));
    }
}
