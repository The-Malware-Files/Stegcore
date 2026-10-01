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
//
// `stegcore init` and `stegcore workflow validate`, driven through the real
// built binary.
//
// The point of running the binary rather than the functions is the exit codes.
// Both commands are meant to be called from a continuous-integration job, so the
// number the process leaves behind is the contract, and the only way to check a
// contract made of `std::process::exit` is to let a process exit.

use std::path::Path;

use assert_cmd::Command as AssertCommand;
use predicates::prelude::*;
use tempfile::TempDir;

/// Exit code for a pipeline that parses and fails validation. Spelled out here
/// rather than imported: a test that reads the constant it is checking would
/// still pass if the constant changed, and a scripted consumer would not.
///
/// It earned its keep immediately. This was 5, which collided with the internal
/// failure code meaning "Stegcore broke, please report this", so a continuous
/// integration job could not tell a mistake in its own pipeline from a bug it
/// should file against us. Moving the constant broke these four tests, which is
/// the duplication working as designed rather than a maintenance cost.
const EXIT_PIPELINE_INVALID: i32 = 6;

fn bin() -> AssertCommand {
    AssertCommand::cargo_bin("stegcore").expect("binary `stegcore` not built")
}

/// A pipeline that parses and validates.
const GOOD: &str = r#"
[pipeline.triage]
input = "path:./incoming"
steps = [
  { analyse = { detectors = ["spa", "rs"] } },
  { manifest = { out = "./records/{{stem}}.json" } },
]
"#;

/// A pipeline that parses but does not validate: it measures and then throws
/// the measurement away, which is the mistake whole-file validation exists to
/// catch and is invisible when each step is read on its own.
const MEASURED_AND_DISCARDED: &str = r#"
[pipeline.pointless]
input = "path:./incoming"
steps = [
  { analyse = { detectors = ["spa"] } },
]
"#;

/// Two pipelines, one of them broken, so the validator has to report on the
/// file rather than stopping at the first name it reads.
const ONE_OF_TWO_BROKEN: &str = r#"
[pipeline.fine]
input = "path:./a"
steps = [
  { analyse = { detectors = ["spa"] } },
  { manifest = { out = "./m/{{stem}}.json" } },
]

[pipeline.empty]
input = "path:./b"
steps = []
"#;

fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("fixture written");
    path
}

// ── stegcore init ──────────────────────────────────────────────────────────

#[test]
fn init_list_names_every_template_without_writing_anything() {
    let dir = TempDir::new().unwrap();
    bin()
        .current_dir(dir.path())
        .args(["init", "--list"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("triage"))
        .stdout(predicate::str::contains("forensics"))
        .stdout(predicate::str::contains("ctf"));
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "--list must not write a file"
    );
}

#[test]
fn init_list_as_json_carries_the_template_version() {
    let dir = TempDir::new().unwrap();
    let out = bin()
        .current_dir(dir.path())
        .args(["--json", "init", "--list"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("JSON on stdout");
    assert_eq!(parsed["ok"], true);
    assert!(parsed["data"]["version"].is_u64(), "version is a number");
    let names: Vec<&str> = parsed["data"]["templates"]
        .as_array()
        .expect("templates array")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert!(names.contains(&"triage"), "{names:?}");
}

#[test]
fn init_writes_a_template_that_then_validates() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("mine.toml");
    bin()
        .current_dir(dir.path())
        .args(["init", "triage", "--out"])
        .arg(&out)
        .assert()
        .code(0);
    assert!(out.is_file(), "the file should be on disk");

    // The promise `init` makes is that what it writes is runnable, so the two
    // commands are checked together rather than separately.
    bin()
        .args(["workflow", "validate"])
        .arg(&out)
        .assert()
        .code(0);
}

#[test]
fn init_defaults_the_filename_to_the_template_name() {
    let dir = TempDir::new().unwrap();
    bin()
        .current_dir(dir.path())
        .args(["init", "ctf"])
        .assert()
        .code(0);
    assert!(dir.path().join("ctf.toml").is_file());
}

#[test]
fn init_refuses_to_overwrite_an_existing_file() {
    let dir = TempDir::new().unwrap();
    let out = dir.path().join("taken.toml");
    std::fs::write(&out, b"do not lose me").unwrap();
    bin()
        .current_dir(dir.path())
        .args(["init", "triage", "--out"])
        .arg(&out)
        .assert()
        .code(3)
        .stderr(predicate::str::contains("already exists"));
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "do not lose me",
        "the existing file must be untouched"
    );
}

#[test]
fn init_names_the_templates_it_does_have_when_asked_for_one_it_does_not() {
    let dir = TempDir::new().unwrap();
    bin()
        .current_dir(dir.path())
        .args(["init", "not-a-template"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("triage"));
}

#[test]
fn init_without_a_template_or_list_is_a_usage_error() {
    let dir = TempDir::new().unwrap();
    bin()
        .current_dir(dir.path())
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("TEMPLATE"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn every_shipped_template_writes_and_validates() {
    for name in ["triage", "forensics", "ctf"] {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join(format!("{name}.toml"));
        bin()
            .current_dir(dir.path())
            .args(["init", name, "--out"])
            .arg(&out)
            .assert()
            .code(0);
        bin()
            .args(["workflow", "validate"])
            .arg(&out)
            .assert()
            .code(0);
    }
}

// ── stegcore workflow validate ─────────────────────────────────────────────

#[test]
fn validate_accepts_a_runnable_pipeline_and_says_what_it_read() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "good.toml", GOOD);
    bin()
        .args(["workflow", "validate"])
        .arg(&path)
        .assert()
        .code(0)
        .stderr(predicate::str::contains("triage"));
}

#[test]
fn validate_rejects_a_pipeline_that_throws_its_analysis_away() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "bad.toml", MEASURED_AND_DISCARDED);
    bin()
        .args(["workflow", "validate"])
        .arg(&path)
        .assert()
        .code(EXIT_PIPELINE_INVALID)
        .stderr(predicate::str::contains("Nothing has been run"));
}

#[test]
fn validate_reports_the_whole_file_not_just_the_first_pipeline() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "mixed.toml", ONE_OF_TWO_BROKEN);
    bin()
        .args(["workflow", "validate"])
        .arg(&path)
        .assert()
        .code(EXIT_PIPELINE_INVALID)
        .stderr(predicate::str::contains("pipeline.empty.steps"));
}

/// Three failures, three codes. A job that retries on "unreadable file" must
/// not retry on "your pipeline has a mistake in it", which is the whole reason
/// the invalid-pipeline code is its own number.
#[test]
fn the_three_failure_modes_have_three_different_exit_codes() {
    let dir = TempDir::new().unwrap();

    // Missing file.
    bin()
        .args(["workflow", "validate"])
        .arg(dir.path().join("absent.toml"))
        .assert()
        .code(3);

    // Present, but not a pipeline file at all.
    let garbage = write(dir.path(), "garbage.toml", "this is not toml at all = = =");
    bin()
        .args(["workflow", "validate"])
        .arg(&garbage)
        .assert()
        .code(4);

    // Parses, does not validate.
    let invalid = write(dir.path(), "invalid.toml", MEASURED_AND_DISCARDED);
    bin()
        .args(["workflow", "validate"])
        .arg(&invalid)
        .assert()
        .code(EXIT_PIPELINE_INVALID);
}

#[test]
fn validate_as_json_reports_runnable_and_an_empty_problem_list() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "good.toml", GOOD);
    let out = bin()
        .args(["--json", "workflow", "validate"])
        .arg(&path)
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("JSON on stdout");
    assert_eq!(parsed["data"]["runnable"], true);
    assert_eq!(parsed["data"]["problems"].as_array().unwrap().len(), 0);
    assert_eq!(parsed["data"]["pipelines"][0], "triage");
}

#[test]
fn validate_as_json_names_each_problem_and_where_it_is() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "bad.toml", MEASURED_AND_DISCARDED);
    let out = bin()
        .args(["--json", "workflow", "validate"])
        .arg(&path)
        .assert()
        .code(EXIT_PIPELINE_INVALID)
        .get_output()
        .stdout
        .clone();
    let parsed: serde_json::Value = serde_json::from_slice(&out).expect("JSON on stdout");
    assert_eq!(parsed["data"]["runnable"], false);
    let problems = parsed["data"]["problems"].as_array().expect("problems");
    assert!(!problems.is_empty());
    assert!(
        problems[0]["at"].as_str().unwrap().starts_with("pipeline."),
        "a problem must say where it is: {problems:?}"
    );
    assert!(problems[0]["reason"].as_str().unwrap().len() > 5);
}

#[test]
fn validate_writes_nothing_at_all() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "good.toml", GOOD);
    let before = std::fs::read_to_string(&path).unwrap();
    bin()
        .args(["workflow", "validate"])
        .arg(&path)
        .assert()
        .code(0);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
}

#[test]
fn validate_under_quiet_prints_nothing_on_success_but_still_exits_zero() {
    let dir = TempDir::new().unwrap();
    let path = write(dir.path(), "good.toml", GOOD);
    bin()
        .args(["--quiet", "workflow", "validate"])
        .arg(&path)
        .assert()
        .code(0)
        .stderr(predicate::str::is_empty());
}

#[test]
fn workflow_without_a_subcommand_is_a_usage_error() {
    bin()
        .arg("workflow")
        .assert()
        .failure()
        .stderr(predicate::str::contains("validate"));
}

#[test]
fn both_commands_appear_in_the_top_level_help() {
    bin()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("workflow"));
}
