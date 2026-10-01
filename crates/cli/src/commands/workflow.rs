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

//! `stegcore init` and `stegcore workflow validate`.
//!
//! Both commands are deliberately side-effect-light. `validate` reads one file
//! and writes nothing at all, so checking a pipeline somebody sent you is safe;
//! `init` writes exactly one file and refuses to overwrite.
//!
//! Running a pipeline is not here. The runner has to drive the analysis and the
//! watch loop, which live elsewhere, and keeping validation separate from
//! execution is what lets the validator be pure.

use std::path::PathBuf;

use stegcore_engine::workflow::dsl::{PipelineFile, Problem};
use stegcore_engine::workflow::templates::{self, TEMPLATES, TEMPLATE_VERSION};

use crate::output::{self, JsonOut};

/// Exit code for a pipeline file that parses but does not validate.
///
/// Its own code, distinct from 4 (unreadable input), because a continuous
/// integration job wants to tell "your pipeline has a mistake in it" from "your
/// file is not a pipeline at all", and both from a crash.
///
/// Six rather than five, because five is taken: `output::exit_code` maps an
/// internal failure to it, meaning "Stegcore broke, please report this". Both
/// codes are new in this release and neither has shipped, so this is a free
/// choice rather than a migration, and the two meanings are as far apart as two
/// meanings get. A continuous integration job that sees five should open a bug
/// against us; one that sees six should fix its own pipeline. Collapsing them
/// would send every one of those bug reports to the wrong place.
pub const EXIT_PIPELINE_INVALID: i32 = 6;

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Starter template to write: triage, forensics or ctf
    ///
    /// Optional only so `--list` can be asked on its own; clap requires it
    /// otherwise, which is what keeps the name from reaching the lookup empty.
    #[arg(required_unless_present = "list")]
    pub template: Option<String>,

    /// Where to write it (defaults to the template's name plus .toml)
    #[arg(long, short)]
    pub out: Option<PathBuf>,

    /// List the templates and what each one is for, writing nothing
    #[arg(long)]
    pub list: bool,
}

#[derive(Debug, clap::Args)]
pub struct ValidateArgs {
    /// Pipeline file to check
    pub pipeline: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct WorkflowArgs {
    #[command(subcommand)]
    pub command: WorkflowCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum WorkflowCommand {
    /// Check a pipeline file and report every problem, running nothing
    Validate(ValidateArgs),
}

/// `stegcore workflow <subcommand>`
pub fn run(args: &WorkflowArgs, verbose: bool, json: bool, quiet: bool) -> ! {
    match &args.command {
        WorkflowCommand::Validate(validate) => run_validate(validate, verbose, json, quiet),
    }
}

/// `stegcore init <template>`
pub fn run_init(args: &InitArgs, verbose: bool, json: bool, quiet: bool) -> ! {
    if args.list {
        list_templates(json);
    }

    let template = match templates::template(args.template.as_deref().unwrap_or_default()) {
        Ok(found) => found,
        Err(e) => {
            if json {
                output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 4);
            }
            output::print_error(&e.to_string(), None);
            std::process::exit(4);
        }
    };

    // Validated before it is written, not after. A starter template is a
    // promise that the file works, and the test suite gates every shipped one,
    // but checking here as well costs microseconds and means a corrupted build
    // cannot hand somebody a broken file.
    if let Err(e) = template.parse() {
        if json {
            output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 1);
        }
        output::print_error(
            &format!("the built-in {} template did not validate", template.name),
            Some(&e.to_string()),
        );
        std::process::exit(1);
    }

    let out = args
        .out
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.toml", template.name)));

    if out.exists() {
        let message = format!(
            "{} already exists. Pass --out to write somewhere else, or move it first.",
            out.display()
        );
        if json {
            output::emit_json(&JsonOut::<()>::failure(&message), 3);
        }
        output::print_error(&message, None);
        std::process::exit(3);
    }

    if let Err(e) = std::fs::write(&out, template.body) {
        let message = format!("could not write {}: {e}", out.display());
        if json {
            output::emit_json(&JsonOut::<()>::failure(&message), 3);
        }
        output::print_error(&message, verbose.then(|| format!("{e:#}")).as_deref());
        std::process::exit(3);
    }

    if json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            template: &'a str,
            version: u32,
            written: String,
        }
        output::emit_json(
            &JsonOut::success(Out {
                template: template.name,
                version: TEMPLATE_VERSION,
                written: out.display().to_string(),
            }),
            0,
        );
    }

    if !quiet {
        output::print_success(&format!(
            "Wrote the {} template (v{TEMPLATE_VERSION}) to {}",
            template.name,
            out.display()
        ));
        output::print_info(&format!("Next: {}", next_step(template.name, &out)));
    }
    std::process::exit(0);
}

/// `stegcore workflow validate <pipeline.toml>`
pub fn run_validate(args: &ValidateArgs, verbose: bool, json: bool, quiet: bool) -> ! {
    let file = match PipelineFile::read(&args.pipeline) {
        Ok(file) => file,
        Err(e) => {
            let public: stegcore_core::errors::StegError = e.into();
            let code = output::exit_code(&public);
            if json {
                output::emit_json(&JsonOut::<()>::failure(&public.to_string()), code);
            }
            output::print_error(
                &public.to_string(),
                verbose.then(|| format!("{public:#}")).as_deref(),
            );
            std::process::exit(code);
        }
    };

    let problems = file.validate();

    if json {
        #[derive(serde::Serialize)]
        struct ProblemOut {
            at: String,
            reason: String,
        }
        #[derive(serde::Serialize)]
        struct Out {
            pipelines: Vec<String>,
            runnable: bool,
            problems: Vec<ProblemOut>,
        }
        let out = Out {
            pipelines: file.pipelines.keys().cloned().collect(),
            runnable: problems.is_empty(),
            problems: problems
                .iter()
                .map(|p| ProblemOut {
                    at: p.at.clone(),
                    reason: p.reason.clone(),
                })
                .collect(),
        };
        let code = if problems.is_empty() {
            0
        } else {
            EXIT_PIPELINE_INVALID
        };
        output::emit_json(&JsonOut::success(out), code);
    }

    if problems.is_empty() {
        if !quiet {
            output::print_success(&summary_line(&file));
            for name in file.pipelines.keys() {
                let pipeline = &file.pipelines[name];
                output::print_info(&format!(
                    "{name}: {} step(s), reading {}",
                    pipeline.steps.len(),
                    pipeline.input.location()
                ));
            }
        }
        std::process::exit(0);
    }

    output::print_error(
        &format!(
            "{} problem(s) in {}. Nothing has been run.",
            problems.len(),
            args.pipeline.display()
        ),
        None,
    );
    for problem in &problems {
        eprintln!("  {}", render(problem));
    }
    std::process::exit(EXIT_PIPELINE_INVALID);
}

fn list_templates(json: bool) -> ! {
    if json {
        #[derive(serde::Serialize)]
        struct Entry<'a> {
            name: &'a str,
            summary: &'a str,
        }
        #[derive(serde::Serialize)]
        struct Out<'a> {
            version: u32,
            templates: Vec<Entry<'a>>,
        }
        output::emit_json(
            &JsonOut::success(Out {
                version: TEMPLATE_VERSION,
                templates: TEMPLATES
                    .iter()
                    .map(|t| Entry {
                        name: t.name,
                        summary: t.summary,
                    })
                    .collect(),
            }),
            0,
        );
    }
    output::print_info(&format!("Starter templates (v{TEMPLATE_VERSION}):"));
    for template in TEMPLATES {
        println!("  {:<10} {}", template.name, template.summary);
    }
    std::process::exit(0);
}

/// One line saying what validated, so a success is not a bare tick.
fn summary_line(file: &PipelineFile) -> String {
    let count = file.pipelines.len();
    if count == 1 {
        format!(
            "{} is runnable",
            file.pipelines
                .keys()
                .next()
                .map(String::as_str)
                .unwrap_or("the pipeline")
        )
    } else {
        format!("all {count} pipelines are runnable")
    }
}

fn render(problem: &Problem) -> String {
    format!("{}: {}", problem.at, problem.reason)
}

/// What to do with the file that was just written.
fn next_step(name: &str, out: &std::path::Path) -> String {
    let path = out.display();
    match name {
        "forensics" => format!(
            "point the input in {path} at your exhibit, then run stegcore workflow validate {path}"
        ),
        "triage" => format!(
            "create ./inbox, ./records and ./recovered, then run stegcore workflow validate {path}"
        ),
        _ => format!("run stegcore workflow validate {path}"),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_invalid_pipeline_code_does_not_collide_with_the_shared_table() {
        // 3 is "cannot read your input", 4 is "cannot understand your input",
        // 5 is "Stegcore broke". A pipeline that parses and fails validation is
        // none of those, so it has its own code and a script can tell all four
        // apart.
        //
        // InternalFailure is the one this test used to omit, and it was a real
        // collision rather than a hypothetical: both were 5, so a job could not
        // tell a mistake in its own pipeline from a bug it should report to us.
        use stegcore_core::errors::StegError;
        for other in [
            StegError::FileNotFound("x".into()),
            StegError::UnsupportedFormat("x".into()),
            StegError::InternalFailure {
                diagnostic: Some("x".into()),
            },
        ] {
            assert_ne!(
                EXIT_PIPELINE_INVALID,
                output::exit_code(&other),
                "{other:?} shares the invalid-pipeline exit code"
            );
        }
        assert_ne!(EXIT_PIPELINE_INVALID, 0);
    }

    #[test]
    fn every_template_has_a_next_step_that_names_the_file() {
        let path = std::path::Path::new("triage.toml");
        for template in TEMPLATES {
            let advice = next_step(template.name, path);
            assert!(
                advice.contains("triage.toml"),
                "{}: {advice}",
                template.name
            );
        }
    }

    #[test]
    fn a_problem_renders_its_path_and_reason() {
        let problem = Problem {
            at: "pipeline.a.steps[2].report.out".to_string(),
            reason: "no placeholder".to_string(),
        };
        assert_eq!(
            render(&problem),
            "pipeline.a.steps[2].report.out: no placeholder"
        );
    }

    #[test]
    fn the_summary_names_the_pipeline_when_there_is_only_one() {
        let file = PipelineFile::parse_runnable(
            r#"
[pipeline.triage]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { manifest = { out = "./m/{{stem}}.json" } },
]
"#,
        )
        .expect("runnable");
        assert_eq!(summary_line(&file), "triage is runnable");
    }

    #[test]
    fn the_summary_counts_them_when_there_are_several() {
        let file = PipelineFile::parse_runnable(
            r#"
[pipeline.a]
input = "path:./x.png"
steps = [
  { analyse = { detectors = ["spa"] } },
  { manifest = { out = "./m/{{stem}}.json" } },
]

[pipeline.b]
input = "path:./y.png"
steps = [
  { analyse = { detectors = ["rs"] } },
  { manifest = { out = "./m/{{stem}}.json" } },
]
"#,
        )
        .expect("runnable");
        assert_eq!(summary_line(&file), "all 2 pipelines are runnable");
    }

    #[test]
    fn every_shipped_template_is_still_valid_from_the_cli_side() {
        for template in TEMPLATES {
            template
                .parse()
                .unwrap_or_else(|e| panic!("{}: {e}", template.name));
        }
    }
}
