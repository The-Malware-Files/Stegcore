// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use std::path::PathBuf;
use std::sync::Arc;

use stegcore_core::steg;

use crate::output::{self, JsonOut, Spinner};

#[derive(Debug, clap::Args)]
pub struct ScoreArgs {
    /// Image or audio file to score
    pub file: PathBuf,
}

pub fn run(
    args: &ScoreArgs,
    verbose: bool,
    json: bool,
    _quiet: bool,
    interrupted: Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    if !args.file.exists() {
        let e = stegcore_core::errors::StegError::FileNotFound(args.file.display().to_string());
        if json {
            output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 3);
        }
        output::die(&e, verbose);
    }

    let spinner = Spinner::new("Scoring…", Arc::clone(&interrupted));

    match steg::assess(&args.file) {
        Ok(score) => {
            let pct = (score * 100.0).round() as u32;
            let label = match pct {
                75..=100 => "Excellent",
                50..=74 => "Good",
                25..=49 => "Fair",
                _ => "Poor — not recommended for embedding",
            };
            spinner.success(&format!("{pct}/100 — {label}"));
            if json {
                #[derive(serde::Serialize)]
                struct Out {
                    score: f64,
                    percent: u32,
                    label: &'static str,
                }
                output::emit_json(
                    &JsonOut::success(Out {
                        score,
                        percent: pct,
                        label,
                    }),
                    0,
                );
            }
            std::process::exit(0);
        }
        Err(e) => {
            spinner.fail(&e.to_string());
            if json {
                output::emit_json(
                    &JsonOut::<()>::failure(&e.to_string()),
                    output::exit_code(&e),
                );
            }
            if verbose {
                output::print_error(&e.to_string(), Some(&format!("{e:#}")));
            } else {
                output::print_error(&e.to_string(), None);
            }
            std::process::exit(output::exit_code(&e));
        }
    }
}
