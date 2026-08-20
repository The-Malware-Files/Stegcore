// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

use std::path::PathBuf;
use std::sync::Arc;

use stegcore_core::steg;

use crate::output::{self, JsonOut, Spinner};
use crate::prompt;

#[derive(Debug, clap::Args)]
pub struct InfoArgs {
    /// Stego file to inspect
    pub file: PathBuf,

    /// Passphrase (omit to be prompted securely)
    ///
    /// The passphrase is required to read embedded metadata because slot
    /// selection is passphrase-seeded for all embedding modes.
    ///
    /// WARNING: a passphrase given here is readable by any local user while the
    /// command runs, because /proc/<pid>/cmdline is world readable. Env vars are
    /// visible to child processes and may be logged in shell history. The
    /// interactive prompt has neither property; prefer it for sensitive use.
    #[arg(long, env = "STEGCORE_PASSPHRASE", hide_env = true)]
    pub passphrase: Option<String>,
    /// Read the passphrase from a file instead. Safer than --passphrase for
    /// scripts: the value never appears in the process command line. One
    /// trailing newline is stripped.
    #[arg(long, conflicts_with = "passphrase", value_name = "PATH")]
    pub passphrase_file: Option<PathBuf>,
}

pub fn run(
    args: &InfoArgs,
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

    let passphrase = match (&args.passphrase, &args.passphrase_file) {
        (_, Some(path)) => match prompt::passphrase_from_file(path) {
            Ok(p) => p,
            Err(e) => output::die(&e, verbose),
        },
        (Some(p), None) => zeroize::Zeroizing::new(p.as_bytes().to_vec()),
        (None, None) => {
            output::print_info("The passphrase is required to read embedded metadata.");
            prompt::prompt_passphrase("Passphrase", &interrupted)
        }
    };

    let spinner = Spinner::new("Reading metadata…", Arc::clone(&interrupted));

    match steg::read_meta(&args.file, &passphrase) {
        Ok(meta) => {
            spinner.success("Metadata");
            if json {
                output::emit_json(&JsonOut::success(&meta), 0);
            }
            // Pretty-print key/value table.
            if let serde_json::Value::Object(map) = &meta {
                let width = map.keys().map(|k| k.len()).max().unwrap_or(0);
                for (k, v) in map {
                    let val_str = match v {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        serde_json::Value::Null => "(none)".into(),
                        other => other.to_string(),
                    };
                    output::print_info(&format!("  {k:<width$}  {val_str}"));
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&meta).unwrap_or_default()
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
