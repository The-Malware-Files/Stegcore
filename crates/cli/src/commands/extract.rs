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
#[command(after_long_help = "\x1b[36mExamples:\x1b[0m
  stegcore extract stego.png -o recovered.txt
  stegcore extract stego.png --stdout
  stegcore extract stego.png --raw | xxd
  stegcore extract stego.png --key-file stego.json
")]
pub struct ExtractArgs {
    /// Stego file to extract from
    pub stego: PathBuf,

    /// Optional path to a .json key file (not required for most extractions)
    #[arg(long)]
    pub key_file: Option<PathBuf>,

    /// Passphrase (omit to be prompted securely).
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

    /// Where to save the extracted payload (default: ./extracted.<stego-stem>).
    /// Cannot be combined with --stdout or --raw.
    #[arg(long, short = 'o', conflicts_with_all = ["stdout", "raw"])]
    pub output: Option<PathBuf>,

    /// Print extracted payload to stdout (text payloads only; use --raw for binary)
    #[arg(long)]
    pub stdout: bool,

    /// Write raw bytes to stdout (for piping: stegcore extract stego.png --raw | xxd).
    /// Cannot be combined with --stdout.
    #[arg(long, conflicts_with = "stdout")]
    pub raw: bool,

    /// Overwrite the output file if it already exists
    #[arg(long)]
    pub force: bool,
}

pub fn run(
    args: &ExtractArgs,
    verbose: bool,
    json: bool,
    _quiet: bool,
    interrupted: Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    // ── Validate inputs ───────────────────────────────────────────────────────
    if !args.stego.exists() {
        let e = stegcore_core::errors::StegError::FileNotFound(args.stego.display().to_string());
        if json {
            output::emit_json(
                &JsonOut::<()>::failure(&e.to_string()),
                output::exit_code(&e),
            );
        }
        output::die(&e, verbose);
    }
    if let Some(kf) = &args.key_file {
        if !kf.exists() {
            let e = stegcore_core::errors::StegError::FileNotFound(kf.display().to_string());
            if json {
                output::emit_json(
                    &JsonOut::<()>::failure(&e.to_string()),
                    output::exit_code(&e),
                );
            }
            output::die(&e, verbose);
        }
    }

    // ── Passphrase ────────────────────────────────────────────────────────────
    let passphrase = match (&args.passphrase, &args.passphrase_file) {
        (_, Some(path)) => match prompt::passphrase_from_file(path) {
            Ok(p) => p,
            Err(e) => output::die(&e, verbose),
        },
        (Some(p), None) => zeroize::Zeroizing::new(p.as_bytes().to_vec()),
        (None, None) => prompt::prompt_passphrase("Passphrase", &interrupted),
    };

    // ── Extract ───────────────────────────────────────────────────────────────
    let start = std::time::Instant::now();
    let spinner = Spinner::new("Extracting…", Arc::clone(&interrupted));

    let result = if let Some(kf_path) = &args.key_file {
        match stegcore_core::keyfile::read_key_file(kf_path) {
            Ok(kf) => steg::extract_with_keyfile(&args.stego, &kf, &passphrase),
            Err(e) => {
                drop(spinner);
                if json {
                    output::emit_json(
                        &JsonOut::<()>::failure(&e.to_string()),
                        output::exit_code(&e),
                    );
                }
                output::die(&e, verbose);
            }
        }
    } else {
        steg::extract(&args.stego, &passphrase)
    };

    match result {
        Ok(data) => {
            let elapsed = start.elapsed();
            spinner.success(&format!(
                "Extracted successfully in {:.1}s",
                elapsed.as_secs_f64()
            ));

            // --raw: write raw bytes to stdout (for piping)
            if args.raw {
                use std::io::Write;
                let mut out = std::io::stdout().lock();
                if let Err(e) = out.write_all(&data) {
                    let err = stegcore_core::errors::StegError::Io(e);
                    output::die(&err, verbose);
                }
                std::process::exit(0);
            }

            if args.stdout {
                // Print as UTF-8 if possible; warn if binary.
                match std::str::from_utf8(&data) {
                    Ok(text) => {
                        // `print!`, not `println!`: the payload's own bytes are
                        // reproduced exactly, so a println here would append a
                        // newline the embedded message never had. A payload
                        // that already ends in "\n" would otherwise come back
                        // with two, which is silently wrong for anyone piping
                        // this into something that checks the bytes.
                        use std::io::Write;
                        print!("{text}");
                        let _ = std::io::stdout().flush();
                    }
                    Err(_) => {
                        output::print_warn(
                            "Payload is not valid UTF-8 — use --raw for binary, or --output to save.",
                        );
                        if json {
                            output::emit_json(
                                &JsonOut::<()>::failure(
                                    "Payload is binary; use --raw or --output.",
                                ),
                                1,
                            );
                        }
                        std::process::exit(1);
                    }
                }
                if json {
                    #[derive(serde::Serialize)]
                    struct Out {
                        bytes: usize,
                    }
                    output::emit_json(&JsonOut::success(Out { bytes: data.len() }), 0);
                }
                std::process::exit(0);
            }

            // Determine output path.
            let out_path = args.output.clone().unwrap_or_else(|| {
                let stem = args.stego.file_stem().unwrap_or_default().to_string_lossy();
                PathBuf::from(format!("extracted_{stem}"))
            });

            // Refuse to clobber an existing file unless --force.
            if !args.force && out_path.exists() {
                let msg = format!(
                    "Output file already exists: {} (use --force to overwrite)",
                    out_path.display()
                );
                if json {
                    output::emit_json(&JsonOut::<()>::failure(&msg), 1);
                }
                output::print_error(&msg, None);
                std::process::exit(1);
            }

            if let Err(e) = std::fs::write(&out_path, &data) {
                let err = stegcore_core::errors::StegError::Io(e);
                if json {
                    output::emit_json(&JsonOut::<()>::failure(&err.to_string()), 3);
                }
                output::die(&err, verbose);
            }

            output::print_info(&format!("Saved → {}", out_path.display()));

            if json {
                #[derive(serde::Serialize)]
                struct Out {
                    output: String,
                    bytes: usize,
                }
                output::emit_json(
                    &JsonOut::success(Out {
                        output: out_path.display().to_string(),
                        bytes: data.len(),
                    }),
                    0,
                );
            }
            std::process::exit(0);
        }
        // Oracle-resistant: same message for wrong passphrase and no payload.
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
