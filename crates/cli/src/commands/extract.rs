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
    /// WARNING: env vars may be logged. Prefer the interactive prompt.
    #[arg(long, env = "STEGCORE_PASSPHRASE", hide_env = true)]
    pub passphrase: Option<String>,

    /// Where to save the extracted payload (default: ./extracted.<stego-stem>)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Print extracted payload to stdout (text payloads only; use --raw for binary)
    #[arg(long)]
    pub stdout: bool,

    /// Write raw bytes to stdout (for piping: stegcore extract stego.png --raw | xxd)
    #[arg(long)]
    pub raw: bool,
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
    let passphrase = match &args.passphrase {
        Some(p) => zeroize::Zeroizing::new(p.as_bytes().to_vec()),
        None => prompt::prompt_passphrase("Passphrase", &interrupted),
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
                    Ok(text) => println!("{text}"),
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
