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
  stegcore embed photo.png secret.txt
  stegcore embed photo.png secret.txt -o stego.png --cipher aes-256-gcm
  stegcore embed photo.png real.txt --deniable --decoy decoy.txt
  echo \"secret\" | stegcore embed photo.png - -o stego.png
")]
pub struct EmbedArgs {
    /// Cover file (PNG, BMP, JPEG, WAV, WebP)
    pub cover: PathBuf,
    /// Message file to hide (use "-" for stdin)
    pub payload: PathBuf,
    /// Output stego file path (auto-generated if omitted)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Embedding mode
    #[arg(long, default_value = "adaptive", value_parser = ["adaptive", "sequential"])]
    pub mode: String,

    /// Cipher to use
    #[arg(long, default_value = "chacha20-poly1305",
          value_parser = ["chacha20-poly1305", "ascon-128", "aes-256-gcm"])]
    pub cipher: String,

    /// Passphrase (omit to be prompted securely).
    /// WARNING: env vars are visible to child processes and may be logged in shell history.
    /// Prefer the interactive prompt for sensitive use.
    #[arg(long, env = "STEGCORE_PASSPHRASE", hide_env = true)]
    pub passphrase: Option<String>,

    /// Enable deniable dual-payload mode
    #[arg(long)]
    pub deniable: bool,

    /// Decoy message file (required when --deniable is set)
    #[arg(long, requires = "deniable")]
    pub decoy: Option<PathBuf>,

    /// Decoy passphrase (omit to be prompted when --deniable is set)
    #[arg(
        long,
        requires = "deniable",
        env = "STEGCORE_DECOY_PASSPHRASE",
        hide_env = true
    )]
    pub decoy_passphrase: Option<String>,

    /// Export a .json key file alongside the output
    #[arg(long)]
    pub export_key: bool,
}

pub fn run(
    args: &EmbedArgs,
    verbose: bool,
    json: bool,
    _quiet: bool,
    interrupted: Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    // ── Smart output naming ───────────────────────────────────────────────────
    let output = args.output.clone().unwrap_or_else(|| {
        let stem = args.cover.file_stem().unwrap_or_default().to_string_lossy();
        let ext = args.cover.extension().unwrap_or_default().to_string_lossy();
        let parent = args
            .cover
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        parent.join(format!("{stem}_stego.{ext}"))
    });

    // ── Validate inputs ───────────────────────────────────────────────────────
    if !args.cover.exists() {
        let e = stegcore_core::errors::StegError::FileNotFound(args.cover.display().to_string());
        if json {
            output::emit_json(
                &JsonOut::<()>::failure(&e.to_string()),
                output::exit_code(&e),
            );
        }
        output::die(&e, verbose);
    }
    if args.payload.as_os_str() != "-" && !args.payload.exists() {
        let e = stegcore_core::errors::StegError::FileNotFound(args.payload.display().to_string());
        if json {
            output::emit_json(
                &JsonOut::<()>::failure(&e.to_string()),
                output::exit_code(&e),
            );
        }
        output::die(&e, verbose);
    }
    if args.deniable {
        match &args.decoy {
            None => {
                output::print_error("--deniable requires --decoy <file>", None);
                std::process::exit(1);
            }
            Some(p) if !p.exists() => {
                let e = stegcore_core::errors::StegError::FileNotFound(p.display().to_string());
                if json {
                    output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 3);
                }
                output::die(&e, verbose);
            }
            _ => {}
        }
    }

    // ── Read payload (supports "-" for stdin) ──────────────────────────────────
    let payload_read = if args.payload.as_os_str() == "-" {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).map(|_| buf)
    } else {
        std::fs::read(&args.payload)
    };
    let payload_bytes = match payload_read {
        Ok(b) if b.is_empty() => {
            let e = stegcore_core::errors::StegError::EmptyPayload;
            if json {
                output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 1);
            }
            output::die(&e, verbose);
        }
        Ok(b) => b,
        Err(e) => {
            let err = stegcore_core::errors::StegError::Io(e);
            if json {
                output::emit_json(&JsonOut::<()>::failure(&err.to_string()), 3);
            }
            output::die(&err, verbose);
        }
    };

    // ── Passphrases ───────────────────────────────────────────────────────────
    let passphrase = match &args.passphrase {
        Some(p) => zeroize::Zeroizing::new(p.as_bytes().to_vec()),
        None => prompt::prompt_passphrase_confirmed("Passphrase", &interrupted),
    };
    if passphrase.is_empty() {
        output::print_error("Passphrase cannot be empty.", None);
        std::process::exit(1);
    }

    // ── Embed ─────────────────────────────────────────────────────────────────
    let spinner = Spinner::new("Embedding…", Arc::clone(&interrupted));

    if args.deniable {
        let decoy_path = args.decoy.as_ref().unwrap();
        let decoy_bytes = match std::fs::read(decoy_path) {
            Ok(b) if b.is_empty() => {
                drop(spinner);
                let e = stegcore_core::errors::StegError::EmptyPayload;
                if json {
                    output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 1);
                }
                output::die(&e, verbose);
            }
            Ok(b) => b,
            Err(e) => {
                drop(spinner);
                let err = stegcore_core::errors::StegError::Io(e);
                if json {
                    output::emit_json(&JsonOut::<()>::failure(&err.to_string()), 3);
                }
                output::die(&err, verbose);
            }
        };
        let decoy_pass = match &args.decoy_passphrase {
            Some(p) => zeroize::Zeroizing::new(p.as_bytes().to_vec()),
            None => prompt::prompt_passphrase_confirmed("Decoy passphrase", &interrupted),
        };
        if decoy_pass.is_empty() {
            drop(spinner);
            output::print_error("Decoy passphrase cannot be empty.", None);
            std::process::exit(1);
        }

        match steg::embed_deniable(
            &args.cover,
            &payload_bytes,
            &decoy_bytes,
            &passphrase,
            &decoy_pass,
            &args.cipher,
            &output,
        ) {
            Ok((real_kf, decoy_kf)) => {
                spinner.success(&format!("Embedded (deniable) → {}", output.display()));
                let real_path = output.with_extension("real.json");
                let decoy_path = output.with_extension("decoy.json");
                // Only write key files if explicitly requested — their
                // existence on disk confirms deniable stego was performed.
                if args.export_key {
                    let _ = stegcore_core::keyfile::write_key_file(&real_path, &real_kf);
                    let _ = stegcore_core::keyfile::write_key_file(&decoy_path, &decoy_kf);
                    output::print_info(&format!("Real key file  → {}", real_path.display()));
                    output::print_info(&format!("Decoy key file → {}", decoy_path.display()));
                }
                if json {
                    #[derive(serde::Serialize)]
                    struct Out {
                        output: String,
                        real_key: Option<String>,
                        decoy_key: Option<String>,
                    }
                    output::emit_json(
                        &JsonOut::success(Out {
                            output: output.display().to_string(),
                            real_key: if args.export_key {
                                Some(real_path.display().to_string())
                            } else {
                                None
                            },
                            decoy_key: if args.export_key {
                                Some(decoy_path.display().to_string())
                            } else {
                                None
                            },
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

    // Non-deniable embed (adaptive or sequential).
    let embed_fn = if args.mode == "sequential" {
        steg::embed_sequential
    } else {
        steg::embed_adaptive
    };

    let start = std::time::Instant::now();
    match embed_fn(
        &args.cover,
        &payload_bytes,
        &passphrase,
        &args.cipher,
        &output,
        args.export_key,
    ) {
        Ok(kf_opt) => {
            let elapsed = start.elapsed();
            let key_path = kf_opt.as_ref().and_then(|kf| {
                let p = output.with_extension("json");
                stegcore_core::keyfile::write_key_file(&p, kf).ok()?;
                Some(p)
            });
            spinner.success("Embedded successfully");

            if !json {
                let cover_name = args
                    .cover
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let out_name = output
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let mode_str = if args.mode == "sequential" {
                    "Standard"
                } else {
                    "Adaptive"
                };
                let time_str = format!("{:.1}s", elapsed.as_secs_f64());
                let mut rows: Vec<(&str, &str)> = vec![
                    ("Cover", &cover_name),
                    ("Output", &out_name),
                    ("Cipher", &args.cipher),
                    ("Mode", mode_str),
                    ("Time", &time_str),
                ];
                let key_str = key_path.as_ref().map(|p| p.display().to_string());
                if let Some(ref ks) = key_str {
                    rows.push(("Key file", ks));
                }
                output::print_summary("✓ Embedded", crossterm::style::Color::Green, &rows);
            }

            if json {
                #[derive(serde::Serialize)]
                struct Out {
                    output: String,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    key_file: Option<String>,
                }
                output::emit_json(
                    &JsonOut::success(Out {
                        output: output.display().to_string(),
                        key_file: key_path.map(|p| p.display().to_string()),
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
