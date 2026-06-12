// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! `stegcore watermark`: write an encrypted ownership mark into a carrier, or
//! read one back with `--verify`.
//!
//! Writing a watermark is gated behind a one-time machine-local consent
//! acknowledgement (`--i-am-authorised`), shared with the desktop app so the
//! operator only confirms once. Reading a mark back (`--verify`) is ungated:
//! the abuse the gate guards against is marking documents you do not own, not
//! reading a mark you already hold the passphrase for.

use std::path::PathBuf;
use std::sync::Arc;

use stegcore_core::{consent, watermark};

use crate::output::{self, JsonOut, Spinner};
use crate::prompt;

/// Exit code used when watermarking is refused for lack of recorded consent.
const EXIT_CONSENT_REQUIRED: i32 = 2;

#[derive(Debug, clap::Args)]
#[command(after_long_help = "\x1b[36mExamples:\x1b[0m
  stegcore watermark photo.png --text \"owner: Acme Corp\" --i-am-authorised
  stegcore watermark photo.png --text \"ref: INV-2026-001\" -o marked.png
  stegcore watermark marked.png --verify
")]
pub struct WatermarkArgs {
    /// Carrier file to watermark (PNG, BMP, WebP, PDF, DOCX, PPTX, XLSX)
    pub file: PathBuf,

    /// Watermark text: the ownership or identity mark to write.
    /// Required unless --verify is set.
    #[arg(short, long)]
    pub text: Option<String>,

    /// Output path (auto-generated as <name>_marked.<ext> if omitted)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Passphrase (omit to be prompted securely).
    /// WARNING: env vars are visible to child processes and may be logged in shell history.
    #[arg(long, env = "STEGCORE_PASSPHRASE", hide_env = true)]
    pub passphrase: Option<String>,

    /// Cipher to use
    #[arg(long, default_value = "chacha20-poly1305",
          value_parser = ["chacha20-poly1305", "ascon-128", "aes-256-gcm"])]
    pub cipher: String,

    /// Confirm you are authorised to watermark this file. Recorded once on this
    /// machine and shared with the desktop app; not needed on later runs.
    #[arg(long)]
    pub i_am_authorised: bool,

    /// Read back and print the watermark instead of writing one.
    #[arg(long)]
    pub verify: bool,

    /// Overwrite the output file if it already exists
    #[arg(long)]
    pub force: bool,
}

pub fn run(
    args: &WatermarkArgs,
    verbose: bool,
    json: bool,
    _quiet: bool,
    interrupted: Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    if !args.file.exists() {
        let e = stegcore_core::errors::StegError::FileNotFound(args.file.display().to_string());
        if json {
            output::emit_json(
                &JsonOut::<()>::failure(&e.to_string()),
                output::exit_code(&e),
            );
        }
        output::die(&e, verbose);
    }

    if args.verify {
        run_verify(args, verbose, json, &interrupted);
    }
    run_write(args, verbose, json, &interrupted);
}

/// Read back and print a watermark. Ungated.
fn run_verify(
    args: &WatermarkArgs,
    verbose: bool,
    json: bool,
    interrupted: &Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    let passphrase = match &args.passphrase {
        Some(p) => zeroize::Zeroizing::new(p.as_bytes().to_vec()),
        None => prompt::prompt_passphrase("Passphrase", interrupted),
    };

    let spinner = Spinner::new("Reading watermark…", Arc::clone(interrupted));
    match watermark::read_watermark(&args.file, &passphrase) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes).to_string();
            spinner.success("Watermark found");
            if json {
                #[derive(serde::Serialize)]
                struct Out {
                    watermark: String,
                }
                output::emit_json(&JsonOut::success(Out { watermark: text }), 0);
            }
            println!("{text}");
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
            output::die(&e, verbose);
        }
    }
}

/// Write a watermark. Gated behind recorded consent.
fn run_write(
    args: &WatermarkArgs,
    verbose: bool,
    json: bool,
    interrupted: &Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    ensure_consent(args, json);

    let Some(text) = args.text.as_deref() else {
        let msg = "Watermark text is required: pass --text \"<mark>\" (or --verify to read one).";
        if json {
            output::emit_json(&JsonOut::<()>::failure(msg), 1);
        }
        output::print_error(msg, None);
        std::process::exit(1);
    };
    if text.is_empty() {
        let e = stegcore_core::errors::StegError::EmptyPayload;
        if json {
            output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 1);
        }
        output::die(&e, verbose);
    }

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| default_output(&args.file));
    if !args.force && output_path.exists() {
        let msg = format!(
            "Output file already exists: {} (use --force to overwrite)",
            output_path.display()
        );
        if json {
            output::emit_json(&JsonOut::<()>::failure(&msg), 1);
        }
        output::print_error(&msg, None);
        std::process::exit(1);
    }

    let passphrase = match &args.passphrase {
        Some(p) => zeroize::Zeroizing::new(p.as_bytes().to_vec()),
        None => prompt::prompt_passphrase_confirmed("Passphrase", interrupted),
    };
    if passphrase.is_empty() {
        output::print_error("Passphrase cannot be empty.", None);
        std::process::exit(1);
    }

    let spinner = Spinner::new("Watermarking…", Arc::clone(interrupted));
    match watermark::watermark(
        &args.file,
        text.as_bytes(),
        &passphrase,
        &args.cipher,
        &output_path,
    ) {
        Ok(written) => {
            spinner.success(&format!("Watermarked → {}", written.display()));
            if json {
                #[derive(serde::Serialize)]
                struct Out {
                    output: String,
                }
                output::emit_json(
                    &JsonOut::success(Out {
                        output: written.display().to_string(),
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
            output::die(&e, verbose);
        }
    }
}

/// Enforce the watermarking consent gate. Records consent when
/// `--i-am-authorised` is given; refuses (exits) when consent is neither
/// recorded nor freshly given.
fn ensure_consent(args: &WatermarkArgs, json: bool) {
    if consent::has_consent() {
        // Already authorised on this machine; re-affirming is a harmless refresh.
        if args.i_am_authorised {
            let _ = consent::grant_consent("cli");
        }
        return;
    }
    if args.i_am_authorised {
        if let Err(e) = consent::grant_consent("cli") {
            let msg = format!("Could not record watermarking consent: {e}");
            if json {
                output::emit_json(&JsonOut::<()>::failure(&msg), output::exit_code(&e));
            }
            output::print_error(&msg, None);
            std::process::exit(output::exit_code(&e));
        }
        return;
    }
    let msg = "Watermarking requires authorisation. Re-run with --i-am-authorised to \
               confirm you are authorised to watermark this file. Consent is recorded \
               once on this machine and shared with the desktop app.";
    if json {
        output::emit_json(&JsonOut::<()>::failure(msg), EXIT_CONSENT_REQUIRED);
    }
    output::print_error(msg, None);
    std::process::exit(EXIT_CONSENT_REQUIRED);
}

/// `<dir>/<stem>_marked.<ext>` beside the input file.
fn default_output(file: &std::path::Path) -> PathBuf {
    let stem = file.file_stem().unwrap_or_default().to_string_lossy();
    let ext = file.extension().unwrap_or_default().to_string_lossy();
    let parent = file.parent().unwrap_or_else(|| std::path::Path::new("."));
    if ext.is_empty() {
        parent.join(format!("{stem}_marked"))
    } else {
        parent.join(format!("{stem}_marked.{ext}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_appends_marked_suffix() {
        let out = default_output(std::path::Path::new("/tmp/photo.png"));
        assert_eq!(out, PathBuf::from("/tmp/photo_marked.png"));
    }

    #[test]
    fn default_output_handles_no_extension() {
        let out = default_output(std::path::Path::new("/tmp/photo"));
        assert_eq!(out, PathBuf::from("/tmp/photo_marked"));
    }

    #[test]
    fn default_output_handles_bare_filename() {
        let out = default_output(std::path::Path::new("photo.webp"));
        assert_eq!(out, PathBuf::from("photo_marked.webp"));
    }
}
