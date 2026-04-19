// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Interactive guided wizard — helps beginners walk through embed or extract
// step-by-step with explanations, native file dialogs where available, and
// robust fallback to stdin-based prompts everywhere else.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use stegcore_core::steg;

use crate::output::{self, Spinner};
use crate::prompt::{self, PickerConfig};

// ── Public entry point ────────────────────────────────────────────────────────

pub fn run(interrupted: Arc<AtomicBool>) -> ! {
    check(interrupted.load(Ordering::SeqCst));

    eprintln!();
    output::print_info("Welcome to the Stegcore wizard.");
    output::print_info("This guided mode walks you through hiding or retrieving a message.");
    output::print_info("At any point press Ctrl-C to cancel without saving anything.");
    eprintln!();

    let choice = prompt::read_menu(
        "What would you like to do?",
        &[
            "Embed — hide a message inside a cover file",
            "Extract — retrieve a hidden message",
        ],
    );

    match choice {
        Some(0) => run_embed(interrupted),
        Some(1) => run_extract(interrupted),
        None => {
            eprintln!();
            output::print_warn("Cancelled.");
            std::process::exit(130);
        }
        _ => unreachable!(),
    }
}

// ── Embed wizard ──────────────────────────────────────────────────────────────

fn run_embed(interrupted: Arc<AtomicBool>) -> ! {
    eprintln!();
    output::print_info("── Embed wizard ────────────────────────────────────");

    // Step 1 — message file.
    eprintln!();
    output::print_info("Step 1 of 7 — Message file");
    output::print_info(
        "Select the file whose contents you want to hide. Any file type is accepted.",
    );
    let payload = pick_existing_file("Message file", &[("All files", &["*"])], &interrupted);

    // Validate: not empty.
    let meta = match std::fs::metadata(&payload) {
        Ok(m) => m,
        Err(e) => {
            output::print_error(&format!("Cannot read {}: {e}", payload.display()), None);
            std::process::exit(3);
        }
    };
    if meta.len() == 0 {
        output::print_error(
            "The message file is empty. Please choose a file that contains data.",
            None,
        );
        std::process::exit(1);
    }
    output::print_success(&format!(
        "Message file: {} ({} bytes)",
        payload.display(),
        meta.len()
    ));

    // Step 2 — cover file.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 2 of 7 — Cover file");
    output::print_info("Select the image or audio file that will carry the hidden message.");
    output::print_info(
        "Supported formats: PNG, BMP, JPEG, WAV, WebP. \
         Use photos with varied texture for best concealment.",
    );
    let cover = pick_existing_file(
        "Cover file",
        &[
            ("Images", &["png", "bmp", "jpg", "jpeg", "webp"]),
            ("Audio", &["wav"]),
        ],
        &interrupted,
    );
    output::print_success(&format!("Cover file: {}", cover.display()));

    // Step 3 — score the cover.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 3 of 7 — Cover quality");
    let spinner = Spinner::new("Scoring cover file…", Arc::clone(&interrupted));
    let score = match steg::assess(&cover) {
        Ok(s) => {
            spinner.success("Cover scored");
            s
        }
        Err(e) => {
            spinner.fail(&e.to_string());
            output::print_error(&e.to_string(), None);
            std::process::exit(output::exit_code(&e));
        }
    };
    let pct = (score * 100.0).round() as u32;
    let label = cover_label(pct);
    output::print_info(&format!("Score: {pct}/100 — {label}"));

    if pct < 25 {
        output::print_warn(
            "This cover file scored poorly. Embedding may be unreliable \
             or detectable. Consider choosing a different cover.",
        );
        match prompt::read_yes_no("Continue anyway?", Some(false)) {
            Some(true) => {}
            _ => {
                output::print_warn("Cancelled.");
                std::process::exit(1);
            }
        }
    }

    // Step 4 — cipher.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 4 of 7 — Encryption cipher");
    output::print_info("Choose the cipher used to encrypt your message before hiding it.");
    let cipher_idx = prompt::read_menu(
        "Cipher",
        &[
            "ChaCha20-Poly1305  (recommended — fast and widely trusted)",
            "Ascon-128          (lightweight, excellent for constrained environments)",
            "AES-256-GCM        (hardware-accelerated AES, widely audited)",
        ],
    );
    let cipher = match cipher_idx {
        Some(0) => "chacha20-poly1305",
        Some(1) => "ascon-128",
        Some(2) => "aes-256-gcm",
        None => {
            output::print_warn("Cancelled.");
            std::process::exit(130);
        }
        _ => unreachable!(),
    };

    // Step 5 — embedding mode.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 5 of 7 — Embedding mode");
    output::print_info("Adaptive mode offers higher resistance to detection and is the default.");
    output::print_info(
        "Standard mode fits more data but is easier to detect with specialist tools.",
    );
    let mode_idx = prompt::read_menu(
        "Mode",
        &[
            "Adaptive  (secure, recommended)",
            "Standard  (higher capacity)",
        ],
    );
    let mode = match mode_idx {
        Some(0) | None => "adaptive",
        Some(1) => "sequential",
        _ => unreachable!(),
    };
    if mode_idx.is_none() {
        output::print_warn("Cancelled.");
        std::process::exit(130);
    }

    // Step 6 — passphrase.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 6 of 7 — Passphrase");
    output::print_info("Your passphrase encrypts the message. You will need it to extract later.");
    output::print_info("Use at least 12 characters. A mix of words, numbers, and symbols is best.");
    let passphrase = prompt::prompt_passphrase_confirmed("Passphrase", &interrupted);

    // Deniable mode option.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Deniable mode hides a second decoy message in the same file.");
    output::print_info(
        "You can reveal the decoy under pressure while keeping your real message safe.",
    );
    let deniable = prompt::read_yes_no("Enable deniable mode?", Some(false)).unwrap_or(false);

    let (decoy_path, decoy_passphrase) = if deniable {
        check_interrupt(&interrupted);
        output::print_info("Deniable mode — decoy file");
        let dp = pick_existing_file("Decoy message file", &[("All files", &["*"])], &interrupted);
        check_interrupt(&interrupted);
        output::print_info("Deniable mode — decoy passphrase");
        output::print_info("This passphrase must be different from your real passphrase.");
        let dpass = prompt_decoy_passphrase(&passphrase, &interrupted);
        (Some(dp), Some(dpass))
    } else {
        (None, None)
    };

    // Export key file option.
    check_interrupt(&interrupted);
    let export_key = prompt::read_yes_no(
        "Export a key file (optional backup for out-of-band sharing)?",
        Some(false),
    )
    .unwrap_or(false);

    // Step 7 — output path.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 7 of 7 — Output path");
    output::print_info(
        "Where should the stego file be saved? \
         Press Enter to use the default path.",
    );
    let default_out = default_output_path(&cover);
    output::print_info(&format!("Default: {}", default_out.display()));
    let out_path = pick_output_path("Output file", &default_out, &interrupted);

    // Confirm before running.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("── Summary ─────────────────────────────────────────");
    output::print_info(&format!("  Message file : {}", payload.display()));
    output::print_info(&format!("  Cover file   : {}", cover.display()));
    output::print_info(&format!("  Cipher       : {cipher}"));
    output::print_info(&format!("  Mode         : {mode}"));
    output::print_info(&format!("  Deniable     : {deniable}"));
    output::print_info(&format!("  Export key   : {export_key}"));
    output::print_info(&format!("  Output       : {}", out_path.display()));
    eprintln!();

    match prompt::read_yes_no("Proceed with embedding?", Some(true)) {
        Some(true) => {}
        _ => {
            output::print_warn("Cancelled — no files were written.");
            std::process::exit(0);
        }
    }

    // Read payload bytes.
    let payload_bytes = match std::fs::read(&payload) {
        Ok(b) => b,
        Err(e) => {
            let err = stegcore_core::errors::StegError::Io(e);
            output::print_error(&err.to_string(), None);
            std::process::exit(output::exit_code(&err));
        }
    };

    // Run.
    check_interrupt(&interrupted);
    let spinner = Spinner::new("Embedding…", Arc::clone(&interrupted));

    if deniable {
        let decoy_path_ref = decoy_path.as_ref().unwrap();
        let decoy_pass_ref = decoy_passphrase.as_ref().unwrap();
        let decoy_bytes = match std::fs::read(decoy_path_ref) {
            Ok(b) => b,
            Err(e) => {
                drop(spinner);
                let err = stegcore_core::errors::StegError::Io(e);
                output::print_error(&err.to_string(), None);
                std::process::exit(output::exit_code(&err));
            }
        };
        match steg::embed_deniable(
            &cover,
            &payload_bytes,
            &decoy_bytes,
            &passphrase,
            decoy_pass_ref,
            cipher,
            &out_path,
        ) {
            Ok((real_kf, decoy_kf)) => {
                spinner.success("Embedded successfully");
                output::print_success(&format!("Stego file: {}", out_path.display()));
                if export_key {
                    let stem = out_path
                        .file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    let parent = out_path
                        .parent()
                        .unwrap_or_else(|| std::path::Path::new("."));
                    write_keyfile(&real_kf, &parent.join(format!("{stem}.real.json")));
                    write_keyfile(&decoy_kf, &parent.join(format!("{stem}.decoy.json")));
                }
            }
            Err(e) => {
                spinner.fail(&e.to_string());
                output::print_error(&e.to_string(), None);
                std::process::exit(output::exit_code(&e));
            }
        }
    } else {
        let result = if mode == "adaptive" {
            steg::embed_adaptive(
                &cover,
                &payload_bytes,
                &passphrase,
                cipher,
                &out_path,
                export_key,
            )
        } else {
            steg::embed_sequential(
                &cover,
                &payload_bytes,
                &passphrase,
                cipher,
                &out_path,
                export_key,
            )
        };
        match result {
            Ok(maybe_kf) => {
                spinner.success("Embedded successfully");
                output::print_success(&format!("Stego file: {}", out_path.display()));
                if let Some(kf) = maybe_kf {
                    let kf_path = out_path.with_extension("json");
                    write_keyfile(&kf, &kf_path);
                }
            }
            Err(e) => {
                spinner.fail(&e.to_string());
                output::print_error(&e.to_string(), None);
                std::process::exit(output::exit_code(&e));
            }
        }
    }

    std::process::exit(0);
}

// ── Extract wizard ────────────────────────────────────────────────────────────

fn run_extract(interrupted: Arc<AtomicBool>) -> ! {
    eprintln!();
    output::print_info("── Extract wizard ───────────────────────────────────");

    // Step 1 — stego file.
    eprintln!();
    output::print_info("Step 1 of 3 — Stego file");
    output::print_info("Select the image or audio file that contains the hidden message.");
    let stego = pick_existing_file(
        "Stego file",
        &[
            ("Images", &["png", "bmp", "jpg", "jpeg", "webp"]),
            ("Audio", &["wav", "flac"]),
        ],
        &interrupted,
    );
    output::print_success(&format!("Stego file: {}", stego.display()));

    // Step 2 — key file (optional).
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 2 of 3 — Key file (optional)");
    output::print_info("Most Stegcore files do not need a key file — just your passphrase.");
    output::print_info("Only provide a key file if you were given one separately.");
    let wants_key = prompt::read_yes_no("Do you have a key file?", Some(false)).unwrap_or(false);

    let key_file = if wants_key {
        check_interrupt(&interrupted);
        let kf_path = pick_existing_file(
            "Key file (.json)",
            &[("Key files", &["json"])],
            &interrupted,
        );
        // Try to read it early to give a clear error before the spinner starts.
        match stegcore_core::keyfile::read_key_file(&kf_path) {
            Ok(kf) => {
                output::print_success("Key file loaded.");
                Some(kf)
            }
            Err(e) => {
                output::print_error(&e.to_string(), None);
                std::process::exit(output::exit_code(&e));
            }
        }
    } else {
        None
    };

    // Step 3 — passphrase + extract.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Step 3 of 3 — Passphrase");
    let passphrase = prompt::prompt_passphrase("Passphrase", &interrupted);

    // Output path.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("Where should the extracted file be saved?");
    let stem = stego.file_stem().unwrap_or_default().to_string_lossy();
    let default_out = PathBuf::from(format!("extracted_{stem}"));
    output::print_info(&format!("Default: {}", default_out.display()));
    let out_path = pick_output_path("Output file", &default_out, &interrupted);

    // Confirm.
    eprintln!();
    check_interrupt(&interrupted);
    output::print_info("── Summary ─────────────────────────────────────────");
    output::print_info(&format!("  Stego file : {}", stego.display()));
    output::print_info(&format!(
        "  Key file   : {}",
        key_file.as_ref().map(|_| "provided").unwrap_or("none")
    ));
    output::print_info(&format!("  Output     : {}", out_path.display()));
    eprintln!();

    match prompt::read_yes_no("Proceed with extraction?", Some(true)) {
        Some(true) => {}
        _ => {
            output::print_warn("Cancelled.");
            std::process::exit(0);
        }
    }

    // Run.
    check_interrupt(&interrupted);
    let spinner = Spinner::new("Extracting…", Arc::clone(&interrupted));

    let result = match key_file {
        Some(ref kf) => steg::extract_with_keyfile(&stego, kf, &passphrase),
        None => steg::extract(&stego, &passphrase),
    };

    match result {
        Ok(data) => {
            spinner.success("Extracted successfully");
            if let Err(e) = std::fs::write(&out_path, &data) {
                let err = stegcore_core::errors::StegError::Io(e);
                output::print_error(&err.to_string(), None);
                std::process::exit(output::exit_code(&err));
            }
            output::print_success(&format!("Saved → {}", out_path.display()));
            output::print_info(&format!("  {} bytes", data.len()));
        }
        Err(e) => {
            spinner.fail(&e.to_string());
            // Oracle-resistant: same message for wrong passphrase and no payload.
            output::print_error(&e.to_string(), None);
            std::process::exit(output::exit_code(&e));
        }
    }

    std::process::exit(0);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn check(interrupted: bool) {
    if interrupted {
        eprintln!();
        std::process::exit(130);
    }
}

fn check_interrupt(interrupted: &Arc<AtomicBool>) {
    if interrupted.load(Ordering::SeqCst) {
        eprintln!();
        output::print_warn("Cancelled.");
        std::process::exit(130);
    }
}

/// Pick an existing file, re-prompting until the path exists and is a file.
fn pick_existing_file(
    title: &str,
    filters: &[(&str, &[&str])],
    interrupted: &Arc<AtomicBool>,
) -> PathBuf {
    loop {
        check_interrupt(interrupted);
        let path = prompt::pick_file(&PickerConfig { title, filters });
        match path {
            None => {
                output::print_warn(
                    "No file selected. Please choose a file to continue, \
                     or press Ctrl-C to cancel.",
                );
            }
            Some(p) if !p.exists() => {
                output::print_warn(&format!(
                    "File not found: {}. Please try again.",
                    p.display()
                ));
            }
            Some(p) if p.is_dir() => {
                output::print_warn("That is a directory, not a file. Please select a file.");
            }
            Some(p) => return p,
        }
    }
}

/// Prompt for an output file path. Accepts the default on empty input.
/// Warns if the destination already exists.
fn pick_output_path(title: &str, default: &Path, interrupted: &Arc<AtomicBool>) -> PathBuf {
    loop {
        check_interrupt(interrupted);
        let raw = match prompt::read_line(&format!("{title} (Enter for default)")) {
            None => return default.to_path_buf(),
            Some(s) => s,
        };
        let path = if raw.is_empty() {
            default.to_path_buf()
        } else {
            PathBuf::from(&raw)
        };
        // Warn if destination already exists, but allow overwrite on confirmation.
        if path.exists() {
            output::print_warn(&format!("{} already exists.", path.display()));
            match prompt::read_yes_no("Overwrite?", Some(false)) {
                Some(true) => return path,
                _ => continue,
            }
        }
        // Parent directory must exist.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                output::print_warn(&format!(
                    "Directory does not exist: {}. Please choose a different path.",
                    parent.display()
                ));
                continue;
            }
        }
        return path;
    }
}

/// Prompt for a decoy passphrase, rejecting any that match the real one.
fn prompt_decoy_passphrase(
    real: &[u8],
    interrupted: &Arc<AtomicBool>,
) -> zeroize::Zeroizing<Vec<u8>> {
    loop {
        check_interrupt(interrupted);
        let dp = prompt::prompt_passphrase_confirmed("Decoy passphrase", interrupted);
        if dp.as_slice() == real {
            output::print_warn(
                "The decoy passphrase must be different from your real passphrase. \
                 Please choose a different one.",
            );
            continue;
        }
        return dp;
    }
}

fn default_output_path(cover: &Path) -> PathBuf {
    let stem = cover.file_stem().unwrap_or_default().to_string_lossy();
    let ext = cover.extension().and_then(|e| e.to_str()).unwrap_or("png");
    let parent = cover.parent().unwrap_or_else(|| std::path::Path::new("."));
    parent.join(format!("{stem}_steg.{ext}"))
}

fn cover_label(pct: u32) -> &'static str {
    match pct {
        75..=100 => "Excellent",
        50..=74 => "Good",
        25..=49 => "Fair",
        _ => "Poor",
    }
}

fn write_keyfile(kf: &stegcore_core::keyfile::KeyFile, path: &Path) {
    match stegcore_core::keyfile::write_key_file(path, kf) {
        Ok(()) => output::print_success(&format!("Key file saved → {}", path.display())),
        Err(e) => output::print_warn(&format!("Could not save key file {}: {e}", path.display())),
    }
}
