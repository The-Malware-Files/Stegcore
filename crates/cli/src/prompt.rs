// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Passphrase prompting and file-picker helpers.
//
// The public API is the thin wrapper that uses stdin / stdout / rpassword;
// the `_with` variants below take a generic `BufRead + Write` (or a
// PassphraseSource trait for the secure prompts) so the prompt logic can
// be unit tested with in-memory streams.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ── Display detection ─────────────────────────────────────────────────────────

/// Returns true when a graphical display is available.
pub fn has_display() -> bool {
    // Linux / BSD: DISPLAY (X11) or WAYLAND_DISPLAY
    if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return true;
    }
    // macOS and Windows always have a display when running interactively.
    cfg!(target_os = "macos") || cfg!(target_os = "windows")
}

// ── File picker ───────────────────────────────────────────────────────────────

pub struct PickerConfig<'a> {
    pub title: &'a str,
    pub filters: &'a [(&'a str, &'a [&'a str])], // (name, extensions)
}

/// Pick a single file. Uses a native file dialog when a display is available;
/// falls back to a stdin path prompt otherwise, with an explanation.
pub fn pick_file(cfg: &PickerConfig<'_>) -> Option<PathBuf> {
    if has_display() {
        #[cfg(not(target_os = "linux"))]
        {
            let mut dialog = rfd::FileDialog::new().set_title(cfg.title);
            for (name, exts) in cfg.filters {
                dialog = dialog.add_filter(*name, exts);
            }
            return dialog.pick_file();
        }
        // On Linux rfd may still fail if running in a terminal without dbus.
        // Fall through to the stdin path below if rfd returns None.
        #[cfg(target_os = "linux")]
        {
            let mut dialog = rfd::FileDialog::new().set_title(cfg.title);
            for (name, exts) in cfg.filters {
                dialog = dialog.add_filter(*name, exts);
            }
            if let Some(p) = dialog.pick_file() {
                return Some(p);
            }
            eprintln!("ℹ  No graphical file picker available — please type the path manually.");
        }
    } else {
        eprintln!(
            "ℹ  No display detected (headless/SSH environment). \
             A graphical file picker is not available — please type the path manually."
        );
    }
    let stdin = io::stdin();
    read_path_with(&mut stdin.lock(), &mut io::stdout(), cfg.title)
}

/// Prompt for a directory path. Same display-availability logic as `pick_file`.
#[allow(dead_code)]
pub fn pick_folder(title: &str) -> Option<PathBuf> {
    if has_display() {
        #[cfg(not(target_os = "linux"))]
        {
            return rfd::FileDialog::new().set_title(title).pick_folder();
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(p) = rfd::FileDialog::new().set_title(title).pick_folder() {
                return Some(p);
            }
            eprintln!("ℹ  No graphical file picker — please type the path manually.");
        }
    }
    let stdin = io::stdin();
    read_path_with(&mut stdin.lock(), &mut io::stdout(), title)
}

// ── Generic, testable readers ────────────────────────────────────────────────

/// Read a single trimmed line. Returns `None` on EOF or read error.
pub fn read_line_with<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
) -> Option<String> {
    let _ = write!(writer, "  {prompt}: ");
    let _ = writer.flush();
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_owned()),
    }
}

/// Read a path from a prompt. Empty input returns `None` so callers can
/// distinguish "no input" from "valid path".
pub fn read_path_with<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
) -> Option<PathBuf> {
    let _ = write!(writer, "  {prompt}: ");
    let _ = writer.flush();
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        }
    }
}

/// Read a yes/no answer. Accepts y/yes/n/no (case-insensitive). Re-prompts on
/// invalid input. Empty input returns the default when one is provided;
/// otherwise re-prompts. Returns `None` on EOF.
pub fn read_yes_no_with<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    default: Option<bool>,
) -> Option<bool> {
    let hint = match default {
        Some(true) => " [Y/n]",
        Some(false) => " [y/N]",
        None => " [y/n]",
    };
    loop {
        let _ = write!(writer, "  {prompt}{hint}: ");
        let _ = writer.flush();
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        match line.trim().to_lowercase().as_str() {
            "y" | "yes" => return Some(true),
            "n" | "no" => return Some(false),
            "" => {
                if let Some(d) = default {
                    return Some(d);
                }
                let _ = writeln!(writer, "  Please enter y or n.");
            }
            _ => {
                let _ = writeln!(writer, "  Please enter y or n.");
            }
        }
    }
}

/// Read a menu choice (1-based) from `reader`. Re-prompts on out-of-range
/// input. Returns `None` on EOF.
pub fn read_menu_with<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    options: &[&str],
) -> Option<usize> {
    for (i, opt) in options.iter().enumerate() {
        let _ = writeln!(writer, "  {}. {}", i + 1, opt);
    }
    loop {
        let answer = read_line_with(reader, writer, prompt)?;
        match answer.trim().parse::<usize>() {
            Ok(n) if n >= 1 && n <= options.len() => return Some(n - 1),
            _ => {
                let _ = writeln!(
                    writer,
                    "  Please enter a number between 1 and {}.",
                    options.len()
                );
            }
        }
    }
}

// ── Passphrase prompting ──────────────────────────────────────────────────────

/// Abstracts the secure-prompt source so the loop logic in
/// `prompt_passphrase_confirmed_with` can be unit tested without driving
/// a real TTY through rpassword.
pub trait PassphraseSource {
    fn read(&mut self, prompt: &str) -> io::Result<String>;
}

/// Default production implementation: rpassword (no-echo terminal read).
pub struct RpasswordSource;

impl PassphraseSource for RpasswordSource {
    fn read(&mut self, prompt: &str) -> io::Result<String> {
        rpassword::prompt_password(prompt)
    }
}

/// Outcome of `prompt_passphrase_confirmed_with`. Lets callers distinguish
/// the interrupted / read-error cases instead of having the loop
/// `process::exit` directly.
#[derive(Debug)]
pub enum PassphraseOutcome {
    Ok(zeroize::Zeroizing<Vec<u8>>),
    Interrupted,
    ReadError(io::Error),
}

/// Prompt for a passphrase securely (no echo).
///
/// If `interrupted` is set (Ctrl-C handler) during the prompt, exits 130.
pub fn prompt_passphrase(
    label: &str,
    interrupted: &Arc<AtomicBool>,
) -> zeroize::Zeroizing<Vec<u8>> {
    if interrupted.load(Ordering::SeqCst) {
        eprintln!();
        std::process::exit(130);
    }
    match RpasswordSource.read(&format!("  {label}: ")) {
        Ok(mut s) => {
            let bytes = zeroize::Zeroizing::new(s.as_bytes().to_vec());
            zeroize::Zeroize::zeroize(&mut s);
            bytes
        }
        Err(e) => {
            eprintln!("✗ Failed to read passphrase: {e}");
            std::process::exit(1);
        }
    }
}

/// Prompt for a passphrase with confirmation (used during embed).
/// Re-prompts until both entries match or the user hits Ctrl-C.
pub fn prompt_passphrase_confirmed(
    label: &str,
    interrupted: &Arc<AtomicBool>,
) -> zeroize::Zeroizing<Vec<u8>> {
    let mut source = RpasswordSource;
    let mut stderr = io::stderr();
    match prompt_passphrase_confirmed_with(&mut source, &mut stderr, label, interrupted) {
        PassphraseOutcome::Ok(bytes) => bytes,
        PassphraseOutcome::Interrupted => {
            eprintln!();
            std::process::exit(130);
        }
        PassphraseOutcome::ReadError(e) => {
            eprintln!("✗ Failed to read passphrase: {e}");
            std::process::exit(1);
        }
    }
}

/// Generic confirmed-passphrase loop, extracted so the empty-rejection +
/// mismatch-retry behaviour can be unit tested with a scripted source.
pub fn prompt_passphrase_confirmed_with<S: PassphraseSource, W: Write>(
    source: &mut S,
    writer: &mut W,
    label: &str,
    interrupted: &Arc<AtomicBool>,
) -> PassphraseOutcome {
    loop {
        if interrupted.load(Ordering::SeqCst) {
            return PassphraseOutcome::Interrupted;
        }
        let mut first = match source.read(&format!("  {label}: ")) {
            Ok(s) => s,
            Err(e) => return PassphraseOutcome::ReadError(e),
        };
        if first.is_empty() {
            let _ = writeln!(writer, "  ⚠  Passphrase cannot be empty. Please try again.");
            continue;
        }
        let mut second = match source.read(&format!("  Confirm {label}: ")) {
            Ok(s) => s,
            Err(e) => {
                zeroize::Zeroize::zeroize(&mut first);
                return PassphraseOutcome::ReadError(e);
            }
        };
        if first == second {
            let bytes = zeroize::Zeroizing::new(first.as_bytes().to_vec());
            zeroize::Zeroize::zeroize(&mut first);
            zeroize::Zeroize::zeroize(&mut second);
            return PassphraseOutcome::Ok(bytes);
        }
        zeroize::Zeroize::zeroize(&mut first);
        zeroize::Zeroize::zeroize(&mut second);
        let _ = writeln!(writer, "  ✗ Passphrases do not match. Please try again.");
    }
}

// ── Public stdin shims (unchanged signatures for existing callers) ───────────

/// Read a single trimmed line from stdin. Returns `None` on EOF.
pub fn read_line(prompt: &str) -> Option<String> {
    let stdin = io::stdin();
    read_line_with(&mut stdin.lock(), &mut io::stdout(), prompt)
}

/// Read a yes/no answer. Accepts y/yes/n/no (case-insensitive).
/// Re-prompts on invalid input. Returns `None` on EOF.
pub fn read_yes_no(prompt: &str, default: Option<bool>) -> Option<bool> {
    let stdin = io::stdin();
    read_yes_no_with(&mut stdin.lock(), &mut io::stdout(), prompt, default)
}

/// Read a menu choice (1-based) from stdin. Re-prompts on out-of-range input.
pub fn read_menu(prompt: &str, options: &[&str]) -> Option<usize> {
    let stdin = io::stdin();
    read_menu_with(&mut stdin.lock(), &mut io::stdout(), prompt, options)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run<F, T>(input: &str, f: F) -> (T, String)
    where
        F: FnOnce(&mut Cursor<Vec<u8>>, &mut Vec<u8>) -> T,
    {
        let mut reader = Cursor::new(input.as_bytes().to_vec());
        let mut writer: Vec<u8> = Vec::new();
        let out = f(&mut reader, &mut writer);
        (out, String::from_utf8(writer).unwrap())
    }

    // ── read_line_with ─────────────────────────────────────────────────────

    #[test]
    fn read_line_returns_trimmed_input() {
        let (got, out) = run("hello world\n", |r, w| read_line_with(r, w, "Name"));
        assert_eq!(got.as_deref(), Some("hello world"));
        assert!(out.contains("Name:"));
    }

    #[test]
    fn read_line_strips_trailing_whitespace() {
        let (got, _) = run("  spaced  \n", |r, w| read_line_with(r, w, "x"));
        assert_eq!(got.as_deref(), Some("spaced"));
    }

    #[test]
    fn read_line_returns_none_on_eof() {
        let (got, _) = run("", |r, w| read_line_with(r, w, "x"));
        assert_eq!(got, None);
    }

    // ── read_path_with ─────────────────────────────────────────────────────

    #[test]
    fn read_path_returns_path_for_non_empty_input() {
        let (got, _) = run("/tmp/foo.png\n", |r, w| read_path_with(r, w, "Path"));
        assert_eq!(got, Some(PathBuf::from("/tmp/foo.png")));
    }

    #[test]
    fn read_path_returns_none_for_empty_input() {
        // Just a newline — input is present but empty after trimming.
        let (got, _) = run("\n", |r, w| read_path_with(r, w, "Path"));
        assert_eq!(got, None);
    }

    #[test]
    fn read_path_returns_none_on_eof() {
        let (got, _) = run("", |r, w| read_path_with(r, w, "Path"));
        assert_eq!(got, None);
    }

    // ── read_yes_no_with ───────────────────────────────────────────────────

    #[test]
    fn read_yes_no_accepts_y_variants() {
        for input in ["y\n", "Y\n", "yes\n", "YES\n", "Yes\n"] {
            let (got, _) = run(input, |r, w| read_yes_no_with(r, w, "OK?", None));
            assert_eq!(got, Some(true), "input={input:?}");
        }
    }

    #[test]
    fn read_yes_no_accepts_n_variants() {
        for input in ["n\n", "N\n", "no\n", "NO\n"] {
            let (got, _) = run(input, |r, w| read_yes_no_with(r, w, "OK?", None));
            assert_eq!(got, Some(false), "input={input:?}");
        }
    }

    #[test]
    fn read_yes_no_empty_returns_default_true() {
        let (got, _) = run("\n", |r, w| read_yes_no_with(r, w, "OK?", Some(true)));
        assert_eq!(got, Some(true));
    }

    #[test]
    fn read_yes_no_empty_returns_default_false() {
        let (got, _) = run("\n", |r, w| read_yes_no_with(r, w, "OK?", Some(false)));
        assert_eq!(got, Some(false));
    }

    #[test]
    fn read_yes_no_empty_without_default_reprompts() {
        // Empty then "y" — should accept the y after re-prompting.
        let (got, out) = run("\ny\n", |r, w| read_yes_no_with(r, w, "OK?", None));
        assert_eq!(got, Some(true));
        assert!(out.contains("Please enter y or n"));
    }

    #[test]
    fn read_yes_no_invalid_then_valid() {
        let (got, out) = run("maybe\nyes\n", |r, w| read_yes_no_with(r, w, "OK?", None));
        assert_eq!(got, Some(true));
        assert!(out.contains("Please enter y or n"));
    }

    #[test]
    fn read_yes_no_eof_returns_none() {
        let (got, _) = run("", |r, w| read_yes_no_with(r, w, "OK?", Some(true)));
        assert_eq!(got, None);
    }

    #[test]
    fn read_yes_no_hint_changes_with_default() {
        let (_, out_true) = run("y\n", |r, w| read_yes_no_with(r, w, "Q", Some(true)));
        assert!(out_true.contains("[Y/n]"));
        let (_, out_false) = run("y\n", |r, w| read_yes_no_with(r, w, "Q", Some(false)));
        assert!(out_false.contains("[y/N]"));
        let (_, out_none) = run("y\n", |r, w| read_yes_no_with(r, w, "Q", None));
        assert!(out_none.contains("[y/n]"));
    }

    // ── read_menu_with ─────────────────────────────────────────────────────

    #[test]
    fn read_menu_returns_zero_indexed_choice() {
        let opts = ["First", "Second", "Third"];
        let (got, out) = run("2\n", |r, w| read_menu_with(r, w, "Pick", &opts));
        assert_eq!(got, Some(1));
        assert!(out.contains("1. First"));
        assert!(out.contains("2. Second"));
        assert!(out.contains("3. Third"));
    }

    #[test]
    fn read_menu_rejects_zero() {
        let opts = ["A", "B"];
        let (got, out) = run("0\n1\n", |r, w| read_menu_with(r, w, "Pick", &opts));
        assert_eq!(got, Some(0));
        assert!(out.contains("between 1 and 2"));
    }

    #[test]
    fn read_menu_rejects_out_of_range() {
        let opts = ["A", "B"];
        let (got, _) = run("99\n2\n", |r, w| read_menu_with(r, w, "Pick", &opts));
        assert_eq!(got, Some(1));
    }

    #[test]
    fn read_menu_rejects_non_numeric() {
        let opts = ["A", "B"];
        let (got, out) = run("abc\n1\n", |r, w| read_menu_with(r, w, "Pick", &opts));
        assert_eq!(got, Some(0));
        assert!(out.contains("between 1 and 2"));
    }

    #[test]
    fn read_menu_returns_none_on_eof() {
        let opts = ["A", "B"];
        let (got, _) = run("", |r, w| read_menu_with(r, w, "Pick", &opts));
        assert_eq!(got, None);
    }

    // ── passphrase loop ────────────────────────────────────────────────────

    /// Scripted source that returns answers in order. After running out it
    /// returns an unexpected-EOF error — keeps tests from hanging.
    struct ScriptedSource {
        answers: Vec<String>,
        idx: usize,
    }

    impl ScriptedSource {
        fn new(answers: &[&str]) -> Self {
            Self {
                answers: answers.iter().map(|s| s.to_string()).collect(),
                idx: 0,
            }
        }
    }

    impl PassphraseSource for ScriptedSource {
        fn read(&mut self, _prompt: &str) -> io::Result<String> {
            if self.idx >= self.answers.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "scripted source exhausted",
                ));
            }
            let v = self.answers[self.idx].clone();
            self.idx += 1;
            Ok(v)
        }
    }

    fn interrupted_off() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[test]
    fn passphrase_confirmed_accepts_matching_pair() {
        let mut src = ScriptedSource::new(&["correct horse", "correct horse"]);
        let mut writer: Vec<u8> = Vec::new();
        let interrupted = interrupted_off();
        match prompt_passphrase_confirmed_with(&mut src, &mut writer, "Passphrase", &interrupted) {
            PassphraseOutcome::Ok(bytes) => assert_eq!(&bytes[..], b"correct horse"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn passphrase_confirmed_rejects_empty_then_retries() {
        // First entry empty (rejected), then a matching pair.
        let mut src = ScriptedSource::new(&["", "hunter2", "hunter2"]);
        let mut writer: Vec<u8> = Vec::new();
        let interrupted = interrupted_off();
        let outcome =
            prompt_passphrase_confirmed_with(&mut src, &mut writer, "Passphrase", &interrupted);
        match outcome {
            PassphraseOutcome::Ok(bytes) => assert_eq!(&bytes[..], b"hunter2"),
            other => panic!("expected Ok, got {other:?}"),
        }
        let out = String::from_utf8(writer).unwrap();
        assert!(out.contains("Passphrase cannot be empty"));
    }

    #[test]
    fn passphrase_confirmed_retries_on_mismatch() {
        // First pair mismatches, second matches.
        let mut src = ScriptedSource::new(&["one", "two", "three", "three"]);
        let mut writer: Vec<u8> = Vec::new();
        let interrupted = interrupted_off();
        let outcome =
            prompt_passphrase_confirmed_with(&mut src, &mut writer, "Passphrase", &interrupted);
        match outcome {
            PassphraseOutcome::Ok(bytes) => assert_eq!(&bytes[..], b"three"),
            other => panic!("expected Ok, got {other:?}"),
        }
        let out = String::from_utf8(writer).unwrap();
        assert!(out.contains("do not match"));
    }

    #[test]
    fn passphrase_confirmed_returns_interrupted() {
        let mut src = ScriptedSource::new(&[]);
        let mut writer: Vec<u8> = Vec::new();
        let interrupted = Arc::new(AtomicBool::new(true));
        let outcome =
            prompt_passphrase_confirmed_with(&mut src, &mut writer, "Passphrase", &interrupted);
        assert!(matches!(outcome, PassphraseOutcome::Interrupted));
    }

    #[test]
    fn passphrase_confirmed_surfaces_read_error_on_first_read() {
        let mut src = ScriptedSource::new(&[]); // immediately errors
        let mut writer: Vec<u8> = Vec::new();
        let interrupted = interrupted_off();
        let outcome =
            prompt_passphrase_confirmed_with(&mut src, &mut writer, "Passphrase", &interrupted);
        assert!(matches!(outcome, PassphraseOutcome::ReadError(_)));
    }

    #[test]
    fn passphrase_confirmed_surfaces_read_error_on_confirm_read() {
        // First read OK, confirm read errors out.
        let mut src = ScriptedSource::new(&["secret"]);
        let mut writer: Vec<u8> = Vec::new();
        let interrupted = interrupted_off();
        let outcome =
            prompt_passphrase_confirmed_with(&mut src, &mut writer, "Passphrase", &interrupted);
        assert!(matches!(outcome, PassphraseOutcome::ReadError(_)));
    }

    // ── display detection ─────────────────────────────────────────────────

    #[test]
    fn has_display_reflects_env() {
        // Save + restore so we don't leak state into other tests.
        let saved_display = std::env::var_os("DISPLAY");
        let saved_wayland = std::env::var_os("WAYLAND_DISPLAY");

        // SAFETY: tests don't run in parallel for env mutation. We restore
        // on the way out. On macOS / Windows has_display is always true so
        // the env-driven branch is the Linux path.
        unsafe {
            std::env::remove_var("DISPLAY");
            std::env::remove_var("WAYLAND_DISPLAY");
        }
        let no_display_result = has_display();

        unsafe {
            std::env::set_var("DISPLAY", ":0");
        }
        let display_set_result = has_display();

        unsafe {
            std::env::remove_var("DISPLAY");
            std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
        }
        let wayland_set_result = has_display();

        // Restore env vars.
        unsafe {
            std::env::remove_var("DISPLAY");
            std::env::remove_var("WAYLAND_DISPLAY");
            if let Some(v) = saved_display {
                std::env::set_var("DISPLAY", v);
            }
            if let Some(v) = saved_wayland {
                std::env::set_var("WAYLAND_DISPLAY", v);
            }
        }

        // On Linux: env removal → false; setting either → true.
        // On macOS / Windows: always true regardless of env vars.
        if cfg!(target_os = "linux") {
            assert!(!no_display_result);
        }
        assert!(display_set_result);
        assert!(wayland_set_result);
    }
}
