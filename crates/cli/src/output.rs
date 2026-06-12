// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// Coloured terminal output, RAII spinner, exit-code mapping.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
use crossterm::ExecutableCommand;
use indicatif::{ProgressBar, ProgressStyle};
use stegcore_core::errors::StegError;

/// Check if stderr is a terminal — skip colour output when piped.
fn is_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

// ── Colours ───────────────────────────────────────────────────────────────────

pub fn print_success(msg: &str) {
    let mut stderr = std::io::stderr();
    if !is_tty() {
        let _ = stderr.execute(Print(format!("✓ {msg}\n")));
        return;
    }
    let _ = stderr.execute(SetForegroundColor(Color::Green));
    let _ = stderr.execute(Print(format!("✓ {msg}\n")));
    let _ = stderr.execute(ResetColor);
}

pub fn print_error(msg: &str, chain: Option<&str>) {
    let mut stderr = std::io::stderr();
    if !is_tty() {
        let _ = stderr.execute(Print(format!("✗ Error: {msg}\n")));
        if let Some(c) = chain {
            let _ = stderr.execute(Print(format!("  {c}\n")));
        }
        return;
    }
    let _ = stderr.execute(SetForegroundColor(Color::Red));
    let _ = stderr.execute(Print(format!("✗ Error: {msg}\n")));
    let _ = stderr.execute(ResetColor);
    if let Some(c) = chain {
        let _ = stderr.execute(SetForegroundColor(Color::DarkGrey));
        let _ = stderr.execute(Print(format!("  {c}\n")));
        let _ = stderr.execute(ResetColor);
    }
}

pub fn print_warn(msg: &str) {
    let mut stderr = std::io::stderr();
    if !is_tty() {
        let _ = stderr.execute(Print(format!("⚠  Warning: {msg}\n")));
        return;
    }
    let _ = stderr.execute(SetForegroundColor(Color::Yellow));
    let _ = stderr.execute(Print(format!("⚠  Warning: {msg}\n")));
    let _ = stderr.execute(ResetColor);
}

pub fn print_info(msg: &str) {
    let mut stderr = std::io::stderr();
    let _ = stderr.execute(SetForegroundColor(Color::Cyan));
    let _ = stderr.execute(Print(format!("  {msg}\n")));
    let _ = stderr.execute(ResetColor);
}

// ── Exit codes ────────────────────────────────────────────────────────────────

pub fn exit_code(e: &StegError) -> i32 {
    match e {
        StegError::InsufficientCapacity { .. }
        | StegError::EmptyPayload
        | StegError::LegacyKeyFile
        | StegError::PoorCoverQuality { .. }
        | StegError::FileTooLarge { .. } => 1,

        StegError::DecryptionFailed | StegError::NoPayloadFound => 2,

        StegError::Io(_) | StegError::FileNotFound(_) => 3,

        StegError::ConsentRequired => 2,

        StegError::UnsupportedFormat(_)
        | StegError::CorruptedFile
        | StegError::Image(_)
        | StegError::Json(_) => 4,
    }
}

/// Print a `StegError` with optional verbose chain, then exit.
pub fn die(e: &StegError, verbose: bool) -> ! {
    let chain = if verbose {
        Some(format!("{e:#}"))
    } else {
        None
    };
    print_error(&e.to_string(), chain.as_deref());
    if let Some(hint) = e.suggestion() {
        print_info(&format!("Suggestion: {hint}"));
    }
    std::process::exit(exit_code(e));
}

// ── RAII Spinner ──────────────────────────────────────────────────────────────

pub struct Spinner {
    pb: ProgressBar,
    #[allow(dead_code)]
    interrupted: Arc<AtomicBool>,
}

impl Spinner {
    pub fn new(msg: &str, interrupted: Arc<AtomicBool>) -> Self {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} {elapsed_precise:.dim}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message(msg.to_owned());
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        Spinner { pb, interrupted }
    }

    /// Check if Ctrl-C was pressed; if so, clean up and exit 130.
    #[allow(dead_code)]
    pub fn check_interrupt(&self) {
        if self.interrupted.load(Ordering::SeqCst) {
            self.pb.finish_and_clear();
            eprintln!();
            std::process::exit(130);
        }
    }

    pub fn success(self, msg: &str) {
        self.pb.finish_and_clear();
        print_success(msg);
    }

    pub fn fail(self, msg: &str) {
        self.pb.finish_and_clear();
        let mut stderr = std::io::stderr();
        let _ = stderr.execute(SetForegroundColor(Color::Red));
        let _ = stderr.execute(Print(format!("✗ {msg}\n")));
        let _ = stderr.execute(ResetColor);
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        // Ensure spinner never leaks if the owner panics or returns early.
        self.pb.finish_and_clear();
    }
}

// ── JSON output helper ────────────────────────────────────────────────────────

use serde::Serialize;

#[derive(Serialize)]
pub struct JsonOut<T: Serialize> {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> JsonOut<T> {
    pub fn success(data: T) -> Self {
        JsonOut {
            ok: true,
            data: Some(data),
            error: None,
        }
    }
    pub fn failure(msg: &str) -> JsonOut<T> {
        JsonOut {
            ok: false,
            data: None,
            error: Some(msg.to_owned()),
        }
    }
}

pub fn emit_json<T: Serialize>(v: &JsonOut<T>, code: i32) -> ! {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into())
    );
    std::process::exit(code);
}

// ── Box-drawing summary card ─────────────────────────────────────────────────

/// Print a bordered summary card with key-value rows.
/// ```text
/// ╭────────────────────────────────╮
/// │  ✓ Embedded successfully       │
/// ├────────────────────────────────┤
/// │  Cover     photo.png           │
/// │  Output    photo_stego.png     │
/// │  Cipher    ChaCha20-Poly1305   │
/// │  Mode      Adaptive            │
/// │  Time      1.2s                │
/// ╰────────────────────────────────╯
/// ```
pub fn print_summary(title: &str, title_color: Color, rows: &[(&str, &str)]) {
    let mut s = std::io::stderr();

    // Calculate column widths
    let label_w = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let value_w = rows.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
    let title_w = title.len() + 4; // "  ✓ " prefix
    let inner = label_w + value_w + 5; // "  label  value  "
    let width = inner.max(title_w) + 2;

    let bar = "─".repeat(width);

    // Top border
    let _ = s.execute(SetForegroundColor(Color::DarkGrey));
    let _ = s.execute(Print(format!("\n  ╭{bar}╮\n")));

    // Title row — coloured left border
    let _ = s.execute(Print("  "));
    let _ = s.execute(SetForegroundColor(title_color));
    let _ = s.execute(Print("┃"));
    let _ = s.execute(Print(format!("  {title}")));
    let _ = s.execute(SetForegroundColor(Color::DarkGrey));
    let pad = width - title_w;
    let _ = s.execute(Print(format!("{:pad$}  │\n", "")));
    let _ = s.execute(Print(format!("  ├{bar}┤\n")));

    // Data rows — coloured left border, bright values
    for (label, value) in rows {
        let _ = s.execute(Print("  "));
        let _ = s.execute(SetForegroundColor(title_color));
        let _ = s.execute(Print("┃"));
        let _ = s.execute(SetForegroundColor(Color::DarkGrey));
        let _ = s.execute(Print(format!("  {label:label_w$}  ")));
        let _ = s.execute(SetForegroundColor(Color::White));
        let vpad = width - label_w - 4;
        let _ = s.execute(Print(format!("{value:vpad$}")));
        let _ = s.execute(SetForegroundColor(Color::DarkGrey));
        let _ = s.execute(Print("│\n"));
    }

    // Bottom border
    let _ = s.execute(Print(format!("  ╰{bar}╯\n\n")));
    let _ = s.execute(ResetColor);
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stegcore_core::errors::StegError;

    // ── exit_code ──────────────────────────────────────────────────────────

    #[test]
    fn exit_code_one_for_capacity_and_payload_errors() {
        assert_eq!(
            exit_code(&StegError::InsufficientCapacity {
                required: 4096,
                available: 1024
            }),
            1
        );
        assert_eq!(exit_code(&StegError::EmptyPayload), 1);
        assert_eq!(exit_code(&StegError::LegacyKeyFile), 1);
        assert_eq!(exit_code(&StegError::PoorCoverQuality { score: 0.1 }), 1);
        assert_eq!(
            exit_code(&StegError::FileTooLarge {
                size_mb: 1,
                max_mb: 0
            }),
            1
        );
    }

    #[test]
    fn exit_code_two_for_extract_failures() {
        assert_eq!(exit_code(&StegError::DecryptionFailed), 2);
        assert_eq!(exit_code(&StegError::NoPayloadFound), 2);
    }

    #[test]
    fn exit_code_three_for_io_and_missing_file() {
        let io = StegError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));
        assert_eq!(exit_code(&io), 3);
        assert_eq!(exit_code(&StegError::FileNotFound("x".into())), 3);
    }

    #[test]
    fn exit_code_four_for_format_and_corruption_errors() {
        assert_eq!(exit_code(&StegError::UnsupportedFormat("tiff".into())), 4);
        assert_eq!(exit_code(&StegError::CorruptedFile), 4);
    }

    // ── JsonOut ────────────────────────────────────────────────────────────

    #[test]
    fn json_out_success_serialises_with_data_only() {
        #[derive(serde::Serialize)]
        struct Body {
            bytes: usize,
        }
        let out = JsonOut::success(Body { bytes: 42 });
        let s = serde_json::to_string(&out).unwrap();
        assert!(s.contains("\"ok\":true"));
        assert!(s.contains("\"bytes\":42"));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn json_out_failure_serialises_with_error_only() {
        let out: JsonOut<()> = JsonOut::failure("something broke");
        let s = serde_json::to_string(&out).unwrap();
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"error\":\"something broke\""));
        assert!(!s.contains("\"data\""));
    }

    // ── Spinner RAII ───────────────────────────────────────────────────────

    #[test]
    fn spinner_drop_does_not_panic_when_owner_returns_early() {
        let interrupted = Arc::new(AtomicBool::new(false));
        // Constructing and dropping the spinner should be panic-free even
        // without an explicit success/fail call.
        let _spinner = Spinner::new("doing thing", interrupted);
        // dropped here implicitly
    }

    #[test]
    fn spinner_success_consumes_and_clears() {
        let interrupted = Arc::new(AtomicBool::new(false));
        let s = Spinner::new("phase 1", interrupted);
        s.success("phase 1 done");
        // If we got here without panicking, the API contract held.
    }

    #[test]
    fn spinner_fail_consumes_and_clears() {
        let interrupted = Arc::new(AtomicBool::new(false));
        let s = Spinner::new("phase 2", interrupted);
        s.fail("phase 2 broke");
    }

    // ── print_summary ──────────────────────────────────────────────────────

    #[test]
    fn print_summary_handles_empty_rows() {
        // Empty rows still renders the title card without panicking on
        // label_w/value_w max-of-empty (returns 0 via unwrap_or).
        print_summary("Title", Color::Green, &[]);
    }

    #[test]
    fn print_summary_renders_typical_card() {
        print_summary(
            "Embedded successfully",
            Color::Green,
            &[
                ("Cover", "photo.png"),
                ("Output", "photo_stego.png"),
                ("Cipher", "ChaCha20-Poly1305"),
                ("Time", "1.2s"),
            ],
        );
    }
}
