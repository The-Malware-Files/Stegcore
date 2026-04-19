// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use std::path::PathBuf;
use std::sync::Arc;

use stegcore_core::analysis::{self, AnalysisReport, Verdict};

use crate::output::{self, JsonOut};

#[derive(Debug, clap::Args)]
#[command(after_long_help = "\x1b[36mExamples:\x1b[0m
  stegcore analyse suspect.png
  stegcore analyse suspect.png --verbose
  stegcore analyse --batch \"*.png\" --json
  stegcore analyse --watch /tmp/incoming/
")]
pub struct AnalyseArgs {
    /// File to analyse (omit when using --batch)
    pub file: Option<PathBuf>,

    /// Glob pattern for batch analysis (e.g. "*.png")
    #[arg(long)]
    pub batch: Option<String>,

    /// Report format
    #[arg(long, default_value = "table",
          value_parser = ["table", "html", "json", "csv"])]
    pub report: String,

    /// Output path for the report file (required for html/csv; optional for json)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Watch a directory for new files and analyse automatically
    #[arg(long)]
    pub watch: Option<PathBuf>,
}

pub fn run(
    args: &AnalyseArgs,
    verbose: bool,
    json: bool,
    _quiet: bool,
    interrupted: Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    // ── Watch mode ────────────────────────────────────────────────────────────
    if let Some(ref watch_dir) = args.watch {
        run_watch(watch_dir, verbose, json, &interrupted);
    }

    // ── Collect paths ─────────────────────────────────────────────────────────
    let paths: Vec<PathBuf> = collect_paths(args, verbose, json);

    if paths.is_empty() {
        output::print_error(
            "No files to analyse. Provide a file argument or --batch <glob>.",
            None,
        );
        std::process::exit(1);
    }

    // ── Run analysis — per-file progress bar ──────────────────────────────────
    let pb = indicatif::ProgressBar::new(paths.len() as u64);
    pb.set_style(
        indicatif::ProgressStyle::with_template(
            "{spinner:.cyan} [{bar:30.cyan/dim}] {pos}/{len} {msg} {eta_precise}",
        )
        .unwrap()
        .progress_chars("█▓░")
        .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let mut reports: Vec<AnalysisReport> = Vec::new();

    for (i, path) in paths.iter().enumerate() {
        if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
            pb.finish_and_clear();
            eprintln!();
            std::process::exit(130);
        }

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());
        pb.set_message(file_name);

        match analysis::analyse(path) {
            Ok(rep) => reports.push(rep),
            Err(e) => {
                output::print_warn(&format!("{}: {}", paths[i].display(), e));
                if verbose {
                    output::print_info(&format!("{e:#}"));
                }
            }
        }
        pb.inc(1);
    }

    pb.finish_and_clear();

    if reports.is_empty() {
        output::print_error("All files failed to analyse.", None);
        std::process::exit(1);
    }

    // ── Output ────────────────────────────────────────────────────────────────
    match args.report.as_str() {
        "table" => {
            if json {
                let data: Vec<serde_json::Value> = reports
                    .iter()
                    .map(|r| serde_json::to_value(r).unwrap_or_default())
                    .collect();
                output::emit_json(&JsonOut::success(data), 0);
            }
            print_table(&reports);
            std::process::exit(0);
        }
        "html" => {
            let html = analysis::generate_html_report(&reports);
            save_or_print(&html, args.output.as_deref(), "report.html", verbose, json);
        }
        "json" => {
            let body = serde_json::to_string_pretty(&reports).unwrap_or_else(|_| "[]".into());
            save_or_print(&body, args.output.as_deref(), "report.json", verbose, json);
        }
        "csv" => {
            let csv = build_csv(&reports);
            save_or_print(&csv, args.output.as_deref(), "report.csv", verbose, json);
        }
        _ => unreachable!(),
    }

    std::process::exit(0);
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn collect_paths(args: &AnalyseArgs, verbose: bool, json: bool) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(f) = &args.file {
        if f.exists() {
            paths.push(f.clone());
        } else {
            let e = stegcore_core::errors::StegError::FileNotFound(f.display().to_string());
            if json {
                output::emit_json(&JsonOut::<()>::failure(&e.to_string()), 3);
            }
            output::die(&e, verbose);
        }
    }

    if let Some(pattern) = &args.batch {
        match glob::glob(pattern) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if entry.is_file() {
                        paths.push(entry);
                    }
                }
            }
            Err(e) => {
                output::print_error(&format!("Invalid glob pattern: {e}"), None);
                std::process::exit(1);
            }
        }
    }

    paths
}

fn save_or_print(
    content: &str,
    out: Option<&std::path::Path>,
    default_name: &str,
    verbose: bool,
    json: bool,
) {
    let path = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(default_name));

    if let Err(e) = std::fs::write(&path, content) {
        let err = stegcore_core::errors::StegError::Io(e);
        if json {
            output::emit_json(&JsonOut::<()>::failure(&err.to_string()), 3);
        }
        output::die(&err, verbose);
    }
    output::print_success(&format!("Report saved → {}", path.display()));
    if json {
        #[derive(serde::Serialize)]
        struct Out {
            report: String,
        }
        output::emit_json(
            &JsonOut::success(Out {
                report: path.display().to_string(),
            }),
            0,
        );
    }
}

fn verdict_str(v: &Verdict) -> &'static str {
    match v {
        Verdict::Clean => "Clean",
        Verdict::Suspicious => "Suspicious",
        Verdict::LikelyStego => "Likely stego",
    }
}

fn score_colour(score: f64) -> crossterm::style::Color {
    if score < 0.25 {
        crossterm::style::Color::Green
    } else if score < 0.55 {
        crossterm::style::Color::Yellow
    } else {
        crossterm::style::Color::Red
    }
}

fn bar(score: f64, width: usize) -> String {
    let filled = ((score * width as f64).round() as usize).min(width);
    let empty = width - filled;
    format!("{}{}", "█".repeat(filled), "░".repeat(empty))
}

fn print_table(reports: &[AnalysisReport]) {
    use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
    use crossterm::ExecutableCommand;
    let mut s = std::io::stderr();

    for (ri, r) in reports.iter().enumerate() {
        if ri > 0 {
            eprintln!();
        }

        let fname = r
            .file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| r.file.display().to_string());
        let score_pct = format!("{:.0}%", r.overall_score * 100.0);
        let header = format!(
            "{}  ·  {}  ·  {}",
            fname,
            r.format.to_uppercase(),
            score_pct
        );

        let width = 56.max(header.len() + 4);
        let bar_line = "─".repeat(width);

        // Top border
        let _ = s.execute(SetForegroundColor(Color::DarkGrey));
        let _ = s.execute(Print(format!("\n  ╭{bar_line}╮\n")));

        // Header
        let _ = s.execute(Print("  │  "));
        let _ = s.execute(SetForegroundColor(Color::Cyan));
        let _ = s.execute(Print(header.to_string()));
        let pad = width - header.len() - 2;
        let _ = s.execute(SetForegroundColor(Color::DarkGrey));
        let _ = s.execute(Print(format!("{:pad$}│\n", "")));
        let _ = s.execute(Print(format!("  ├{bar_line}┤\n")));

        // Per-test bars
        for t in &r.tests {
            let pct = (t.score * 100.0).round() as u32;
            let colour = score_colour(t.score);
            let b = bar(t.score, 16);

            let _ = s.execute(Print("  │  "));
            let _ = s.execute(SetForegroundColor(Color::Reset));
            let _ = s.execute(Print(format!("{:20} ", t.name)));
            let _ = s.execute(SetForegroundColor(colour));
            let _ = s.execute(Print(format!("{b} {pct:3}%")));
            let _ = s.execute(SetForegroundColor(Color::DarkGrey));

            // Pad to fill the box width
            let used = 20 + 1 + 16 + 1 + 4 + 2; // name+space+bar+space+pct%+borders
            let rpad = width.saturating_sub(used);
            let _ = s.execute(Print(format!("{:rpad$}│\n", "")));
        }

        // Tool fingerprint
        if let Some(fp) = &r.tool_fingerprint {
            let _ = s.execute(Print("  │  "));
            let _ = s.execute(SetForegroundColor(Color::Red));
            let sig = format!("Signature: {fp}");
            let _ = s.execute(Print(&sig));
            let spad = if width > sig.len() + 2 {
                width - sig.len() - 2
            } else {
                0
            };
            let _ = s.execute(SetForegroundColor(Color::DarkGrey));
            let _ = s.execute(Print(format!("{:spad$}│\n", "")));
        }

        // Separator
        let _ = s.execute(SetForegroundColor(Color::DarkGrey));
        let _ = s.execute(Print(format!("  ├{bar_line}┤\n")));

        // Verdict
        let verdict = verdict_str(&r.verdict);
        let colour = match r.verdict {
            Verdict::Clean => Color::Green,
            Verdict::Suspicious => Color::Yellow,
            Verdict::LikelyStego => Color::Red,
        };
        let icon = match r.verdict {
            Verdict::Clean => "✓",
            Verdict::Suspicious => "⚠",
            Verdict::LikelyStego => "✗",
        };
        let _ = s.execute(Print("  │  "));
        let _ = s.execute(SetForegroundColor(colour));
        let vstr = format!("{icon} {verdict}");
        let _ = s.execute(Print(&vstr));
        let vpad = if width > vstr.len() + 2 {
            width - vstr.len() - 2
        } else {
            0
        };
        let _ = s.execute(SetForegroundColor(Color::DarkGrey));
        let _ = s.execute(Print(format!("{:vpad$}│\n", "")));

        // Bottom border
        let _ = s.execute(Print(format!("  ╰{bar_line}╯\n")));
        let _ = s.execute(ResetColor);
    }
}

fn build_csv(reports: &[AnalysisReport]) -> String {
    let mut out = String::from("file,format,verdict,score,fingerprint\n");
    for r in reports {
        out.push_str(&format!(
            "{},{},{},{:.4},{}\n",
            csv_escape(&r.file.display().to_string()),
            csv_escape(&r.format),
            verdict_str(&r.verdict),
            r.overall_score,
            csv_escape(r.tool_fingerprint.as_deref().unwrap_or("")),
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

// ── Watch mode ───────────────────────────────────────────────────────────────

fn run_watch(
    dir: &std::path::Path,
    verbose: bool,
    _json: bool,
    interrupted: &Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    use notify::{EventKind, RecursiveMode, Watcher};
    use std::sync::mpsc;

    if !dir.is_dir() {
        output::print_error(&format!("{} is not a directory", dir.display()), None);
        std::process::exit(1);
    }

    output::print_info(&format!("Watching {} for new files…", dir.display()));
    output::print_info("Press Ctrl-C to stop.");

    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })
    .expect("Failed to create file watcher");

    watcher
        .watch(dir, RecursiveMode::NonRecursive)
        .expect("Failed to watch directory");

    let supported = ["png", "bmp", "jpg", "jpeg", "webp", "wav", "flac"];

    loop {
        if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!();
            std::process::exit(130);
        }

        if let Ok(event) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for path in &event.paths {
                    let ext = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.to_lowercase())
                        .unwrap_or_default();
                    if supported.contains(&ext.as_str()) && path.is_file() {
                        output::print_info(&format!("New file: {}", path.display()));
                        match analysis::analyse(path) {
                            Ok(report) => print_table(&[report]),
                            Err(e) => {
                                output::print_warn(&format!("{}: {}", path.display(), e));
                                if verbose {
                                    output::print_info(&format!("{e:#}"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
