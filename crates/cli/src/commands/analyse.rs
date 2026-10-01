// Author:  Daniel Iwugo
// Comment: Christ is King
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

    /// Output path for the report file (required for html/csv; for json, omit
    /// to print to stdout)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,

    /// Overwrite the report file if it already exists
    #[arg(long)]
    pub force: bool,

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
            save_or_print(
                &html,
                args.output.as_deref(),
                "report.html",
                verbose,
                json,
                args.force,
            );
        }
        "json" => {
            let body = serde_json::to_string_pretty(&reports).unwrap_or_else(|_| "[]".into());
            match args.output.as_deref() {
                // A path was given: write the report there (with the overwrite guard).
                Some(path) => {
                    save_or_print(&body, Some(path), "report.json", verbose, json, args.force)
                }
                // No path: the JSON report goes to stdout, as the help text promises.
                None => {
                    println!("{body}");
                    std::process::exit(0);
                }
            }
        }
        "csv" => {
            let csv = build_csv(&reports);
            save_or_print(
                &csv,
                args.output.as_deref(),
                "report.csv",
                verbose,
                json,
                args.force,
            );
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
    force: bool,
) {
    let path = out
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(default_name));

    // Refuse to clobber an existing report unless --force.
    if !force && path.exists() {
        let msg = format!(
            "Report file already exists: {} (use --force to overwrite)",
            path.display()
        );
        if json {
            output::emit_json(&JsonOut::<()>::failure(&msg), 1);
        }
        output::print_error(&msg, None);
        std::process::exit(1);
    }

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

/// Break a line into segments that fit `width` display columns, on word
/// boundaries, indenting continuations by two spaces.
///
/// Counts `chars()` rather than bytes: the coverage strings name tools and
/// formats, and a byte count would mis-pad the box the moment one is
/// non-ASCII.
fn wrap_to(line: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![line.to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in line.split_whitespace() {
        let indent = if out.is_empty() { 0 } else { 2 };
        let projected = if cur.is_empty() {
            indent + word.chars().count()
        } else {
            cur.chars().count() + 1 + word.chars().count()
        };
        if !cur.is_empty() && projected > width {
            out.push(cur);
            cur = format!("  {word}");
        } else if cur.is_empty() {
            cur = if out.is_empty() {
                word.to_string()
            } else {
                format!("  {word}")
            };
        } else {
            cur.push(' ');
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Whether a named detector's score contributes to the ensemble verdict.
///
/// Matched on the display name because that is what the report carries; the
/// engine's own exclusion is positional (it drops `tests[0]` and `tests[3]`).
/// Two places deciding the same thing is a drift risk and is noted in the
/// sprint plan as worth collapsing into the `Coverage` record, which travels
/// with the report and would let the engine say this once.
fn test_counts_toward_verdict(name: &str) -> bool {
    !matches!(name, "Chi-Squared" | "LSB Entropy")
}

fn verdict_str(v: &Verdict) -> &'static str {
    match v {
        // "Nothing found" reports an observation; "Clean" reported a
        // conclusion the engine had not earned. See Verdict's own docs.
        Verdict::Clean => "Nothing found",
        Verdict::NotAssessed => "Not assessed",
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

        // Per-test bars.
        //
        // Chi-Squared and LSB Entropy are excluded from the verdict (Q-37:
        // near-zero signal on natural covers, and they nearly double the
        // ensemble false-positive rate without buying detection). They were
        // still drawn identically to the three detectors that decide it, and
        // they are the two that look alarming: measured over 200 ordinary
        // photographs, LSB Entropy has a median of 0.993 and reads above 99%
        // on 54% of them, while Chi-Squared sits at a median of 0.507. A
        // reader reasonably concluded the statistics drove the verdict. They
        // are marked here rather than hidden, because removing them would lose
        // information a specialist uses.
        for t in &r.tests {
            let pct = (t.score * 100.0).round() as u32;
            let counts = test_counts_toward_verdict(&t.name);
            let colour = if counts {
                score_colour(t.score)
            } else {
                Color::DarkGrey
            };
            let b = bar(t.score, 16);
            let mark = if counts { "  " } else { " ·" };

            let _ = s.execute(Print("  │  "));
            let _ = s.execute(SetForegroundColor(if counts {
                Color::Reset
            } else {
                Color::DarkGrey
            }));
            let _ = s.execute(Print(format!("{:20} ", t.name)));
            let _ = s.execute(SetForegroundColor(colour));
            let _ = s.execute(Print(format!("{b} {pct:3}%{mark}")));
            let _ = s.execute(SetForegroundColor(Color::DarkGrey));

            // Pad to fill the box width
            let used = 20 + 1 + 16 + 1 + 4 + 2 + 2; // name+bar+pct+mark+borders
            let rpad = width.saturating_sub(used);
            let _ = s.execute(Print(format!("{:rpad$}│\n", "")));
        }
        if r.tests.iter().any(|t| !test_counts_toward_verdict(&t.name)) {
            let note = "· not counted toward the verdict";
            let _ = s.execute(Print("  │  "));
            let _ = s.execute(SetForegroundColor(Color::DarkGrey));
            let _ = s.execute(Print(note));
            let npad = width.saturating_sub(note.len() + 2);
            let _ = s.execute(Print(format!("{:npad$}│\n", "")));
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
            // Deliberately not green and not red: it is neither reassurance
            // nor an alarm, and colouring it either way would be a claim.
            Verdict::NotAssessed => Color::Cyan,
            Verdict::Suspicious => Color::Yellow,
            Verdict::LikelyStego => Color::Red,
        };
        let icon = match r.verdict {
            Verdict::Clean => "✓",
            Verdict::NotAssessed => "—",
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

        // What was and was not examined.
        //
        // This is the change a user asked for by name, having watched the tool
        // report a clean verdict on a file they had filled with steghide a
        // minute earlier: "one honest line would fix it". It goes under the
        // verdict so the verdict is never read without it.
        if let Some(cov) = &r.coverage {
            let mut lines: Vec<String> = Vec::new();
            for c in &cov.checked {
                lines.push(format!("checked: {c}"));
            }
            for n in &cov.not_checked {
                lines.push(format!("NOT checked: {n}"));
            }
            if !lines.is_empty() {
                let _ = s.execute(SetForegroundColor(Color::DarkGrey));
                let _ = s.execute(Print(format!("  ├{bar_line}┤\n")));
                for line in lines {
                    // Wrap by words so a long detector list does not run past
                    // the box it is drawn inside.
                    for seg in wrap_to(&line, width.saturating_sub(4)) {
                        let _ = s.execute(Print("  │  "));
                        let _ = s.execute(SetForegroundColor(
                            if seg.starts_with("NOT") || seg.starts_with("  ") {
                                Color::Yellow
                            } else {
                                Color::DarkGrey
                            },
                        ));
                        let _ = s.execute(Print(&seg));
                        let _ = s.execute(SetForegroundColor(Color::DarkGrey));
                        let pad = width.saturating_sub(seg.chars().count() + 2);
                        let _ = s.execute(Print(format!("{:pad$}│\n", "")));
                    }
                }
            }
        }

        // Bottom border
        let _ = s.execute(Print(format!("  ╰{bar_line}╯\n")));
        let _ = s.execute(ResetColor);
    }
}

/// The verdict as a stable token for machine-read output.
///
/// Deliberately not `verdict_str`, which is prose for a human reading a
/// terminal and is free to be reworded. A CSV goes into somebody's script, so it
/// carries the same snake_case tokens the JSON output does: one vocabulary for
/// machines, one for people, and rewording the terminal never breaks a pipeline.
fn verdict_token(v: &Verdict) -> &'static str {
    match v {
        Verdict::Clean => "clean",
        Verdict::NotAssessed => "not_assessed",
        Verdict::Suspicious => "suspicious",
        Verdict::LikelyStego => "likely_stego",
    }
}

fn build_csv(reports: &[AnalysisReport]) -> String {
    let mut out = String::from("file,format,verdict,score,fingerprint\n");
    for r in reports {
        out.push_str(&format!(
            "{},{},{},{:.4},{}\n",
            csv_escape(&r.file.display().to_string()),
            csv_escape(&r.format),
            verdict_token(&r.verdict),
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

/// File extensions the watch loop accepts.
const WATCH_SUPPORTED_EXTENSIONS: &[&str] = &["png", "bmp", "jpg", "jpeg", "webp", "wav", "flac"];

/// Decide whether the watch loop should analyse a freshly-seen path:
/// must be a real file and carry one of the supported extensions.
/// Kept as a pure function so the dispatch rule can be unit-tested
/// without standing up a real notify watcher.
fn watch_path_is_analysable(path: &std::path::Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    WATCH_SUPPORTED_EXTENSIONS.contains(&ext.as_str()) && path.is_file()
}

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

    loop {
        if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!();
            std::process::exit(130);
        }

        if let Ok(event) = rx.recv_timeout(std::time::Duration::from_millis(200)) {
            if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                for path in &event.paths {
                    if watch_path_is_analysable(path) {
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(file: &str, verdict: Verdict, score: f64, fp: Option<&str>) -> AnalysisReport {
        AnalysisReport {
            file: PathBuf::from(file),
            format: "png".into(),
            tests: vec![],
            overall_score: score,
            verdict,
            tool_fingerprint: fp.map(|s| s.to_owned()),
            tool_fingerprint_tier: None,
            block_entropy: None,
            coverage: None,
        }
    }

    // ── verdict_str ────────────────────────────────────────────────────────

    #[test]
    fn verdict_str_maps_every_verdict() {
        assert_eq!(verdict_str(&Verdict::Clean), "Nothing found");
        assert_eq!(verdict_str(&Verdict::NotAssessed), "Not assessed");
        assert_eq!(verdict_str(&Verdict::Suspicious), "Suspicious");
        assert_eq!(verdict_str(&Verdict::LikelyStego), "Likely stego");
    }

    /// The whole point of splitting `NotAssessed` out of `Clean` is that a user
    /// can tell them apart, so the two must never render the same words. A later
    /// tidy-up that collapsed them would silently restore the bug.
    #[test]
    fn nothing_found_and_not_assessed_read_differently() {
        assert_ne!(
            verdict_str(&Verdict::Clean),
            verdict_str(&Verdict::NotAssessed)
        );
    }

    // ── score_colour ───────────────────────────────────────────────────────

    #[test]
    fn score_colour_is_green_below_25pct() {
        assert!(matches!(score_colour(0.0), crossterm::style::Color::Green));
        assert!(matches!(score_colour(0.24), crossterm::style::Color::Green));
    }

    #[test]
    fn score_colour_is_yellow_in_mid_band() {
        assert!(matches!(
            score_colour(0.25),
            crossterm::style::Color::Yellow
        ));
        assert!(matches!(
            score_colour(0.54),
            crossterm::style::Color::Yellow
        ));
    }

    #[test]
    fn score_colour_is_red_above_55pct() {
        assert!(matches!(score_colour(0.55), crossterm::style::Color::Red));
        assert!(matches!(score_colour(1.0), crossterm::style::Color::Red));
    }

    // ── bar ────────────────────────────────────────────────────────────────

    #[test]
    fn bar_fully_empty_at_zero() {
        let b = bar(0.0, 10);
        assert_eq!(b.chars().filter(|&c| c == '░').count(), 10);
        assert_eq!(b.chars().filter(|&c| c == '█').count(), 0);
    }

    #[test]
    fn bar_fully_filled_at_one() {
        let b = bar(1.0, 10);
        assert_eq!(b.chars().filter(|&c| c == '█').count(), 10);
        assert_eq!(b.chars().filter(|&c| c == '░').count(), 0);
    }

    #[test]
    fn bar_half_filled_at_point_five() {
        let b = bar(0.5, 10);
        assert_eq!(b.chars().filter(|&c| c == '█').count(), 5);
        assert_eq!(b.chars().filter(|&c| c == '░').count(), 5);
    }

    #[test]
    fn bar_clamps_above_one() {
        // Scores can never exceed 1 in practice but the helper must not panic.
        let b = bar(1.5, 8);
        assert_eq!(b.chars().filter(|&c| c == '█').count(), 8);
    }

    // ── csv_escape ─────────────────────────────────────────────────────────

    #[test]
    fn csv_escape_passes_clean_strings_through() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("file.png"), "file.png");
    }

    #[test]
    fn csv_escape_quotes_comma_strings() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_escape_doubles_inner_quotes() {
        assert_eq!(csv_escape("she said \"hi\""), "\"she said \"\"hi\"\"\"");
    }

    #[test]
    fn csv_escape_quotes_newline_strings() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    // ── build_csv ──────────────────────────────────────────────────────────

    #[test]
    fn build_csv_emits_header() {
        let csv = build_csv(&[]);
        assert_eq!(csv, "file,format,verdict,score,fingerprint\n");
    }

    #[test]
    fn build_csv_renders_one_row_per_report() {
        let reports = vec![
            sample_report("a.png", Verdict::Clean, 0.1, None),
            sample_report(
                "b.png",
                Verdict::Suspicious,
                0.5,
                Some("openstego/null-lsb"),
            ),
            sample_report("c.png", Verdict::LikelyStego, 0.9, None),
        ];
        let csv = build_csv(&reports);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4); // header + 3 rows
        assert!(lines[1].contains("a.png"));
        assert!(lines[1].contains("clean"));
        assert!(lines[2].contains("suspicious"));
        assert!(lines[2].contains("openstego/null-lsb"));
        assert!(lines[3].contains("likely_stego"));
    }

    /// The CSV is a machine contract and the terminal is not, so they are allowed
    /// to diverge, but the CSV must match what the JSON output serialises or a
    /// consumer reading both gets two vocabularies for one field.
    #[test]
    fn csv_tokens_match_the_json_serialisation() {
        for v in [
            Verdict::Clean,
            Verdict::NotAssessed,
            Verdict::Suspicious,
            Verdict::LikelyStego,
        ] {
            let json = serde_json::to_string(&v).expect("verdict serialises");
            let expected = format!("\"{}\"", verdict_token(&v));
            assert_eq!(json, expected, "CSV token and JSON drifted for {v:?}");
        }
    }

    /// A token that reached the CSV with a comma or a space in it would need
    /// quoting the writer does not apply to this column.
    #[test]
    fn csv_tokens_need_no_escaping() {
        for v in [
            Verdict::Clean,
            Verdict::NotAssessed,
            Verdict::Suspicious,
            Verdict::LikelyStego,
        ] {
            let t = verdict_token(&v);
            assert_eq!(csv_escape(t), t, "{t} would have to be quoted");
        }
    }

    #[test]
    fn build_csv_quotes_paths_with_commas() {
        let r = sample_report("path,with,commas.png", Verdict::Clean, 0.0, None);
        let csv = build_csv(&[r]);
        assert!(csv.contains("\"path,with,commas.png\""));
    }

    // ── watch_path_is_analysable ───────────────────────────────────────────

    #[test]
    fn watch_rejects_unsupported_extensions() {
        // tempfile gives us a real file on disk.
        let tmp = tempfile::NamedTempFile::with_suffix(".txt").unwrap();
        assert!(!watch_path_is_analysable(tmp.path()));
    }

    #[test]
    fn watch_accepts_png() {
        let tmp = tempfile::NamedTempFile::with_suffix(".png").unwrap();
        assert!(watch_path_is_analysable(tmp.path()));
    }

    #[test]
    fn watch_accepts_extension_case_insensitively() {
        let tmp = tempfile::NamedTempFile::with_suffix(".PNG").unwrap();
        assert!(watch_path_is_analysable(tmp.path()));
        let tmp = tempfile::NamedTempFile::with_suffix(".WAV").unwrap();
        assert!(watch_path_is_analysable(tmp.path()));
    }

    #[test]
    fn watch_rejects_directories_with_supported_extension() {
        // A directory named `foo.png` should still be skipped because it's
        // not a file. `tempfile::tempdir` doesn't suffix; just craft a path.
        let dir = tempfile::tempdir().unwrap();
        let pseudo = dir.path().join("not-a-file.png");
        std::fs::create_dir(&pseudo).unwrap();
        assert!(!watch_path_is_analysable(&pseudo));
    }

    #[test]
    fn watch_rejects_path_without_extension() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        assert!(!watch_path_is_analysable(tmp.path()));
    }
}
