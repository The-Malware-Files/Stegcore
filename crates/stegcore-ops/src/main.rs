// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! `stegcore-ops`: operations tooling for Stegcore. Replaces the former
//! `audit.py`/`score.py` orchestration scripts with a single Rust binary and
//! hosts the comparative benchmark renderer. `calibrate.py` (numpy-heavy)
//! stays in Python by design.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

mod audit;
mod benchmark;
mod corpus;
mod embedders;
mod metrics;
mod score;

use audit::AuditSummary;
use embedders::{Embedder, LsbStegEmbedder, OpenStegoEmbedder};

#[derive(Parser)]
#[command(
    name = "stegcore-ops",
    about = "Stegcore operations tooling: dataset audit, score collection, benchmarking.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Audit a labelled image dataset: re-derive hashes, validate PNG magic,
    /// parse the claimed tool, and drop cross-label duplicates.
    Audit(AuditArgs),
    /// Score accepted samples: run the engine's analyse over each and record
    /// the detector scores, verdict and fingerprint as JSONL (resumable).
    Score(ScoreArgs),
    /// Benchmark detection accuracy from a scores JSONL: ensemble confusion at
    /// a threshold plus ROC AUC for the ensemble and each detector.
    Benchmark(BenchmarkArgs),
    /// Fetch seeded, royalty-free natural-image covers into a dataset's clean
    /// split, so detection runs have an honest false-positive baseline.
    Corpus(CorpusArgs),
    /// Embed the clean covers with a comparator tool to build the stego split,
    /// giving the benchmark both classes (so it can report ROC AUC).
    Embed(EmbedArgs),
}

#[derive(Clone, clap::ValueEnum)]
enum Tool {
    Lsbsteg,
    Openstego,
}

#[derive(clap::Args)]
struct EmbedArgs {
    /// Dataset root (clean covers in <root>/test/test/clean; stego written to
    /// <root>/test/test/stego).
    #[arg(long)]
    root: PathBuf,
    /// Embedder to drive.
    #[arg(long, value_enum)]
    tool: Tool,
    /// Maximum covers to embed (default: all clean covers).
    #[arg(long)]
    count: Option<usize>,
    /// Payload text hidden in each cover.
    #[arg(long, default_value = "Stegcore benchmark payload.")]
    payload_text: String,
    /// LSBSteg: python interpreter (the venv with cv2).
    #[arg(long)]
    python: Option<PathBuf>,
    /// LSBSteg: path to LSBSteg.py.
    #[arg(long)]
    script: Option<PathBuf>,
    /// OpenStego: docker image tag.
    #[arg(long, default_value = "stegcore-cmp/openstego:0.8.6")]
    image: String,
    /// OpenStego: docker executable (override for non-standard setups).
    #[arg(long, default_value = "docker")]
    docker_bin: PathBuf,
}

#[derive(clap::Args)]
struct CorpusArgs {
    /// Dataset root to populate (covers land in <root>/test/test/clean).
    #[arg(long)]
    out: PathBuf,
    /// Number of covers to fetch.
    #[arg(long, default_value_t = 24)]
    count: u32,
    /// Square cover side in pixels.
    #[arg(long, default_value_t = 256)]
    size: u32,
    /// Seed prefix; image `<prefix><index>` is stable and reproducible.
    #[arg(long, default_value = "stegcore")]
    seed_prefix: String,
    /// Per-cover fetch retries (the network here is flaky).
    #[arg(long, default_value_t = 4)]
    retries: u32,
}

#[derive(clap::Args)]
struct BenchmarkArgs {
    /// Scores JSONL produced by the `score` command.
    #[arg(long)]
    scores: PathBuf,
    /// Output report JSON.
    #[arg(long)]
    out: PathBuf,
    /// Ensemble decision threshold for the confusion matrix.
    #[arg(long, default_value_t = 0.55)]
    threshold: f64,
}

#[derive(clap::Args)]
struct ScoreArgs {
    /// Audit JSONL produced by the `audit` command.
    #[arg(long)]
    audit: PathBuf,
    /// Output scores JSONL (appended; existing hashes are skipped on resume).
    #[arg(long)]
    out: PathBuf,
    /// Path to the `stegcore` engine binary.
    #[arg(long)]
    bin: PathBuf,
    /// Directory the audit's relative sample paths resolve against.
    #[arg(long)]
    path_root: PathBuf,
    /// Worker count. Defaults to one fewer than the available CPUs.
    #[arg(long)]
    jobs: Option<usize>,
    /// Per-sample analyse timeout in seconds.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
}

#[derive(clap::Args)]
struct AuditArgs {
    /// Dataset root holding the train/val/test splits.
    #[arg(long)]
    root: PathBuf,
    /// Output JSONL path. Defaults to `audit-<date>.jsonl` beside the root.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Drop rate (percent) above which the run exits non-zero for review.
    #[arg(long, default_value_t = 5.0)]
    max_drop_rate: f64,
}

/// Render the human-readable audit summary. Kept separate from I/O so it can
/// be asserted directly in tests.
fn format_summary(s: &AuditSummary) -> String {
    let mut out = String::new();
    out.push_str("=== AUDIT SUMMARY ===\n");
    out.push_str(&format!("Total files scanned:  {}\n", s.total()));
    out.push_str(&format!("Accepted:             {}\n", s.accepted));
    out.push_str(&format!("Dropped:              {}\n", s.dropped));
    out.push_str(&format!("Drop rate:            {:.2}%\n", s.drop_rate()));

    out.push_str("\nDrops by reason:\n");
    let mut reasons: Vec<_> = s.drop_reasons.iter().collect();
    reasons.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (reason, count) in reasons {
        out.push_str(&format!("  {reason:<40} {count:>6}\n"));
    }

    out.push_str("\nAccepted by (split, label, variant):\n");
    for ((split, label, variant), count) in &s.by_split_label_variant {
        out.push_str(&format!(
            "  {split:<6} {label:<6} {variant:<6} {count:>6}\n"
        ));
    }

    out.push_str("\nAccepted stego by claimed tool:\n");
    let mut tools: Vec<_> = s.by_tool.iter().collect();
    tools.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (tool, count) in tools {
        out.push_str(&format!("  {tool:<10} {count:>6}\n"));
    }

    out.push_str(&format!(
        "\nCross-folder SHA256 duplicates: {} hashes across {} files\n",
        s.duplicate_hashes, s.duplicate_files
    ));
    out
}

fn run_audit_cmd(args: AuditArgs) -> ExitCode {
    if !args.root.is_dir() {
        eprintln!("error: dataset root not found: {}", args.root.display());
        return ExitCode::FAILURE;
    }
    let out = args.out.unwrap_or_else(|| {
        let date = chrono::Local::now().format("%Y-%m-%d");
        let parent = args.root.parent().unwrap_or(&args.root);
        parent.join(format!("audit-{date}.jsonl"))
    });

    println!("Auditing dataset at {}", args.root.display());
    println!("Writing JSONL to {}", out.display());

    let summary = match audit::run_audit(&args.root, &out) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: audit failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    print!("\n{}", format_summary(&summary));

    if summary.drop_rate() > args.max_drop_rate {
        eprintln!(
            "\nerror: drop rate {:.2}% exceeds the {:.2}% ceiling; halting for review",
            summary.drop_rate(),
            args.max_drop_rate
        );
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn run_score_cmd(args: ScoreArgs) -> ExitCode {
    if !args.bin.is_file() {
        eprintln!("error: engine binary not found: {}", args.bin.display());
        return ExitCode::FAILURE;
    }
    if !args.audit.is_file() {
        eprintln!("error: audit JSONL not found: {}", args.audit.display());
        return ExitCode::FAILURE;
    }
    let jobs = args.jobs.unwrap_or_else(score::default_jobs);
    println!(
        "Scoring with {jobs} workers; engine {}\nReading audit {}\nWriting scores to {}",
        args.bin.display(),
        args.audit.display(),
        args.out.display()
    );

    match score::run_score(
        &args.audit,
        &args.out,
        &args.bin,
        &args.path_root,
        jobs,
        Duration::from_secs(args.timeout_secs),
    ) {
        Ok(outcome) => {
            println!(
                "\nComplete: {} scored, {} errors, {} skipped (resume)",
                outcome.scored, outcome.errors, outcome.skipped
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: score run failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_benchmark_cmd(args: BenchmarkArgs) -> ExitCode {
    if !args.scores.is_file() {
        eprintln!("error: scores JSONL not found: {}", args.scores.display());
        return ExitCode::FAILURE;
    }
    let records = match benchmark::load_scores(&args.scores) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: could not read scores: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = benchmark::build_report(&records, args.threshold);
    print!("{}", benchmark::format_report(&report));
    if let Err(e) = benchmark::write_report(&report, &args.out) {
        eprintln!("error: could not write report: {e}");
        return ExitCode::FAILURE;
    }
    println!("\nReport written to {}", args.out.display());
    ExitCode::SUCCESS
}

fn run_corpus_cmd(args: CorpusArgs) -> ExitCode {
    let clean_dir = args.out.join("test").join("test").join("clean");
    println!(
        "Fetching {} natural covers ({}x{}) into {}",
        args.count,
        args.size,
        args.size,
        clean_dir.display()
    );
    let size = args.size;
    let retries = args.retries;
    let prefix = args.seed_prefix.clone();
    let result = corpus::run_fetch(&clean_dir, args.count, |i| {
        corpus::curl_download(&format!("{prefix}{i}"), size, retries)
    });
    match result {
        Ok(outcome) => {
            println!(
                "\nFetched {} covers, {} failed. Clean split: {}",
                outcome.fetched,
                outcome.failed,
                clean_dir.display()
            );
            if outcome.fetched == 0 {
                eprintln!("error: no covers fetched");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: corpus fetch failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn gather_covers(clean_dir: &Path, limit: Option<usize>) -> std::io::Result<Vec<PathBuf>> {
    let mut covers: Vec<PathBuf> = std::fs::read_dir(clean_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "png"))
        .collect();
    covers.sort();
    if let Some(n) = limit {
        covers.truncate(n);
    }
    Ok(covers)
}

fn run_embed_cmd(args: EmbedArgs) -> ExitCode {
    let clean_dir = args.root.join("test").join("test").join("clean");
    let stego_dir = args.root.join("test").join("test").join("stego");
    if !clean_dir.is_dir() {
        eprintln!("error: clean split not found: {}", clean_dir.display());
        return ExitCode::FAILURE;
    }

    let embedder: Box<dyn Embedder> = match args.tool {
        Tool::Lsbsteg => match (args.python, args.script) {
            (Some(python), Some(script)) => Box::new(LsbStegEmbedder { python, script }),
            _ => {
                eprintln!("error: --python and --script are required for lsbsteg");
                return ExitCode::FAILURE;
            }
        },
        Tool::Openstego => Box::new(OpenStegoEmbedder {
            image: args.image,
            docker_bin: args.docker_bin,
        }),
    };

    let covers = match gather_covers(&clean_dir, args.count) {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => {
            eprintln!("error: no clean covers in {}", clean_dir.display());
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("error: could not read covers: {e}");
            return ExitCode::FAILURE;
        }
    };

    let payload = match tempfile::NamedTempFile::new() {
        Ok(mut f) => {
            use std::io::Write;
            if let Err(e) = f.write_all(args.payload_text.as_bytes()) {
                eprintln!("error: could not write payload: {e}");
                return ExitCode::FAILURE;
            }
            f
        }
        Err(e) => {
            eprintln!("error: could not create payload: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!(
        "Embedding {} covers with {} into {}",
        covers.len(),
        embedder.id(),
        stego_dir.display()
    );
    match embedders::embed_corpus(embedder.as_ref(), &covers, payload.path(), &stego_dir) {
        Ok(o) => {
            println!("\nEmbedded {}, failed {}.", o.embedded, o.failed);
            if o.embedded == 0 {
                eprintln!("error: no covers embedded");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: embed run failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Audit(args) => run_audit_cmd(args),
        Command::Score(args) => run_score_cmd(args),
        Command::Benchmark(args) => run_benchmark_cmd(args),
        Command::Corpus(args) => run_corpus_cmd(args),
        Command::Embed(args) => run_embed_cmd(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn format_summary_renders_all_sections() {
        let mut s = AuditSummary {
            accepted: 3,
            dropped: 1,
            ..Default::default()
        };
        s.drop_reasons.insert("magic-mismatch".into(), 1);
        s.by_split_label_variant
            .insert(("train".into(), "clean".into(), "-".into()), 2);
        s.by_tool.insert("steghide".into(), 1);
        s.duplicate_hashes = 0;
        s.duplicate_files = 0;

        let text = format_summary(&s);
        assert!(text.contains("Total files scanned:  4"));
        assert!(text.contains("Drop rate:            25.00%"));
        assert!(text.contains("magic-mismatch"));
        assert!(text.contains("train  clean"));
        assert!(text.contains("steghide"));
        assert!(text.contains("Cross-folder SHA256 duplicates: 0 hashes across 0 files"));
    }

    #[test]
    fn cli_parses_audit_subcommand() {
        let cli = Cli::try_parse_from([
            "stegcore-ops",
            "audit",
            "--root",
            "/data/x",
            "--max-drop-rate",
            "3.0",
        ])
        .unwrap();
        let Command::Audit(args) = cli.command else {
            panic!("expected the audit subcommand");
        };
        assert_eq!(args.root, PathBuf::from("/data/x"));
        assert_eq!(args.max_drop_rate, 3.0);
        assert!(args.out.is_none());
    }

    #[test]
    fn cli_rejects_missing_root() {
        // `--root` is required, so parsing without it must error.
        assert!(Cli::try_parse_from(["stegcore-ops", "audit"]).is_err());
    }

    #[test]
    fn empty_summary_formats_with_zero_rate() {
        let s = AuditSummary {
            drop_reasons: BTreeMap::new(),
            ..Default::default()
        };
        let text = format_summary(&s);
        assert!(text.contains("Drop rate:            0.00%"));
    }
}
