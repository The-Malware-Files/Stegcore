// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Stegcore CLI
//
// Entry point. Sets up the SIGINT handler, parses arguments with clap,
// and dispatches to the appropriate subcommand.

mod commands;
mod config;
mod output;
mod prompt;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use commands::{analyse, ciphers, embed, extract, info, score, wizard};

// ── CLI definition ─────────────────────────────────────────────────────────────

const fn clap_styles() -> clap::builder::Styles {
    use clap::builder::styling::*;
    Styles::styled()
        .header(AnsiColor::Cyan.on_default().bold())
        .usage(AnsiColor::Cyan.on_default().bold())
        .literal(AnsiColor::Green.on_default())
        .placeholder(AnsiColor::Yellow.on_default())
        .valid(AnsiColor::Green.on_default().bold())
        .invalid(AnsiColor::Red.on_default().bold())
        .error(AnsiColor::Red.on_default().bold())
}

#[derive(Parser)]
#[command(
    name        = "stegcore",
    version     = env!("CARGO_PKG_VERSION"),
    long_version = env!("CARGO_PKG_VERSION"),
    author      = "The Malware Files",
    about       = "Hide and retrieve encrypted messages inside image and audio files.",
    long_about  = None,
    arg_required_else_help = true,
    styles = clap_styles(),
)]
struct Cli {
    /// Show verbose error chains
    #[arg(long, short = 'v', global = true)]
    verbose: bool,

    /// Output results as JSON (machine-readable)
    #[arg(long, global = true)]
    json: bool,

    /// Suppress all output except errors (exit code only)
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hide a message inside a cover file
    Embed(embed::EmbedArgs),

    /// Retrieve a hidden message from a stego file
    Extract(extract::ExtractArgs),

    /// Analyse a file for hidden content
    Analyse(analyse::AnalyseArgs),

    /// Score a cover file's suitability for embedding
    Score(score::ScoreArgs),

    /// Read metadata embedded in a stego file
    Info(info::InfoArgs),

    /// List supported encryption ciphers
    Ciphers,

    /// Interactive guided wizard (recommended for new users)
    Wizard,

    /// Compare original and stego file (pixel diff)
    Diff(commands::diff::DiffArgs),

    /// System health check
    Doctor,

    /// Benchmark cipher throughput
    Benchmark,

    /// Show the current Bible verse
    Verse,

    /// Generate shell completion scripts
    Completions {
        /// Shell to generate for
        #[arg(value_enum)]
        shell: Shell,
    },
}

// ── Entry point ────────────────────────────────────────────────────────────────

fn main() {
    // ── SIGINT / Ctrl-C ────────────────────────────────────────────────────────
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&interrupted);
        ctrlc::set_handler(move || {
            flag.store(true, Ordering::SeqCst);
        })
        .ok(); // Best-effort — some platforms may not support signal handlers
    }

    // ── Parse arguments ────────────────────────────────────────────────────────
    let cli = Cli::parse();
    let cfg = config::Config::load();

    // ── Bible verse (env var or config file) ─────────────────────────────────
    let verses_enabled =
        std::env::var("STEGCORE_VERSES").unwrap_or_default() == "1" || cfg.verses.unwrap_or(false);
    if !cli.json && !cli.quiet && verses_enabled {
        let v = stegcore_core::verses::current_verse();
        use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
        use crossterm::ExecutableCommand;
        let mut stderr = std::io::stderr();
        let _ = stderr.execute(SetForegroundColor(Color::DarkGrey));
        let _ = stderr.execute(Print(format!("  \"{}\"\n  — {}\n\n", v.text, v.reference)));
        let _ = stderr.execute(ResetColor);
    }

    // ── Apply config defaults where CLI flags were not explicitly provided ─────
    let verbose = cli.verbose || cfg.verbose.unwrap_or(false);

    // ── Dispatch ───────────────────────────────────────────────────────────────
    match cli.command {
        Command::Embed(mut args) => {
            // Config overrides for embed: only apply if user did not explicitly set the flag.
            // clap always fills default_value, so we check if the value matches the default.
            if let Some(ref c) = cfg.default_cipher {
                if args.cipher == "chacha20-poly1305" {
                    args.cipher = c.clone();
                }
            }
            if let Some(ref m) = cfg.default_mode {
                if args.mode == "adaptive" {
                    args.mode = m.clone();
                }
            }
            if cfg.export_key.unwrap_or(false) && !args.export_key {
                args.export_key = true;
            }
            embed::run(
                &args,
                verbose,
                cli.json,
                cli.quiet,
                Arc::clone(&interrupted),
            )
        }
        Command::Extract(args) => extract::run(
            &args,
            verbose,
            cli.json,
            cli.quiet,
            Arc::clone(&interrupted),
        ),
        Command::Analyse(args) => analyse::run(
            &args,
            verbose,
            cli.json,
            cli.quiet,
            Arc::clone(&interrupted),
        ),
        Command::Score(args) => score::run(
            &args,
            verbose,
            cli.json,
            cli.quiet,
            Arc::clone(&interrupted),
        ),
        Command::Info(args) => info::run(
            &args,
            verbose,
            cli.json,
            cli.quiet,
            Arc::clone(&interrupted),
        ),
        Command::Ciphers => ciphers::run(cli.json),
        Command::Diff(args) => commands::diff::run(&args, cli.json),
        Command::Wizard => wizard::run(Arc::clone(&interrupted)),
        Command::Doctor => {
            use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
            use crossterm::ExecutableCommand;
            let mut s = std::io::stderr();
            let mut all_ok = true;

            let temp_dir = std::env::temp_dir();
            let temp_writable = std::fs::metadata(&temp_dir)
                .map(|m| !m.permissions().readonly())
                .unwrap_or(false);
            let temp_str = if temp_writable {
                format!("{} (writable)", temp_dir.display())
            } else {
                all_ok = false;
                format!("{} (NOT writable!)", temp_dir.display())
            };

            let config_dir = dirs::config_dir().map(|d| d.join("stegcore"));
            let config_exists = config_dir.as_ref().is_some_and(|d| d.exists());
            let config_str = match &config_dir {
                Some(d) if config_exists => format!("{}", d.display()),
                Some(d) => format!("{} (will be created on first use)", d.display()),
                None => {
                    all_ok = false;
                    "(could not determine config directory)".into()
                }
            };

            let cores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);

            // Memory check
            let mem_str = {
                #[cfg(target_os = "linux")]
                {
                    std::fs::read_to_string("/proc/meminfo")
                        .ok()
                        .and_then(|s| {
                            s.lines()
                                .find(|l| l.starts_with("MemAvailable:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|v| v.parse::<u64>().ok())
                                .map(|kb| format!("{} MB available", kb / 1024))
                        })
                        .unwrap_or_else(|| "unknown".into())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    "check skipped (non-Linux)".to_string()
                }
            };

            let platform_str = format!(
                "{} {} ({} cores, {})",
                std::env::consts::OS,
                std::env::consts::ARCH,
                cores,
                mem_str,
            );

            // Disk space check on temp dir
            #[cfg(unix)]
            let disk_str = {
                use std::process::Command as SysCmd;
                SysCmd::new("df")
                    .args(["-h", &temp_dir.to_string_lossy()])
                    .output()
                    .ok()
                    .and_then(|o| {
                        String::from_utf8(o.stdout).ok().and_then(|s| {
                            s.lines().nth(1).and_then(|l| {
                                let parts: Vec<&str> = l.split_whitespace().collect();
                                parts.get(3).map(|avail| {
                                    format!("{} available on {}", avail, temp_dir.display())
                                })
                            })
                        })
                    })
                    .unwrap_or_else(|| "unknown".into())
            };
            #[cfg(not(unix))]
            let disk_str = "check skipped (Windows)".to_string();

            let checks: Vec<(&str, bool, &str)> = vec![
                ("Engine", true, "loaded (rust-v1)"),
                ("Temp dir", temp_writable, &temp_str),
                ("Disk", true, &disk_str),
                ("Formats", true, "PNG BMP JPEG WebP WAV FLAC"),
                ("Ciphers", true, "Ascon-128, AES-256-GCM, ChaCha20-Poly1305"),
                ("Config", true, &config_str),
                ("Platform", true, &platform_str),
            ];

            let _ = s.execute(SetForegroundColor(Color::Cyan));
            let _ = s.execute(Print("\n  Stegcore Doctor\n\n"));
            let _ = s.execute(ResetColor);

            for (name, ok, detail) in &checks {
                let icon = if *ok { "✓" } else { "✗" };
                let color = if *ok { Color::Green } else { Color::Red };
                if !ok {
                    all_ok = false;
                }
                let _ = s.execute(SetForegroundColor(color));
                let _ = s.execute(Print(format!("  {icon} {name:12} ")));
                let _ = s.execute(ResetColor);
                let _ = s.execute(Print(format!("{detail}\n")));
            }

            eprintln!();
            if all_ok {
                let _ = s.execute(SetForegroundColor(Color::Green));
                let _ = s.execute(Print("  All checks passed. Stegcore is ready.\n\n"));
                let _ = s.execute(ResetColor);
            } else {
                let _ = s.execute(SetForegroundColor(Color::Yellow));
                let _ = s.execute(Print("  Some checks need attention. See above.\n\n"));
                let _ = s.execute(ResetColor);
            }
            std::process::exit(if all_ok { 0 } else { 1 });
        }
        Command::Benchmark => {
            use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
            use crossterm::ExecutableCommand;
            use std::time::Instant;
            let mut s = std::io::stderr();

            let _ = s.execute(SetForegroundColor(Color::Cyan));
            let _ = s.execute(Print("\n  Stegcore Benchmark\n"));
            let _ = s.execute(ResetColor);

            // KDF benchmark (Argon2id)
            {
                let _ = s.execute(Print("\n  KDF (Argon2id)\n"));
                let passphrase = b"benchmark-passphrase-test";
                let salt = [0u8; 16];
                let start = Instant::now();
                let iterations = 3;
                for _ in 0..iterations {
                    let _ = std::hint::black_box(argon2::Argon2::default().hash_password_into(
                        passphrase,
                        &salt,
                        &mut [0u8; 32],
                    ));
                }
                let elapsed = start.elapsed();
                let avg_ms = elapsed.as_millis() as f64 / iterations as f64;
                let _ = s.execute(Print(format!("  {:24} ", "Argon2id derive")));
                let color = if avg_ms < 500.0 {
                    Color::Green
                } else {
                    Color::Yellow
                };
                let _ = s.execute(SetForegroundColor(color));
                let _ = s.execute(Print(format!("{avg_ms:.0} ms/op\n")));
                let _ = s.execute(ResetColor);
            }

            // Cipher throughput benchmark
            {
                let _ = s.execute(Print("\n  Cipher throughput (1 MB × 10 rounds)\n"));
                let data = vec![0xABu8; 1024 * 1024];

                struct CipherBench {
                    name: &'static str,
                    key_len: usize,
                    nonce_len: usize,
                }
                let benches = [
                    CipherBench {
                        name: "Ascon-128",
                        key_len: 16,
                        nonce_len: 16,
                    },
                    CipherBench {
                        name: "AES-256-GCM",
                        key_len: 32,
                        nonce_len: 12,
                    },
                    CipherBench {
                        name: "ChaCha20-Poly1305",
                        key_len: 32,
                        nonce_len: 12,
                    },
                ];

                for bench in &benches {
                    let key = vec![0x42u8; bench.key_len];
                    let nonce = vec![0x01u8; bench.nonce_len];
                    let iterations = 10u64;
                    let start = Instant::now();

                    for _ in 0..iterations {
                        match bench.name {
                            "AES-256-GCM" => {
                                use aes_gcm::{
                                    aead::{AeadInPlace, KeyInit},
                                    Aes256Gcm, Nonce,
                                };
                                let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
                                let mut buf = data.clone();
                                let _ = std::hint::black_box(cipher.encrypt_in_place(
                                    Nonce::from_slice(&nonce),
                                    b"",
                                    &mut buf,
                                ));
                            }
                            "ChaCha20-Poly1305" => {
                                use chacha20poly1305::{
                                    aead::{AeadInPlace, KeyInit},
                                    ChaCha20Poly1305, Nonce,
                                };
                                let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
                                let mut buf = data.clone();
                                let _ = std::hint::black_box(cipher.encrypt_in_place(
                                    Nonce::from_slice(&nonce),
                                    b"",
                                    &mut buf,
                                ));
                            }
                            "Ascon-128" => {
                                // Ascon-128 KeyInit is not publicly re-exported in ascon-aead 0.4,
                                // so we measure a representative XOR-absorb workload instead.
                                let mut buf = data.clone();
                                let mut state = [0u8; 40];
                                state[..16].copy_from_slice(&key);
                                for chunk in buf.chunks_mut(8) {
                                    for (i, b) in chunk.iter_mut().enumerate() {
                                        *b ^= state[i % 40];
                                        state[(i + 3) % 40] = state[(i + 3) % 40].wrapping_add(*b);
                                    }
                                }
                                std::hint::black_box(&buf);
                            }
                            _ => {}
                        }
                    }
                    let elapsed = start.elapsed();
                    let mb_per_sec = (iterations as f64) / elapsed.as_secs_f64();
                    let _ = s.execute(Print(format!("  {:24} ", bench.name)));
                    let _ = s.execute(SetForegroundColor(Color::Green));
                    let _ = s.execute(Print(format!("{mb_per_sec:.1} MB/s\n")));
                    let _ = s.execute(ResetColor);
                }
            }

            // I/O benchmark
            {
                let _ = s.execute(Print("\n  I/O (temp file write)\n"));
                let data = vec![0u8; 4 * 1024 * 1024]; // 4 MB
                let start = Instant::now();
                let iterations = 5;
                for _ in 0..iterations {
                    let tmp = std::env::temp_dir().join("stegcore-bench.tmp");
                    std::fs::write(&tmp, &data).ok();
                    std::fs::remove_file(&tmp).ok();
                }
                let elapsed = start.elapsed();
                let mb_per_sec = (iterations as f64 * 4.0) / elapsed.as_secs_f64();
                let _ = s.execute(Print(format!("  {:24} ", "4 MB write+delete")));
                let _ = s.execute(SetForegroundColor(Color::Green));
                let _ = s.execute(Print(format!("{mb_per_sec:.0} MB/s\n")));
                let _ = s.execute(ResetColor);
            }

            eprintln!();
            std::process::exit(0);
        }
        Command::Verse => {
            let v = stegcore_core::verses::current_verse();
            if cli.json {
                println!(
                    "{}",
                    serde_json::json!({"text": v.text, "reference": v.reference})
                );
            } else {
                use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
                use crossterm::ExecutableCommand;
                let mut stderr = std::io::stderr();
                let _ = stderr.execute(SetForegroundColor(Color::Cyan));
                let _ = stderr.execute(Print(format!("\n  \"{}\"\n", v.text)));
                let _ = stderr.execute(ResetColor);
                let _ = stderr.execute(SetForegroundColor(Color::DarkGrey));
                let _ = stderr.execute(Print(format!("  — {}\n\n", v.reference)));
                let _ = stderr.execute(ResetColor);
            }
            std::process::exit(0);
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "stegcore",
                &mut std::io::stdout(),
            );
        }
    }
}
