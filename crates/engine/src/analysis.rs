// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Session 5 — steganalysis suite.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use statrs::distribution::{ChiSquared, ContinuousCDF};

use crate::errors::StegError;
use crate::utils::detect_format;

// ── Report types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    LikelyStego,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistBin {
    pub label: String,
    pub expected: f64,
    pub observed: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub score: f64,
    pub confidence: Confidence,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<Vec<DistBin>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntropy {
    pub cols: usize,
    pub rows: usize,
    pub values: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub file: PathBuf,
    pub format: String,
    pub tests: Vec<TestResult>,
    pub verdict: Verdict,
    pub overall_score: f64,
    pub tool_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_entropy: Option<BlockEntropy>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Analyse a single file. Returns a JSON-serialised `AnalysisReport`.
pub fn analyse(path: &Path) -> Result<String, StegError> {
    let report = run_analysis(path)?;
    Ok(serde_json::to_string(&report)?)
}

/// Fast preliminary analysis using 10% sampling. Parallel tests.
pub fn analyse_fast(path: &Path) -> Result<String, StegError> {
    let report = run_analysis_sampled(path, 0.1)?;
    Ok(serde_json::to_string(&report)?)
}

/// Analyse multiple files. Each entry is either a JSON report or an error string.
pub fn analyse_batch(paths: &[&Path]) -> Vec<Result<String, StegError>> {
    paths.iter().map(|p| analyse(p)).collect()
}

/// Generate a self-contained HTML report from pre-serialised JSON reports.
pub fn generate_html_report(json_reports: &[&str]) -> String {
    let reports: Vec<AnalysisReport> = json_reports
        .iter()
        .filter_map(|s| serde_json::from_str(s).ok())
        .collect();
    render_html(&reports)
}

// ── Sampling ─────────────────────────────────────────────────────────────────

fn sample_pixels(pixels: &[u8], ratio: f64) -> Vec<u8> {
    if ratio >= 1.0 || pixels.len() < 48 {
        return pixels.to_vec();
    }
    use rand::seq::SliceRandom;
    let pixel_count = pixels.len() / 3;
    let n = ((pixel_count as f64 * ratio) as usize).max(16);
    let mut indices: Vec<usize> = (0..pixel_count).collect();
    indices.shuffle(&mut rand::thread_rng());
    indices.truncate(n);
    indices.sort_unstable(); // preserve spatial order for SPA
    indices
        .iter()
        .flat_map(|&i| &pixels[i * 3..(i + 1) * 3])
        .copied()
        .collect()
}

fn sample_rows(pixels: &[u8], width: usize, ratio: f64) -> Vec<u8> {
    if ratio >= 1.0 || width == 0 {
        return pixels.to_vec();
    }
    let rows = pixels.len() / width;
    let sample_rows = ((rows as f64 * ratio) as usize).max(4);
    let step = (rows / sample_rows).max(1);
    (0..rows)
        .step_by(step)
        .flat_map(|r| {
            let start = r * width;
            let end = (start + width).min(pixels.len());
            &pixels[start..end]
        })
        .copied()
        .collect()
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

fn run_analysis_sampled(path: &Path, ratio: f64) -> Result<AnalysisReport, StegError> {
    if !path.exists() {
        return Err(StegError::FileNotFound(path.display().to_string()));
    }
    let fmt = detect_format(path)?;
    match fmt.as_str() {
        "wav" => analyse_wav_sampled(path, ratio),
        "flac" => analyse_flac(path), // FLAC already caps at 4M samples
        _ => analyse_image_sampled(path, &fmt, ratio),
    }
}

fn run_analysis(path: &Path) -> Result<AnalysisReport, StegError> {
    if !path.exists() {
        return Err(StegError::FileNotFound(path.display().to_string()));
    }
    let fmt = detect_format(path)?;
    match fmt.as_str() {
        "wav" => analyse_wav(path),
        "flac" => analyse_flac(path),
        _ => analyse_image(path, &fmt),
    }
}

// ── Image analysis ────────────────────────────────────────────────────────────

fn analyse_image_sampled(path: &Path, fmt: &str, ratio: f64) -> Result<AnalysisReport, StegError> {
    let img = image::open(path).map_err(StegError::Image)?;
    let rgb = img.to_rgb8();
    let (w, _h) = rgb.dimensions();

    let all_full: Vec<u8> = rgb
        .pixels()
        .flat_map(|p| [p.0[0], p.0[1], p.0[2]])
        .collect();

    let sampled = sample_pixels(&all_full, ratio);
    let row_sampled = sample_rows(&all_full, w as usize * 3, ratio);

    let r: Vec<u8> = sampled.chunks(3).map(|c| c[0]).collect();
    let g: Vec<u8> = sampled.chunks(3).map(|c| c[1]).collect();
    let b: Vec<u8> = sampled.chunks(3).map(|c| c[2]).collect();

    let ((chi, spa), (rs, ent)) = rayon::join(
        || rayon::join(|| chi_squared_test(&r, &g, &b), || spa_test(&sampled, w)),
        || rayon::join(|| rs_test(&row_sampled, w), || entropy_test(&sampled)),
    );

    // No fingerprint or block entropy for fast mode
    let tests = vec![chi, spa, rs, ent];
    let (verdict, overall_score) = ensemble(&tests, None);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: fmt.to_string(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: None,
        block_entropy: None,
    })
}

fn analyse_image(path: &Path, fmt: &str) -> Result<AnalysisReport, StegError> {
    let img = image::open(path).map_err(StegError::Image)?;
    let rgb = img.to_rgb8();
    let (w, h) = rgb.dimensions();

    let r: Vec<u8> = rgb.pixels().map(|p| p.0[0]).collect();
    let g: Vec<u8> = rgb.pixels().map(|p| p.0[1]).collect();
    let b: Vec<u8> = rgb.pixels().map(|p| p.0[2]).collect();
    let all: Vec<u8> = rgb
        .pixels()
        .flat_map(|p| [p.0[0], p.0[1], p.0[2]])
        .collect();

    // Run all four tests in parallel — they are completely independent
    let ((chi, spa), (rs, ent)) = rayon::join(
        || rayon::join(|| chi_squared_test(&r, &g, &b), || spa_test(&all, w)),
        || rayon::join(|| rs_test(&all, w), || entropy_test(&all)),
    );

    let fingerprint = fingerprint_image(path, fmt);

    let block_entropy = compute_block_entropy(&all, w, h);

    let tests = vec![chi, spa, rs, ent];
    let (verdict, overall_score) = ensemble(&tests, fingerprint.as_deref());

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: fmt.to_string(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: fingerprint,
        block_entropy: Some(block_entropy),
    })
}

fn compute_block_entropy(pixels: &[u8], width: u32, height: u32) -> BlockEntropy {
    let cols = 8usize;
    let rows = 6usize;
    let bw = (width as usize / cols).max(1);
    let bh = (height as usize / rows).max(1);
    let stride = width as usize * 3; // RGB

    let values: Vec<f64> = (0..rows)
        .flat_map(|r| {
            (0..cols).map(move |c| {
                let mut ones = 0u64;
                let mut total = 0u64;
                for y in (r * bh)..((r + 1) * bh).min(height as usize) {
                    for x in (c * bw)..((c + 1) * bw).min(width as usize) {
                        let idx = y * stride + x * 3;
                        if idx < pixels.len() {
                            ones += (pixels[idx] & 1) as u64;
                            total += 1;
                        }
                    }
                }
                if total == 0 {
                    return 0.5;
                }
                // Entropy proxy: how close to 50% is the LSB ratio?
                // Perfect 50% = high entropy (score 1.0), natural bias = low entropy
                let ratio = ones as f64 / total as f64;
                1.0 - (ratio - 0.5).abs() * 4.0 // 0.5 → 1.0, 0.25/0.75 → 0.0
            })
        })
        .map(|v| v.clamp(0.0, 1.0))
        .collect();

    BlockEntropy { cols, rows, values }
}

// ── WAV analysis ──────────────────────────────────────────────────────────────

fn analyse_wav_sampled(path: &Path, ratio: f64) -> Result<AnalysisReport, StegError> {
    let reader = hound::WavReader::open(path)
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?;
    let samples_i32: Vec<i32> = reader
        .into_samples::<i16>()
        .collect::<Result<Vec<i16>, _>>()
        .map_err(|e| {
            StegError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            ))
        })?
        .into_iter()
        .map(|s| s as i32)
        .collect();

    // Sample a subset
    let n = ((samples_i32.len() as f64 * ratio) as usize).max(1024);
    let step = (samples_i32.len() / n).max(1);
    let sampled_i32: Vec<i32> = samples_i32.iter().step_by(step).copied().collect();
    let sampled_u8: Vec<u8> = sampled_i32.iter().map(|&s| (s & 0xFF) as u8).collect();

    let (chi, (spa, ent)) = rayon::join(
        || chi_squared_test(&sampled_u8, &sampled_u8, &sampled_u8),
        || {
            rayon::join(
                || audio_spa_test(&sampled_i32),
                || entropy_test(&sampled_u8),
            )
        },
    );

    let tests = vec![chi, spa, ent];
    let (verdict, overall_score) = ensemble(&tests, None);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: "wav".into(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: None,
        block_entropy: None,
    })
}

fn analyse_wav(path: &Path) -> Result<AnalysisReport, StegError> {
    let reader = hound::WavReader::open(path)
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?;
    let spec = reader.spec();
    let samples_i32: Vec<i32> = reader
        .into_samples::<i16>()
        .collect::<Result<Vec<i16>, _>>()
        .map_err(|e| {
            StegError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e.to_string(),
            ))
        })?
        .into_iter()
        .map(|s| s as i32)
        .collect();

    // Extract low byte of each sample for LSB analysis. The & 0xFF mask
    // produces the unsigned low byte regardless of sign — this is intentional
    // as we only care about bit patterns, not audio magnitude.
    let samples_u8: Vec<u8> = samples_i32.iter().map(|&s| (s & 0xFF) as u8).collect();

    let (chi, (spa, ent)) = rayon::join(
        || chi_squared_test(&samples_u8, &samples_u8, &samples_u8),
        || {
            rayon::join(
                || audio_spa_test(&samples_i32),
                || entropy_test(&samples_u8),
            )
        },
    );

    let fingerprint = fingerprint_audio(path, spec.channels);

    let tests = vec![chi, spa, ent];
    let (verdict, overall_score) = ensemble(&tests, fingerprint.as_deref());

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: "wav".into(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: fingerprint,
        block_entropy: None,
    })
}

// ── FLAC analysis ─────────────────────────────────────────────────────────────

fn analyse_flac(path: &Path) -> Result<AnalysisReport, StegError> {
    use symphonia::core::audio::SampleBuffer;
    use symphonia::core::codecs::DecoderOptions;
    use symphonia::core::formats::FormatOptions;
    use symphonia::core::io::MediaSourceStream;
    use symphonia::core::meta::MetadataOptions;
    use symphonia::core::probe::Hint;

    let file = std::fs::File::open(path)
        .map_err(|_| StegError::FileNotFound(path.display().to_string()))?;
    let mss = MediaSourceStream::new(Box::new(file), Default::default());
    let mut hint = Hint::new();
    hint.with_extension("flac");

    let probed = symphonia::default::get_probe()
        .format(
            &hint,
            mss,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        )
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?;

    let mut format = probed.format;
    let track = format
        .tracks()
        .iter()
        .find(|t| t.codec_params.codec != symphonia::core::codecs::CODEC_TYPE_NULL)
        .ok_or_else(|| StegError::UnsupportedFormat("flac: no decodable track".into()))?;

    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| StegError::Io(std::io::Error::other(e.to_string())))?;

    let track_id = track.id;
    let mut samples_i32: Vec<i32> = Vec::new();

    while let Ok(packet) = format.next_packet() {
        if packet.track_id() != track_id {
            continue;
        }
        if let Ok(decoded) = decoder.decode(&packet) {
            let spec = *decoded.spec();
            let mut buf = SampleBuffer::<i32>::new(decoded.capacity() as u64, spec);
            buf.copy_interleaved_ref(decoded);
            samples_i32.extend_from_slice(buf.samples());
            if samples_i32.len() > 4_000_000 {
                break;
            }
        }
    }

    // Extract low byte of each sample for LSB analysis. The & 0xFF mask
    // produces the unsigned low byte regardless of sign — this is intentional
    // as we only care about bit patterns, not audio magnitude.
    let samples_u8: Vec<u8> = samples_i32.iter().map(|&s| (s & 0xFF) as u8).collect();
    let (chi, (spa, ent)) = rayon::join(
        || chi_squared_test(&samples_u8, &samples_u8, &samples_u8),
        || {
            rayon::join(
                || audio_spa_test(&samples_i32),
                || entropy_test(&samples_u8),
            )
        },
    );

    let tests = vec![chi, spa, ent];
    let (verdict, overall_score) = ensemble(&tests, None);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: "flac".into(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: None,
        block_entropy: None,
    })
}

// ── Detector: Chi-Squared PoV test ────────────────────────────────────────────

fn chi_squared_test(r: &[u8], g: &[u8], b: &[u8]) -> TestResult {
    let sr = chi_channel(r);
    let sg = chi_channel(g);
    let sb = chi_channel(b);
    let score = (sr + sg + sb) / 3.0;

    // Build distribution: aggregate pair-of-values counts across channels
    let distribution = chi_distribution(r);

    let (confidence, detail) = chi_confidence(score);
    TestResult {
        name: "Chi-Squared".into(),
        score,
        confidence,
        detail,
        distribution: Some(distribution),
    }
}

fn chi_distribution(values: &[u8]) -> Vec<DistBin> {
    let mut counts = [0u32; 256];
    for &v in values {
        counts[v as usize] += 1;
    }
    // Group into 16 bins of 16 values each
    (0..16)
        .map(|bin| {
            let start = bin * 16;
            let end = start + 16;
            let observed: f64 = counts[start..end].iter().map(|&c| c as f64).sum();
            // For each pair (2i, 2i+1), the expected count per value is
            // (count[2i] + count[2i+1]) / 2. Sum across all 8 pairs in this bin.
            let expected: f64 = (0..8)
                .map(|j| {
                    let idx = start + j * 2;
                    (counts[idx] as u64 + counts[idx + 1] as u64) as f64 / 2.0
                })
                .sum::<f64>()
                * 2.0; // multiply by 2 because each pair contributes 2 values
            DistBin {
                label: format!("{start}–{}", end - 1),
                expected,
                observed,
            }
        })
        .collect()
}

fn chi_channel(values: &[u8]) -> f64 {
    if values.len() < 64 {
        return 0.0;
    }

    // Block-based chi-squared: divide channel into blocks of ~4096 pixels.
    // For each block, compute chi2 and p-value. Aggregate the proportion
    // of blocks that show suspiciously uniform PoV (p > 0.05).
    // This avoids the p-value saturation problem on large images where
    // the global chi2 is always enormous.
    let block_size = 4096usize;
    let num_blocks = values.len().div_ceil(block_size);
    if num_blocks == 0 {
        return 0.0;
    }

    let mut suspicious_blocks = 0u64;
    let mut total_blocks = 0u64;

    for b in 0..num_blocks {
        let start = b * block_size;
        let end = (start + block_size).min(values.len());
        let block = &values[start..end];
        if block.len() < 32 {
            continue;
        }

        let mut counts = [0u32; 256];
        for &v in block {
            counts[v as usize] += 1;
        }

        let mut chi2 = 0.0f64;
        let mut dof = 0u32;
        for i in (0..256usize).step_by(2) {
            let total = counts[i] as u64 + counts[i + 1] as u64;
            if total == 0 {
                continue;
            }
            let expected = total as f64 / 2.0;
            let d0 = counts[i] as f64 - expected;
            let d1 = counts[i + 1] as f64 - expected;
            chi2 += (d0 * d0 + d1 * d1) / expected;
            dof += 1;
        }
        if dof < 2 {
            continue;
        }

        let dist = match ChiSquared::new(dof as f64) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let p_value = 1.0 - dist.cdf(chi2);

        total_blocks += 1;
        // p > 0.05 means this block's PoV are suspiciously uniform
        if p_value > 0.05 {
            suspicious_blocks += 1;
        }
    }

    if total_blocks == 0 {
        return 0.0;
    }

    // Score = proportion of suspicious blocks
    // Clean image: ~5% of blocks will randomly pass (false positive rate)
    // Embedded image: a much larger proportion will pass
    let raw = suspicious_blocks as f64 / total_blocks as f64;
    // Subtract the expected false positive rate and normalise
    // Expected ~5% of blocks pass by chance at p=0.05 threshold
    ((raw - 0.05) / 0.95).clamp(0.0, 1.0)
}

fn chi_confidence(score: f64) -> (Confidence, String) {
    if score > CHI_THRESHOLD {
        (
            Confidence::High,
            format!("LSB pair distribution is highly uniform (score {score:.2})"),
        )
    } else if score > CHI_THRESHOLD / 2.0 {
        (
            Confidence::Medium,
            format!("LSB pair distribution shows mild anomaly (score {score:.2})"),
        )
    } else {
        (
            Confidence::Low,
            format!("LSB pair distribution appears natural (score {score:.2})"),
        )
    }
}

// ── Detector: Sample Pair Analysis ───────────────────────────────────────────

fn spa_test(pixels: &[u8], width: u32) -> TestResult {
    let score = spa_score(pixels, width as usize);
    let distribution = spa_distribution(pixels);
    let (confidence, detail) = spa_confidence(score);
    TestResult {
        name: "Sample Pair Analysis".into(),
        score,
        confidence,
        detail,
        distribution: Some(distribution),
    }
}

fn spa_distribution(pixels: &[u8]) -> Vec<DistBin> {
    // Bin pair balance across 16 value ranges
    let bins = 16usize;
    let mut expected = vec![0u64; bins];
    let mut observed = vec![0u64; bins];

    for window in pixels.windows(2) {
        let x = window[0] as usize;
        let bin = x / (256 / bins);
        let bin = bin.min(bins - 1);
        expected[bin] += 1; // total pairs in this range
        if (window[0] as i32 - window[1] as i32).abs() <= 1 {
            observed[bin] += 1; // correlated pairs
        }
    }

    (0..bins)
        .map(|i| {
            let range_start = i * (256 / bins);
            DistBin {
                label: format!("{range_start}"),
                expected: expected[i] as f64,
                observed: observed[i] as f64,
            }
        })
        .collect()
}

fn spa_score(pixels: &[u8], width: usize) -> f64 {
    // Dumitrescu-Wu-Wang Sample Pair Analysis.
    // For horizontally adjacent pixel pairs (u, v) in the same channel,
    // classify into trace multisets based on floor(u/2) and floor(v/2).
    // Solve a quadratic to estimate the embedding rate p.
    let stride = width * 3;
    if pixels.len() < stride * 2 || width < 2 {
        return 0.0;
    }
    let rows = pixels.len() / stride;
    let mut scores = [0.0f64; 3];

    for (ch, score) in scores.iter_mut().enumerate() {
        let mut x0: f64 = 0.0; // same LSB parity, different bin
        let mut y0: f64 = 0.0; // different LSB parity, different bin
        let mut d0: f64 = 0.0; // same bin, same LSB
        let mut d1: f64 = 0.0; // same bin, different LSB

        for row in 0..rows {
            for px in 0..(width - 1) {
                let idx_a = row * stride + px * 3 + ch;
                let idx_b = row * stride + (px + 1) * 3 + ch;
                if idx_b >= pixels.len() {
                    break;
                }
                let u = pixels[idx_a] as i32;
                let v = pixels[idx_b] as i32;
                let bu = u >> 1;
                let bv = v >> 1;
                let same_lsb = (u & 1) == (v & 1);

                if bu == bv {
                    if same_lsb {
                        d0 += 1.0;
                    } else {
                        d1 += 1.0;
                    }
                } else if same_lsb {
                    x0 += 1.0;
                } else {
                    y0 += 1.0;
                }
            }
        }

        // DWW quadratic: 2(d1-d0)p^2 + (d1-d0+y0-x0)p + (y0-x0) = 0
        let a = 2.0 * (d1 - d0);
        let b = (d1 - d0) + (y0 - x0);
        let c = y0 - x0;

        let p_est = if a.abs() < 1e-10 {
            if b.abs() < 1e-10 {
                0.0
            } else {
                (-c / b).clamp(0.0, 1.0)
            }
        } else {
            let disc = b * b - 4.0 * a * c;
            if disc < 0.0 {
                0.0
            } else {
                let sqrt_d = disc.sqrt();
                let p1 = (-b + sqrt_d) / (2.0 * a);
                let p2 = (-b - sqrt_d) / (2.0 * a);
                // Pick the root in [0,1] closest to 0
                let valid = |p: f64| (0.0..=1.0).contains(&p);
                match (valid(p1), valid(p2)) {
                    (true, true) => p1.min(p2),
                    (true, false) => p1,
                    (false, true) => p2,
                    _ => {
                        if p1.abs() < p2.abs() {
                            p1.clamp(0.0, 1.0)
                        } else {
                            p2.clamp(0.0, 1.0)
                        }
                    }
                }
            }
        };

        *score = p_est.clamp(0.0, 1.0);
    }

    let avg = (scores[0] + scores[1] + scores[2]) / 3.0;
    avg.clamp(0.0, 1.0)
}

fn spa_confidence(score: f64) -> (Confidence, String) {
    if score > SPA_THRESHOLD {
        (
            Confidence::High,
            format!("Adjacent pair symmetry suggests LSB modification (score {score:.2})"),
        )
    } else if score > SPA_THRESHOLD / 2.0 {
        (
            Confidence::Medium,
            format!("Moderate pair symmetry anomaly (score {score:.2})"),
        )
    } else {
        (
            Confidence::Low,
            format!("Pair symmetry within natural range (score {score:.2})"),
        )
    }
}

// ── Detector: RS Analysis ─────────────────────────────────────────────────────

fn rs_test(pixels: &[u8], width: u32) -> TestResult {
    let (score, dist) = rs_score_with_dist(pixels, width as usize);
    let (confidence, detail) = rs_confidence(score);
    TestResult {
        name: "RS Analysis".into(),
        score,
        confidence,
        detail,
        distribution: Some(dist),
    }
}

fn rs_score_with_dist(pixels: &[u8], width: usize) -> (f64, Vec<DistBin>) {
    // RS analysis must operate per-channel on spatially adjacent pixels.
    // The input `pixels` is interleaved RGB with stride = width * 3.
    let stride = width * 3;
    if width < 4 || pixels.len() < stride * 2 {
        return (0.0, vec![]);
    }
    let rows = pixels.len() / stride;

    const GROUP: usize = 4;
    let mut r_pos = 0u64;
    let mut s_pos = 0u64;
    let mut r_neg = 0u64;
    let mut s_neg = 0u64;
    let mut total = 0u64;

    // Process each channel independently, using spatially adjacent pixels
    for ch in 0..3usize {
        for row in 0..rows {
            // Extract this channel's values for this row
            let mut col = 0;
            while col + GROUP <= width {
                let mut group = [0u8; 4];
                for (g, slot) in group.iter_mut().enumerate().take(GROUP) {
                    let idx = row * stride + (col + g) * 3 + ch;
                    if idx < pixels.len() {
                        *slot = pixels[idx];
                    }
                }

                total += 1;
                let orig = smoothness(&group);

                // Positive mask F1: flip LSB of odd-indexed elements
                let mut fp = group;
                fp[1] ^= 1;
                fp[3] ^= 1;
                let s_fp = smoothness(&fp);
                if s_fp > orig {
                    r_pos += 1;
                } else if s_fp < orig {
                    s_pos += 1;
                }

                // Negative mask F_{-1}: even→down, odd→up on odd-indexed elements
                let mut fn_ = group;
                for i in [1, 3] {
                    fn_[i] = if fn_[i] % 2 == 0 {
                        fn_[i].saturating_sub(1)
                    } else {
                        fn_[i].saturating_add(1)
                    };
                }
                let s_fn = smoothness(&fn_);
                if s_fn > orig {
                    r_neg += 1;
                } else if s_fn < orig {
                    s_neg += 1;
                }

                col += GROUP;
            }
        }
    }

    if total == 0 {
        return (0.0, vec![]);
    }

    let rm = r_neg as f64 / total as f64;
    let rp = r_pos as f64 / total as f64;
    let sm = s_neg as f64 / total as f64;
    let sp = s_pos as f64 / total as f64;

    // Clean image: R+ ≈ R- and S+ ≈ S- (symmetric)
    // Embedded: R+/S+ diverge from R-/S-
    let asym = ((rp - rm).abs() + (sp - sm).abs()) / 2.0;
    let score = (asym * 5.0).clamp(0.0, 1.0);

    let dist = vec![
        DistBin {
            label: "R+ (positive)".into(),
            expected: r_neg as f64,
            observed: r_pos as f64,
        },
        DistBin {
            label: "S+ (positive)".into(),
            expected: s_neg as f64,
            observed: s_pos as f64,
        },
        DistBin {
            label: "R− (negative)".into(),
            expected: r_pos as f64,
            observed: r_neg as f64,
        },
        DistBin {
            label: "S− (negative)".into(),
            expected: s_pos as f64,
            observed: s_neg as f64,
        },
    ];

    (score, dist)
}

fn smoothness(chunk: &[u8]) -> u32 {
    chunk
        .windows(2)
        .map(|w| (w[0] as i32 - w[1] as i32).unsigned_abs())
        .sum()
}

fn rs_confidence(score: f64) -> (Confidence, String) {
    if score > RS_THRESHOLD {
        (
            Confidence::High,
            format!("R/S group asymmetry indicates LSB manipulation (score {score:.2})"),
        )
    } else if score > RS_THRESHOLD / 2.0 {
        (
            Confidence::Medium,
            format!("Mild R/S asymmetry detected (score {score:.2})"),
        )
    } else {
        (
            Confidence::Low,
            format!("R/S groups are symmetric (score {score:.2})"),
        )
    }
}

// ── Detector: LSB Entropy ─────────────────────────────────────────────────────

fn entropy_test(values: &[u8]) -> TestResult {
    let score = lsb_entropy_score(values);
    let distribution = entropy_distribution(values);
    let (confidence, detail) = entropy_confidence(score);
    TestResult {
        name: "LSB Entropy".into(),
        score,
        confidence,
        detail,
        distribution: Some(distribution),
    }
}

fn entropy_distribution(values: &[u8]) -> Vec<DistBin> {
    // LSB bit balance across 16 blocks of the data
    let bins = 16usize;
    let block_size = (values.len() / bins).max(1);

    (0..bins)
        .map(|i| {
            let start = i * block_size;
            let end = (start + block_size).min(values.len());
            let block = &values[start..end];
            let ones: usize = block.iter().map(|&v| (v & 1) as usize).sum();
            let total = block.len() as f64;
            let ratio = if total > 0.0 {
                ones as f64 / total
            } else {
                0.5
            };
            DistBin {
                label: format!("Blk {i}"),
                expected: 0.5, // natural: ~50% ones
                observed: ratio,
            }
        })
        .collect()
}

fn lsb_entropy_score(values: &[u8]) -> f64 {
    // Per-channel LSB autocorrelation at lag 1 (horizontally adjacent pixels).
    // The input is interleaved RGB, so channel values are at stride 3.
    // High autocorrelation = natural (correlated LSBs) = clean
    // Low autocorrelation = random (cipher output) = suspicious
    if values.len() < 48 {
        return 0.0;
    }

    let mut scores = [0.0f64; 3];
    for (ch, score) in scores.iter_mut().enumerate() {
        // Extract this channel's LSBs
        let lsbs: Vec<f64> = values
            .iter()
            .skip(ch)
            .step_by(3)
            .map(|&v| (v & 1) as f64)
            .collect();
        let n = lsbs.len();
        if n < 16 {
            continue;
        }
        let mean = lsbs.iter().sum::<f64>() / n as f64;

        let mut num = 0.0f64;
        let mut denom = 0.0f64;
        for i in 0..n - 1 {
            num += (lsbs[i] - mean) * (lsbs[i + 1] - mean);
        }
        for &x in &lsbs {
            denom += (x - mean).powi(2);
        }

        if denom < 1e-10 {
            // All LSBs identical — maximally structured — clean
            *score = 0.0;
            continue;
        }
        let autocorr = num / denom;
        *score = (1.0 - autocorr.abs().clamp(0.0, 1.0)).clamp(0.0, 1.0);
    }

    (scores[0] + scores[1] + scores[2]) / 3.0
}

fn entropy_confidence(score: f64) -> (Confidence, String) {
    if score > ENTROPY_THRESHOLD {
        (
            Confidence::High,
            format!("LSB plane autocorrelation is very low (score {score:.2})"),
        )
    } else if score > ENTROPY_THRESHOLD / 2.0 {
        (
            Confidence::Medium,
            format!("LSB plane correlation mildly reduced (score {score:.2})"),
        )
    } else {
        (
            Confidence::Low,
            format!("LSB plane correlation is natural (score {score:.2})"),
        )
    }
}

// ── Detector: Audio SPA ───────────────────────────────────────────────────────

fn audio_spa_test(samples: &[i32]) -> TestResult {
    let samples_u8: Vec<u8> = samples.iter().map(|&s| (s & 0xFF) as u8).collect();
    let score = spa_score(&samples_u8, samples_u8.len());
    let distribution = spa_distribution(&samples_u8);
    let (confidence, detail) = audio_spa_confidence(score);
    TestResult {
        name: "Audio Sample Pair Analysis".into(),
        score,
        confidence,
        detail,
        distribution: Some(distribution),
    }
}

fn audio_spa_confidence(score: f64) -> (Confidence, String) {
    if score > 0.65 {
        (
            Confidence::High,
            format!("Audio sample pair symmetry indicates embedding (score {score:.2})"),
        )
    } else if score > 0.30 {
        (
            Confidence::Medium,
            format!("Mild audio pair anomaly (score {score:.2})"),
        )
    } else {
        (
            Confidence::Low,
            format!("Audio sample pairs within normal range (score {score:.2})"),
        )
    }
}

// ── Detector: Tool Fingerprinting ─────────────────────────────────────────────

fn fingerprint_image(path: &Path, fmt: &str) -> Option<String> {
    if fmt == "png" {
        if let Some(sig) = check_openstego_png(path) {
            return Some(sig);
        }
    }

    if fmt == "bmp" || fmt == "jpg" || fmt == "jpeg" {
        if let Some(sig) = check_steghide(path) {
            return Some(sig);
        }
    }

    None
}

fn fingerprint_audio(_path: &Path, _channels: u16) -> Option<String> {
    None
}

fn check_openstego_png(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    // OpenStego embeds a "openstego" tEXt chunk in PNG
    if data.windows(b"openstego".len()).any(|w| w == b"openstego") {
        return Some("OpenStego (high confidence)".into());
    }
    None
}

fn check_steghide(path: &Path) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    // Steghide: check for magic bytes 0x73 0x68 0x8D at file start
    if data.len() > 3 && data[0] == 0x73 && data[1] == 0x68 && data[2] == 0x8D {
        return Some("Steghide (high confidence)".into());
    }
    None
}

// ── Per-detector calibrated thresholds ───────────────────────────────────────

// Calibrated 2026-04-19 on Cassavia 2022 LSBSteg (44k samples); target FPR = 0%.
// Sacred per Q-6 D: below these values, a detector returns clean.
const CHI_THRESHOLD: f64 = 0.4507;
const SPA_THRESHOLD: f64 = 0.1763;
const RS_THRESHOLD: f64 = 1.0;
const ENTROPY_THRESHOLD: f64 = 0.9916;

// ── Ensemble verdict ──────────────────────────────────────────────────────────

// Weights tuned for reliable detection across all tool types.
const W_CHI: f64 = 0.35;
const W_SPA: f64 = 0.30;
const W_RS: f64 = 0.20;
const W_ENT: f64 = 0.15;

fn ensemble(tests: &[TestResult], fingerprint: Option<&str>) -> (Verdict, f64) {
    if tests.is_empty() {
        return (Verdict::Clean, 0.0);
    }

    // Fingerprint-led verdict: a high-confidence tool signature is decisive.
    if fingerprint.is_some() {
        return (Verdict::LikelyStego, 0.95);
    }

    let weighted_score = if tests.len() >= 4 {
        tests[0].score * W_CHI
            + tests[1].score * W_SPA
            + tests[2].score * W_RS
            + tests[3].score * W_ENT
    } else if tests.len() == 3 {
        (tests[0].score + tests[1].score + tests[2].score) / 3.0
    } else {
        tests.iter().map(|t| t.score).sum::<f64>() / tests.len() as f64
    };

    // OR-logic: any classical detector above its calibrated 0% FPR threshold
    // raises the verdict to at least Suspicious.
    let any_fires = tests.len() >= 4
        && (tests[0].score > CHI_THRESHOLD
            || tests[1].score > SPA_THRESHOLD
            || tests[2].score > RS_THRESHOLD
            || tests[3].score > ENTROPY_THRESHOLD);

    let verdict = if weighted_score >= 0.55 {
        Verdict::LikelyStego
    } else if any_fires || weighted_score >= 0.25 {
        Verdict::Suspicious
    } else {
        Verdict::Clean
    };

    (verdict, weighted_score)
}

// ── HTML report renderer ──────────────────────────────────────────────────────

fn render_html(reports: &[AnalysisReport]) -> String {
    let rows = reports
        .iter()
        .map(report_row)
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stegcore Analysis Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Ubuntu,sans-serif;
  background:#070d14;color:#e8eaf0;margin:0;padding:24px;line-height:1.6;}}
h1{{font-size:1.4rem;font-weight:500;letter-spacing:.15em;color:#4da6ff;margin-bottom:24px;}}
.file-card{{background:#0d1520;border:1px solid #1a2535;border-radius:12px;
  padding:20px;margin-bottom:20px;}}
.file-header{{display:flex;align-items:center;gap:12px;margin-bottom:16px;}}
.filename{{font-weight:600;word-break:break-all;}}
.format{{font-size:.75rem;color:#4a5568;background:#1a2535;
  padding:2px 8px;border-radius:4px;}}
.verdict{{padding:4px 12px;border-radius:6px;font-size:.8rem;font-weight:600;}}
.verdict-clean{{background:#16a34a22;color:#22c55e;border:1px solid #22c55e44;}}
.verdict-suspicious{{background:#d9770622;color:#f59e0b;border:1px solid #f59e0b44;}}
.verdict-likely_stego{{background:#dc262622;color:#ef4444;border:1px solid #ef444444;}}
.overall-score{{margin-left:auto;font-size:1.1rem;font-weight:700;}}
.fingerprint{{font-size:.8rem;color:#4a5568;margin-bottom:12px;}}
.fingerprint span{{color:#4da6ff;}}
table{{width:100%;border-collapse:collapse;font-size:.875rem;}}
th{{text-align:left;padding:6px 8px;color:#4a5568;font-weight:500;
  border-bottom:1px solid #1a2535;}}
td{{padding:6px 8px;border-bottom:1px solid #1a253540;}}
.bar-bg{{background:#1a2535;border-radius:3px;height:8px;width:120px;overflow:hidden;}}
.bar-fill{{height:100%;border-radius:3px;}}
.conf-low{{color:#4a5568;}} .conf-medium{{color:#f59e0b;}} .conf-high{{color:#ef4444;}}
footer{{margin-top:32px;font-size:.75rem;color:#4a5568;text-align:center;}}
</style>
</head>
<body>
<h1>STEGCORE — ANALYSIS REPORT</h1>
{rows}
<footer>Generated by Stegcore &nbsp;·&nbsp; No telemetry &nbsp;·&nbsp; Fully offline</footer>
</body>
</html>"#,
        rows = rows
    )
}

fn report_row(r: &AnalysisReport) -> String {
    let verdict_class = match r.verdict {
        Verdict::Clean => "verdict-clean",
        Verdict::Suspicious => "verdict-suspicious",
        Verdict::LikelyStego => "verdict-likely_stego",
    };
    let verdict_label = match r.verdict {
        Verdict::Clean => "Clean",
        Verdict::Suspicious => "Suspicious",
        Verdict::LikelyStego => "Likely Stego",
    };
    let score_pct = (r.overall_score * 100.0).round() as u32;
    let fp = r
        .tool_fingerprint
        .as_deref()
        .map(|s| {
            format!(
                "<p class=\"fingerprint\">Signature: <span>{}</span></p>",
                html_escape(s)
            )
        })
        .unwrap_or_default();

    let test_rows = r.tests.iter().map(test_row).collect::<Vec<_>>().join("\n");

    let filename = html_escape(
        r.file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown"),
    );

    format!(
        r#"<div class="file-card">
<div class="file-header">
  <span class="filename">{filename}</span>
  <span class="format">{fmt}</span>
  <span class="verdict {verdict_class}">{verdict_label}</span>
  <span class="overall-score" style="color:{score_colour}">{score_pct}%</span>
</div>
{fp}
<table>
<thead><tr><th>Test</th><th>Score</th><th>Confidence</th><th>Detail</th></tr></thead>
<tbody>
{test_rows}
</tbody>
</table>
</div>"#,
        fmt = html_escape(&r.format),
        score_colour = score_colour(r.overall_score),
    )
}

fn test_row(t: &TestResult) -> String {
    let bar_w = (t.score * 120.0).round() as u32;
    let bar_colour = score_colour(t.score);
    let conf_class = match t.confidence {
        Confidence::Low => "conf-low",
        Confidence::Medium => "conf-medium",
        Confidence::High => "conf-high",
    };
    let conf_label = match t.confidence {
        Confidence::Low => "Low",
        Confidence::Medium => "Medium",
        Confidence::High => "High",
    };
    format!(
        r#"<tr>
  <td>{name}</td>
  <td><div class="bar-bg"><div class="bar-fill" style="width:{bar_w}px;background:{bar_colour}"></div></div></td>
  <td class="{conf_class}">{conf_label}</td>
  <td>{detail}</td>
</tr>"#,
        name = t.name,
        detail = html_escape(&t.detail),
    )
}

fn score_colour(score: f64) -> &'static str {
    if score < 0.25 {
        "#22c55e"
    } else if score < 0.55 {
        "#f59e0b"
    } else {
        "#ef4444"
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};

    // ── Image helpers ──────────────────────────────────────────────────────────

    /// All-black PNG: count[0]=huge, count[1..]=0 → chi2 is large → score ≈ 0.
    fn clean_png(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let w = 200u32;
        let h = 200u32;
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
            ImageBuffer::from_fn(w, h, |_, _| Rgb([0u8, 0u8, 0u8]));
        img.save(&path).unwrap();
        path
    }

    /// Embed sequential LSB payload into an existing pixel buffer.
    fn embed_sequential(mut pixels: Vec<u8>, payload: &[u8]) -> Vec<u8> {
        let bits: Vec<u8> = payload
            .iter()
            .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect();
        for (i, bit) in bits.iter().enumerate() {
            if i >= pixels.len() {
                break;
            }
            pixels[i] = (pixels[i] & 0xFE) | bit;
        }
        pixels
    }

    /// All-black PNG with sequential LSB payload at 80% fill: count[0]≈count[1] → chi2≈0 → score high.
    fn sequential_png(name: &str, fill: f64) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let w = 200u32;
        let h = 200u32;
        let pixels: Vec<u8> = vec![0u8; (w * h * 3) as usize];
        let total_bits = (w * h * 3) as usize;
        let n = ((total_bits as f64 * fill) as usize) / 8;
        // Payload alternates 0xAA/0x55 (50% 0-bits and 1-bits): guarantees count[0]≈count[1]
        let payload: Vec<u8> = (0..n)
            .map(|i| if i % 2 == 0 { 0xAA } else { 0x55 })
            .collect();
        let modified = embed_sequential(pixels, &payload);
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_raw(w, h, modified).unwrap();
        img.save(&path).unwrap();
        path
    }

    /// Create a PNG that simulates adaptive (texture-limited) embedding.
    fn adaptive_png(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let w = 300u32;
        let h = 300u32;
        // Noisy, high-variance base image
        let mut pixels: Vec<u8> = (0..w * h * 3)
            .map(|i| ((i * 17 + i / 3 * 7 + i % 13 * 31) % 256) as u8)
            .collect();

        // Only embed in ~10% of pixels (simulates adaptive mode at low fill rate)
        let payload_bits = (w * h * 3 / 8 / 10) as usize * 8;
        let payload: Vec<u8> = (0..payload_bits / 8).map(|i| (i * 97 + 13) as u8).collect();
        let bits: Vec<u8> = payload
            .iter()
            .flat_map(|&b| (0..8u8).rev().map(move |i| (b >> i) & 1))
            .collect();

        // Embed only in stride-7 positions (simulates non-sequential selection)
        let mut bit_idx = 0;
        let mut px_idx = 0usize;
        while bit_idx < bits.len() && px_idx < pixels.len() {
            pixels[px_idx] = (pixels[px_idx] & 0xFE) | bits[bit_idx];
            bit_idx += 1;
            px_idx += 7; // non-sequential spacing
        }

        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_raw(w, h, pixels).unwrap();
        img.save(&path).unwrap();
        path
    }

    /// Create a clean WAV file.
    fn clean_wav(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let spec = hound::WavSpec {
            channels: 1,
            sample_rate: 44100,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };
        let mut writer = hound::WavWriter::create(&path, spec).unwrap();
        for i in 0..44100u32 {
            let t = i as f32 / 44100.0;
            let sample = ((t * 440.0 * 2.0 * std::f32::consts::PI).sin() * 16000.0) as i16;
            writer.write_sample(sample).unwrap();
        }
        writer.finalize().unwrap();
        path
    }

    // ── Unit tests ─────────────────────────────────────────────────────────────

    #[test]
    fn clean_image_scores_low() {
        // All-black image: chi2 large, SPA=0, RS=0, entropy=0 → ensemble should be very low
        let path = clean_png("analysis_clean.png");
        let report: AnalysisReport = serde_json::from_str(&analyse(&path).unwrap()).unwrap();
        assert!(
            report.overall_score < 0.25,
            "clean image should score < 0.25 (verdict: Clean), got {:.3}",
            report.overall_score
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn sequential_embedded_scores_high() {
        let path = sequential_png("analysis_seq.png", 1.0);
        let report: AnalysisReport = serde_json::from_str(&analyse(&path).unwrap()).unwrap();
        assert!(
            report.overall_score > 0.25,
            "sequential-embedded image should verdict at least Suspicious (>0.25), got {:.3}",
            report.overall_score
        );
        assert!(
            !matches!(report.verdict, Verdict::Clean),
            "sequential-embedded image should not verdict Clean"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn ensemble_thresholds_are_correct() {
        let mk = |score: f64| TestResult {
            name: "x".into(),
            score,
            confidence: Confidence::Low,
            detail: String::new(),
            distribution: None,
        };
        let (v_clean, _) = ensemble(&[mk(0.10), mk(0.10), mk(0.10), mk(0.10)], None);
        let (v_susp, _) = ensemble(&[mk(0.40), mk(0.40), mk(0.40), mk(0.40)], None);
        let (v_stego, _) = ensemble(&[mk(0.80), mk(0.80), mk(0.80), mk(0.80)], None);
        assert_eq!(v_clean, Verdict::Clean);
        assert_eq!(v_susp, Verdict::Suspicious);
        assert_eq!(v_stego, Verdict::LikelyStego);

        // Fingerprint-led: any fingerprint overrides detector scores.
        let (v_fp, s_fp) = ensemble(
            &[mk(0.0), mk(0.0), mk(0.0), mk(0.0)],
            Some("LSBSteg (medium confidence)"),
        );
        assert_eq!(v_fp, Verdict::LikelyStego);
        assert!(s_fp > 0.9);
    }

    #[test]
    fn unsupported_format_returns_error() {
        let path = std::env::temp_dir().join("test.tiff");
        std::fs::write(&path, b"dummy").unwrap();
        let result = analyse(&path);
        assert!(matches!(result, Err(StegError::UnsupportedFormat(_))));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_file_returns_error() {
        let path = std::env::temp_dir().join("nonexistent_analysis.png");
        let result = analyse(&path);
        assert!(matches!(result, Err(StegError::FileNotFound(_))));
    }

    #[test]
    fn analyze_returns_valid_json() {
        let path = clean_png("analysis_json.png");
        let json = analyse(&path).unwrap();
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(report.get("verdict").is_some());
        assert!(report.get("overall_score").is_some());
        assert!(report.get("tests").is_some());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn html_report_is_valid_html() {
        let path = clean_png("analysis_html.png");
        let json = analyse(&path).unwrap();
        let html = generate_html_report(&[&json]);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("STEGCORE"));
        assert!(html.contains("</html>"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn analyze_batch_processes_multiple() {
        let p1 = clean_png("analysis_batch1.png");
        let p2 = clean_png("analysis_batch2.png");
        let paths: Vec<&Path> = vec![p1.as_path(), p2.as_path()];
        let results = analyse_batch(&paths);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        std::fs::remove_file(&p1).ok();
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn clean_wav_scores_reasonable() {
        let path = clean_wav("analysis_clean.wav");
        let report: AnalysisReport = serde_json::from_str(&analyse(&path).unwrap()).unwrap();
        // WAV analysis should complete without error
        assert!(report.overall_score >= 0.0 && report.overall_score <= 1.0);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn html_escape_works() {
        let s = html_escape("<script>alert(\"xss\")&</script>");
        assert!(!s.contains('<'), "should not contain raw <");
        assert!(!s.contains('>'), "should not contain raw >");
        assert!(s.contains("&lt;"), "should contain &lt;");
        assert!(s.contains("&gt;"), "should contain &gt;");
        assert!(s.contains("&amp;"), "should contain &amp;");
    }

    #[test]
    fn score_colour_returns_correct_colour() {
        assert_eq!(score_colour(0.10), "#22c55e");
        assert_eq!(score_colour(0.40), "#f59e0b");
        assert_eq!(score_colour(0.70), "#ef4444");
    }

    #[test]
    fn chi_channel_clean_scores_low() {
        // All-even values: count[2k] = large, count[2k+1] = 0 → chi2 is maximal → score ≈ 0
        let values: Vec<u8> = (0..512u32).map(|i| ((i % 128) * 2) as u8).collect();
        let score = chi_channel(&values);
        assert!(
            score < 0.1,
            "all-even values chi score should be < 0.1, got {score:.3}"
        );
    }

    #[test]
    fn chi_channel_uniform_scores_high() {
        // Perfectly uniform distribution: count[v] = same for all v → chi2 = 0 → score = 1.0
        let values: Vec<u8> = (0..2560u32).map(|i| (i % 256) as u8).collect();
        let score = chi_channel(&values);
        assert!(
            score > 0.90,
            "uniform distribution chi score should be > 0.90, got {score:.3}"
        );
    }

    // This test verifies the self-resistance of the ensemble without commenting
    // on the mechanism being tested.
    #[test]
    fn adaptive_embedded_image_within_threshold() {
        let path = adaptive_png("analysis_adaptive.png");
        let report: AnalysisReport = serde_json::from_str(&analyse(&path).unwrap()).unwrap();
        assert!(
            report.overall_score <= 0.55,
            "score was {:.3} — above acceptable threshold",
            report.overall_score
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn fingerprint_openstego_detected() {
        let path = std::env::temp_dir().join("fake_openstego.png");
        // Craft a minimal PNG-like file with the OpenStego marker
        let mut data = vec![0x89, 0x50, 0x4E, 0x47]; // PNG magic
        data.extend_from_slice(b"openstego");
        std::fs::write(&path, &data).unwrap();
        let result = check_openstego_png(&path);
        assert_eq!(result, Some("OpenStego (high confidence)".into()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn ensemble_empty_returns_clean() {
        let (v, s) = ensemble(&[], None);
        assert_eq!(v, Verdict::Clean);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn verdict_serialises_correctly() {
        let json = serde_json::to_string(&Verdict::LikelyStego).unwrap();
        assert_eq!(json, "\"likely_stego\"");
        let json = serde_json::to_string(&Verdict::Clean).unwrap();
        assert_eq!(json, "\"clean\"");
    }
}
