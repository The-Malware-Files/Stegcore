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

// Session 5 — steganalysis suite.
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use statrs::distribution::{ChiSquared, ContinuousCDF};

use crate::errors::StegError;
use crate::utils::detect_format;

// ── Report types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every check that this format's main threat needs was run, and none of
    /// them found anything. Only reachable when `Coverage::adequate` holds.
    Clean,
    /// Nothing was found, but the checks that ran cannot speak to how this
    /// format is actually attacked, so the result carries no information
    /// either way. See `Coverage`.
    ///
    /// This state exists because the one it replaced was actively dangerous.
    /// `analyse` used to report `Clean` on a JPEG carrying a steghide payload,
    /// and a user who had embedded that payload himself a minute earlier
    /// concluded, correctly, that a clean verdict from this tool meant nothing
    /// at all. A detector that clears a file it cannot assess is worse than one
    /// that declines to answer.
    NotAssessed,
    Suspicious,
    LikelyStego,
}

/// What an analysis was and was not able to look for.
///
/// `analyse_image` decodes to RGB and runs five spatial detectors whatever the
/// container was, so on a JPEG it measures the decompressed pixels and nothing
/// in the DCT coefficients, which is where JPEG steganography lives. That is
/// not a weakness to be hedged about: measured over 120 matched cover/stego
/// pairs, adding a steghide payload moved the median score of all five
/// detectors by `+0.0000`, changed no verdict, and the four files flagged were
/// the same four flagged as clean covers. The detector responds to the cover
/// and not to the payload, so its silence on a JPEG is uninformative.
///
/// Carrying that as data rather than as prose means the CLI, the GUI and any
/// JSON consumer all say the same thing, and a future detector that closes the
/// gap removes an entry here rather than needing every surface re-edited.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Coverage {
    /// Plain-language descriptions of what was examined.
    pub checked: Vec<String>,
    /// Plain-language descriptions of what was not, and so cannot be ruled out.
    pub not_checked: Vec<String>,
    /// True when `not_checked` holds nothing that this format's principal
    /// embedders rely on. False forces `Clean` down to `NotAssessed`.
    pub adequate: bool,
}

impl Coverage {
    /// Coverage for a still image, which depends entirely on the container.
    ///
    /// Lossless rasters keep every pixel the embedder wrote, so the spatial
    /// detectors are measuring the thing that was attacked. A JPEG does not:
    /// the payload is in the quantised coefficients and the pixels we get back
    /// have been through an inverse DCT that does not preserve it.
    fn for_image(fmt: &str) -> Self {
        let structural = "appended data and tool signatures".to_string();
        let spatial = "spatial LSB statistics (sample pair, RS, weighted stego)".to_string();
        match fmt {
            "jpg" | "jpeg" => Self {
                checked: vec![
                    structural,
                    "spatial LSB statistics, on the decompressed image".to_string(),
                ],
                not_checked: vec![
                    "DCT coefficient statistics, where JPEG steganography hides \
                     (steghide, outguess, F5, nsF5, J-UNIWARD)"
                        .to_string(),
                ],
                adequate: false,
            },
            _ => Self {
                checked: vec![structural, spatial],
                not_checked: vec![],
                adequate: true,
            },
        }
    }

    /// Coverage for audio. The spatial-equivalent sample-pair test runs on the
    /// decoded samples, which for WAV and FLAC is what the embedder wrote.
    fn for_audio() -> Self {
        Self {
            checked: vec!["appended data and tool signatures".to_string()],
            not_checked: vec![
                "sample statistics calibrated for audio, so a quiet result here \
                 means the structural checks found nothing rather than that the \
                 file was cleared"
                    .to_string(),
            ],
            adequate: false,
        }
    }

    /// Coverage for `analyse --fast` on audio. Separate from [`Self::for_sampled`]
    /// because that one names pixels and an image, which is the wrong thing to
    /// tell somebody who handed over a recording.
    fn for_sampled_audio(ratio: f64) -> Self {
        Self {
            checked: vec![format!(
                "sample pair statistics on about {:.0}% of the frames",
                ratio * 100.0
            )],
            not_checked: vec![
                "the frames in between".to_string(),
                "appended data and tool signatures, which fast mode skips".to_string(),
                "any calibrated audio statistic, because none has been calibrated \
                 yet, so a quiet result here clears nothing"
                    .to_string(),
            ],
            adequate: false,
        }
    }

    /// Coverage for `analyse --fast`, which samples a fraction of the file and
    /// skips the fingerprint pass entirely, so it can never clear anything.
    fn for_sampled(ratio: f64) -> Self {
        Self {
            checked: vec![format!(
                "spatial LSB statistics on a {:.0}% sample of the image",
                ratio * 100.0
            )],
            not_checked: vec![
                "the remaining pixels".to_string(),
                "appended data and tool signatures, which fast mode skips".to_string(),
            ],
            adequate: false,
        }
    }
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
    /// Lowercase tier of the matched fingerprint — `"exact"` or `"heuristic"`.
    /// Always `None` when `tool_fingerprint` is `None`. Kept as a parallel
    /// scalar (rather than restructuring `tool_fingerprint` into an object)
    /// to stay backward-compatible with CLI JSON / CSV consumers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_fingerprint_tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_entropy: Option<BlockEntropy>,
    /// What this analysis could and could not look for. Optional so a report
    /// deserialised from an older release still loads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Catch panics from third-party decoders / dependencies and convert them into
/// a clean `StegError::CaughtPanic` rather than letting them unwind out of the
/// engine. Found-by-fuzz: malformed JPEG input panics somewhere inside the
/// `image` crate's JPEG decoder, and we don't want that to abort a calling
/// process (CLI, GUI, library consumer).
///
/// The error says a panic happened and writes the detail to a diagnostic file.
/// It used to return `Internal`, which the public error layer then reported as a
/// corrupt file, telling the user their file was damaged when in fact our own
/// code or one of our dependencies had crashed on a file that may be fine.
fn catch_engine_panic<R>(
    operation: &str,
    subject: &Path,
    f: impl FnOnce() -> Result<R, StegError> + std::panic::UnwindSafe,
) -> Result<R, StegError> {
    match std::panic::catch_unwind(f) {
        Ok(r) => r,
        Err(payload) => Err(crate::errors::caught_panic(
            operation,
            Some(subject),
            payload.as_ref(),
        )),
    }
}

/// Analyse a single file. Returns a JSON-serialised `AnalysisReport`.
pub fn analyse(path: &Path) -> Result<String, StegError> {
    let subject = path.to_path_buf();
    let inner = subject.clone();
    catch_engine_panic("analyse", &subject, move || {
        let report = run_analysis(&inner)?;
        Ok(serde_json::to_string(&report)?)
    })
}

/// Fast preliminary analysis using 10% sampling. Parallel tests.
pub fn analyse_fast(path: &Path) -> Result<String, StegError> {
    let subject = path.to_path_buf();
    let inner = subject.clone();
    catch_engine_panic("analyse (fast)", &subject, move || {
        let report = run_analysis_sampled(&inner, 0.1)?;
        Ok(serde_json::to_string(&report)?)
    })
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
    let img = crate::utils::open_image_by_content(path)?;
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
    let coverage = Coverage::for_sampled(ratio);
    let (verdict, overall_score) = ensemble(&tests, None, &coverage);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: fmt.to_string(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: None,
        tool_fingerprint_tier: None,
        block_entropy: None,
        coverage: Some(coverage),
    })
}

fn analyse_image(path: &Path, fmt: &str) -> Result<AnalysisReport, StegError> {
    let img = crate::utils::open_image_by_content(path)?;
    let rgb = img.to_rgb8();
    let (w, h) = rgb.dimensions();

    let r: Vec<u8> = rgb.pixels().map(|p| p.0[0]).collect();
    let g: Vec<u8> = rgb.pixels().map(|p| p.0[1]).collect();
    let b: Vec<u8> = rgb.pixels().map(|p| p.0[2]).collect();
    let all: Vec<u8> = rgb
        .pixels()
        .flat_map(|p| [p.0[0], p.0[1], p.0[2]])
        .collect();

    // Run all five detectors in parallel — they are completely independent.
    let (((chi, spa), (rs, ent)), ws) = rayon::join(
        || {
            rayon::join(
                || rayon::join(|| chi_squared_test(&r, &g, &b), || spa_test(&all, w)),
                || rayon::join(|| rs_test(&all, w), || entropy_test(&all)),
            )
        },
        || ws_test(&all, w),
    );

    let fingerprint = fingerprint_image(path, fmt);

    let block_entropy = compute_block_entropy(&all, w, h);

    // WS (tests[4]) is reported but not yet ensemble-weighted — Phase 3
    // calibration sets its weight + threshold (with the Q-37 chi²/entropy call).
    let tests = vec![chi, spa, rs, ent, ws];
    let coverage = Coverage::for_image(fmt);
    let (verdict, overall_score) = ensemble(&tests, fingerprint.as_ref(), &coverage);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: fmt.to_string(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: fingerprint.as_ref().map(|f| f.label()),
        tool_fingerprint_tier: fingerprint.as_ref().map(|f| f.tier_str().to_string()),
        block_entropy: Some(block_entropy),
        coverage: Some(coverage),
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
//
// The audio path streams the file rather than decoding it into a `Vec`. Holding
// every sample cost about 14 times the file size in peak resident memory, with no
// limit anywhere in the path: a 120 MB 8-bit cover drove `score` to 1.80 GiB and
// `analyse` to 1.49 GiB, both exiting 0.
//
// It streamed TWICE until this change, and the second pass is now gone. Audio used
// to produce `[chi, spa, entropy]`, and chi-squared and LSB entropy count toward
// nothing: `detector_threshold` has no calibrated number for either name, because
// both manufacture false positives (Q-37) and because a 16-bit audio LSB plane is
// near-random by construction, so an entropy test cannot separate anything on it.
// The second pass existed only to centre the entropy sums on a mean the first pass
// had to count first. Decoding a whole file a second time to compute two numbers
// the verdict then discards is pure cost, so both detectors and the pass behind
// them are gone. Measured on a 133 MB, 13 minute stereo recording: `analyse` fell
// from 3.29 s to 1.73 s, best of five.
//
// What remains is the sample pair estimate, and it is computed by
// `crate::audio_analysis`, which is the single implementation of the audio
// statistics. There is no second copy of the rules here to drift out of step with
// it, which is the defect this replaces: the accumulator that used to live here
// split samples into three pseudo-channels on a two-channel file.

/// The audio sample pair detector, built from the statistics
/// [`crate::audio_analysis::analyse_stream`] measured in one pass.
///
/// The score is the largest per-channel embedding-rate estimate, clamped to
/// `[0, 1]`. The largest rather than the mean, because a payload written into one
/// channel of a stereo file is still a payload and averaging it against an
/// untouched channel halves it for no reason.
///
/// Confidence is always `Low`, and that is a statement rather than a placeholder.
/// No audio corpus has been calibrated, so there is no number this estimate may be
/// compared against (CLAUDE.md A3), and `detector_threshold` returns `None` for
/// this name so the figure is reported while the carrier reports as not assessed.
/// The bands this replaces sat at 0.30 and 0.65, which were image numbers applied
/// to audio, and they are how nine of nine provably clean recordings came to be
/// flagged.
fn audio_spa_result(stats: &crate::audio_analysis::AudioStatistics) -> TestResult {
    // fold rather than a max over the iterator: `f64` has no total order, and the
    // one NaN a degenerate channel could produce must not win the comparison.
    let (score, roughness) = stats.per_channel.iter().fold((0.0f64, 0.0f64), |acc, c| {
        if c.spa_alpha > acc.0 {
            (c.spa_alpha, c.roughness)
        } else {
            acc
        }
    });
    let score = score.clamp(0.0, 1.0);

    let distribution = stats
        .per_channel
        .iter()
        .map(|c| DistBin {
            label: format!("Ch {}", c.channel),
            // A clean channel's estimated embedding rate is zero, so that is the
            // expectation the observed estimate is read against.
            expected: 0.0,
            observed: c.spa_alpha,
        })
        .collect();

    let plural = if stats.per_channel.len() == 1 {
        "channel"
    } else {
        "channels"
    };
    let detail = format!(
        "Estimated embedding rate {score:.3}, the highest of {} {plural}. Neighbour \
         roughness in that channel is {roughness:.2}; at around 1.15 the samples \
         move as much as independent noise does and the estimate stops meaning \
         anything. Audio has no calibrated threshold, so this figure is reported \
         and not judged.",
        stats.per_channel.len()
    );

    TestResult {
        name: "Audio Sample Pair Analysis".into(),
        score,
        confidence: Confidence::Low,
        detail,
        distribution: Some(distribution),
    }
}

/// Measure a WAV stream in one pass and return the detector results.
fn stream_wav_tests(
    source: crate::wav::ChunkSource,
) -> Result<(hound::WavSpec, Vec<TestResult>), StegError> {
    let spec = source.spec();
    let stats = crate::audio_analysis::analyse_stream(source)?;
    Ok((spec, vec![audio_spa_result(&stats)]))
}

fn analyse_wav_sampled(path: &Path, ratio: f64) -> Result<AnalysisReport, StegError> {
    // The stride comes from the data chunk's declared length rather than from a
    // counting pass: it is a how-much-to-look budget, not a measurement, and
    // paying a whole extra decode to choose it would undo the point of fast mode.
    //
    // It counts FRAMES, not interleaved samples. A stride in samples rotates the
    // channel assignment on any file whose channel count shares no factor with it,
    // which attaches the right numbers to the wrong channel; a whole frame keeps
    // the interleaving intact whatever the stride.
    let source = crate::wav::source(path)?;
    let channels = (source.spec().channels as usize).max(1);
    let declared_frames = source.declared_samples() as usize / channels;
    let wanted = ((declared_frames as f64 * ratio) as usize).max(1024);
    let frame_stride = (declared_frames / wanted).max(1);

    let (_spec, tests) = stream_wav_tests(source.with_frame_stride(frame_stride))?;
    let coverage = Coverage::for_sampled_audio(ratio);
    let (verdict, overall_score) = ensemble(&tests, None, &coverage);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: "wav".into(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: None,
        tool_fingerprint_tier: None,
        block_entropy: None,
        coverage: Some(coverage),
    })
}

fn analyse_wav(path: &Path) -> Result<AnalysisReport, StegError> {
    let (spec, tests) = stream_wav_tests(crate::wav::source(path)?)?;
    let fingerprint = fingerprint_audio(path, spec.channels);
    let coverage = Coverage::for_audio();
    let (verdict, overall_score) = ensemble(&tests, fingerprint.as_ref(), &coverage);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: "wav".into(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: fingerprint.as_ref().map(|f| f.label()),
        tool_fingerprint_tier: fingerprint.as_ref().map(|f| f.tier_str().to_string()),
        block_entropy: None,
        coverage: Some(coverage),
    })
}

// ── FLAC analysis ─────────────────────────────────────────────────────────────

fn analyse_flac(path: &Path) -> Result<AnalysisReport, StegError> {
    // flac-io decodes a whole stream into memory, so guard the input size
    // before reading: a multi-gigabyte file is refused rather than risked. A
    // quarter-gibibyte covers any realistic music file by a wide margin.
    const MAX_FLAC_BYTES: u64 = 256 * 1024 * 1024;
    // The statistical tests only need a representative prefix; cap the decoded
    // sample count so analysis time stays bounded regardless of clip length.
    const ANALYSIS_SAMPLE_CAP: usize = 4_000_000;

    let meta =
        std::fs::metadata(path).map_err(|_| StegError::FileNotFound(path.display().to_string()))?;
    if meta.len() > MAX_FLAC_BYTES {
        return Err(StegError::UnsupportedFormat(format!(
            "flac file is too large to analyse ({} bytes, limit {MAX_FLAC_BYTES})",
            meta.len()
        )));
    }

    let bytes = std::fs::read(path).map_err(StegError::Io)?;
    let audio =
        flac_io::decode(&bytes).map_err(|e| StegError::UnsupportedFormat(format!("flac: {e}")))?;

    // Interleave the per-channel samples into one stream (matching the layout
    // the previous decoder produced), capped at the analysis budget.
    let channels = audio.channels as usize;
    let mut samples_i32: Vec<i32> =
        Vec::with_capacity((audio.samples_per_channel() * channels).min(ANALYSIS_SAMPLE_CAP));
    'outer: for i in 0..audio.samples_per_channel() {
        for ch in &audio.samples {
            samples_i32.push(ch[i]);
            if samples_i32.len() >= ANALYSIS_SAMPLE_CAP {
                break 'outer;
            }
        }
    }

    // One detector, through the same statistics the WAV path uses, with the
    // channel count taken from the FLAC header. The chi-squared and LSB entropy
    // tests that used to run beside it counted toward nothing and cost a second
    // whole-stream copy as `u8` plus the `rayon::join` that existed only to
    // parallelise them.
    let source = crate::audio_analysis::SliceSource::new(
        &samples_i32,
        channels,
        u16::from(audio.bits_per_sample),
    );
    let tests = vec![audio_spa_result(&crate::audio_analysis::analyse_stream(
        source,
    )?)];
    let coverage = Coverage::for_audio();
    let (verdict, overall_score) = ensemble(&tests, None, &coverage);

    Ok(AnalysisReport {
        file: path.to_path_buf(),
        format: "flac".into(),
        tests,
        verdict,
        overall_score,
        tool_fingerprint: None,
        tool_fingerprint_tier: None,
        block_entropy: None,
        coverage: Some(coverage),
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
    // Sample Pair Analysis (Dumitrescu, Wu & Wang, 2003).
    //
    // Ported from Aletheia's `spa_image` (daniellerch/aletheia,
    // aletheialib/attacks.py @ df4fc2e5). The embedding-rate estimate is
    // computed independently per channel; we return the maximum across the
    // three channels — the decision statistic Aletheia's `spa_detect` uses.
    // The previous body was a horizontal-pair approximation with an ad-hoc
    // quadratic; this is the literature-faithful detector.
    let stride = width.saturating_mul(3);
    if stride == 0 || pixels.len() < stride.saturating_mul(2) {
        return 0.0;
    }
    let alpha = (0..3)
        .map(|ch| aletheia_spa(pixels, width, ch))
        .fold(0.0_f64, f64::max);
    alpha.clamp(0.0, 1.0)
}

/// Estimate the LSB-replacement embedding rate (`alpha`) of a single channel
/// via Sample Pair Analysis over vertically adjacent pixel pairs.
///
/// Faithful port of Aletheia's `spa_image` (aletheialib/attacks.py @ df4fc2e5);
/// returns the raw estimate (≈ 0 for a clean cover — may be slightly negative),
/// the caller clamps for the ensemble. Aletheia's reference forms the
/// pair-count constant from a transposed width/height; for a square image —
/// every calibration corpus here is square — that equals the true pair count
/// `(rows - 1) · width`, which we use so the estimate is correct for
/// non-square images too.
fn aletheia_spa(pixels: &[u8], width: usize, channel: usize) -> f64 {
    let stride = width * 3;
    if width == 0 || pixels.len() < stride * 2 {
        return 0.0;
    }
    let rows = pixels.len() / stride;
    if rows < 2 {
        return 0.0;
    }

    let mut x: i64 = 0; // DWW trace-set counts (pair orientation vs. parity)
    let mut y: i64 = 0;
    let mut k: i64 = 0; // pairs whose top 7 bits are equal
    let mut pair_count: i64 = 0;

    for row in 0..rows - 1 {
        let top = row * stride;
        let bot = top + stride;
        for col in 0..width {
            let off = col * 3 + channel;
            let r = pixels[top + off] as i32;
            let s = pixels[bot + off] as i32;
            pair_count += 1;

            let s_even = (s & 1) == 0;
            let r_lt = r < s;
            let r_gt = r > s;

            if (s_even && r_lt) || (!s_even && r_gt) {
                x += 1;
            }
            if (s_even && r_gt) || (!s_even && r_lt) {
                y += 1;
            }
            if (r & 0xFE) == (s & 0xFE) {
                k += 1;
            }
        }
    }

    if k == 0 {
        return 0.0; // degenerate: Aletheia aborts here
    }

    // DWW quadratic  a·beta² + b·beta + c = 0
    let a = (2 * k) as f64;
    let b = (2 * (2 * x - pair_count)) as f64;
    let c = (y - x) as f64;

    // a = 2k > 0, so the smaller real root is (-b - √disc) / 2a. A negative
    // discriminant means complex-conjugate roots whose shared real part is
    // -b/2a (Aletheia takes the minimum of the two real parts).
    let disc = b * b - 4.0 * a * c;
    let beta = if disc < 0.0 {
        -b / (2.0 * a)
    } else {
        (-b - disc.sqrt()) / (2.0 * a)
    };

    2.0 * beta // alpha = 2·beta
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
    // RS analysis (Fridrich, Goljan & Du, 2001).
    //
    // Ported from Aletheia's `rs_image` (daniellerch/aletheia,
    // aletheialib/attacks.py @ df4fc2e5). Each channel is de-interleaved into a
    // contiguous plane, the per-channel embedding-rate estimate is computed,
    // and the maximum across channels is returned. The previous body was an
    // ad-hoc R/S asymmetry heuristic; this is the literature-faithful detector.
    let stride = width.saturating_mul(3);
    if stride == 0 || pixels.len() < stride.saturating_mul(2) {
        return (0.0, vec![]);
    }
    let rows = pixels.len() / stride;
    if rows < 4 || width < 4 {
        return (0.0, vec![]);
    }

    let mut per_channel = [0.0f64; 3];
    for (ch, slot) in per_channel.iter_mut().enumerate() {
        let mut plane = Vec::with_capacity(rows * width);
        for row in 0..rows {
            let base = row * stride + ch;
            for col in 0..width {
                plane.push(pixels[base + col * 3] as i32);
            }
        }
        *slot = aletheia_rs(&plane, rows, width);
    }

    let score = per_channel
        .iter()
        .copied()
        .fold(0.0_f64, f64::max)
        .clamp(0.0, 1.0);
    let dist = (0..3)
        .map(|ch| DistBin {
            label: format!("channel {ch} estimate"),
            expected: 0.0,
            observed: per_channel[ch].clamp(0.0, 1.0),
        })
        .collect();
    (score, dist)
}

/// Which flip a 3×3 window's centre pixel undergoes in RS analysis.
#[derive(Clone, Copy)]
enum RsMask {
    /// M+ : flip the centre pixel's LSB (`centre ^ 1`).
    Plus,
    /// M- : increment the centre pixel (`centre + 1`).
    Minus,
}

/// Sum of absolute neighbour differences over a flattened 3×3 window —
/// Aletheia's `smoothness` (vertical diffs + horizontal diffs).
fn rs_window_smoothness(w: &[i32; 9]) -> i64 {
    let mut s = 0i64;
    for r in 0..2 {
        for c in 0..3 {
            s += (w[r * 3 + c] - w[(r + 1) * 3 + c]).unsigned_abs() as i64;
        }
    }
    for r in 0..3 {
        for c in 0..2 {
            s += (w[r * 3 + c] - w[r * 3 + c + 1]).unsigned_abs() as i64;
        }
    }
    s
}

/// Aletheia's `difference`: sweep every 3×3 window of `plane`, classify the
/// sign of the smoothness change when the centre pixel is flipped under
/// `mask`, and return R − S (regular minus singular group rate).
fn rs_difference(plane: &[i32], rows: usize, cols: usize, mask: RsMask) -> f64 {
    if rows < 4 || cols < 4 {
        return 0.0;
    }
    let (mut r_count, mut s_count, mut n) = (0i64, 0i64, 0i64);
    for i in 0..rows - 3 {
        for j in 0..cols - 3 {
            let mut w = [0i32; 9];
            for dr in 0..3 {
                for dc in 0..3 {
                    w[dr * 3 + dc] = plane[(i + dr) * cols + (j + dc)];
                }
            }
            let orig = rs_window_smoothness(&w);
            let mut f = w;
            f[4] = match mask {
                RsMask::Plus => w[4] ^ 1,
                RsMask::Minus => w[4] + 1,
            };
            n += 1;
            match rs_window_smoothness(&f).cmp(&orig) {
                std::cmp::Ordering::Greater => r_count += 1,
                std::cmp::Ordering::Less => s_count += 1,
                std::cmp::Ordering::Equal => {}
            }
        }
    }
    if n == 0 {
        return 0.0;
    }
    (r_count - s_count) as f64 / n as f64
}

/// RS embedding-rate estimate for one channel plane — faithful port of
/// Aletheia's `rs_image`. Returns ≈ 0 for a clean cover.
fn aletheia_rs(plane: &[i32], rows: usize, cols: usize) -> f64 {
    let inverted: Vec<i32> = plane.iter().map(|&v| v ^ 1).collect();
    let d0 = rs_difference(plane, rows, cols, RsMask::Plus);
    let d1 = rs_difference(&inverted, rows, cols, RsMask::Plus);
    let n_d0 = rs_difference(plane, rows, cols, RsMask::Minus);
    let n_d1 = rs_difference(&inverted, rows, cols, RsMask::Minus);

    // Aletheia: solve(2(d1+d0), n_d0-n_d1-d1-3d0, d0-n_d0); z = root of min |·|.
    let a = 2.0 * (d1 + d0);
    let b = n_d0 - n_d1 - d1 - 3.0 * d0;
    let c = d0 - n_d0;
    if a.abs() < 1e-12 {
        return 0.0;
    }
    let disc = b * b - 4.0 * a * c;
    if disc < 0.0 {
        return 0.0; // Aletheia's real-valued sqrt yields NaN here → no detection
    }
    let sq = disc.sqrt();
    let p0 = (-b + sq) / (2.0 * a);
    let p1 = (-b - sq) / (2.0 * a);
    let z = if p0.abs() < p1.abs() { p0 } else { p1 };
    if (z - 0.5).abs() < 1e-12 {
        return 0.0;
    }
    z / (z - 0.5)
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

// ── Detector: Weighted Stego (WS) ─────────────────────────────────────────────

fn ws_test(pixels: &[u8], width: u32) -> TestResult {
    let score = ws_score(pixels, width as usize);
    let (confidence, detail) = ws_confidence(score);
    TestResult {
        name: "Weighted Stego".into(),
        score,
        confidence,
        detail,
        distribution: None,
    }
}

fn ws_score(pixels: &[u8], width: usize) -> f64 {
    // Weighted Stego-image steganalysis (Ker & Böhme, 2008 — "Revisiting
    // Weighted Stego-Image Steganalysis").
    //
    // Ported from Aletheia's WS.m (the Fridrich / Binghamton reference). The
    // change-rate estimate `beta` is computed per channel; the detection
    // statistic is `alpha = 2·beta`, maximised across the three channels.
    let stride = width.saturating_mul(3);
    if stride == 0 || pixels.len() < stride.saturating_mul(2) {
        return 0.0;
    }
    let rows = pixels.len() / stride;
    if rows < 3 || width < 3 {
        return 0.0;
    }
    let mut max_alpha = 0.0_f64;
    for ch in 0..3 {
        let mut plane = Vec::with_capacity(rows * width);
        for row in 0..rows {
            let base = row * stride + ch;
            for col in 0..width {
                plane.push(pixels[base + col * 3] as f64);
            }
        }
        let alpha = 2.0 * aletheia_ws(&plane, rows, width);
        if alpha > max_alpha {
            max_alpha = alpha;
        }
    }
    max_alpha.clamp(0.0, 1.0)
}

/// Weighted-Stego change-rate estimate (`beta`) for one channel plane —
/// faithful port of Aletheia's WS.m (Ker & Böhme 2008). Each interior pixel
/// contributes a residual against a Ker-Böhme cover estimate, weighted by the
/// inverse of its local variance; `beta` is the weighted mean. ≈ 0 for a clean
/// cover.
fn aletheia_ws(plane: &[f64], rows: usize, cols: usize) -> f64 {
    if rows < 3 || cols < 3 {
        return 0.0;
    }
    let at = |i: usize, j: usize| plane[i * cols + j];
    let mut num = 0.0_f64; // Σ w·(S − X̂)·(S − S̄)
    let mut wsum = 0.0_f64; // Σ w  — normaliser

    for i in 1..rows - 1 {
        for j in 1..cols - 1 {
            // 3×3 local variance → moderated inverse-variance weight
            let (mut s, mut sq) = (0.0_f64, 0.0_f64);
            for di in 0..3 {
                for dj in 0..3 {
                    let v = at(i + di - 1, j + dj - 1);
                    s += v;
                    sq += v * v;
                }
            }
            let mean = s / 9.0;
            let w = 1.0 / (5.0 + (sq / 9.0 - mean * mean));

            // Ker-Böhme cover estimate from the 8 neighbours
            let x_hat = 0.25
                * (-(at(i - 1, j - 1) + at(i + 1, j - 1) + at(i + 1, j + 1) + at(i - 1, j + 1))
                    + 2.0 * (at(i, j - 1) + at(i, j + 1) + at(i - 1, j) + at(i + 1, j)));

            let centre = at(i, j);
            // S − S̄ : +1 when the centre LSB is 1, −1 when 0
            let flip = if centre as i64 & 1 == 1 { 1.0 } else { -1.0 };

            num += w * (centre - x_hat) * flip;
            wsum += w;
        }
    }

    if wsum <= 0.0 {
        return 0.0;
    }
    num / wsum
}

fn ws_confidence(score: f64) -> (Confidence, String) {
    if score > WS_THRESHOLD {
        (
            Confidence::High,
            format!("Weighted-stego residual indicates LSB replacement (score {score:.2})"),
        )
    } else if score > WS_THRESHOLD / 2.0 {
        (
            Confidence::Medium,
            format!("Mild weighted-stego anomaly (score {score:.2})"),
        )
    } else {
        (
            Confidence::Low,
            format!("Weighted-stego residual within natural range (score {score:.2})"),
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

// ── Detector: Tool Fingerprinting ─────────────────────────────────────────────

// ── Tool fingerprints ─────────────────────────────────────────────────────────

/// Confidence tier of a structural tool fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FpTier {
    /// Exact signature — a magic byte sequence or format marker unique to the
    /// tool. Decisive on its own.
    Exact,
    /// Heuristic structural signal — e.g. a plausible length header with no
    /// magic. Strong corroboration, but a clean low-entropy image can match by
    /// chance, so it is not decisive without statistical support.
    Heuristic,
}

/// A matched tool fingerprint: the tool name and the confidence tier of the
/// match. The verdict treats `Exact` matches as decisive and `Heuristic`
/// matches as corroborating only.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    tool: String,
    tier: FpTier,
}

impl Fingerprint {
    fn exact(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            tier: FpTier::Exact,
        }
    }

    fn heuristic(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            tier: FpTier::Heuristic,
        }
    }

    /// Human-readable label for reports — names the tool and the match tier.
    fn label(&self) -> String {
        match self.tier {
            FpTier::Exact => format!("{} (exact signature)", self.tool),
            FpTier::Heuristic => format!("{} (heuristic match)", self.tool),
        }
    }

    /// Lowercase tier discriminator used in machine-readable output
    /// (`tool_fingerprint_tier` field). Stays stable across releases —
    /// frontends key off this for badge colour.
    fn tier_str(&self) -> &'static str {
        match self.tier {
            FpTier::Exact => "exact",
            FpTier::Heuristic => "heuristic",
        }
    }
}

fn fingerprint_image(path: &Path, fmt: &str) -> Option<Fingerprint> {
    // OpenStego's default (no-password) embed scatters the `OPENSTEGO` header
    // magic across the LSB plane under a fixed PRNG seed. `check_openstego`
    // replays that generator to reconstruct and confirm the magic; the literal
    // string never appears sequentially, so the replay is the only way to see
    // it (verified against real OpenStego 0.8.6 output). Lossless raster only.
    if fmt == "png" || fmt == "bmp" {
        if let Some(sig) = check_openstego(path) {
            return Some(sig);
        }
    }

    // Steghide is not fingerprinted structurally: its `73 68 8D` ("shm") magic
    // lives *inside* the encrypted embedded stream, not at any fixed offset in
    // the carrier — a Steghide JPEG still starts `FF D8 FF`, so the old offset-0
    // check (verified empirically) never fired. A real detector needs to
    // brute-force the 32-bit seed (CVE-2021-27211) and confirm the magic in the
    // decrypted stream — heavy and dual-use, deferred to v4.1+ (tech-debt T-26).
    // Until then Steghide is caught only via the statistical detectors.

    // Exact: Camouflage appends its container after the carrier's EOF marker,
    // led by a fixed `00 00 XX ED CD 01` signature (works on any carrier whose
    // logical end we can locate).
    if let Some(sig) = check_camouflage(path, fmt) {
        return Some(sig);
    }

    // Heuristic: F5 (and the James/Weeks JpegEncoder lineage it derives from)
    // writes a distinctive JPEG comment. Corroborating, not decisive.
    if fmt == "jpg" || fmt == "jpeg" {
        if let Some(sig) = check_f5(path) {
            return Some(sig);
        }
    }

    // LSBSteg targets lossless raster formats only (it rewrites JPEG → PNG).
    if fmt == "png" || fmt == "bmp" {
        if let Some(sig) = check_lsbsteg(path) {
            return Some(sig);
        }
    }

    // Heuristic, format-agnostic: any data appended past the carrier's logical
    // EOF marker. Catches the whole append-after-EOF tool class (the
    // Camouflage-specific exact check above runs first when its signature fits).
    if let Some(sig) = check_appended(path, fmt) {
        return Some(sig);
    }

    None
}

fn fingerprint_audio(_path: &Path, _channels: u16) -> Option<Fingerprint> {
    None
}

/// LSBSteg (Robin David) — CLI `encode_binary` mode writes a 64-bit big-endian
/// payload-length header into the first 64 LSBs of the carrier, traversed
/// row-major and channel-inner in OpenCV BGR order, before the payload itself.
/// We read those 64 LSBs back as a length: for a genuine LSBSteg image it is
/// the exact payload byte count (small, plausible); for a clean image the bits
/// are effectively random, yielding a value on the order of 2^64. The image is
/// flagged only when the recovered length is a payload that physically fits the
/// carrier. LSBSteg has no magic bytes, so this length header is its only
/// structural tell: on a low-entropy (e.g. grayscale) cover a small plausible
/// length can arise by chance (~0.2% empirically), so this is a `Heuristic`
/// match — corroborating, not decisive.
fn check_lsbsteg(path: &Path) -> Option<Fingerprint> {
    let rgb = crate::utils::open_image_by_content(path).ok()?.to_rgb8();
    let (w, h) = rgb.dimensions();
    let px: Vec<_> = rgb.pixels().take(22).collect();
    if px.len() < 22 {
        return None; // smaller than the 64-bit header — cannot be LSBSteg output
    }
    // LSBSteg traverses OpenCV BGR channels (0=B, 1=G, 2=R); image-crate pixels
    // are RGB, so channel k of the header maps to RGB index [2, 1, 0][k].
    const BGR: [usize; 3] = [2, 1, 0];
    let mut len: u64 = 0;
    for k in 0..64usize {
        let bit = u64::from(px[k / 3].0[BGR[k % 3]] & 1);
        len = (len << 1) | bit;
    }
    // A genuine payload is non-empty and — header + payload — fits the carrier's
    // LSB capacity across all eight bit-planes (LSBSteg spills upward as planes
    // fill).
    let capacity_bits = u64::from(w) * u64::from(h) * 3 * 8;
    if len > 0 && len.saturating_mul(8).saturating_add(64) <= capacity_bits {
        return Some(Fingerprint::heuristic("LSBSteg"));
    }
    None
}

/// Cap on raw bytes read for structural fingerprinting. Larger carriers are not
/// fingerprinted (the statistical detectors still run); matches the FLAC cap.
const MAX_FINGERPRINT_BYTES: u64 = 256 * 1024 * 1024;

/// Read a file in full for byte-level fingerprinting, refusing oversized inputs.
fn read_for_fingerprint(path: &Path) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > MAX_FINGERPRINT_BYTES {
        return None;
    }
    std::fs::read(path).ok()
}

/// Hard cap on segments/chunks walked while locating a carrier's end, so a
/// malformed structure cannot loop unboundedly (§2.1 resource caps).
const MAX_STRUCTURE_STEPS: usize = 100_000;

/// Offset just past a carrier's logical end. Found by *parsing* the format, not
/// by searching for the end marker: appended payload data can itself contain
/// the marker bytes (`IEND`, `FF D9`), and a naive search would be spoofed into
/// reporting a false end and missing the appended data. Returns None if the
/// structure does not parse.
fn format_eof(bytes: &[u8], fmt: &str) -> Option<usize> {
    match fmt {
        "png" => png_end(bytes),
        "jpg" | "jpeg" => jpeg_end(bytes),
        // BMP records its total file size in a 4-byte LE field at offset 2.
        "bmp" => {
            let n = u32::from_le_bytes(bytes.get(2..6)?.try_into().ok()?) as usize;
            (n >= 54 && n <= bytes.len()).then_some(n)
        }
        _ => None,
    }
}

/// Walk the PNG chunk stream from the signature to the IEND chunk and return the
/// offset just past its CRC. Bytes after that are appended data; a stray `IEND`
/// inside them cannot move this (unlike a reverse byte-search).
fn png_end(bytes: &[u8]) -> Option<usize> {
    const SIG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if bytes.len() < SIG.len() || &bytes[..SIG.len()] != SIG {
        return None;
    }
    let mut pos = SIG.len();
    for _ in 0..MAX_STRUCTURE_STEPS {
        // Each chunk: 4-byte BE length + 4-byte type + data + 4-byte CRC.
        if pos.checked_add(8)? > bytes.len() {
            return None;
        }
        let data_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().ok()?) as usize;
        let is_iend = &bytes[pos + 4..pos + 8] == b"IEND";
        let next = pos.checked_add(12)?.checked_add(data_len)?;
        if next > bytes.len() {
            return None;
        }
        if is_iend {
            return Some(next);
        }
        pos = next;
    }
    None
}

/// Walk JPEG markers to the EOI (FF D9), parsing segment lengths and the
/// entropy-coded scan rather than searching for the marker bytes (which appear
/// legitimately inside scan data and can appear in appended payloads).
fn jpeg_end(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 2 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None;
    }
    let mut pos = 2;
    for _ in 0..MAX_STRUCTURE_STEPS {
        // Markers may be preceded by fill 0xFF bytes.
        let mut m = pos;
        while m < bytes.len() && bytes[m] == 0xFF {
            m += 1;
        }
        if m >= bytes.len() || bytes[pos] != 0xFF {
            return None; // not aligned on a marker
        }
        let marker = bytes[m];
        pos = m + 1;
        match marker {
            0xD9 => return Some(pos),       // EOI
            0xD0..=0xD7 | 0x01 => continue, // standalone (RSTn, TEM)
            0xDA => {
                // SOS: skip its header, then scan entropy data to the next marker.
                let seg = u16::from_be_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?) as usize;
                pos = pos.checked_add(seg)?;
                while pos + 1 < bytes.len() {
                    if bytes[pos] == 0xFF {
                        let n = bytes[pos + 1];
                        if n == 0x00 || (0xD0..=0xD7).contains(&n) {
                            pos += 2; // stuffed 0xFF00 or restart marker
                            continue;
                        }
                        break; // a real marker — re-enter the outer loop
                    }
                    pos += 1;
                }
            }
            _ => {
                // Segment with a 2-byte length.
                let seg = u16::from_be_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?) as usize;
                if seg < 2 {
                    return None;
                }
                pos = pos.checked_add(seg)?;
            }
        }
    }
    None
}

/// Minimum appended-data size treated as suspicious. Below this a few trailing
/// bytes are likely benign padding, not a hidden payload.
const MIN_APPENDED_BYTES: usize = 16;

/// Camouflage (PRIORITY-1, Exact) concatenates its container after the carrier's
/// EOF marker. The appended blob begins with a fixed 6-byte signature
/// `00 00 XX ED CD 01` (`SIG1` at offset 0, `SIG2` at offset 3), verified
/// against zsteg's reference samples. The carrier itself is left byte-identical,
/// so this is detected purely from the trailer; near-zero false-positive risk on
/// clean files (a 5-fixed-byte tail at the first appended byte).
fn check_camouflage(path: &Path, fmt: &str) -> Option<Fingerprint> {
    let bytes = read_for_fingerprint(path)?;
    let eof = format_eof(&bytes, fmt)?;
    let trailer = bytes.get(eof..)?;
    (trailer.len() >= 6 && trailer[0..2] == [0x00, 0x00] && trailer[3..6] == [0xED, 0xCD, 0x01])
        .then(|| Fingerprint::exact("Camouflage"))
}

/// F5 (Heuristic) is built on the James R. Weeks `JpegEncoder`, which stamps a
/// distinctive comment (COM, marker FF FE) into the JPEG. Mainstream encoders
/// never emit this string, so its presence corroborates F5-family output. It is
/// Heuristic, not Exact: F5's comment is user-overridable and some builds
/// default to a GD-library mimic string instead, so a miss does not rule F5 out.
fn check_f5(path: &Path) -> Option<Fingerprint> {
    const MARKER: &[u8] = b"JPEG Encoder Copyright 1998, James R. Weeks and BioElectroMech";
    let bytes = read_for_fingerprint(path)?;
    bytes
        .windows(MARKER.len())
        .any(|w| w == MARKER)
        .then(|| Fingerprint::heuristic("F5"))
}

/// Generic append-after-EOF (Heuristic): any non-trivial data past the carrier's
/// logical end. Catches the whole class of "concatenate the payload" tools
/// (Camouflage, Xiao, Invisible Secrets, naive `cat`) that the Camouflage exact
/// check does not specifically match. Heuristic because some pipelines append
/// benign trailers; the verdict floors at Suspicious rather than deciding.
fn check_appended(path: &Path, fmt: &str) -> Option<Fingerprint> {
    let bytes = read_for_fingerprint(path)?;
    let eof = format_eof(&bytes, fmt)?;
    let trailer = bytes.get(eof..)?;
    (trailer.len() >= MIN_APPENDED_BYTES).then(|| Fingerprint::heuristic("appended data after EOF"))
}

/// A minimal reimplementation of `java.util.Random`'s 48-bit linear
/// congruential generator. OpenStego's default plugin scatters payload bits to
/// pixel positions drawn from this generator, so reproducing its exact stream
/// is the only way to locate the scattered header (see `check_openstego`).
struct JavaRandom {
    seed: u64,
}

impl JavaRandom {
    const MULT: u64 = 0x5_DEEC_E66D;
    const ADD: u64 = 0xB;
    const MASK: u64 = (1 << 48) - 1;

    fn new(seed: u64) -> Self {
        Self {
            seed: (seed ^ Self::MULT) & Self::MASK,
        }
    }

    fn next(&mut self, bits: u32) -> u32 {
        self.seed = self.seed.wrapping_mul(Self::MULT).wrapping_add(Self::ADD) & Self::MASK;
        (self.seed >> (48 - bits)) as u32
    }

    /// Equivalent to `java.util.Random.nextInt(bound)` for `bound > 0`. The
    /// power-of-two fast path consumes exactly one draw even when `bound == 1`
    /// (where it always returns 0); reproducing that consumption is essential
    /// to keep the stream aligned with OpenStego's generator.
    fn next_int(&mut self, bound: u32) -> u32 {
        if bound & bound.wrapping_neg() == bound {
            return ((u64::from(bound) * u64::from(self.next(31))) >> 31) as u32;
        }
        loop {
            let bits = self.next(31);
            let val = bits % bound;
            // The JDK rejects draws that would bias the modulo; the guard fires
            // only in the top sliver of the 31-bit range, almost never for our
            // bounds (image dimensions and 3).
            if bits - val + (bound - 1) < (1 << 31) {
                return val;
            }
        }
    }
}

/// OpenStego (default RandomLSB plugin, no password). OpenStego scatters each
/// payload bit to a pixel and channel chosen from a `java.util.Random` stream
/// seeded from the password; with no password that seed is the fixed constant
/// `98234782` (`StringUtil.passwordHash("")`). We replay that exact stream,
/// reconstruct the 9-byte `OPENSTEGO` header magic from the scattered LSBs and
/// confirm it. The magic is 72 bits, so a chance match on a clean image is
/// about 2^-72: this is an `Exact`-tier, decisive fingerprint. Password
/// protected OpenStego output is seeded from an MD5 of the password we cannot
/// predict, so by design only the default no-password embed is caught here.
fn check_openstego(path: &Path) -> Option<Fingerprint> {
    const MAGIC: &[u8; 9] = b"OPENSTEGO";
    const NO_PASSWORD_SEED: u64 = 98_234_782;
    // Generous per-bit redraw cap: real OpenStego covers have capacity far
    // above the 72 bits we read, so collisions are negligible; the cap only
    // bounds pathological tiny inputs that sit just above the capacity floor.
    const MAX_REDRAWS: u32 = 4096;

    let rgb = crate::utils::open_image_by_content(path).ok()?.to_rgb8();
    let (w, h) = rgb.dimensions();

    // The header is read at channelBitsUsed = 1 (one LSB per chosen channel),
    // so the 72-bit magic needs 72 distinct (pixel, channel) positions. A
    // carrier with fewer positions than that cannot be OpenStego output.
    let capacity = u64::from(w) * u64::from(h) * 3;
    if capacity < (MAGIC.len() as u64) * 8 {
        return None;
    }

    // OpenStego stores channels B, G, R; image-crate pixels are RGB, so channel
    // k reads RGB index BGR[k] (the same mapping LSBSteg uses above).
    const BGR: [usize; 3] = [2, 1, 0];

    let mut rng = JavaRandom::new(NO_PASSWORD_SEED);
    let mut used: HashSet<(u32, u32, u8)> = HashSet::new();
    let mut magic = [0u8; MAGIC.len()];
    for byte in &mut magic {
        let mut acc = 0u8;
        for _ in 0..8 {
            // Redraw until an unused (x, y, channel) appears — OpenStego's own
            // collision rejection. channelBitsUsed is 1, so the bit-position
            // draw is always 0 but is still consumed to keep the stream aligned.
            let mut found = None;
            for _ in 0..MAX_REDRAWS {
                let x = rng.next_int(w);
                let y = rng.next_int(h);
                let ch = rng.next_int(3) as u8;
                let _bit = rng.next_int(1); // always 0; consumes one draw
                if used.insert((x, y, ch)) {
                    found = Some((x, y, ch));
                    break;
                }
            }
            let (x, y, ch) = found?;
            let comp = rgb.get_pixel(x, y).0[BGR[ch as usize]];
            acc = (acc << 1) | (comp & 1);
        }
        *byte = acc;
    }

    (&magic == MAGIC).then(|| Fingerprint::exact("OpenStego"))
}

// ── Per-detector calibrated thresholds ───────────────────────────────────────

// Recalibrated 2026-06-14 on the UNION of Cassavia 2022 + BOSSbase 1.01 + a
// 5.6k ALASKA2 cover sample. The 2026-05-22 thresholds (Cassavia/BOSSbase only)
// leaked ~22% combined FPR on ALASKA2's JPEG-decompressed covers (domain shift);
// adding ALASKA2 to the clean distribution and relaxing to the documented ~4%
// combined-ensemble ceiling brings ALASKA2 FPR to ~4% (Cassavia 0.0%, BOSSbase
// 0.1%) while keeping LSB-replacement detection strong at moderate payloads
// (p=0.2: 94%, p>=0.3: 100%). Subtle embeds (p<=0.1) stay weak: the classical-
// detector ceiling, documented as the frontier. Thresholds are the per-detector
// scores whose OR over SPA/RS/WS = ~4% on the worst (ALASKA2) clean split.
// Sacred per Q-6 D: below these values, a detector returns clean.
const CHI_THRESHOLD: f64 = 0.884868;
const SPA_THRESHOLD: f64 = 0.376977;
const RS_THRESHOLD: f64 = 0.305266;
const ENTROPY_THRESHOLD: f64 = 0.999742;
const WS_THRESHOLD: f64 = 0.194851;

// ── Ensemble verdict ──────────────────────────────────────────────────────────

// Q-37 resolved post-calibration: chi² and LSB-entropy carry near-zero signal
// on natural-image covers (AUC ~0.53 / ~0.72) and nearly double the ensemble
// FPR without buying detection (sweep: ~0.3pp gain for ~70% more FPR). They
// are excluded from the verdict OR and weighted_score. SPA, RS and WS have
// near-identical AUC (~0.76 to 0.80), so they carry equal weight, which is now
// expressed as the mean over the detectors that actually ran rather than as
// three constants of 1/3. The constants only held while exactly three detectors
// always ran; a carrier with fewer would have been scored as though the absent
// ones returned zero, which reads as evidence of cleanliness that nobody
// gathered.

// The bands `overall_score` is read against. A report carries both a verdict
// and a score, and a consumer that has only the number must be able to recover
// the verdict from it: `score >= SUSPICIOUS_FLOOR` means not clean, and
// `score >= LIKELY_STEGO_FLOOR` means likely stego.
//
// That did not hold. The OR-logic below raises the verdict to Suspicious when
// any ONE of SPA, RS or WS crosses its own threshold, while the score is the
// mean of all three, so a single detector firing alone is divided by three. WS
// fires at 0.195; on its own that contributes about 0.065 to the mean. The
// verdict said suspicious and the score sat in the clean band.
//
// Measured 2026-09-15 over 1,040 analyses: 39 of them (3.75%) disagreed, every
// one of them suspicious-but-scoring-clean. Found while a third-party
// comparison thresholded the score and recorded 0% detection on an arm where
// this engine's own verdict was correct on every image.
const SUSPICIOUS_FLOOR: f64 = 0.25;
const LIKELY_STEGO_FLOOR: f64 = 0.55;

// A heuristic fingerprint corroborates more strongly than a lone detector, so
// it floors higher within the same band. Deliberate, and unchanged.
const FINGERPRINT_FLOOR: f64 = 0.40;

/// Whether a named detector's score contributes to the verdict.
///
/// Defined as "it has a calibrated threshold", which is the only condition that
/// matters and covers both reasons a detector might not count. Chi-squared and
/// LSB entropy have none, resolved post-calibration as Q-37: on natural-image
/// covers they carry near-zero signal (AUC about 0.53 and 0.72) and nearly double
/// the ensemble false-positive rate for about 0.3 percentage points of detection.
/// Audio's sample-pair detector has none either, because no calibration sweep has
/// been run for audio. Both are still computed and still reported, because a human
/// reading the numbers may want them; they simply do not vote.
///
/// Public because the CLI greys exactly these rows out, and it used to decide that
/// separately by matching two names while the engine decided it by position. Two
/// places deciding the same thing drifted, and the drift was visible: audio's
/// sample-pair row rendered as counting while the engine did not count it. One
/// function now answers it for both, so the display and the verdict cannot
/// disagree about which detectors counted.
pub fn test_counts_toward_verdict(name: &str) -> bool {
    detector_threshold(name).is_some()
}

/// The calibrated firing threshold for a named detector, or None when the
/// detector has no calibrated threshold on this carrier.
///
/// None is not "never fires by accident"; it is a statement that we have no
/// number we are entitled to compare against. The spatial thresholds were set
/// against a documented false-positive ceiling on a union of three corpora
/// (CLAUDE.md A3). No equivalent sweep has been run for audio, so the audio
/// detectors return None and the carrier is reported as not assessed rather than
/// judged against a figure borrowed from images.
fn detector_threshold(name: &str) -> Option<f64> {
    match name {
        "Sample Pair Analysis" => Some(SPA_THRESHOLD),
        "RS Analysis" => Some(RS_THRESHOLD),
        "Weighted Stego" => Some(WS_THRESHOLD),
        _ => None,
    }
}

fn ensemble(
    tests: &[TestResult],
    fingerprint: Option<&Fingerprint>,
    coverage: &Coverage,
) -> (Verdict, f64) {
    // An exact tool signature (magic bytes) is decisive on its own, and stays
    // decisive whatever the coverage: finding a thing is not weakened by the
    // other places you did not look. Note for anyone reading the display: when
    // this fires, no statistic below contributed to the verdict.
    if matches!(fingerprint, Some(fp) if fp.tier == FpTier::Exact) {
        return (Verdict::LikelyStego, 0.95);
    }

    if tests.is_empty() {
        // No detectors ran — a heuristic match alone is only corroborating.
        return match fingerprint {
            Some(_) => (Verdict::Suspicious, FINGERPRINT_FLOOR),
            None => (nothing_found(coverage), 0.0),
        };
    }

    // Q-37's exclusion is by NAME, not by position, and that is the whole point
    // of this block.
    //
    // It used to index `tests[1]`, `tests[2]`, `tests[4]` behind a
    // `tests.len() >= 5` guard, which silently did the opposite of what it says
    // on any format producing a different number of detectors. Audio produces
    // three, `[chi, spa, entropy]`, so the guard was false, `any_fires` could
    // never fire, and `weighted_score` fell through to the mean of ALL THREE.
    // Chi-squared and entropy are excluded precisely because they manufacture
    // false positives, and on audio they were the only two contributing, while
    // the one legitimate detector returned a constant zero. Measured on nine
    // provably clean recordings: nine of nine flagged, four of them as likely
    // stego, from a mean of (1.0000 + 0.0 + 0.9932) / 3 = 0.664 against a
    // LikelyStego floor of 0.55.
    //
    // Position is the wrong key for a rule about which detector a name refers
    // to. Matching the name cannot drift when a format produces a different set.
    // A detector counts only if it has a CALIBRATED THRESHOLD. That is one
    // condition doing two jobs, and both matter.
    //
    // It excludes chi-squared and entropy, which is Q-37, because they have no
    // threshold precisely for that reason. And it excludes any detector on a
    // carrier we have never calibrated, which is what audio is: a score with no
    // threshold is a number we are not entitled to compare against anything.
    //
    // Both halves have to gate the SCORE and not just the vote. Letting an
    // uncalibrated detector into `weighted_score` would walk the false positive
    // straight back in through the `>= SUSPICIOUS_FLOOR` branch below, which is
    // how the audio path flagged nine of nine clean recordings in the first
    // place: the two detectors with no threshold were the only ones contributing.
    let counted: Vec<(&TestResult, f64)> = tests
        .iter()
        .filter_map(|t| detector_threshold(&t.name).map(|limit| (t, limit)))
        .collect();

    let weighted_score = if counted.is_empty() {
        // Nothing calibrated ran. Zero is the right score because it is the only
        // honest one, and `nothing_found` reads the coverage to decide whether
        // that means clean or means we did not look.
        0.0
    } else {
        // Equal weights, as the calibration found; see the note on the
        // thresholds above for why this is a mean rather than fixed weights.
        counted.iter().map(|(t, _)| t.score).sum::<f64>() / counted.len() as f64
    };

    // OR-logic: any calibrated detector above its own threshold raises the
    // verdict to at least Suspicious.
    let any_fires = counted.iter().any(|(t, limit)| t.score > *limit);

    let verdict = if weighted_score >= LIKELY_STEGO_FLOOR {
        Verdict::LikelyStego
    } else if any_fires || weighted_score >= SUSPICIOUS_FLOOR {
        Verdict::Suspicious
    } else {
        // Nothing fired. Whether that means clean or means unassessed is a
        // question about what ran, not about the scores.
        nothing_found(coverage)
    };

    // A heuristic fingerprint corroborates: it cannot leave the verdict at a
    // negative, but, unlike an exact signature, it never forces LikelyStego.
    if fingerprint.is_some() && matches!(verdict, Verdict::Clean | Verdict::NotAssessed) {
        return (Verdict::Suspicious, weighted_score.max(FINGERPRINT_FLOOR));
    }

    let score = band_score(&verdict, weighted_score);
    (verdict, score)
}

/// The verdict for "no detector fired", which depends on whether the detectors
/// that ran were the ones this format needed.
///
/// Keeping this in one function rather than inlining the branch twice is
/// deliberate: it is the rule that stops a green tick appearing on a file the
/// engine cannot assess, and a rule worth one name is worth not duplicating.
fn nothing_found(coverage: &Coverage) -> Verdict {
    if coverage.adequate {
        Verdict::Clean
    } else {
        Verdict::NotAssessed
    }
}

/// Lift a score into the band its verdict implies, so the two agree.
///
/// Only ever raises, and only when the OR-logic has already decided the image
/// is suspicious on evidence the weighted mean dilutes. It never lowers a
/// score, so nothing that was flagged stops being flagged.
fn band_score(verdict: &Verdict, weighted_score: f64) -> f64 {
    match verdict {
        Verdict::LikelyStego => weighted_score.max(LIKELY_STEGO_FLOOR),
        Verdict::Suspicious => weighted_score.max(SUSPICIOUS_FLOOR),
        Verdict::Clean | Verdict::NotAssessed => weighted_score,
    }
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
        Verdict::NotAssessed => "verdict-not_assessed",
        Verdict::Suspicious => "verdict-suspicious",
        Verdict::LikelyStego => "verdict-likely_stego",
    };
    let verdict_label = match r.verdict {
        Verdict::Clean => "Nothing found",
        Verdict::NotAssessed => "Not assessed",
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

    /// Coverage for a container the spatial detectors genuinely cover, which is
    /// what the threshold and banding tests below are about. PNG is the honest
    /// choice: a JPEG would return inadequate coverage and turn every `Clean`
    /// expectation into `NotAssessed`, which is correct behaviour and would make
    /// those tests about the wrong thing.
    fn png() -> Coverage {
        Coverage::for_image("png")
    }

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

    /// Embed `header` bytes into a noisy cover using OpenStego's exact
    /// no-password scatter (seed 98234782, channelBitsUsed = 1), so the
    /// resulting PNG reads back through `check_openstego`. Bits are written
    /// MSB-first to match the read order.
    fn openstego_embed(w: u32, h: u32, header: &[u8]) -> std::path::PathBuf {
        let mut img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(w, h, |x, y| {
            let v = ((x * 7 + y * 13) % 256) as u8;
            Rgb([v, v.wrapping_add(40), v.wrapping_add(90)])
        });
        const BGR: [usize; 3] = [2, 1, 0];
        let mut rng = JavaRandom::new(98_234_782);
        let mut used: HashSet<(u32, u32, u8)> = HashSet::new();
        for &byte in header {
            for i in (0..8u8).rev() {
                let bitval = (byte >> i) & 1;
                let (x, y, ch) = loop {
                    let x = rng.next_int(w);
                    let y = rng.next_int(h);
                    let ch = rng.next_int(3) as u8;
                    let _ = rng.next_int(1);
                    if used.insert((x, y, ch)) {
                        break (x, y, ch);
                    }
                };
                let idx = BGR[ch as usize];
                let px = img.get_pixel_mut(x, y);
                px.0[idx] = (px.0[idx] & 0xFE) | bitval;
            }
        }
        let path = std::env::temp_dir().join(format!("openstego_synth_{w}x{h}.png"));
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

    // ── SPA detector (Phase 2.2 — Aletheia port) ───────────────────────────────

    /// Smooth low-frequency RGB cover (no LSB structure) — a natural-ish image
    /// for exercising Sample Pair Analysis.
    fn smooth_cover(w: u32, h: u32) -> Vec<u8> {
        let mut px = Vec::with_capacity((w * h * 3) as usize);
        for y in 0..h {
            for x in 0..w {
                let base =
                    128.0 + 60.0 * ((x as f64) / 9.0).sin() + 40.0 * ((y as f64) / 7.0).cos();
                for ch in 0..3 {
                    px.push((base + 9.0 * ch as f64).clamp(0.0, 255.0) as u8);
                }
            }
        }
        px
    }

    /// LSB-replace a pseudo-random `rate` fraction of samples with random bits
    /// (deterministic LCG — reproducible across runs).
    fn lsb_replace(mut px: Vec<u8>, rate: f64) -> Vec<u8> {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for s in px.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let pick = (state >> 33) as f64 / (1u64 << 31) as f64;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            if pick < rate {
                *s = (*s & 0xFE) | ((state >> 40) & 1) as u8;
            }
        }
        px
    }

    #[test]
    fn spa_clean_smooth_image_scores_low() {
        let score = spa_score(&smooth_cover(128, 128), 128);
        assert!(
            score < 0.20,
            "clean image SPA score should be low, got {score:.3}"
        );
    }

    #[test]
    fn spa_full_lsb_embed_scores_high() {
        let stego = lsb_replace(smooth_cover(128, 128), 1.0);
        let score = spa_score(&stego, 128);
        assert!(
            score > 0.60,
            "fully embedded image SPA score should be high, got {score:.3}"
        );
    }

    #[test]
    fn spa_estimate_increases_with_embedding_rate() {
        let cover = smooth_cover(128, 128);
        let s0 = spa_score(&cover, 128);
        let s_half = spa_score(&lsb_replace(cover.clone(), 0.5), 128);
        let s_full = spa_score(&lsb_replace(cover, 1.0), 128);
        assert!(
            s0 < s_half && s_half < s_full,
            "SPA estimate should grow with rate: clean={s0:.3} half={s_half:.3} full={s_full:.3}"
        );
    }

    // ── RS detector (Phase 2.3 — Aletheia port) ────────────────────────────────

    #[test]
    fn rs_clean_smooth_image_scores_low() {
        let (score, _) = rs_score_with_dist(&smooth_cover(96, 96), 96);
        assert!(
            score < 0.30,
            "clean image RS score should be low, got {score:.3}"
        );
    }

    #[test]
    fn rs_full_lsb_embed_scores_high() {
        let stego = lsb_replace(smooth_cover(96, 96), 1.0);
        let (score, _) = rs_score_with_dist(&stego, 96);
        assert!(
            score > 0.40,
            "fully embedded image RS score should be high, got {score:.3}"
        );
    }

    #[test]
    fn rs_estimate_increases_with_embedding_rate() {
        let cover = smooth_cover(96, 96);
        let (s0, _) = rs_score_with_dist(&cover, 96);
        let (s_full, _) = rs_score_with_dist(&lsb_replace(cover, 1.0), 96);
        assert!(
            s_full > s0,
            "RS estimate should grow with embedding: clean={s0:.3} full={s_full:.3}"
        );
    }

    // ── WS detector (Phase 2.4 — Aletheia port) ────────────────────────────────

    #[test]
    fn ws_clean_smooth_image_scores_low() {
        let score = ws_score(&smooth_cover(96, 96), 96);
        assert!(
            score < 0.30,
            "clean image WS score should be low, got {score:.3}"
        );
    }

    #[test]
    fn ws_full_lsb_embed_scores_high() {
        let score = ws_score(&lsb_replace(smooth_cover(96, 96), 1.0), 96);
        assert!(
            score > 0.50,
            "fully embedded image WS score should be high, got {score:.3}"
        );
    }

    #[test]
    fn ws_estimate_increases_with_embedding_rate() {
        let cover = smooth_cover(96, 96);
        let s0 = ws_score(&cover, 96);
        let s_full = ws_score(&lsb_replace(cover, 1.0), 96);
        assert!(
            s_full > s0,
            "WS estimate should grow with embedding: clean={s0:.3} full={s_full:.3}"
        );
    }

    /// The report carries a verdict and a score, and a consumer holding only
    /// the number must be able to recover the verdict from it. Pinned because
    /// it silently stopped being true: the OR-logic raises the verdict on one
    /// detector while the score divides that detector's evidence by three, so a
    /// lone WS hit produced `suspicious` with a score in the clean band. That
    /// cost a third-party comparison its result before the cause was found.
    #[test]
    fn score_always_lands_in_the_band_its_verdict_implies() {
        // The real detector names, because the ensemble keys on them. These
        // tests used a placeholder name and five positional slots, which is the
        // defect that let the audio path average two uncalibrated detectors into
        // a verdict: a dummy name passes a positional check and fails a named one.
        let named = |name: &str, score: f64| TestResult {
            name: name.into(),
            score,
            confidence: Confidence::Low,
            detail: String::new(),
            distribution: None,
        };
        // Index order is the order `analyse_image` builds them in.
        let mk_all = |scores: [f64; 5]| {
            [
                named("Chi-Squared", scores[0]),
                named("Sample Pair Analysis", scores[1]),
                named("RS Analysis", scores[2]),
                named("LSB Entropy", scores[3]),
                named("Weighted Stego", scores[4]),
            ]
        };
        // [chi, spa, rs, entropy, ws]. WS alone just over its 0.194851
        // threshold: the OR fires, the mean is about 0.2/3 = 0.067.
        let lone_ws = mk_all([0.0, 0.0, 0.0, 0.0, 0.20]);
        let (verdict, score) = ensemble(&lone_ws, None, &png());
        assert_eq!(
            verdict,
            Verdict::Suspicious,
            "one calibrated detector fired"
        );
        assert!(
            score >= SUSPICIOUS_FLOOR,
            "suspicious verdict scored {score}, which reads as clean"
        );

        // The same for SPA and RS alone, so the property is not WS-specific.
        for idx in [1usize, 2usize] {
            let mut scores = [0.0f64; 5];
            scores[idx] = 0.99;
            let t = mk_all(scores);
            let (v, s) = ensemble(&t, None, &png());
            assert_eq!(v, Verdict::Suspicious);
            assert!(s >= SUSPICIOUS_FLOOR, "detector {idx} scored {s}");
        }

        // And the bands stay mutually exclusive at the top end.
        let (v, s) = ensemble(&mk_all([0.8, 0.8, 0.8, 0.8, 0.8]), None, &png());
        assert_eq!(v, Verdict::LikelyStego);
        assert!(s >= LIKELY_STEGO_FLOOR);

        // A clean result is never lifted: nothing here invents suspicion.
        let (v, s) = ensemble(&mk_all([0.02, 0.02, 0.02, 0.02, 0.02]), None, &png());
        assert_eq!(v, Verdict::Clean);
        assert!(s < SUSPICIOUS_FLOOR, "clean verdict scored {s}");
    }

    #[test]
    fn ensemble_thresholds_are_correct() {
        // The real detector names, because the ensemble keys on them. These
        // tests used a placeholder name and five positional slots, which is the
        // defect that let the audio path average two uncalibrated detectors into
        // a verdict: a dummy name passes a positional check and fails a named one.
        let named = |name: &str, score: f64| TestResult {
            name: name.into(),
            score,
            confidence: Confidence::Low,
            detail: String::new(),
            distribution: None,
        };
        // Index order is the order `analyse_image` builds them in.
        let mk_all = |scores: [f64; 5]| {
            [
                named("Chi-Squared", scores[0]),
                named("Sample Pair Analysis", scores[1]),
                named("RS Analysis", scores[2]),
                named("LSB Entropy", scores[3]),
                named("Weighted Stego", scores[4]),
            ]
        };
        // Detector array is [chi, spa, rs, entropy, ws] — 5 elements. Clean
        // test value (0.02) sits below every calibrated threshold (min = WS
        // 0.040); suspicious (0.40) exceeds them all; stego (0.80) crosses
        // the LikelyStego score cutoff of 0.55 on the weighted mean too.
        let (v_clean, _) = ensemble(&mk_all([0.02, 0.02, 0.02, 0.02, 0.02]), None, &png());
        let (v_susp, _) = ensemble(&mk_all([0.40, 0.40, 0.40, 0.40, 0.40]), None, &png());
        let (v_stego, _) = ensemble(&mk_all([0.80, 0.80, 0.80, 0.80, 0.80]), None, &png());
        assert_eq!(v_clean, Verdict::Clean);
        assert_eq!(v_susp, Verdict::Suspicious);
        assert_eq!(v_stego, Verdict::LikelyStego);

        // An exact tool signature is decisive regardless of detector scores.
        let exact = Fingerprint::exact("OpenStego");
        let (v_fp, s_fp) = ensemble(&mk_all([0.0, 0.0, 0.0, 0.0, 0.0]), Some(&exact), &png());
        assert_eq!(v_fp, Verdict::LikelyStego);
        assert!(s_fp > 0.9);

        // A heuristic fingerprint corroborates — it lifts a Clean verdict to
        // Suspicious but never on its own forces LikelyStego.
        let heuristic = Fingerprint::heuristic("LSBSteg");
        let (v_h, _) = ensemble(&mk_all([0.0, 0.0, 0.0, 0.0, 0.0]), Some(&heuristic), &png());
        assert_eq!(v_h, Verdict::Suspicious);
    }

    #[test]
    fn java_random_matches_jdk_reference() {
        // Reference values from an independent java.util.Random for seed
        // 98234782 — pins our LCG against the JDK without going through the
        // read path (so the detection tests below are not self-referential).
        let mut r = JavaRandom::new(98_234_782);
        assert_eq!(
            [r.next(31), r.next(31), r.next(31), r.next(31)],
            [1_575_575_240, 2_094_774_454, 1_062_897_968, 1_329_206_273]
        );
        let mut r = JavaRandom::new(98_234_782);
        let mut seq = Vec::new();
        for _ in 0..3 {
            seq.push(r.next_int(256));
            seq.push(r.next_int(256));
            seq.push(r.next_int(3));
            seq.push(r.next_int(1));
        }
        assert_eq!(seq, [187, 249, 2, 0, 164, 172, 1, 0, 109, 148, 2, 0]);
    }

    #[test]
    fn detects_openstego_no_password() {
        let path = openstego_embed(64, 64, b"OPENSTEGO");
        assert_eq!(
            check_openstego(&path),
            Some(Fingerprint::exact("OpenStego"))
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn openstego_clean_image_no_false_positive() {
        let clean = clean_png("openstego_clean.png");
        assert_eq!(check_openstego(&clean), None);
        std::fs::remove_file(&clean).ok();
        // A cover carrying a different scattered magic must not match.
        let wrong = openstego_embed(64, 64, b"NOTSTEGO!");
        assert_eq!(check_openstego(&wrong), None);
        std::fs::remove_file(&wrong).ok();
    }

    #[test]
    fn openstego_tiny_image_below_capacity_is_none() {
        // 4x4x3 = 48 positions < 72 magic bits: the capacity guard returns
        // None before any RNG draw, so no unbounded redraw loop can occur.
        let path = std::env::temp_dir().join("openstego_tiny.png");
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_fn(4, 4, |_, _| Rgb([1, 2, 3]));
        img.save(&path).unwrap();
        assert_eq!(check_openstego(&path), None);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn analyse_flags_openstego_as_exact() {
        let path = openstego_embed(96, 96, b"OPENSTEGO");
        let report = run_analysis(&path).unwrap();
        assert_eq!(report.tool_fingerprint_tier.as_deref(), Some("exact"));
        assert!(report.tool_fingerprint.unwrap().contains("OpenStego"));
        assert_eq!(report.verdict, Verdict::LikelyStego);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    #[ignore = "needs the real OpenStego sample via STEGCORE_OPENSTEGO_SAMPLE"]
    fn detects_real_openstego_sample() {
        let p = std::env::var("STEGCORE_OPENSTEGO_SAMPLE").unwrap();
        assert_eq!(
            check_openstego(std::path::Path::new(&p)),
            Some(Fingerprint::exact("OpenStego"))
        );
    }

    /// A minimal valid PNG: signature + a zero-length IHDR-ish chunk + IEND.
    fn minimal_png() -> Vec<u8> {
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        p.extend_from_slice(&[0, 0, 0, 0]); // chunk length 0
        p.extend_from_slice(b"IEND");
        p.extend_from_slice(&[0xae, 0x42, 0x60, 0x82]); // CRC
        p
    }

    #[test]
    fn format_eof_parses_each_format() {
        let png = minimal_png();
        assert_eq!(format_eof(&png, "png"), Some(png.len()));

        // JPEG: SOI, an APP0 segment (len incl. 2-byte length field), then EOI.
        let jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0xAA, 0xBB, 0xFF, 0xD9];
        assert_eq!(format_eof(&jpg, "jpg"), Some(jpg.len()));
        assert_eq!(format_eof(&jpg, "jpeg"), Some(jpg.len()));

        let mut bmp = vec![0u8; 60];
        bmp[0] = b'B';
        bmp[1] = b'M';
        bmp[2..6].copy_from_slice(&60u32.to_le_bytes());
        assert_eq!(format_eof(&bmp, "bmp"), Some(60));
        bmp[2..6].copy_from_slice(&9999u32.to_le_bytes()); // bogus oversized size
        assert_eq!(format_eof(&bmp, "bmp"), None);

        assert_eq!(format_eof(&png, "webp"), None); // unhandled format
        assert_eq!(format_eof(b"not a png", "png"), None); // bad signature
        assert_eq!(format_eof(&[0xFF, 0xD8, 0x00], "jpg"), None); // truncated marker
    }

    #[test]
    fn format_eof_ignores_marker_bytes_in_appended_payload() {
        // The end must be found by parsing, not by searching for the marker: a
        // payload that itself contains IEND / FF D9 must not move the detected
        // end (the evasion the parser closes).
        let mut png = minimal_png();
        let real_end = png.len();
        png.extend_from_slice(b"....IEND....more appended payload bytes here....");
        assert_eq!(format_eof(&png, "png"), Some(real_end));

        let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0xAA, 0xBB, 0xFF, 0xD9];
        let real_end = jpg.len();
        jpg.extend_from_slice(&[0x00, 0xFF, 0xD9, 0x11, 0x22, 0xFF, 0xD9, 0x33]);
        assert_eq!(format_eof(&jpg, "jpg"), Some(real_end));
    }

    /// Save a small valid PNG to a temp path and return it.
    fn tmp_png(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let img: ImageBuffer<Rgb<u8>, Vec<u8>> =
            ImageBuffer::from_fn(8, 8, |_, _| Rgb([10, 20, 30]));
        img.save(&path).unwrap();
        path
    }

    #[test]
    fn camouflage_exact_on_trailer_signature() {
        let path = tmp_png("camo_sig.png");
        let mut bytes = std::fs::read(&path).unwrap();
        // 00 00 XX ED CD 01 + filler -> Camouflage signature.
        bytes.extend_from_slice(&[0x00, 0x00, 0x42, 0xED, 0xCD, 0x01, 0, 0, 0, 0, 0, 0]);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            check_camouflage(&path, "png"),
            Some(Fingerprint::exact("Camouflage"))
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn camouflage_none_without_signature() {
        let path = tmp_png("camo_clean.png");
        assert_eq!(check_camouflage(&path, "png"), None); // no trailer
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn appended_heuristic_above_threshold_only() {
        let path = tmp_png("append.png");
        assert_eq!(check_appended(&path, "png"), None); // clean: nothing trailing

        let mut b = std::fs::read(&path).unwrap();
        b.extend_from_slice(b"tiny"); // < MIN_APPENDED_BYTES
        std::fs::write(&path, &b).unwrap();
        assert_eq!(check_appended(&path, "png"), None);

        let mut b = std::fs::read(&path).unwrap();
        b.extend_from_slice(b"0123456789abcdefXYZ"); // >= MIN_APPENDED_BYTES total trailer
        std::fs::write(&path, &b).unwrap();
        assert_eq!(
            check_appended(&path, "png"),
            Some(Fingerprint::heuristic("appended data after EOF"))
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn f5_heuristic_on_weeks_comment() {
        let path = std::env::temp_dir().join("f5.jpg");
        let mut bytes = vec![0xFF, 0xD8];
        bytes.extend_from_slice(b"JPEG Encoder Copyright 1998, James R. Weeks and BioElectroMech");
        bytes.extend_from_slice(&[0xFF, 0xD9]);
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(check_f5(&path), Some(Fingerprint::heuristic("F5")));

        std::fs::write(&path, [0xFFu8, 0xD8, 0x11, 0x22, 0xFF, 0xD9]).unwrap();
        assert_eq!(check_f5(&path), None); // no marker
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn read_for_fingerprint_reads_small_file() {
        let path = std::env::temp_dir().join("rf.bin");
        std::fs::write(&path, b"hello").unwrap();
        assert_eq!(read_for_fingerprint(&path).as_deref(), Some(&b"hello"[..]));
        std::fs::remove_file(&path).ok();
        assert_eq!(read_for_fingerprint(&path), None); // missing file
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

    // ── Streaming audio detectors ───────────────────────────────────────────
    //
    // The contract is exactness: the streaming accumulators must produce the
    // same f64 the whole-file detectors produced, not merely a close one, or
    // every calibrated audio threshold shifts underneath us. Each test below
    // compares against the whole-file functions, which the image and FLAC
    // paths still use, so they stay the reference rather than becoming dead
    // code nobody can check against.

    /// Write a WAV holding the given samples, so a streaming read has
    /// something with awkward content (not a smooth sine) to chew on.
    fn wav_with(name: &str, bits: u16, channels: u16, samples: &[i32]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        let spec = hound::WavSpec {
            channels,
            sample_rate: 44100,
            bits_per_sample: bits,
            sample_format: hound::SampleFormat::Int,
        };
        let mut writer = hound::WavWriter::create(&path, spec).unwrap();
        for &s in samples {
            writer.write_sample(s).unwrap();
        }
        writer.finalize().unwrap();
        path
    }

    /// Pseudo-random samples with a fixed seed, so a failure is reproducible.
    fn lcg_samples(n: usize, bits: u16) -> Vec<i32> {
        let span: i64 = 1 << (bits - 1);
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        (0..n)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let v = ((state >> 33) as i64 % span) - span / 2;
                v as i32
            })
            .collect()
    }

    /// The one audio detector, measured over a slice instead of over the reader.
    ///
    /// This is the reference the reader path is checked against: the statistics
    /// have one implementation, so the only thing left to prove about the reader
    /// is that it delivers the same samples with the same channel layout.
    fn slice_tests(samples: &[i32], channels: usize, bits: u16) -> TestResult {
        let source = crate::audio_analysis::SliceSource::new(samples, channels, bits);
        audio_spa_result(&crate::audio_analysis::analyse_stream(source).unwrap())
    }

    fn assert_same_test(streamed: &TestResult, reference: &TestResult) {
        assert_eq!(streamed.name, reference.name);
        assert_eq!(
            streamed.score.to_bits(),
            reference.score.to_bits(),
            "{}: reader {} vs slice {}",
            streamed.name,
            streamed.score,
            reference.score
        );
        assert_eq!(streamed.detail, reference.detail, "detail text diverged");
        let sd = streamed.distribution.as_ref().unwrap();
        let rd = reference.distribution.as_ref().unwrap();
        assert_eq!(sd.len(), rd.len(), "bin count");
        for (a, b) in sd.iter().zip(rd) {
            assert_eq!(a.label, b.label, "bin label");
            assert_eq!(a.observed.to_bits(), b.observed.to_bits(), "observed");
        }
    }

    #[test]
    fn the_reader_path_agrees_with_the_slice_path_across_sample_widths() {
        // 8-bit mono and 16-bit stereo, at a length that is not a whole multiple
        // of the chunk size, so the carried-over previous sample and the carried
        // channel phase are both exercised across a chunk edge.
        let n = crate::wav::CHUNK_SAMPLES * 2 + 1234;
        for (bits, channels) in [(8u16, 1u16), (16, 2)] {
            let samples = lcg_samples(n, bits);
            let path = wav_with(
                &format!("stream_{bits}_{channels}.wav"),
                bits,
                channels,
                &samples,
            );
            let (spec, streamed) = stream_wav_tests(crate::wav::source(&path).unwrap()).unwrap();
            assert_eq!(spec.channels, channels);
            assert_eq!(streamed.len(), 1, "audio produces one detector");
            assert_same_test(
                &streamed[0],
                &slice_tests(&samples, channels as usize, bits),
            );
            std::fs::remove_file(&path).ok();
        }
    }

    /// The test that fails on the three-channel assumption.
    ///
    /// The accumulator this replaced partitioned samples with `index % 3` and held
    /// `[u64; 3]` of per-channel state, an RGB layout applied to audio, whatever
    /// the header said. One bin per declared channel is the observable that cannot
    /// survive that: a stereo file reported three.
    #[test]
    fn the_channel_count_comes_from_the_header_not_from_a_three_channel_assumption() {
        for channels in [1u16, 2, 4] {
            let samples = lcg_samples(40_000 * channels as usize, 16);
            let path = wav_with(&format!("stream_ch_{channels}.wav"), 16, channels, &samples);
            let (_spec, tests) = stream_wav_tests(crate::wav::source(&path).unwrap()).unwrap();
            let bins = tests[0].distribution.as_ref().unwrap();
            assert_eq!(
                bins.len(),
                channels as usize,
                "a {channels}-channel file reported {} channels",
                bins.len()
            );
            for (i, b) in bins.iter().enumerate() {
                assert_eq!(b.label, format!("Ch {i}"));
            }
            std::fs::remove_file(&path).ok();
        }
    }

    /// A three-way split over a two-channel file does not merely blur the answer.
    ///
    /// Measured on a 13 minute real stereo recording, first million frames: the
    /// estimate read 0.234 and 0.365 per channel with the header honoured and 0.705
    /// to 0.710 under the three-way split, against 0.917 and 0.937 for the same
    /// file fully LSB-replaced. The synthetic stereo fixture below reproduces the
    /// same effect, and this test pins the direction of it: pairing samples that
    /// are not temporally adjacent in one channel destroys the correlation the
    /// estimate reads, so the wrong split inflates a clean file.
    #[test]
    fn the_three_channel_split_inflates_a_clean_stereo_estimate() {
        // Left is a smooth ramp, right is a different smooth ramp at another rate,
        // so the two channels are individually correlated and jointly unrelated.
        // Interleaving them and splitting three ways mixes both into every bucket.
        let frames = 200_000usize;
        let mut samples: Vec<i32> = Vec::with_capacity(frames * 2);
        for i in 0..frames {
            samples.push(((i as i64 * 3) % 20_000) as i32 - 10_000);
            samples.push(((i as i64 * 11) % 9_000) as i32 - 4_500);
        }
        let honoured = slice_tests(&samples, 2, 16).score;
        let assumed = slice_tests(&samples, 3, 16).score;
        assert!(
            assumed > honoured + 0.1,
            "the three-way split read {assumed:.6} against {honoured:.6} for the \
             header's two channels; if that gap has closed the fixture no longer \
             separates the two layouts and this test is no longer measuring anything"
        );
    }

    /// Decimation keeps whole frames, so a channel cannot leak into its neighbour.
    ///
    /// A stride counted in interleaved samples rotates the channel assignment
    /// whenever it shares no factor with the channel count. Channel 0 here is
    /// constant, so a single leaked sample from channel 1 is visible: a constant
    /// channel has an estimate of exactly zero and nothing else does.
    #[test]
    fn a_decimated_read_keeps_whole_frames() {
        let frames = 60_000usize;
        let mut samples: Vec<i32> = Vec::with_capacity(frames * 2);
        for i in 0..frames {
            samples.push(1234);
            samples.push(((i as i64 * 7919) % 20_000) as i32 - 10_000);
        }
        let path = wav_with("stream_frames.wav", 16, 2, &samples);
        for stride in [2usize, 3, 7, 1000] {
            let source = crate::wav::source(&path).unwrap().with_frame_stride(stride);
            let (_spec, tests) = stream_wav_tests(source).unwrap();
            let bins = tests[0].distribution.as_ref().unwrap();
            assert_eq!(bins.len(), 2, "stride {stride} changed the channel count");
            assert_eq!(
                bins[0].observed, 0.0,
                "stride {stride}: a constant channel 0 read {}, so a sample from \
                 channel 1 reached it",
                bins[0].observed
            );
            assert_ne!(
                bins[1].observed, 0.0,
                "stride {stride}: channel 1 is not constant and must not read zero"
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn short_and_empty_audio_files_measure_rather_than_fail() {
        for n in [0usize, 1, 5, 47, 63, 64] {
            let samples = lcg_samples(n, 16);
            let path = wav_with(&format!("stream_short_{n}.wav"), 16, 1, &samples);
            let (_spec, tests) = stream_wav_tests(crate::wav::source(&path).unwrap()).unwrap();
            assert_eq!(tests.len(), 1);
            assert!(
                tests[0].score.is_finite(),
                "{n} samples produced {}",
                tests[0].score
            );
            if n == 0 {
                assert_eq!(tests[0].score, 0.0, "a file with no audio claims nothing");
            }
            assert_same_test(&tests[0], &slice_tests(&samples, 1, 16));
            std::fs::remove_file(&path).ok();
        }
    }

    #[test]
    fn a_wav_too_short_to_measure_no_longer_panics() {
        // Five samples used to make entropy_distribution index a slice from 6,
        // which panicked, was caught, and was reported to the user as a corrupt
        // file. That detector is gone from the audio path; the file must still
        // analyse rather than fail.
        let path = wav_with("stream_tiny_five.wav", 8, 1, &[1, 2, 3, 4, 5]);
        let json = analyse(&path).expect("a five-sample WAV must analyse, not fail");
        let report: AnalysisReport = serde_json::from_str(&json).unwrap();
        let spa = report
            .tests
            .iter()
            .find(|t| t.name == "Audio Sample Pair Analysis")
            .expect("the audio detector must be reported");
        assert!(spa.score.is_finite());
        assert_eq!(spa.distribution.as_ref().unwrap().len(), 1);
        std::fs::remove_file(&path).ok();
    }

    /// Audio reports the one detector it has, and no uncalibrated one beside it.
    ///
    /// Chi-squared and LSB entropy were on the audio path and counted toward
    /// nothing, which is why they are gone. If either comes back, the second decode
    /// pass comes back with it and the Q-37 exclusion is carrying two detectors
    /// that exist only to be discarded.
    #[test]
    fn audio_reports_only_the_detector_that_could_ever_count() {
        let samples = lcg_samples(100_000, 16);
        let path = wav_with("stream_only_spa.wav", 16, 2, &samples);
        let report: AnalysisReport = serde_json::from_str(&analyse(&path).unwrap()).unwrap();
        let names: Vec<&str> = report.tests.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["Audio Sample Pair Analysis"]);
        // Reported, never judged: no audio corpus has been calibrated.
        assert!(!test_counts_toward_verdict(&report.tests[0].name));
        assert!(matches!(report.tests[0].confidence, Confidence::Low));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    #[ignore = "temporary wall-time probe; needs STEGCORE_BENCH_WAV"]
    fn audio_wall_time_probe() {
        let p = std::path::PathBuf::from(std::env::var("STEGCORE_BENCH_WAV").unwrap());
        let _ = analyse(&p).unwrap();
        let mut t: Vec<f64> = Vec::new();
        for _ in 0..5 {
            let s = std::time::Instant::now();
            let _ = analyse(&p).unwrap();
            t.push(s.elapsed().as_secs_f64());
        }
        t.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "PROBE analyse min={:.3} med={:.3} max={:.3}",
            t[0], t[2], t[4]
        );
        let mut f: Vec<f64> = Vec::new();
        let _ = analyse_fast(&p).unwrap();
        for _ in 0..5 {
            let s = std::time::Instant::now();
            let _ = analyse_fast(&p).unwrap();
            f.push(s.elapsed().as_secs_f64());
        }
        f.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!("PROBE fast min={:.3} med={:.3} max={:.3}", f[0], f[2], f[4]);
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
    fn ensemble_empty_returns_clean() {
        let (v, s) = ensemble(&[], None, &png());
        assert_eq!(v, Verdict::Clean);
        assert_eq!(s, 0.0);
    }

    /// The whole reason `ensemble` takes a coverage argument: finding nothing in a
    /// container we did not actually search is not a clean result, and reporting
    /// it as one is the false negative that let steghide through 120 times out of
    /// 120. The spatial detectors read the LSB plane, JPEG steganography lives in
    /// the DCT coefficients, and a JPEG's LSB plane is smoothed by decompression,
    /// so a near-zero score there is an absence of evidence rather than evidence
    /// of absence.
    #[test]
    fn nothing_found_in_an_unsearched_container_is_not_reported_as_clean() {
        // The real detector names, because the ensemble keys on them. These
        // tests used a placeholder name and five positional slots, which is the
        // defect that let the audio path average two uncalibrated detectors into
        // a verdict: a dummy name passes a positional check and fails a named one.
        let named = |name: &str, score: f64| TestResult {
            name: name.into(),
            score,
            confidence: Confidence::Low,
            detail: String::new(),
            distribution: None,
        };
        // Index order is the order `analyse_image` builds them in.
        let mk_all = |scores: [f64; 5]| {
            [
                named("Chi-Squared", scores[0]),
                named("Sample Pair Analysis", scores[1]),
                named("RS Analysis", scores[2]),
                named("LSB Entropy", scores[3]),
                named("Weighted Stego", scores[4]),
            ]
        };
        let quiet = mk_all([0.02, 0.02, 0.02, 0.02, 0.02]);

        let (png_verdict, _) = ensemble(&quiet, None, &Coverage::for_image("png"));
        let (jpeg_verdict, _) = ensemble(&quiet, None, &Coverage::for_image("jpg"));

        assert_eq!(
            png_verdict,
            Verdict::Clean,
            "a container we do search, with nothing in it, is a clean result"
        );
        assert_eq!(
            jpeg_verdict,
            Verdict::NotAssessed,
            "a JPEG's DCT coefficients are never examined, so silence there \
             must not be reported as a clean result"
        );
    }

    /// Inadequate coverage must not invent suspicion either. It downgrades a
    /// claim we cannot support; it does not upgrade one we can.
    #[test]
    fn inadequate_coverage_does_not_manufacture_a_positive() {
        // The real detector names, because the ensemble keys on them. These
        // tests used a placeholder name and five positional slots, which is the
        // defect that let the audio path average two uncalibrated detectors into
        // a verdict: a dummy name passes a positional check and fails a named one.
        let named = |name: &str, score: f64| TestResult {
            name: name.into(),
            score,
            confidence: Confidence::Low,
            detail: String::new(),
            distribution: None,
        };
        // Index order is the order `analyse_image` builds them in.
        let mk_all = |scores: [f64; 5]| {
            [
                named("Chi-Squared", scores[0]),
                named("Sample Pair Analysis", scores[1]),
                named("RS Analysis", scores[2]),
                named("LSB Entropy", scores[3]),
                named("Weighted Stego", scores[4]),
            ]
        };
        let loud = mk_all([0.80, 0.80, 0.80, 0.80, 0.80]);

        let (v, _) = ensemble(&loud, None, &Coverage::for_image("jpg"));
        assert_eq!(
            v,
            Verdict::LikelyStego,
            "a detector that did fire still counts, whatever else went unchecked"
        );
    }

    #[test]
    fn verdict_serialises_correctly() {
        let json = serde_json::to_string(&Verdict::LikelyStego).unwrap();
        assert_eq!(json, "\"likely_stego\"");
        let json = serde_json::to_string(&Verdict::Clean).unwrap();
        assert_eq!(json, "\"clean\"");
    }

    // ── Private helper coverage (v4.0.1 engine >=90% gate) ────────────────────
    //
    // Per-detector confidence functions, sampling helpers, distribution
    // builders. These get exercised indirectly by the integration tests,
    // but explicit unit tests give the per-crate gate the headroom it
    // needs and document the contract each helper enforces.

    #[test]
    fn chi_confidence_bands() {
        let (c, msg) = chi_confidence(CHI_THRESHOLD + 0.01);
        assert!(matches!(c, Confidence::High));
        assert!(msg.contains("highly uniform"));

        let (c, msg) = chi_confidence(CHI_THRESHOLD / 2.0 + 0.001);
        assert!(matches!(c, Confidence::Medium));
        assert!(msg.contains("mild anomaly"));

        let (c, msg) = chi_confidence(0.0);
        assert!(matches!(c, Confidence::Low));
        assert!(msg.contains("natural"));
    }

    #[test]
    fn spa_confidence_bands() {
        let (c, _) = spa_confidence(SPA_THRESHOLD + 0.001);
        assert!(matches!(c, Confidence::High));
        let (c, _) = spa_confidence(SPA_THRESHOLD / 2.0 + 0.001);
        assert!(matches!(c, Confidence::Medium));
        let (c, _) = spa_confidence(0.0);
        assert!(matches!(c, Confidence::Low));
    }

    #[test]
    fn rs_confidence_bands() {
        let (c, _) = rs_confidence(RS_THRESHOLD + 0.001);
        assert!(matches!(c, Confidence::High));
        let (c, _) = rs_confidence(RS_THRESHOLD / 2.0 + 0.001);
        assert!(matches!(c, Confidence::Medium));
        let (c, _) = rs_confidence(0.0);
        assert!(matches!(c, Confidence::Low));
    }

    #[test]
    fn ws_confidence_bands() {
        let (c, _) = ws_confidence(WS_THRESHOLD + 0.001);
        assert!(matches!(c, Confidence::High));
        let (c, _) = ws_confidence(WS_THRESHOLD / 2.0 + 0.001);
        assert!(matches!(c, Confidence::Medium));
        let (c, _) = ws_confidence(0.0);
        assert!(matches!(c, Confidence::Low));
    }

    #[test]
    fn entropy_confidence_bands() {
        let (c, _) = entropy_confidence(ENTROPY_THRESHOLD + 0.0001);
        assert!(matches!(c, Confidence::High));
        let (c, _) = entropy_confidence(ENTROPY_THRESHOLD / 2.0 + 0.001);
        assert!(matches!(c, Confidence::Medium));
        let (c, _) = entropy_confidence(0.0);
        assert!(matches!(c, Confidence::Low));
    }

    #[test]
    fn sample_pixels_returns_all_when_input_tiny() {
        // <48 bytes triggers the small-input short-circuit.
        let pixels: Vec<u8> = (0..30).collect();
        let out = sample_pixels(&pixels, 0.5);
        assert_eq!(out, pixels, "tiny input should be returned verbatim");
    }

    #[test]
    fn sample_pixels_returns_all_when_ratio_high() {
        let pixels: Vec<u8> = (0..600).map(|i| (i & 0xFF) as u8).collect();
        let out = sample_pixels(&pixels, 1.0);
        assert_eq!(out, pixels, "ratio >= 1.0 should bypass sampling");
    }

    #[test]
    fn sample_pixels_shrinks_when_ratio_small() {
        let pixels: Vec<u8> = (0..900).map(|i| (i & 0xFF) as u8).collect();
        let out = sample_pixels(&pixels, 0.1);
        assert!(
            out.len() < pixels.len(),
            "sampling should shrink the buffer"
        );
        assert!(!out.is_empty(), "sampling should keep at least the minimum");
        assert_eq!(out.len() % 3, 0, "sampled output must stay pixel-aligned");
    }

    #[test]
    fn sample_rows_returns_all_when_width_zero() {
        let pixels: Vec<u8> = (0..600).map(|i| (i & 0xFF) as u8).collect();
        let out = sample_rows(&pixels, 0, 0.1);
        assert_eq!(out, pixels, "width 0 is defensive: return input unchanged");
    }

    #[test]
    fn sample_rows_returns_all_when_ratio_high() {
        let pixels: Vec<u8> = (0..600).map(|i| (i & 0xFF) as u8).collect();
        let out = sample_rows(&pixels, 60, 1.0);
        assert_eq!(out, pixels, "ratio >= 1.0 should bypass row sampling");
    }

    #[test]
    fn sample_rows_shrinks_when_ratio_small() {
        let pixels: Vec<u8> = (0..6000).map(|i| (i & 0xFF) as u8).collect();
        let out = sample_rows(&pixels, 60, 0.1);
        assert!(out.len() < pixels.len(), "row sampling should shrink");
    }

    #[test]
    fn compute_block_entropy_basic_shape() {
        // 100x100 RGB image -> 30000 byte pixel buffer.
        let pixels: Vec<u8> = (0..30000).map(|i| (i % 256) as u8).collect();
        let be = compute_block_entropy(&pixels, 100, 100);
        // Grid is fixed at 8 columns x 6 rows (heatmap renderer assumes
        // this shape).
        assert_eq!(be.cols, 8, "column count must be 8");
        assert_eq!(be.rows, 6, "row count must be 6");
        assert_eq!(be.values.len(), 48, "flat grid must be 8*6 = 48 cells");
        for v in &be.values {
            assert!((0.0..=1.0).contains(v), "entropy must be in [0,1]");
        }
    }

    #[test]
    fn compute_block_entropy_degenerate_dimensions() {
        // Tiny image (< block grid) still produces a 48-cell grid with each
        // cell either falling back to 0.5 (no pixels in block) or computed.
        let pixels: Vec<u8> = vec![128u8; 4 * 4 * 3];
        let be = compute_block_entropy(&pixels, 4, 4);
        assert_eq!(be.values.len(), 48);
        for v in &be.values {
            assert!((0.0..=1.0).contains(v));
        }
    }

    #[test]
    fn chi_distribution_returns_distribution_bins() {
        let values: Vec<u8> = (0..1024u32).map(|i| (i % 256) as u8).collect();
        let bins = chi_distribution(&values);
        assert!(!bins.is_empty(), "distribution should not be empty");
    }

    #[test]
    fn spa_distribution_returns_distribution_bins() {
        let values: Vec<u8> = (0..1500u32).map(|i| (i % 256) as u8).collect();
        let bins = spa_distribution(&values);
        assert!(!bins.is_empty(), "SPA distribution should not be empty");
    }

    #[test]
    fn html_escape_handles_empty_string() {
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn html_escape_handles_quote_chars() {
        let s = html_escape("a'b\"c");
        assert!(!s.contains('"'), "double quote should be escaped");
    }

    #[test]
    fn score_colour_low_high_boundary() {
        // 0.0 and 1.0 should not panic and map to known bucket colours.
        let zero = score_colour(0.0);
        let one = score_colour(1.0);
        assert!(zero.starts_with('#'));
        assert!(one.starts_with('#'));
    }

    // ── The audio detector's reported shape ───────────────────────────────────

    /// The bands this replaces sat at 0.30 and 0.65. They were image numbers used
    /// on audio and they are why nine of nine provably clean recordings were
    /// flagged. Confidence is now pinned Low whatever the estimate reads, because
    /// no audio corpus has been calibrated, and that is the property worth a test:
    /// a band reintroduced here would make a claim no measurement supports.
    #[test]
    fn the_audio_detector_never_claims_confidence_it_has_not_earned() {
        let cases: [(&[i32], usize); 3] = [
            (&[], 1),
            // Strongly correlated: a smooth ramp.
            (&[100, 101, 102, 103, 104, 105, 106, 107, 108, 109], 1),
            // Alternating, so adjacent samples are maximally far apart.
            (&[0, 30_000, 0, 30_000, 0, 30_000, 0, 30_000], 2),
        ];
        for (samples, channels) in cases {
            let r = slice_tests(samples, channels, 16);
            assert_eq!(r.name, "Audio Sample Pair Analysis");
            assert!(matches!(r.confidence, Confidence::Low), "{}", r.detail);
            assert!(
                (0.0..=1.0).contains(&r.score),
                "score {} out of range",
                r.score
            );
            assert!(
                r.detail.contains("no calibrated threshold"),
                "the detail must say the figure is not judged: {}",
                r.detail
            );
            assert_eq!(r.distribution.as_ref().unwrap().len(), channels);
        }
    }

    /// An estimate above one is clamped, and one below zero does not go negative.
    ///
    /// `spa_alpha` is a root of a quadratic and is not bounded by the mathematics:
    /// a degenerate channel can return a large negative number, and `score` is a
    /// field the report colours a bar from, so it has to stay inside its range.
    #[test]
    fn the_audio_score_stays_within_range_on_a_degenerate_channel() {
        // A pure alternation between two values drives the trace sets to the edge.
        let samples: Vec<i32> = (0..10_000)
            .map(|i| if i % 2 == 0 { -32_000 } else { 32_000 })
            .collect();
        let r = slice_tests(&samples, 1, 16);
        assert!((0.0..=1.0).contains(&r.score), "score was {}", r.score);
        // A constant channel carries no pairs to estimate from, so it claims zero.
        let flat = vec![7i32; 10_000];
        assert_eq!(slice_tests(&flat, 1, 16).score, 0.0);
    }

    // ── spa_score / aletheia_spa edges ────────────────────────────────────

    #[test]
    fn spa_score_handles_zero_width() {
        // width = 0 means we cannot compute stride, must return 0.0 safely.
        let pixels: Vec<u8> = vec![10u8; 90];
        assert_eq!(spa_score(&pixels, 0), 0.0);
    }

    #[test]
    fn spa_score_handles_input_smaller_than_two_strides() {
        // width 4 → stride 12; fewer than 24 bytes can't form pairs.
        let pixels: Vec<u8> = vec![10u8; 20];
        assert_eq!(spa_score(&pixels, 4), 0.0);
    }

    // ── catch_engine_panic ───────────────────────────────────────────────
    //
    // A caught panic is now reported as what it is, a failure inside Stegcore,
    // and the detail goes to a diagnostic file instead of into the user's face
    // or into nothing. Each test below points the diagnostic directory at a
    // temporary location so a test run never writes into the real one.

    /// Run `f` with the diagnostic directory pointed somewhere disposable, and
    /// hand back that directory so the test can inspect what landed in it.
    fn with_diagnostic_dir<R>(name: &str, f: impl FnOnce() -> R) -> (R, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("stegcore_diag_test_{name}"));
        std::fs::remove_dir_all(&dir).ok();
        // Single-threaded by necessity: the variable is process wide, so these
        // tests set it, use it and clear it rather than running in parallel with
        // each other. They are serialised by the lock below.
        let _guard = DIAG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("STEGCORE_DIAGNOSTIC_DIR", &dir);
        let out = f();
        std::env::remove_var("STEGCORE_DIAGNOSTIC_DIR");
        (out, dir)
    }

    static DIAG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn catch_engine_panic_passes_through_ok() {
        let r: Result<i32, StegError> = catch_engine_panic("test", Path::new("x"), || Ok(42));
        assert_eq!(r.unwrap(), 42);
    }

    #[test]
    fn catch_engine_panic_passes_through_err() {
        let r: Result<i32, StegError> =
            catch_engine_panic("test", Path::new("x"), || Err(StegError::EmptyPayload));
        assert!(matches!(r, Err(StegError::EmptyPayload)));
    }

    #[test]
    fn catch_engine_panic_captures_static_str_panic() {
        let (r, _dir) = with_diagnostic_dir("static", || {
            catch_engine_panic::<i32>("test", Path::new("x"), || {
                panic!("static panic message");
            })
        });
        match r {
            Err(StegError::CaughtPanic { detail, .. }) => {
                assert!(detail.contains("static panic"))
            }
            other => panic!("expected CaughtPanic, got {other:?}"),
        }
    }

    #[test]
    fn catch_engine_panic_captures_owned_string_panic() {
        let (r, _dir) = with_diagnostic_dir("owned", || {
            catch_engine_panic::<i32>("test", Path::new("x"), || {
                let msg = String::from("owned panic message");
                panic!("{msg}");
            })
        });
        match r {
            Err(StegError::CaughtPanic { detail, .. }) => {
                assert!(detail.contains("owned panic"))
            }
            other => panic!("expected CaughtPanic, got {other:?}"),
        }
    }

    #[test]
    fn catch_engine_panic_captures_non_string_panic_with_fallback() {
        // A non-string panic payload must still produce a clean error with a
        // stable fallback message that doesn't leak debug detail.
        let (r, _dir) = with_diagnostic_dir("nonstring", || {
            catch_engine_panic::<i32>("test", Path::new("x"), || {
                std::panic::panic_any(42i32);
            })
        });
        match r {
            Err(StegError::CaughtPanic { detail, .. }) => {
                assert!(detail.contains("panic in engine dependency"));
            }
            other => panic!("expected CaughtPanic with fallback, got {other:?}"),
        }
    }

    #[test]
    fn a_caught_panic_writes_a_diagnostic_naming_the_file_and_the_operation() {
        // The baseline requires every failure to leave a path a user can paste
        // into a bug report. Before this, the panic detail was dropped on the
        // floor and the user was told their file was corrupt.
        let (r, dir) = with_diagnostic_dir("contents", || {
            catch_engine_panic::<i32>("analyse", Path::new("/covers/holiday.png"), || {
                panic!("decoder fell over");
            })
        });
        let err = r.unwrap_err();
        let path = match &err {
            StegError::CaughtPanic { diagnostic, .. } => {
                diagnostic.clone().expect("a diagnostic must be written")
            }
            other => panic!("expected CaughtPanic, got {other:?}"),
        };
        assert!(
            path.exists(),
            "diagnostic file missing at {}",
            path.display()
        );
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("analyse"), "operation missing: {body}");
        assert!(body.contains("holiday.png"), "subject missing: {body}");
        assert!(
            body.contains("decoder fell over"),
            "panic detail missing: {body}"
        );
        assert!(
            body.contains("not necessarily a problem with the file"),
            "the file must say the input may be fine: {body}"
        );

        // And the message the user sees names the path, says it was us, and
        // does not repeat the panic text.
        let shown = err.to_string();
        assert!(shown.contains("Stegcore itself failed"), "{shown}");
        assert!(shown.contains(&path.display().to_string()), "{shown}");
        assert!(!shown.contains("decoder fell over"), "{shown}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_diagnostic_that_cannot_be_written_says_so_rather_than_pretending() {
        // Point the directory at something that cannot hold files. The error
        // still arrives, and its message admits there is no diagnostic.
        let _guard = DIAG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let blocker = std::env::temp_dir().join("stegcore_diag_blocker_file");
        std::fs::write(&blocker, b"not a directory").unwrap();
        std::env::set_var("STEGCORE_DIAGNOSTIC_DIR", blocker.join("under"));
        let r = catch_engine_panic::<i32>("analyse", Path::new("x"), || panic!("boom"));
        std::env::remove_var("STEGCORE_DIAGNOSTIC_DIR");
        std::fs::remove_file(&blocker).ok();
        match r {
            Err(e @ StegError::CaughtPanic { .. }) => {
                assert!(matches!(
                    &e,
                    StegError::CaughtPanic {
                        diagnostic: None,
                        ..
                    }
                ));
                assert!(e
                    .to_string()
                    .contains("No diagnostic file could be written"));
            }
            other => panic!("expected CaughtPanic, got {other:?}"),
        }
    }

    // ── rs_window_smoothness ─────────────────────────────────────────────

    #[test]
    fn rs_window_smoothness_zero_for_flat_window() {
        let flat = [100i32; 9];
        assert_eq!(rs_window_smoothness(&flat), 0);
    }

    #[test]
    fn rs_window_smoothness_increases_with_noise() {
        let flat = [100i32; 9];
        let noisy = [100, 150, 100, 150, 100, 150, 100, 150, 100];
        let s_flat = rs_window_smoothness(&flat);
        let s_noisy = rs_window_smoothness(&noisy);
        assert!(s_noisy > s_flat);
    }

    // ── public analyse + analyse_batch + generate_html_report ────────────

    #[test]
    fn analyse_returns_error_for_missing_file() {
        // catch_engine_panic preserves the underlying file-not-found error.
        let p = std::path::PathBuf::from("/tmp/stegcore-analysis-noexist-12345.png");
        let _ = std::fs::remove_file(&p);
        let r = analyse(&p);
        assert!(r.is_err());
    }

    #[test]
    fn analyse_batch_preserves_per_path_results() {
        let p1 = std::path::PathBuf::from("/tmp/stegcore-batch-noexist-1.png");
        let p2 = std::path::PathBuf::from("/tmp/stegcore-batch-noexist-2.png");
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
        let results = analyse_batch(&[p1.as_path(), p2.as_path()]);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_err()));
    }

    #[test]
    fn generate_html_report_from_empty_inputs_renders_envelope() {
        let html = generate_html_report(&[]);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("</html>"));
    }
}
