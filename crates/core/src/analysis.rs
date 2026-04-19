// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use crate::errors::StegError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── Types (mirrored from stegcore-engine) ────────────────────────────────────

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
pub struct TestResult {
    pub name: String,
    pub score: f64,
    pub confidence: Confidence,
    pub detail: String,
    /// Distribution data for charting — varies by test type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distribution: Option<Vec<DistBin>>,
}

/// A single bin in a histogram or distribution chart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistBin {
    pub label: String,
    pub expected: f64,
    pub observed: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub file: PathBuf,
    pub format: String,
    pub tests: Vec<TestResult>,
    pub verdict: Verdict,
    pub overall_score: f64,
    pub tool_fingerprint: Option<String>,
    /// Per-block entropy values for heatmap visualisation (row-major, 0.0–1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_entropy: Option<BlockEntropy>,
}

/// Grid of per-block entropy values for heatmap rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntropy {
    pub cols: usize,
    pub rows: usize,
    pub values: Vec<f64>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Analyse a single file for steganographic content.
pub fn analyse(path: &Path) -> Result<AnalysisReport, StegError> {
    let json_str = stegcore_engine::analysis::analyse(path).map_err(StegError::from)?;
    serde_json::from_str::<AnalysisReport>(&json_str).map_err(StegError::Json)
}

/// Fast preliminary analysis using 10% sampling.
pub fn analyse_fast(path: &Path) -> Result<AnalysisReport, StegError> {
    let json_str = stegcore_engine::analysis::analyse_fast(path).map_err(StegError::from)?;
    serde_json::from_str::<AnalysisReport>(&json_str).map_err(StegError::Json)
}

/// Analyse multiple files in parallel.
pub fn analyse_batch(paths: &[&Path]) -> Vec<Result<AnalysisReport, StegError>> {
    use rayon::prelude::*;
    paths.par_iter().map(|p| analyse(p)).collect()
}

/// Generate a self-contained HTML report from a set of analysis results.
pub fn generate_html_report(reports: &[AnalysisReport]) -> String {
    let rows: String = reports.iter().map(render_report_row).collect();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stegcore Analysis Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Ubuntu, sans-serif;
          background: #070d14; color: #e8eaf0; margin: 0; padding: 2rem; }}
  h1   {{ font-size: 1.5rem; font-weight: 500; letter-spacing: 0.1em; margin-bottom: 2rem; }}
  .file-block {{ background: #0d1520; border: 1px solid #1a2535; border-radius: 12px;
                  padding: 1.5rem; margin-bottom: 1.5rem; }}
  .file-name {{ font-size: 1rem; font-weight: 600; margin-bottom: 0.25rem; }}
  .file-meta {{ font-size: 0.8rem; color: #4a5568; margin-bottom: 1rem; }}
  .verdict {{ display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.3rem 0.8rem;
               border-radius: 6px; font-size: 0.85rem; font-weight: 600; margin-bottom: 1rem; }}
  .verdict-clean      {{ background: rgba(34,197,94,0.15); color: #22c55e; }}
  .verdict-suspicious {{ background: rgba(245,158,11,0.15); color: #f59e0b; }}
  .verdict-stego      {{ background: rgba(239,68,68,0.15);  color: #ef4444; }}
  .fingerprint {{ font-size: 0.8rem; color: #4a5568; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th    {{ text-align: left; color: #4a5568; font-weight: 500; padding: 0.4rem 0.5rem;
            border-bottom: 1px solid #1a2535; }}
  td    {{ padding: 0.5rem; border-bottom: 1px solid #1a253544; vertical-align: middle; }}
  .bar-bg  {{ background: #1a2535; border-radius: 4px; height: 6px; width: 140px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; }}
  .conf-low  {{ color: #4a5568; }} .conf-med {{ color: #f59e0b; }} .conf-high {{ color: #ef4444; }}
</style>
</head>
<body>
<h1>STEGCORE — Analysis Report</h1>
{rows}
</body>
</html>"#,
        rows = rows,
    )
}

// ── Internal HTML helpers ─────────────────────────────────────────────────────

fn render_report_row(r: &AnalysisReport) -> String {
    let verdict_class = match r.verdict {
        Verdict::Clean => "verdict-clean",
        Verdict::Suspicious => "verdict-suspicious",
        Verdict::LikelyStego => "verdict-stego",
    };
    let verdict_label = match r.verdict {
        Verdict::Clean => "✓ Clean",
        Verdict::Suspicious => "⚠ Suspicious",
        Verdict::LikelyStego => "✗ Likely Stego",
    };
    let fp = r
        .tool_fingerprint
        .as_deref()
        .map(|s| format!("<p class=\"fingerprint\">Signature: {}</p>", html_escape(s)))
        .unwrap_or_default();

    let test_rows: String = r.tests.iter().map(render_test_row).collect();

    format!(
        r#"<div class="file-block">
  <div class="file-name">{file}</div>
  <div class="file-meta">Format: {fmt} &nbsp;|&nbsp; Overall score: {score:.2}</div>
  <div class="verdict {vclass}">{vlabel}</div>
  {fp}
  <table>
    <tr><th>Detector</th><th>Score</th><th>Confidence</th><th>Detail</th></tr>
    {test_rows}
  </table>
</div>"#,
        file = html_escape(&r.file.display().to_string()),
        fmt = html_escape(&r.format),
        score = r.overall_score,
        vclass = verdict_class,
        vlabel = verdict_label,
        fp = fp,
        test_rows = test_rows,
    )
}

fn render_test_row(t: &TestResult) -> String {
    let score_pct = (t.score * 100.0).round() as u32;
    let bar_colour = score_colour(t.score);
    let conf_class = match t.confidence {
        Confidence::Low => "conf-low",
        Confidence::Medium => "conf-med",
        Confidence::High => "conf-high",
    };
    let conf_label = match t.confidence {
        Confidence::Low => "Low",
        Confidence::Medium => "Medium",
        Confidence::High => "High",
    };

    // Distribution chart SVG (if data available)
    let dist_svg = if let Some(ref bins) = t.distribution {
        render_dist_chart(bins)
    } else {
        String::new()
    };

    format!(
        r#"<tr>
  <td>{name}</td>
  <td>
    <div class="bar-bg">
      <div class="bar-fill" style="width:{pct}%;background:{colour}"></div>
    </div>
    <span style="font-size:0.75rem;color:#4a5568">{pct}%</span>
  </td>
  <td class="{cclass}">{clabel}</td>
  <td style="color:#4a5568">{detail}</td>
</tr>{dist_row}"#,
        name = html_escape(&t.name),
        pct = score_pct,
        colour = bar_colour,
        cclass = conf_class,
        clabel = conf_label,
        detail = html_escape(&t.detail),
        dist_row = if dist_svg.is_empty() {
            String::new()
        } else {
            format!(
                r#"<tr><td colspan="4" style="padding:8px 0">{}</td></tr>"#,
                dist_svg
            )
        },
    )
}

fn render_dist_chart(bins: &[DistBin]) -> String {
    if bins.is_empty() {
        return String::new();
    }
    let max_val = bins
        .iter()
        .flat_map(|b| [b.expected, b.observed])
        .fold(1.0_f64, f64::max);
    let n = bins.len();
    let w = 100.0 / n as f64;
    let bar_w = w * 0.35;

    let mut bars = String::new();
    for (i, b) in bins.iter().enumerate() {
        let x = i as f64 * w;
        let eh = (b.expected / max_val) * 45.0;
        let oh = (b.observed / max_val) * 45.0;
        let obs_colour = score_colour(b.observed / max_val);
        bars.push_str(&format!(
            "<rect x=\"{x1}\" y=\"{y1}\" width=\"{bw}\" height=\"{eh}\" \
             fill=\"#2a7fff\" opacity=\"0.4\"/>\
             <rect x=\"{x2}\" y=\"{y2}\" width=\"{bw}\" height=\"{oh}\" \
             fill=\"{oc}\"/>",
            x1 = x + w * 0.1,
            y1 = 50.0 - eh,
            bw = bar_w,
            eh = eh,
            x2 = x + w * 0.1 + bar_w + 1.0,
            y2 = 50.0 - oh,
            oh = oh,
            oc = obs_colour,
        ));
    }

    format!(
        "<svg viewBox=\"0 0 100 50\" width=\"100%\" \
         style=\"max-height:80px;display:block\" preserveAspectRatio=\"none\">\
         {bars}\
         <line x1=\"0\" y1=\"50\" x2=\"100\" y2=\"50\" stroke=\"#1a2535\" \
         stroke-width=\"0.3\"/></svg>",
        bars = bars,
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

// ── CSV export ──────────────────────────────────────────────────────────────

/// Generate a CSV report with test scores and distribution data.
pub fn generate_csv_report(reports: &[AnalysisReport]) -> String {
    let mut out = String::from(
        "File,Format,Verdict,Overall Score,Tool Fingerprint,Test,Score,Confidence,Detail\n",
    );

    for r in reports {
        let verdict = match r.verdict {
            Verdict::Clean => "Clean",
            Verdict::Suspicious => "Suspicious",
            Verdict::LikelyStego => "Likely Stego",
        };
        let fp = r.tool_fingerprint.as_deref().unwrap_or("");

        for t in &r.tests {
            let conf = match t.confidence {
                Confidence::Low => "Low",
                Confidence::Medium => "Medium",
                Confidence::High => "High",
            };
            out.push_str(&format!(
                "\"{}\",{},{},{:.4},{},{},{:.4},{},\"{}\"\n",
                csv_escape(&r.file.display().to_string()),
                r.format,
                verdict,
                r.overall_score,
                fp,
                csv_escape(&t.name),
                t.score,
                conf,
                csv_escape(&t.detail),
            ));
        }

        // Distribution data as separate rows
        for t in &r.tests {
            if let Some(ref bins) = t.distribution {
                out.push_str(&format!(
                    "\n# Distribution: {} — {}\n",
                    r.file.display(),
                    t.name
                ));
                out.push_str("Bin,Expected,Observed\n");
                for b in bins {
                    out.push_str(&format!(
                        "{},{:.4},{:.4}\n",
                        csv_escape(&b.label),
                        b.expected,
                        b.observed,
                    ));
                }
            }
        }
    }

    out
}

fn csv_escape(s: &str) -> String {
    s.replace('"', "\"\"")
}

/// Generate a JSON report with full data including distributions.
pub fn generate_json_report(reports: &[AnalysisReport]) -> String {
    serde_json::to_string_pretty(reports).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_serialises_snake_case() {
        assert_eq!(serde_json::to_string(&Verdict::Clean).unwrap(), "\"clean\"");
        assert_eq!(
            serde_json::to_string(&Verdict::Suspicious).unwrap(),
            "\"suspicious\""
        );
        assert_eq!(
            serde_json::to_string(&Verdict::LikelyStego).unwrap(),
            "\"likely_stego\""
        );
    }

    #[test]
    fn confidence_serialises_snake_case() {
        assert_eq!(serde_json::to_string(&Confidence::Low).unwrap(), "\"low\"");
        assert_eq!(
            serde_json::to_string(&Confidence::Medium).unwrap(),
            "\"medium\""
        );
        assert_eq!(
            serde_json::to_string(&Confidence::High).unwrap(),
            "\"high\""
        );
    }

    #[test]
    fn analysis_report_round_trip() {
        let report = AnalysisReport {
            file: PathBuf::from("/tmp/test.png"),
            format: "png".into(),
            tests: vec![TestResult {
                name: "Chi-Squared".into(),
                score: 0.42,
                confidence: Confidence::Medium,
                detail: "Moderate anomaly".into(),
                distribution: None,
            }],
            verdict: Verdict::Suspicious,
            overall_score: 0.42,
            tool_fingerprint: None,
            block_entropy: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AnalysisReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.format, "png");
        assert_eq!(parsed.verdict, Verdict::Suspicious);
        assert_eq!(parsed.tests.len(), 1);
    }

    #[test]
    fn html_report_contains_file_and_verdict() {
        let report = AnalysisReport {
            file: PathBuf::from("test.png"),
            format: "png".into(),
            tests: vec![TestResult {
                name: "Chi-Squared".into(),
                score: 0.1,
                confidence: Confidence::Low,
                detail: "Natural".into(),
                distribution: None,
            }],
            verdict: Verdict::Clean,
            overall_score: 0.1,
            tool_fingerprint: None,
            block_entropy: None,
        };
        let html = generate_html_report(&[report]);
        assert!(html.contains("test.png"));
        assert!(html.contains("Clean"));
        assert!(html.contains("Chi-Squared"));
    }

    #[test]
    fn html_report_escapes_xss() {
        let report = AnalysisReport {
            file: PathBuf::from("<script>alert(1)</script>.png"),
            format: "png".into(),
            tests: vec![],
            verdict: Verdict::Clean,
            overall_score: 0.0,
            tool_fingerprint: Some("<img src=x>".into()),
            block_entropy: None,
        };
        let html = generate_html_report(&[report]);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<img src=x>"));
    }

    #[test]
    fn csv_report_has_header_and_data() {
        let report = AnalysisReport {
            file: PathBuf::from("test.png"),
            format: "png".into(),
            tests: vec![TestResult {
                name: "RS Analysis".into(),
                score: 0.5,
                confidence: Confidence::High,
                detail: "Asymmetric".into(),
                distribution: None,
            }],
            verdict: Verdict::Suspicious,
            overall_score: 0.5,
            tool_fingerprint: None,
            block_entropy: None,
        };
        let csv = generate_csv_report(&[report]);
        assert!(csv.starts_with("File,Format,Verdict"));
        assert!(csv.contains("RS Analysis"));
        assert!(csv.contains("0.5000"));
    }

    #[test]
    fn csv_escapes_quotes_in_filename() {
        let report = AnalysisReport {
            file: PathBuf::from("test\"file.png"),
            format: "png".into(),
            tests: vec![TestResult {
                name: "Test".into(),
                score: 0.1,
                confidence: Confidence::Low,
                detail: "ok".into(),
                distribution: None,
            }],
            verdict: Verdict::Clean,
            overall_score: 0.0,
            tool_fingerprint: None,
            block_entropy: None,
        };
        let csv = generate_csv_report(&[report]);
        assert!(csv.contains("test\"\"file.png"));
    }

    #[test]
    fn json_report_is_valid_json() {
        let report = AnalysisReport {
            file: PathBuf::from("test.png"),
            format: "png".into(),
            tests: vec![],
            verdict: Verdict::Clean,
            overall_score: 0.1,
            tool_fingerprint: None,
            block_entropy: None,
        };
        let json = generate_json_report(&[report]);
        let parsed: Vec<AnalysisReport> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn score_colour_green_for_low() {
        assert_eq!(score_colour(0.1), "#22c55e");
    }

    #[test]
    fn score_colour_amber_for_mid() {
        assert_eq!(score_colour(0.4), "#f59e0b");
    }

    #[test]
    fn score_colour_red_for_high() {
        assert_eq!(score_colour(0.8), "#ef4444");
    }

    #[test]
    fn html_escape_handles_all_chars() {
        assert_eq!(html_escape("<>&\""), "&lt;&gt;&amp;&quot;");
    }

    #[test]
    fn csv_escape_doubles_quotes() {
        assert_eq!(csv_escape("hello\"world"), "hello\"\"world");
    }

    #[test]
    fn block_entropy_serialises() {
        let be = BlockEntropy {
            cols: 4,
            rows: 3,
            values: vec![0.5; 12],
        };
        let json = serde_json::to_string(&be).unwrap();
        assert!(json.contains("\"cols\":4"));
    }
}
