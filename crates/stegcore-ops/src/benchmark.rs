// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Detection benchmark over a `score` JSONL.
//!
//! Reuses the per-sample scores collected by the `score` command: each record
//! carries the ground-truth label, the ensemble score and the five individual
//! detector scores. This module turns those into detection metrics, the ROC
//! AUC for the ensemble and for each detector, and a confusion matrix for the
//! ensemble at a chosen decision threshold. Driving the external comparator
//! tools and rendering the graphs build on this same report.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::Serialize;

use crate::metrics::{roc_auc, roc_curve, Confusion};
use crate::score::ScoreRecord;

/// AUC and ROC curve for one score column.
#[derive(Debug, Clone, Serialize)]
pub struct DetectorReport {
    pub name: String,
    /// Samples that had both a label and this score present.
    pub samples: usize,
    pub auc: Option<f64>,
    pub roc: Vec<(f64, f64)>,
}

/// The ensemble confusion matrix at a decision threshold.
#[derive(Debug, Clone, Serialize)]
pub struct EnsembleConfusion {
    pub threshold: f64,
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    pub fn_: u64,
    pub tpr: f64,
    pub fpr: f64,
    pub precision: f64,
    pub accuracy: f64,
    pub f1: f64,
}

/// Full detection benchmark for one scores file.
#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub n_samples: usize,
    pub n_stego: usize,
    pub n_clean: usize,
    pub ensemble: EnsembleConfusion,
    pub detectors: Vec<DetectorReport>,
}

/// The score columns reported, paired with how to read each from a record.
/// The ensemble is listed first so it heads the report.
type Column = (&'static str, fn(&ScoreRecord) -> Option<f64>);
const COLUMNS: &[Column] = &[
    ("ensemble", |r| r.overall_score),
    ("chi", |r| r.chi),
    ("spa", |r| r.spa),
    ("rs", |r| r.rs),
    ("entropy", |r| r.entropy),
    ("ws", |r| r.ws),
];

/// Read scored samples from a JSONL file, skipping blank or malformed lines.
pub fn load_scores(path: &Path) -> std::io::Result<Vec<ScoreRecord>> {
    let file = File::open(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<ScoreRecord>(&line) {
            out.push(rec);
        }
    }
    Ok(out)
}

/// True when a record's label marks it stego (the positive class). Records
/// with no label are not classifiable and are excluded by the caller.
fn is_stego(rec: &ScoreRecord) -> Option<bool> {
    rec.label.as_deref().map(|l| l == "stego")
}

/// Gather `(score, label)` pairs for one column over records that carry both.
fn column_pairs(
    records: &[ScoreRecord],
    read: fn(&ScoreRecord) -> Option<f64>,
) -> (Vec<f64>, Vec<bool>) {
    let mut scores = Vec::new();
    let mut labels = Vec::new();
    for rec in records {
        if let (Some(label), Some(score)) = (is_stego(rec), read(rec)) {
            scores.push(score);
            labels.push(label);
        }
    }
    (scores, labels)
}

/// Build the detection report at the given ensemble decision threshold.
pub fn build_report(records: &[ScoreRecord], threshold: f64) -> BenchmarkReport {
    let labelled: Vec<&ScoreRecord> = records.iter().filter(|r| is_stego(r).is_some()).collect();
    let n_stego = labelled
        .iter()
        .filter(|r| is_stego(r) == Some(true))
        .count();
    let n_clean = labelled.len() - n_stego;

    // Ensemble confusion at the threshold, over records with an ensemble score.
    let (ens_scores, ens_labels) = column_pairs(records, |r| r.overall_score);
    let preds: Vec<bool> = ens_scores.iter().map(|&s| s >= threshold).collect();
    let c = Confusion::tally(&ens_labels, &preds);
    let ensemble = EnsembleConfusion {
        threshold,
        tp: c.tp,
        fp: c.fp,
        tn: c.tn,
        fn_: c.fn_,
        tpr: c.tpr(),
        fpr: c.fpr(),
        precision: c.precision(),
        accuracy: c.accuracy(),
        f1: c.f1(),
    };

    let detectors = COLUMNS
        .iter()
        .map(|&(name, read)| {
            let (scores, labels) = column_pairs(records, read);
            DetectorReport {
                name: name.to_string(),
                samples: scores.len(),
                auc: roc_auc(&scores, &labels),
                roc: roc_curve(&scores, &labels),
            }
        })
        .collect();

    BenchmarkReport {
        n_samples: labelled.len(),
        n_stego,
        n_clean,
        ensemble,
        detectors,
    }
}

/// Write the report as pretty JSON.
pub fn write_report(report: &BenchmarkReport, out: &Path) -> std::io::Result<()> {
    let mut file = File::create(out)?;
    file.write_all(serde_json::to_string_pretty(report)?.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// A short human-readable summary of the report.
pub fn format_report(report: &BenchmarkReport) -> String {
    let mut out = String::new();
    out.push_str("=== DETECTION BENCHMARK ===\n");
    out.push_str(&format!(
        "Samples: {} ({} stego, {} clean)\n",
        report.n_samples, report.n_stego, report.n_clean
    ));
    let e = &report.ensemble;
    out.push_str(&format!(
        "Ensemble @ {:.2}: TPR={:.3} FPR={:.3} precision={:.3} F1={:.3}\n",
        e.threshold, e.tpr, e.fpr, e.precision, e.f1
    ));
    out.push_str("\nAUC by detector:\n");
    for d in &report.detectors {
        let auc = d
            .auc
            .map(|a| format!("{a:.4}"))
            .unwrap_or_else(|| "n/a".into());
        out.push_str(&format!("  {:<10} {:>8}  (n={})\n", d.name, auc, d.samples));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn rec(label: &str, ensemble: f64, chi: f64) -> ScoreRecord {
        ScoreRecord {
            path: "x".into(),
            sha256: "h".into(),
            label: Some(label.into()),
            overall_score: Some(ensemble),
            chi: Some(chi),
            ..Default::default()
        }
    }

    #[test]
    fn report_separates_perfectly() {
        let records = vec![
            rec("clean", 0.01, 0.02),
            rec("clean", 0.10, 0.05),
            rec("stego", 0.80, 0.90),
            rec("stego", 0.95, 0.95),
        ];
        let r = build_report(&records, 0.5);
        assert_eq!((r.n_samples, r.n_stego, r.n_clean), (4, 2, 2));
        // Threshold 0.5 splits cleanly: 2 TP, 2 TN, no errors.
        assert_eq!((r.ensemble.tp, r.ensemble.tn), (2, 2));
        assert_eq!(r.ensemble.fp + r.ensemble.fn_, 0);
        assert!((r.ensemble.tpr - 1.0).abs() < 1e-12);
        let ens = r.detectors.iter().find(|d| d.name == "ensemble").unwrap();
        assert_eq!(ens.auc, Some(1.0));
        assert_eq!(ens.samples, 4);
    }

    #[test]
    fn detector_with_no_scores_reports_none_auc() {
        // Records carry no `spa` column → that detector has zero samples.
        let records = vec![rec("clean", 0.1, 0.2), rec("stego", 0.9, 0.8)];
        let r = build_report(&records, 0.5);
        let spa = r.detectors.iter().find(|d| d.name == "spa").unwrap();
        assert_eq!(spa.samples, 0);
        assert_eq!(spa.auc, None);
    }

    #[test]
    fn unlabelled_records_are_excluded() {
        let mut unlabelled = rec("stego", 0.9, 0.9);
        unlabelled.label = None;
        let records = vec![rec("clean", 0.1, 0.2), unlabelled];
        let r = build_report(&records, 0.5);
        assert_eq!(r.n_samples, 1);
    }

    #[test]
    fn load_and_write_round_trip() {
        let tmp = TempDir::new().unwrap();
        let scores = tmp.path().join("scores.jsonl");
        let lines = [
            serde_json::to_string(&rec("clean", 0.05, 0.1)).unwrap(),
            "".to_string(),
            "garbage".to_string(),
            serde_json::to_string(&rec("stego", 0.9, 0.85)).unwrap(),
        ];
        fs::write(&scores, lines.join("\n")).unwrap();

        let loaded = load_scores(&scores).unwrap();
        assert_eq!(loaded.len(), 2); // blank + garbage skipped

        let report = build_report(&loaded, 0.5);
        let out = tmp.path().join("report.json");
        write_report(&report, &out).unwrap();
        let back: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(back["n_samples"], 2);
        assert!(format_report(&report).contains("DETECTION BENCHMARK"));
    }
}
