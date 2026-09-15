// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Detection metrics for the comparative benchmark.
//!
//! Pure functions over labels and scores: a binary confusion matrix (positive
//! = stego), the rank-based ROC AUC (Mann-Whitney, tie-aware), and the ROC
//! curve points. These are deliberately storage- and tool-agnostic so the
//! same code scores Stegcore's ensemble, any single detector, or an external
//! comparator.

use std::cmp::Ordering;

/// Binary classification counts. Positive is "stego".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Confusion {
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    pub fn_: u64,
}

impl Confusion {
    /// Tally counts from per-sample labels and predicted-positive flags. The
    /// two slices are walked pairwise; a length mismatch simply stops at the
    /// shorter one (the caller builds both from the same record set).
    pub fn tally(labels: &[bool], predicted_positive: &[bool]) -> Self {
        let mut c = Confusion::default();
        for (&label, &pred) in labels.iter().zip(predicted_positive) {
            match (label, pred) {
                (true, true) => c.tp += 1,
                (false, true) => c.fp += 1,
                (false, false) => c.tn += 1,
                (true, false) => c.fn_ += 1,
            }
        }
        c
    }

    fn ratio(num: u64, den: u64) -> f64 {
        if den == 0 {
            0.0
        } else {
            num as f64 / den as f64
        }
    }

    /// True-positive rate (detection rate / recall): tp / (tp + fn).
    pub fn tpr(&self) -> f64 {
        Self::ratio(self.tp, self.tp + self.fn_)
    }

    /// False-positive rate: fp / (fp + tn).
    pub fn fpr(&self) -> f64 {
        Self::ratio(self.fp, self.fp + self.tn)
    }

    /// Precision: tp / (tp + fp).
    pub fn precision(&self) -> f64 {
        Self::ratio(self.tp, self.tp + self.fp)
    }

    /// Accuracy: (tp + tn) / total.
    pub fn accuracy(&self) -> f64 {
        Self::ratio(self.tp + self.tn, self.tp + self.tn + self.fp + self.fn_)
    }

    /// F1 score: harmonic mean of precision and recall; 0 when both are 0.
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.tpr());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

fn cmp_f64(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

/// Rank-based ROC AUC (equivalent to the Mann-Whitney U statistic), tie-aware
/// via average ranks. Returns `None` when one class is absent, since AUC is
/// undefined without both a positive and a negative sample.
pub fn roc_auc(scores: &[f64], labels: &[bool]) -> Option<f64> {
    debug_assert_eq!(scores.len(), labels.len());
    let n_pos = labels.iter().filter(|&&l| l).count();
    let n_neg = labels.len() - n_pos;
    if n_pos == 0 || n_neg == 0 {
        return None;
    }

    // Indices sorted by ascending score.
    let mut idx: Vec<usize> = (0..scores.len()).collect();
    idx.sort_by(|&a, &b| cmp_f64(scores[a], scores[b]));

    // Average ranks (1-based), tie groups share the mean of their positions.
    let mut ranks = vec![0.0f64; scores.len()];
    let mut i = 0;
    while i < idx.len() {
        let mut j = i;
        while j + 1 < idx.len() && scores[idx[j + 1]] == scores[idx[i]] {
            j += 1;
        }
        let avg = ((i + 1) + (j + 1)) as f64 / 2.0;
        for &k in &idx[i..=j] {
            ranks[k] = avg;
        }
        i = j + 1;
    }

    let sum_pos: f64 = labels
        .iter()
        .zip(&ranks)
        .filter(|(&l, _)| l)
        .map(|(_, &r)| r)
        .sum();
    let auc = (sum_pos - (n_pos * (n_pos + 1)) as f64 / 2.0) / (n_pos as f64 * n_neg as f64);
    Some(auc)
}

/// ROC curve as `(fpr, tpr)` points, swept from the highest score downward
/// (predicted positive when `score >= threshold`). Begins at `(0, 0)` and ends
/// at `(1, 1)`. Empty when either class is absent.
pub fn roc_curve(scores: &[f64], labels: &[bool]) -> Vec<(f64, f64)> {
    let n_pos = labels.iter().filter(|&&l| l).count() as f64;
    let n_neg = labels.len() as f64 - n_pos;
    if n_pos == 0.0 || n_neg == 0.0 {
        return Vec::new();
    }

    let mut pairs: Vec<(f64, bool)> = scores.iter().copied().zip(labels.iter().copied()).collect();
    pairs.sort_by(|a, b| cmp_f64(b.0, a.0)); // descending score

    let mut curve = vec![(0.0, 0.0)];
    let (mut tp, mut fp) = (0.0f64, 0.0f64);
    let mut i = 0;
    while i < pairs.len() {
        let thr = pairs[i].0;
        // Advance over every sample at this threshold before recording a point,
        // so tied scores collapse to a single ROC vertex.
        while i < pairs.len() && pairs[i].0 == thr {
            if pairs[i].1 {
                tp += 1.0;
            } else {
                fp += 1.0;
            }
            i += 1;
        }
        curve.push((fp / n_neg, tp / n_pos));
    }
    curve
}

/// The best true-positive rate this detector reaches without exceeding
/// `max_fpr`. `None` when either class is absent.
///
/// This is the headline number for an external evaluation and accuracy is not.
/// A detector facing a corpus that is mostly clean can score 95% accuracy by
/// answering "clean" every time, and a false-positive rate chosen after seeing
/// the results is not a measurement. Pinning the false-positive budget first and
/// asking what detection it buys is the comparison that survives review.
pub fn tpr_at_fpr(scores: &[f64], labels: &[bool], max_fpr: f64) -> Option<f64> {
    let curve = roc_curve(scores, labels);
    if curve.is_empty() {
        return None;
    }
    // The curve is a step function, so the answer is the highest point whose
    // false-positive rate is still inside the budget. The epsilon absorbs the
    // representation error in ratios like 1/3, which would otherwise drop an
    // operating point that is exactly on the limit.
    let best = curve
        .iter()
        .filter(|&&(fpr, _)| fpr <= max_fpr + 1e-12)
        .map(|&(_, tpr)| tpr)
        .fold(f64::NEG_INFINITY, f64::max);
    Some(if best.is_finite() { best } else { 0.0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpr_at_fpr_perfect_separation_is_one_at_zero_budget() {
        let scores = [0.1, 0.2, 0.8, 0.9];
        let labels = [false, false, true, true];
        assert_eq!(tpr_at_fpr(&scores, &labels, 0.0), Some(1.0));
    }

    #[test]
    fn tpr_at_fpr_tightens_as_the_budget_shrinks() {
        // 2 pos (0.9, 0.4), 2 neg (0.5, 0.1). Catching the 0.4 positive means
        // first admitting the 0.5 negative, so a zero-FPR budget buys half.
        let scores = [0.9, 0.4, 0.5, 0.1];
        let labels = [true, true, false, false];
        assert_eq!(tpr_at_fpr(&scores, &labels, 0.0), Some(0.5));
        assert_eq!(tpr_at_fpr(&scores, &labels, 0.5), Some(1.0));
    }

    #[test]
    fn tpr_at_fpr_is_zero_when_the_budget_buys_nothing() {
        // Every negative outranks every positive: no detection at zero FPR.
        let scores = [0.1, 0.2, 0.8, 0.9];
        let labels = [true, true, false, false];
        assert_eq!(tpr_at_fpr(&scores, &labels, 0.0), Some(0.0));
    }

    #[test]
    fn tpr_at_fpr_undefined_with_single_class() {
        assert_eq!(tpr_at_fpr(&[0.1, 0.2], &[true, true], 0.01), None);
    }

    /// A detector that only answers yes or no has two operating points, so the
    /// budget either admits its false positives or refuses them outright. This
    /// is exactly why `Detector::is_graded` exists: the number is real, but it
    /// cannot be traded off the way a graded detector's can.
    #[test]
    fn tpr_at_fpr_handles_a_binary_detector() {
        let scores = [1.0, 1.0, 1.0, 0.0];
        let labels = [true, true, false, false];
        assert_eq!(tpr_at_fpr(&scores, &labels, 0.0), Some(0.0));
        assert_eq!(tpr_at_fpr(&scores, &labels, 0.5), Some(1.0));
    }

    #[test]
    fn confusion_counts_and_rates() {
        // labels:  S S S C C   (3 stego, 2 clean)
        // preds:   1 1 0 1 0
        let labels = [true, true, true, false, false];
        let preds = [true, true, false, true, false];
        let c = Confusion::tally(&labels, &preds);
        assert_eq!((c.tp, c.fn_, c.fp, c.tn), (2, 1, 1, 1));
        assert!((c.tpr() - 2.0 / 3.0).abs() < 1e-12);
        assert!((c.fpr() - 0.5).abs() < 1e-12);
        assert!((c.precision() - 2.0 / 3.0).abs() < 1e-12);
        assert!((c.accuracy() - 3.0 / 5.0).abs() < 1e-12);
        assert!((c.f1() - 2.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn confusion_zero_denominators_are_zero_not_nan() {
        let c = Confusion::default();
        assert_eq!(c.tpr(), 0.0);
        assert_eq!(c.fpr(), 0.0);
        assert_eq!(c.precision(), 0.0);
        assert_eq!(c.accuracy(), 0.0);
        assert_eq!(c.f1(), 0.0);
    }

    #[test]
    fn auc_perfect_separation_is_one() {
        let scores = [0.1, 0.2, 0.8, 0.9];
        let labels = [false, false, true, true];
        assert_eq!(roc_auc(&scores, &labels), Some(1.0));
    }

    #[test]
    fn auc_reversed_is_zero_and_random_is_half() {
        let scores = [0.9, 0.8, 0.2, 0.1];
        let labels = [false, false, true, true];
        assert_eq!(roc_auc(&scores, &labels), Some(0.0));

        // Perfectly interleaved with ties handled by average rank → 0.5.
        let s = [0.5, 0.5, 0.5, 0.5];
        let l = [true, false, true, false];
        assert_eq!(roc_auc(&s, &l), Some(0.5));
    }

    #[test]
    fn auc_undefined_with_single_class() {
        assert_eq!(roc_auc(&[0.1, 0.2], &[true, true]), None);
        assert_eq!(roc_auc(&[0.1, 0.2], &[false, false]), None);
    }

    #[test]
    fn auc_matches_manual_small_case() {
        // 2 pos, 2 neg; one pos below one neg → AUC = 3/4.
        let scores = [0.3, 0.4, 0.35, 0.2];
        let labels = [true, true, false, false];
        let auc = roc_auc(&scores, &labels).unwrap();
        assert!((auc - 0.75).abs() < 1e-12, "auc={auc}");
    }

    #[test]
    fn roc_curve_reaches_corners() {
        let scores = [0.1, 0.2, 0.8, 0.9];
        let labels = [false, false, true, true];
        let curve = roc_curve(&scores, &labels);
        assert_eq!(curve.first(), Some(&(0.0, 0.0)));
        assert_eq!(curve.last(), Some(&(1.0, 1.0)));
        // Perfect separation: tpr hits 1.0 before any fpr accrues.
        assert!(curve.iter().any(|&(fpr, tpr)| fpr == 0.0 && tpr == 1.0));
    }

    #[test]
    fn roc_curve_empty_without_both_classes() {
        assert!(roc_curve(&[0.1, 0.2], &[true, true]).is_empty());
    }
}
