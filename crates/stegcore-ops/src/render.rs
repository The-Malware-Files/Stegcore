// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Benchmark charts, rendered to SVG.
//!
//! Two artefacts from a [`BenchmarkReport`]: a ROC-curve overlay (one line per
//! detector, with its AUC in the legend) and an AUC bar chart. SVG keeps text
//! as markup, so there is no font asset and no system-font dependency; the
//! files are scalable vector artefacts suited to the README and book. The
//! detectability heatmap across multiple tools follows once external detectors
//! are driven.

use std::path::Path;

use plotters::prelude::*;

use crate::benchmark::BenchmarkReport;

/// Distinct colours for up to six detector curves.
fn palette(i: usize) -> RGBColor {
    const COLOURS: [RGBColor; 6] = [
        RGBColor(0x1f, 0x77, 0xb4),
        RGBColor(0xd6, 0x27, 0x28),
        RGBColor(0x2c, 0xa0, 0x2c),
        RGBColor(0xff, 0x7f, 0x0e),
        RGBColor(0x94, 0x67, 0xbd),
        RGBColor(0x8c, 0x56, 0x4b),
    ];
    COLOURS[i % COLOURS.len()]
}

/// Render the ROC-curve overlay to `out` as SVG.
pub fn render_roc(report: &BenchmarkReport, out: &Path) -> Result<(), String> {
    let area = SVGBackend::new(out, (760, 620)).into_drawing_area();
    area.fill(&WHITE).map_err(|e| e.to_string())?;

    let mut chart = ChartBuilder::on(&area)
        .caption("ROC by detector", ("sans-serif", 22))
        .margin(14)
        .x_label_area_size(44)
        .y_label_area_size(52)
        .build_cartesian_2d(0f64..1f64, 0f64..1f64)
        .map_err(|e| e.to_string())?;
    chart
        .configure_mesh()
        .x_desc("False positive rate")
        .y_desc("True positive rate")
        .draw()
        .map_err(|e| e.to_string())?;

    // Chance diagonal for reference.
    chart
        .draw_series(LineSeries::new(
            [(0.0, 0.0), (1.0, 1.0)],
            BLACK.mix(0.3).stroke_width(1),
        ))
        .map_err(|e| e.to_string())?;

    for (i, d) in report.detectors.iter().enumerate() {
        if d.roc.len() < 2 {
            continue;
        }
        let colour = palette(i);
        let auc = d
            .auc
            .map(|a| format!("{a:.3}"))
            .unwrap_or_else(|| "n/a".into());
        chart
            .draw_series(LineSeries::new(
                d.roc.iter().map(|&(x, y)| (x, y)),
                colour.stroke_width(2),
            ))
            .map_err(|e| e.to_string())?
            .label(format!("{} (AUC {auc})", d.name))
            .legend(move |(x, y)| PathElement::new([(x, y), (x + 18, y)], colour.stroke_width(2)));
    }

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.85))
        .border_style(BLACK.mix(0.4))
        .position(SeriesLabelPosition::LowerRight)
        .draw()
        .map_err(|e| e.to_string())?;
    area.present().map_err(|e| e.to_string())?;
    Ok(())
}

/// Render an AUC bar chart (one bar per detector) to `out` as SVG.
pub fn render_auc_bars(report: &BenchmarkReport, out: &Path) -> Result<(), String> {
    let area = SVGBackend::new(out, (760, 480)).into_drawing_area();
    area.fill(&WHITE).map_err(|e| e.to_string())?;

    let n = report.detectors.len().max(1);
    let mut chart = ChartBuilder::on(&area)
        .caption("Detector AUC", ("sans-serif", 22))
        .margin(14)
        .x_label_area_size(60)
        .y_label_area_size(52)
        .build_cartesian_2d(0f64..n as f64, 0f64..1f64)
        .map_err(|e| e.to_string())?;

    // Label each x slot with its detector name.
    let names: Vec<String> = report.detectors.iter().map(|d| d.name.clone()).collect();
    chart
        .configure_mesh()
        .disable_x_mesh()
        .x_labels(n)
        .x_label_formatter(&|x| {
            let idx = *x as usize;
            names.get(idx).cloned().unwrap_or_default()
        })
        .y_desc("AUC")
        .draw()
        .map_err(|e| e.to_string())?;

    for (i, d) in report.detectors.iter().enumerate() {
        let auc = d.auc.unwrap_or(0.0);
        let colour = palette(i);
        let x0 = i as f64 + 0.15;
        let x1 = i as f64 + 0.85;
        chart
            .draw_series(std::iter::once(Rectangle::new(
                [(x0, 0.0), (x1, auc)],
                colour.filled(),
            )))
            .map_err(|e| e.to_string())?;
    }
    area.present().map_err(|e| e.to_string())?;
    Ok(())
}

/// A detection-rate matrix: rows (embedders, plus a clean false-positive row),
/// columns (detectors), cells (the rate, 0..1).
#[derive(Debug, Clone)]
pub struct HeatmapData {
    pub detectors: Vec<String>,
    pub rows: Vec<HeatmapRow>,
}

#[derive(Debug, Clone)]
pub struct HeatmapRow {
    pub label: String,
    /// One rate per detector, in `detectors` order.
    pub rates: Vec<f64>,
    pub n: usize,
}

/// White-to-blue sequential shade for a rate in 0..1.
fn heat_colour(rate: f64) -> RGBColor {
    let r = rate.clamp(0.0, 1.0);
    RGBColor(
        (255.0 - r * 225.0) as u8,
        (255.0 - r * 175.0) as u8,
        (255.0 - r * 95.0) as u8,
    )
}

/// Render the detectability heatmap to `out` as SVG: a grid of detection-rate
/// cells, shaded and labelled, with embedder rows and detector columns.
pub fn render_heatmap(data: &HeatmapData, out: &Path) -> Result<(), String> {
    let cols = data.detectors.len().max(1);
    let rows = data.rows.len().max(1);
    let (cell, left, top, pad) = (78i32, 150i32, 96i32, 16i32);
    let w = (left + cols as i32 * cell + pad) as u32;
    let h = (top + rows as i32 * cell + pad) as u32;
    let area = SVGBackend::new(out, (w, h)).into_drawing_area();
    area.fill(&WHITE).map_err(|e| e.to_string())?;

    let title = ("sans-serif", 18).into_text_style(&area).color(&BLACK);
    let label = ("sans-serif", 14).into_text_style(&area).color(&BLACK);
    area.draw_text("Detectability heatmap (detection rate)", &title, (12, 10))
        .map_err(|e| e.to_string())?;

    // Column headers (detectors).
    for (j, name) in data.detectors.iter().enumerate() {
        let x = left + j as i32 * cell + 6;
        area.draw_text(name, &label, (x, top - 22))
            .map_err(|e| e.to_string())?;
    }

    for (i, row) in data.rows.iter().enumerate() {
        let y = top + i as i32 * cell;
        area.draw_text(
            &format!("{} (n={})", row.label, row.n),
            &label,
            (8, y + cell / 2),
        )
        .map_err(|e| e.to_string())?;
        for (j, &rate) in row.rates.iter().enumerate() {
            let x = left + j as i32 * cell;
            area.draw(&Rectangle::new(
                [(x, y), (x + cell - 3, y + cell - 3)],
                heat_colour(rate).filled(),
            ))
            .map_err(|e| e.to_string())?;
            // Dark text on light cells, white on saturated ones.
            let text_colour = if rate >= 0.5 { WHITE } else { BLACK };
            let cell_label = ("sans-serif", 15)
                .into_text_style(&area)
                .color(&text_colour);
            area.draw_text(&format!("{rate:.2}"), &cell_label, (x + 18, y + cell / 2))
                .map_err(|e| e.to_string())?;
        }
    }
    area.present().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::benchmark::{BenchmarkReport, DetectorReport, EnsembleConfusion};
    use tempfile::TempDir;

    fn report() -> BenchmarkReport {
        BenchmarkReport {
            n_samples: 4,
            n_stego: 2,
            n_clean: 2,
            ensemble: EnsembleConfusion {
                threshold: 0.5,
                tp: 2,
                fp: 0,
                tn: 2,
                fn_: 0,
                tpr: 1.0,
                fpr: 0.0,
                precision: 1.0,
                accuracy: 1.0,
                f1: 1.0,
            },
            detectors: vec![
                DetectorReport {
                    name: "ensemble".into(),
                    samples: 4,
                    auc: Some(0.91),
                    roc: vec![(0.0, 0.0), (0.0, 1.0), (1.0, 1.0)],
                },
                DetectorReport {
                    name: "chi".into(),
                    samples: 4,
                    auc: Some(0.5),
                    roc: vec![(0.0, 0.0), (1.0, 1.0)],
                },
            ],
        }
    }

    #[test]
    fn roc_svg_has_expected_markup() {
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join("roc.svg");
        render_roc(&report(), &out).unwrap();
        let svg = std::fs::read_to_string(&out).unwrap();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        assert!(svg.contains("ROC by detector"));
        assert!(svg.contains("ensemble"));
        assert!(svg.len() > 500);
    }

    #[test]
    fn auc_bars_svg_renders() {
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join("auc.svg");
        render_auc_bars(&report(), &out).unwrap();
        let svg = std::fs::read_to_string(&out).unwrap();
        assert!(svg.contains("<svg") && svg.contains("</svg>"));
        assert!(svg.contains("Detector AUC"));
    }

    #[test]
    fn heatmap_svg_renders() {
        let data = HeatmapData {
            detectors: vec!["stegcore".into(), "stegexpose".into()],
            rows: vec![
                HeatmapRow {
                    label: "lsbsteg".into(),
                    rates: vec![0.91, 1.0],
                    n: 16,
                },
                HeatmapRow {
                    label: "clean (FPR)".into(),
                    rates: vec![0.0, 0.05],
                    n: 16,
                },
            ],
        };
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join("heatmap.svg");
        render_heatmap(&data, &out).unwrap();
        let svg = std::fs::read_to_string(&out).unwrap();
        assert!(svg.contains("<svg") && svg.contains("</svg>"));
        assert!(svg.contains("Detectability heatmap"));
        assert!(svg.contains("lsbsteg"));
    }

    #[test]
    fn roc_handles_detector_without_curve() {
        // A detector whose ROC is empty (single-class) must be skipped cleanly.
        let mut r = report();
        r.detectors.push(DetectorReport {
            name: "spa".into(),
            samples: 0,
            auc: None,
            roc: vec![],
        });
        let tmp = TempDir::new().unwrap();
        let out = tmp.path().join("roc.svg");
        render_roc(&r, &out).unwrap();
        assert!(out.is_file());
    }
}
