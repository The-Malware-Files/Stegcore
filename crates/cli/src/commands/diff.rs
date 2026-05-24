// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use std::path::PathBuf;

use crate::output;

/// Pure summary of a pixel-diff comparison. Kept separate from the
/// presentation in `run` so the decision logic can be unit-tested.
#[derive(Debug, PartialEq)]
pub(crate) struct DiffSummary {
    pub width: u32,
    pub height: u32,
    pub total_pixels: usize,
    pub total_channels: usize,
    pub changed_pixels: usize,
    pub changed_channels: usize,
    pub max_delta: u8,
    pub lsb_only: bool,
}

impl DiffSummary {
    pub fn pct_pixels(&self) -> f64 {
        if self.total_pixels == 0 {
            0.0
        } else {
            (self.changed_pixels as f64 / self.total_pixels as f64) * 100.0
        }
    }
    pub fn pct_channels(&self) -> f64 {
        if self.total_channels == 0 {
            0.0
        } else {
            (self.changed_channels as f64 / self.total_channels as f64) * 100.0
        }
    }
}

/// Compute a diff summary for two pixel buffers. Assumes RGB8 layout
/// (3 bytes/pixel) and matching dimensions; callers validate dimensions
/// before calling.
pub(crate) fn compute_diff_summary(
    orig_raw: &[u8],
    steg_raw: &[u8],
    w: u32,
    h: u32,
) -> DiffSummary {
    let total_pixels = (w * h) as usize;
    let total_channels = total_pixels * 3;

    let mut changed_channels = 0usize;
    let mut max_delta: u8 = 0;
    let mut lsb_only = true;

    for i in 0..total_channels {
        if orig_raw[i] != steg_raw[i] {
            changed_channels += 1;
            let delta = orig_raw[i].abs_diff(steg_raw[i]);
            if delta > max_delta {
                max_delta = delta;
            }
            if delta > 1 {
                lsb_only = false;
            }
        }
    }

    let mut changed_pixels = 0usize;
    for p in 0..total_pixels {
        let i = p * 3;
        if orig_raw[i] != steg_raw[i]
            || orig_raw[i + 1] != steg_raw[i + 1]
            || orig_raw[i + 2] != steg_raw[i + 2]
        {
            changed_pixels += 1;
        }
    }

    DiffSummary {
        width: w,
        height: h,
        total_pixels,
        total_channels,
        changed_pixels,
        changed_channels,
        max_delta,
        lsb_only,
    }
}

#[derive(Debug, clap::Args)]
pub struct DiffArgs {
    /// Original (clean) file
    pub original: PathBuf,
    /// Stego (embedded) file
    pub stego: PathBuf,
}

pub fn run(args: &DiffArgs, _json: bool) -> ! {
    use crossterm::style::{Color, Print, ResetColor, SetForegroundColor};
    use crossterm::ExecutableCommand;

    let mut stderr = std::io::stderr();

    let orig = match image::open(&args.original) {
        Ok(img) => img.to_rgb8(),
        Err(e) => {
            output::print_error(
                &format!("Cannot open {}: {e}", args.original.display()),
                None,
            );
            std::process::exit(3);
        }
    };
    let steg = match image::open(&args.stego) {
        Ok(img) => img.to_rgb8(),
        Err(e) => {
            output::print_error(&format!("Cannot open {}: {e}", args.stego.display()), None);
            std::process::exit(3);
        }
    };

    if orig.dimensions() != steg.dimensions() {
        output::print_error("Images have different dimensions", None);
        std::process::exit(1);
    }

    let (w, h) = orig.dimensions();
    let summary = compute_diff_summary(orig.as_raw(), steg.as_raw(), w, h);
    let DiffSummary {
        total_pixels,
        changed_pixels,
        changed_channels,
        max_delta,
        lsb_only,
        ..
    } = summary;
    let pct_pixels = summary.pct_pixels();
    let pct_channels = summary.pct_channels();

    eprintln!();
    let _ = stderr.execute(SetForegroundColor(Color::Cyan));
    let _ = stderr.execute(Print("  Pixel Diff\n\n"));
    let _ = stderr.execute(ResetColor);

    let _ = stderr.execute(Print(format!("  Dimensions:       {w} × {h}\n")));
    let _ = stderr.execute(Print(format!("  Total pixels:     {total_pixels}\n")));

    let color = if pct_pixels < 1.0 {
        Color::Green
    } else if pct_pixels < 10.0 {
        Color::Yellow
    } else {
        Color::Red
    };
    let _ = stderr.execute(SetForegroundColor(color));
    let _ = stderr.execute(Print(format!(
        "  Changed pixels:   {changed_pixels} ({pct_pixels:.2}%)\n"
    )));
    let _ = stderr.execute(ResetColor);
    let _ = stderr.execute(Print(format!(
        "  Changed channels: {changed_channels} ({pct_channels:.2}%)\n"
    )));
    let _ = stderr.execute(Print(format!("  Max delta:        {max_delta}\n")));

    let _ = stderr.execute(SetForegroundColor(if lsb_only {
        Color::Green
    } else {
        Color::Yellow
    }));
    let _ = stderr.execute(Print(format!(
        "  LSB-only:         {}\n",
        if lsb_only { "yes" } else { "no" }
    )));
    let _ = stderr.execute(ResetColor);

    if lsb_only && changed_pixels > 0 {
        output::print_success("Changes are LSB-only — visually imperceptible.");
    } else if changed_pixels == 0 {
        output::print_success("Files are identical.");
    } else {
        output::print_warn("Some changes exceed LSB — may be visually detectable.");
    }

    eprintln!();
    std::process::exit(0);
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_buffers_report_no_changes() {
        let orig = vec![10u8, 20, 30, 40, 50, 60]; // 2 pixels
        let s = compute_diff_summary(&orig, &orig, 2, 1);
        assert_eq!(s.changed_pixels, 0);
        assert_eq!(s.changed_channels, 0);
        assert_eq!(s.max_delta, 0);
        assert!(s.lsb_only); // vacuously true — no changes seen
        assert_eq!(s.pct_pixels(), 0.0);
        assert_eq!(s.pct_channels(), 0.0);
    }

    #[test]
    fn lsb_only_diff_detected_as_lsb_only() {
        // Single bit flipped in the LSB of one channel.
        let orig = vec![10u8, 20, 30, 40, 50, 60];
        let mut steg = orig.clone();
        steg[0] ^= 1;
        steg[3] ^= 1;
        let s = compute_diff_summary(&orig, &steg, 2, 1);
        assert_eq!(s.changed_pixels, 2);
        assert_eq!(s.changed_channels, 2);
        assert_eq!(s.max_delta, 1);
        assert!(s.lsb_only);
    }

    #[test]
    fn delta_above_one_clears_lsb_only_flag() {
        let orig = vec![10u8, 20, 30];
        let mut steg = orig.clone();
        steg[1] = steg[1].wrapping_add(7); // delta of 7 — not LSB-only
        let s = compute_diff_summary(&orig, &steg, 1, 1);
        assert_eq!(s.changed_channels, 1);
        assert_eq!(s.max_delta, 7);
        assert!(!s.lsb_only);
    }

    #[test]
    fn percentages_normalised_against_totals() {
        // 2 of 4 pixels changed → 50% pixels, 50% channels.
        let orig = vec![0u8; 12]; // 4 pixels
        let mut steg = orig.clone();
        steg[0] = 1;
        steg[3] = 1;
        // Only one channel changed per pixel → 2 pixels, 2 channels.
        let s = compute_diff_summary(&orig, &steg, 4, 1);
        assert_eq!(s.changed_pixels, 2);
        assert_eq!(s.changed_channels, 2);
        assert!((s.pct_pixels() - 50.0).abs() < 0.001);
    }

    #[test]
    fn zero_pixel_buffer_does_not_divide_by_zero() {
        let s = compute_diff_summary(&[], &[], 0, 0);
        assert_eq!(s.pct_pixels(), 0.0);
        assert_eq!(s.pct_channels(), 0.0);
    }

    #[test]
    fn dimensions_propagate_into_summary() {
        let orig = vec![0u8; 3 * 4];
        let s = compute_diff_summary(&orig, &orig, 4, 1);
        assert_eq!(s.width, 4);
        assert_eq!(s.height, 1);
        assert_eq!(s.total_pixels, 4);
        assert_eq!(s.total_channels, 12);
    }
}
