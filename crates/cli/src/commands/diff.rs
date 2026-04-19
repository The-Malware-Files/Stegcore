// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use std::path::PathBuf;

use crate::output;

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
    let total_pixels = (w * h) as usize;
    let total_channels = total_pixels * 3;

    let orig_raw = orig.as_raw();
    let steg_raw = steg.as_raw();

    let mut changed_pixels = 0usize;
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

    // Count unique pixels changed
    for p in 0..total_pixels {
        let i = p * 3;
        if orig_raw[i] != steg_raw[i]
            || orig_raw[i + 1] != steg_raw[i + 1]
            || orig_raw[i + 2] != steg_raw[i + 2]
        {
            changed_pixels += 1;
        }
    }

    let pct_pixels = (changed_pixels as f64 / total_pixels as f64) * 100.0;
    let pct_channels = (changed_channels as f64 / total_channels as f64) * 100.0;

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
