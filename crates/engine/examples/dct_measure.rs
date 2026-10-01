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

//! Print the DCT-domain features of every JPEG named on standard input, one
//! path per line, as CSV.
//!
//! This is the measurement side of `dct_analysis`: the thresholds that module
//! deliberately does not contain are set by running this over a real corpus of
//! matched cover and stego pairs and reading the separation off the
//! distributions. The calibration driver in `private/calibration/` builds those
//! pairs and consumes this output.
//!
//! Usage:
//!
//! ```text
//! find corpus -name '*.jpg' | cargo run --release --example dct_measure
//! ```
//!
//! A file that cannot be measured prints a row with the reason in its last
//! field rather than being skipped, because a silently shorter output would
//! make the corpus size a guess.

use std::io::{BufWriter, Read, Write};

use stegcore_engine::dct_analysis::dct_features;

fn main() {
    let mut input = String::new();
    if let Err(err) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("could not read the path list: {err}");
        std::process::exit(2);
    }

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let header = "path,width,height,luma_blocks,ac_samples,ac_zero_ratio,ac_one_ratio,\
                  pov_equalisation,blockiness,calibrated,cal_ac_zero_ratio,cal_ac_one_ratio,\
                  cal_pov_equalisation,cal_blockiness,delta_ac_zero_ratio,delta_ac_one_ratio,\
                  delta_pov_equalisation,delta_blockiness,error";
    if writeln!(out, "{header}").is_err() {
        return;
    }

    let mut failures = 0usize;
    // An error row has to carry the same number of fields as a measured one, or
    // every value in it lands in the wrong column and the failures read as
    // measurements rather than as failures. Built by joining the fields so the
    // count cannot drift from the header, and the reason is quoted because a
    // `StegError` message may contain a comma.
    let columns = header.split(',').count();
    let error_row = |path: &str, reason: String| {
        let mut fields = vec![path.to_string()];
        fields.resize(columns - 1, String::new());
        fields.push(format!("\"{}\"", reason.replace('"', "'")));
        fields.join(",")
    };
    for path in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let row = match std::fs::read(path) {
            Err(err) => {
                failures += 1;
                error_row(path, format!("read failed: {err}"))
            }
            Ok(bytes) => match dct_features(&bytes) {
                Err(err) => {
                    failures += 1;
                    error_row(path, err.to_string())
                }
                Ok(f) => format!(
                    "{path},{},{},{},{},{:.10},{:.10},{:.10},{:.6},{},{:.10},{:.10},{:.10},\
                     {:.6},{:.10},{:.10},{:.10},{:.6},",
                    f.width,
                    f.height,
                    f.luma_blocks,
                    f.ac_samples,
                    f.ac_zero_ratio,
                    f.ac_one_ratio,
                    f.pov_equalisation,
                    f.blockiness,
                    f.calibrated,
                    f.cal_ac_zero_ratio,
                    f.cal_ac_one_ratio,
                    f.cal_pov_equalisation,
                    f.cal_blockiness,
                    f.delta_ac_zero_ratio,
                    f.delta_ac_one_ratio,
                    f.delta_pov_equalisation,
                    f.delta_blockiness,
                ),
            },
        };
        if writeln!(out, "{row}").is_err() {
            return;
        }
    }
    if let Err(err) = out.flush() {
        eprintln!("could not flush the output: {err}");
        std::process::exit(2);
    }
    if failures > 0 {
        eprintln!("{failures} file(s) could not be measured; see the error column");
    }
}
