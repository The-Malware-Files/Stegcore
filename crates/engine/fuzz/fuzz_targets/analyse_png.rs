// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Fuzz target: analyse() given arbitrary bytes labelled as PNG.
//
// The engine's analyse() path reads the file, dispatches to the image
// crate's PNG decoder, and runs the steganalysis pipeline. This target
// hits the PNG decoder + the analysis dispatcher; the goal is to find
// any input that panics, aborts, or unwinds out of analyse().
//
// A clean Err return is acceptable. A panic is not.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use stegcore_engine::analysis;

fuzz_target!(|data: &[u8]| {
    let mut tmp = match tempfile::Builder::new().suffix(".png").tempfile() {
        Ok(t) => t,
        Err(_) => return,
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    if tmp.flush().is_err() {
        return;
    }
    // Drop the file handle but keep the path on disk for the duration of
    // the analyse call. into_temp_path() persists the file; let it
    // delete itself when the TempPath drops at end of scope.
    let path = match tmp.into_temp_path().keep() {
        Ok(p) => p,
        Err(_) => return,
    };
    let _ = analysis::analyse(&path);
    let _ = std::fs::remove_file(&path);
});
