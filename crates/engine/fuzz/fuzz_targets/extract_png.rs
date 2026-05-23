// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Fuzz target: extract() given arbitrary bytes labelled as PNG.
//
// Exercises the most adversarial user-facing path: "user runs
// stegcore extract on a file someone else sent them". The file may be
// crafted to confuse the meta-JSON parser, the AEAD decryption path,
// the slot permutation, or the multi-pass extraction logic.
//
// extract() may return Err — that is fine. It must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use stegcore_engine::steg;

const PASSPHRASE: &[u8] = b"fuzz-fixed-passphrase";

fuzz_target!(|data: &[u8]| {
    let mut tmp = match tempfile::Builder::new().suffix(".png").tempfile() {
        Ok(t) => t,
        Err(_) => return,
    };
    if tmp.write_all(data).is_err() || tmp.flush().is_err() {
        return;
    }
    let path = match tmp.into_temp_path().keep() {
        Ok(p) => p,
        Err(_) => return,
    };
    let _ = steg::extract(&path, PASSPHRASE);
    let _ = std::fs::remove_file(&path);
});
