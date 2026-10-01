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

//! Embed a pseudorandom payload into a JPEG through the engine's own
//! coefficient path, for the DCT feature measurement.
//!
//! The calibration driver needs stego files made by Stegcore itself, not only
//! by third-party tools, because Stegcore's JPEG output is currently invisible
//! to Stegcore's own analysis. Going through the engine here rather than
//! through the CLI keeps the measurement independent of the command-line
//! crate's build.
//!
//! Usage:
//!
//! ```text
//! jsteg_embed <cover.jpg> <stego.jpg> <fraction-of-capacity>
//! ```
//!
//! Exits 0 on success, 1 on a usage or embedding failure, with the reason on
//! standard error.

use stegcore_engine::jpeg_dct::{embed_jpeg, jpeg_capacity};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, cover_path, stego_path, fraction] = args.as_slice() else {
        eprintln!("usage: jsteg_embed <cover.jpg> <stego.jpg> <fraction-of-capacity>");
        std::process::exit(1);
    };
    let fraction: f64 = match fraction.parse() {
        Ok(value) if (0.0..=1.0).contains(&value) => value,
        _ => {
            eprintln!("the fraction of capacity must be a number between 0 and 1");
            std::process::exit(1);
        }
    };

    let cover = match std::fs::read(cover_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("could not read {cover_path}: {err}");
            std::process::exit(1);
        }
    };
    let capacity = match jpeg_capacity(&cover) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("no capacity in {cover_path}: {err}");
            std::process::exit(1);
        }
    };
    // Four bytes go to the length prefix the engine writes, so the usable
    // capacity is below the reported figure; leaving a small margin keeps a
    // fraction of 1.0 from failing on rounding alone.
    let wanted = ((capacity as f64) * fraction) as usize;
    let payload_len = wanted.min(capacity.saturating_sub(8));
    if payload_len == 0 {
        eprintln!("{cover_path} has no usable capacity at fraction {fraction}");
        std::process::exit(1);
    }

    // A deterministic, incompressible payload: a real one would be ciphertext,
    // and a run of identical bytes would understate the coefficient changes.
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let payload: Vec<u8> = (0..payload_len)
        .map(|_| {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            ((z ^ (z >> 31)) & 0xFF) as u8
        })
        .collect();

    match embed_jpeg(&cover, &payload, b"benchmark") {
        Ok(stego) => {
            if let Err(err) = std::fs::write(stego_path, &stego) {
                eprintln!("could not write {stego_path}: {err}");
                std::process::exit(1);
            }
            println!("{payload_len}");
        }
        Err(err) => {
            eprintln!("embed failed for {cover_path}: {err}");
            std::process::exit(1);
        }
    }
}
