// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use crate::output::{self, JsonOut};

pub fn run(json: bool) -> ! {
    #[derive(serde::Serialize)]
    struct Cipher {
        id: &'static str,
        name: &'static str,
        default: bool,
        note: &'static str,
    }

    let ciphers = [
        Cipher {
            id: "chacha20-poly1305",
            name: "ChaCha20-Poly1305",
            default: true,
            note: "Fast, authenticated stream cipher. Recommended for most uses.",
        },
        Cipher {
            id: "ascon-128",
            name: "Ascon-128",
            default: false,
            note: "Lightweight AEAD cipher. Winner of the NIST lightweight crypto competition.",
        },
        Cipher {
            id: "aes-256-gcm",
            name: "AES-256-GCM",
            default: false,
            note: "Hardware-accelerated AES in Galois/Counter mode. Widely audited.",
        },
    ];

    if json {
        output::emit_json(&JsonOut::success(&ciphers), 0);
    }

    for c in &ciphers {
        let tag = if c.default { " (default)" } else { "" };
        output::print_info(&format!("{}  {}{}", c.id, c.name, tag));
        eprintln!("       {}", c.note);
    }

    std::process::exit(0);
}
