// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Permutation test vectors: the published, tracked record that ties specific
//! (passphrase, slot count) inputs to the exact embedding positions Stegcore
//! selects. A third-party tool that reproduces these positions is running
//! Stegcore's seed derivation. The fixture is the evidence; this test keeps it
//! honest by re-deriving every entry from the live algorithm.
//!
//! After a deliberate, version-bumped change to the seed derivation, regenerate
//! the fixture with `REGEN_VECTORS=1 cargo test -p stegcore-engine
//! --test forensic_vectors`. Without that flag the test only verifies, so an
//! accidental change to the algorithm fails CI instead of silently rewriting
//! the published vectors.

use std::path::{Path, PathBuf};

use stegcore_engine::forensics::{embedding_positions, WIRE_FORMAT_VERSION};

/// The pinned inputs. Chosen to exercise: the empty passphrase (the no-password
/// path), an ordinary passphrase, a non-power-of-two count, a power-of-two
/// count, and a passphrase longer than the 32-byte seed (the XOR-fold path).
const CASES: &[(&str, usize)] = &[
    ("", 64),
    ("correct horse battery staple", 64),
    ("correct horse battery staple", 257),
    ("p@ssw0rd-2026", 1024),
    (
        "a deliberately long passphrase that runs well past thirty two bytes so the fold path is exercised",
        1000,
    ),
];

fn vectors_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/permutation_vectors.json")
}

#[test]
fn permutation_vectors_match_or_regenerate() {
    if std::env::var("REGEN_VECTORS").is_ok() {
        let entries: Vec<serde_json::Value> = CASES
            .iter()
            .map(|&(passphrase, slot_count)| {
                serde_json::json!({
                    "passphrase": passphrase,
                    "slot_count": slot_count,
                    "positions": embedding_positions(passphrase.as_bytes(), slot_count),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "wire_format": WIRE_FORMAT_VERSION,
            "note": "Canonical Stegcore embedding positions, published as a \
                     timestamped record. A third-party tool that reproduces these \
                     exact positions is running Stegcore's position selection.",
            "vectors": entries,
        });
        std::fs::create_dir_all(vectors_path().parent().unwrap()).unwrap();
        std::fs::write(
            vectors_path(),
            format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()),
        )
        .unwrap();
        eprintln!("regenerated {}", vectors_path().display());
        return;
    }

    let raw = std::fs::read_to_string(vectors_path()).unwrap_or_else(|_| {
        panic!(
            "permutation vectors fixture missing; bootstrap it with \
             REGEN_VECTORS=1 cargo test -p stegcore-engine --test forensic_vectors"
        )
    });
    let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        doc["wire_format"].as_str(),
        Some(WIRE_FORMAT_VERSION),
        "vectors describe a different wire format than the engine produces"
    );
    let vectors = doc["vectors"].as_array().unwrap();
    assert_eq!(
        vectors.len(),
        CASES.len(),
        "vector count drifted from CASES"
    );

    for v in vectors {
        let passphrase = v["passphrase"].as_str().unwrap();
        let slot_count = v["slot_count"].as_u64().unwrap() as usize;
        let expected: Vec<usize> = v["positions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as usize)
            .collect();
        let actual = embedding_positions(passphrase.as_bytes(), slot_count);
        assert_eq!(
            actual, expected,
            "embedding permutation changed for ({passphrase:?}, {slot_count}); the seed \
             derivation moved. If deliberate, bump WIRE_FORMAT_VERSION and regenerate \
             the vectors, do not edit them in place"
        );
    }
}
