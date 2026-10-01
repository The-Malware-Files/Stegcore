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

//! The wild-sample verifier hashes bytes and never interprets them.
//!
//! # Why this file exists at all
//!
//! The verifier is the only part of the wild-sample machinery that reads
//! untrusted content, and the content in question is live malware sitting on a
//! machine built to hold it. Its safety argument is one sentence: *the only
//! operation performed on a sample byte is `Sha256::update`*. A sentence in a
//! doc comment is not a control, because the next person to add a convenience
//! (sniff the real media type while we are here, warn if the PNG header is
//! wrong) would be adding a parser to the one module that must not have one,
//! and nothing would stop them.
//!
//! So the property is checked two ways.
//!
//! **Statically**, by reading the verifier's own source and failing if it names
//! a decoder, a deserialiser or a subprocess. Crude, and crude is the point: it
//! fires on the attempt rather than on the consequence, and it fires in CI
//! before anybody has to reason about whether the new call is safe.
//!
//! **Behaviourally**, by feeding the verifier content no decoder would accept
//! and content designed to make one fall over, and showing the answer depends
//! on nothing but the bytes.
//!
//! # What it cannot check
//!
//! A decoder reached indirectly, through a helper in another module that the
//! guard list does not name. That is a real gap and it is why the verifier
//! calls nothing but `std::fs`, `std::io::Read` and the engine's own SHA-256,
//! which is a pure function over bytes with no allocation sized from content.
//! The static check lists the names a reviewer would have to go out of their
//! way to hide; it is a tripwire, not a proof.

use std::fs;

use stegcore_engine::bruteforce::digest::{hex, sha256_bytes};
use stegcore_engine::wild::manifest::{
    Payload, Provenance, Terms, WildManifest, WildSample, WILD_MANIFEST_FORMAT,
};
use stegcore_engine::wild::verify::verify_directory;

/// The verifier's source, as compiled into this test binary.
const VERIFIER_SOURCE: &str = include_str!("../src/wild/verify.rs");

/// The part of that source that ships, which is everything above its own test
/// module.
///
/// The split is deliberate and it is the one concession this guard makes. The
/// verifier's tests legitimately deserialise a *report*, which is our own JSON
/// and not sample content, and a guard that cannot tell those apart would
/// either fire on a safe call or be weakened until it fired on nothing. The
/// line is drawn at `#[cfg(test)]` because that is exactly the line between
/// code that runs on the isolated machine and code that does not.
fn shipping_source() -> &'static str {
    VERIFIER_SOURCE
        .split("#[cfg(test)]")
        .next()
        .expect("split always yields at least one part")
}

/// Tokens that would mean the verifier had started interpreting sample content.
///
/// Each one is a crate or call that turns bytes into structure. The list is the
/// decoder surface the engine actually has (every third-party parser in
/// `Cargo.toml` that could be pointed at a sample), plus the generic ways to
/// reach one.
const FORBIDDEN: &[&str] = &[
    "image::",
    "ImageReader",
    "DynamicImage",
    "png::",
    "Decoder",
    "hound",
    "flac_io",
    "dct_io",
    "lopdf",
    "zip::",
    "lz4_flex",
    "ruzstd",
    "serde_json::from",
    "toml::from",
    "from_slice",
    "from_reader",
    "Command::new",
    "std::process",
];

#[test]
fn the_verifier_source_names_no_decoder() {
    // The guard list itself lives in this file and not in the verifier, so
    // searching the verifier's source cannot match the list.
    let source = shipping_source();
    let mut found = Vec::new();
    for token in FORBIDDEN {
        if source.contains(token) {
            found.push(*token);
        }
    }
    assert!(
        found.is_empty(),
        "crates/engine/src/wild/verify.rs now names {found:?}. That module reads live \
         malware samples; its entire safety argument is that the only thing it does with \
         a sample byte is hash it. If the new call genuinely belongs there, it belongs \
         behind a different boundary, and this test is the conversation."
    );
}

#[test]
fn the_verifier_source_hashes_and_does_nothing_else_with_a_buffer() {
    // The buffer appears exactly twice: filled by `read`, handed to `update`.
    let updates = VERIFIER_SOURCE
        .matches("hasher.update(&buffer[..n])")
        .count();
    assert_eq!(
        updates, 1,
        "the single place sample bytes are consumed has moved or multiplied"
    );
    let reads = shipping_source()
        .matches("file.read(&mut buffer[..room])")
        .count();
    assert_eq!(
        reads, 1,
        "the single place sample bytes are read has changed"
    );
}

fn provenance() -> Provenance {
    Provenance {
        origin: "Synthesised in this test. Nothing was obtained from anywhere.".to_string(),
        reobtain: "Re-run the test; it writes its own bytes.".to_string(),
        verified: "2026-10-01".to_string(),
        note: "These bytes exist only inside this test binary. Nothing here describes a \
               real sample, and nothing was fetched."
            .to_string(),
    }
}

fn terms() -> Terms {
    Terms {
        licence: "AGPL-3.0-or-later".to_string(),
        redistributable: true,
        note: "Test fixture, written by this file.".to_string(),
    }
}

fn manifest_for(files: &[(&str, &[u8])], dir: &std::path::Path) -> WildManifest {
    let mut samples = Vec::new();
    for (id, bytes) in files {
        let digest = hex(&sha256_bytes(bytes));
        fs::write(dir.join(&digest), bytes).expect("write the fixture");
        samples.push(WildSample {
            id: (*id).to_string(),
            sha256: digest,
            bytes: bytes.len() as u64,
            media: "application/octet-stream".to_string(),
            family: "synthetic".to_string(),
            campaign: None,
            payload: Payload::Unknown,
            tool: None,
            truth_basis: None,
            provenance: provenance(),
            terms: terms(),
        });
    }
    let manifest = WildManifest {
        format: WILD_MANIFEST_FORMAT,
        corpus: "verifier-fixture".to_string(),
        note: "Bytes written by tests/wild_verifier_never_parses.rs.".to_string(),
        compiled: "2026-10-01".to_string(),
        samples,
    };
    manifest.validate().expect("the fixture manifest is valid");
    manifest
}

#[test]
fn content_that_would_stop_a_decoder_dead_verifies_on_its_bytes_alone() {
    let dir = tempfile::tempdir().expect("tempdir");

    // A PNG signature with an IHDR claiming a 65535 by 65535 image and then
    // nothing, which is the shape of a decompression bomb; a zip local-file
    // header truncated mid-field; a GIF signature with no logical screen
    // descriptor; a WAV RIFF header declaring a chunk far larger than the file;
    // and a run of null bytes. Every one of these is a file that a parser
    // either refuses or allocates wildly for. To this module they are lengths
    // and digests.
    let png_bomb: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xff\xff\xff\xff\xff\xff\xff";
    let zip_truncated: &[u8] = b"PK\x03\x04\x14\x00\x00\x00\x08";
    let gif_headless: &[u8] = b"GIF89a";
    let wav_overlong: &[u8] = b"RIFF\xff\xff\xff\xffWAVEfmt \xff\xff\xff\xff";
    let nulls = vec![0u8; 8192];
    let high_bytes: Vec<u8> = (0..=255u8).cycle().take(5000).collect();

    let files: Vec<(&str, &[u8])> = vec![
        ("png-bomb", png_bomb),
        ("zip-truncated", zip_truncated),
        ("gif-headless", gif_headless),
        ("wav-overlong", wav_overlong),
        ("nulls", &nulls),
        ("high-bytes", &high_bytes),
    ];
    let manifest = manifest_for(&files, dir.path());

    let report = verify_directory(&manifest, dir.path()).expect("verify");
    assert!(
        report.is_clean(),
        "every fixture should verify on its bytes: {report:?}"
    );
    assert_eq!(report.matched.len(), files.len());
}

#[test]
fn one_flipped_bit_is_the_whole_difference_between_pass_and_fail() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = b"\x89PNG\r\n\x1a\n-------- the carrier bytes --------".to_vec();
    let manifest = manifest_for(&[("sample", &original)], dir.path());

    let report = verify_directory(&manifest, dir.path()).expect("verify");
    assert!(report.is_clean());

    let mut flipped = original.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    fs::write(dir.path().join(&manifest.samples[0].sha256), &flipped).expect("rewrite");

    let report = verify_directory(&manifest, dir.path()).expect("verify");
    assert_eq!(report.digest_mismatch.len(), 1);
    assert!(report.size_mismatch.is_empty(), "the length did not change");
    assert!(!report.is_clean());
}

#[test]
fn a_file_of_zero_bytes_is_caught_by_the_manifest_rather_than_by_a_parser() {
    // Belt and braces on the boundary case: a zero-byte entry is refused at
    // manifest validation, so the verifier is never handed one and never has
    // to decide what an empty file means.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut manifest = manifest_for(&[("sample", b"not empty")], dir.path());
    manifest.samples[0].bytes = 0;
    assert!(manifest.validate().is_err());

    // And if one reaches the directory anyway, it is simply unaccounted for.
    let empty_digest = hex(&sha256_bytes(b""));
    fs::write(dir.path().join(&empty_digest), b"").expect("write");
    let clean = manifest_for(&[("sample", b"not empty")], dir.path());
    let report = verify_directory(&clean, dir.path()).expect("verify");
    assert_eq!(report.unexpected, vec![empty_digest]);
}
