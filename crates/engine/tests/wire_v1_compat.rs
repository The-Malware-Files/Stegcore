// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! A payload sealed by the zstd-era engine must stay readable forever.
//!
//! This fixture was produced by the engine as it stood on 2026-08-20, before
//! compression moved from zstd to lz4. It cannot be regenerated: nothing writes
//! zstd any more. That is the point. If this test ever fails, a build has lost
//! the ability to open files people already have, which for a tool whose whole
//! promise is getting hidden data back is the worst failure available to it.
//!
//! Do not "fix" a failure here by regenerating the fixture.

use stegcore_engine::steg::open_blob;

/// `seal_blob(b"v1-fixture-passphrase", …, ChaCha20Poly1305)`, engine tag
/// `rust-v1`, payload compressed with zstd.
const V1_BLOB_HEX: &str = "00e67b22656e67696e65223a22727573742d7631222c22636970686572223a2263686163686132302d706f6c7931333035222c226d6f6465223a2277617465726d61726b222c226e6f6e6365223a2230776c673044543478724a6f74675068222c2273616c74223a224b76415952364e554d66494c494c653946504a5570304730384b334d626d704866736373414c4a7437666b3d222c22636970686572746578745f6c656e223a37372c2264656e6961626c65223a66616c73652c22706172746974696f6e5f73656564223a6e756c6c2c22706172746974696f6e5f68616c66223a6e756c6c7d2442a4532da38833b934127834130b4f05e5556d9275153d2846f252814a947c085bd4bee86ad68a321be3752a40d755f1f3dfb3fafd539461c55394df485bbdc56d94bb1c24cc7ec5f37f0597";

const V1_PASSPHRASE: &[u8] = b"v1-fixture-passphrase";
const V1_PLAINTEXT: &[u8] = b"compatibility fixture: sealed by the zstd-era engine";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn zstd_era_payload_still_opens() {
    let blob = hex_to_bytes(V1_BLOB_HEX);
    let recovered = open_blob(&blob, V1_PASSPHRASE)
        .expect("a rust-v1 payload must still open after the move to lz4");
    assert_eq!(
        recovered, V1_PLAINTEXT,
        "the rust-v1 payload opened but came back wrong"
    );
}

#[test]
fn zstd_era_payload_still_rejects_the_wrong_passphrase() {
    let blob = hex_to_bytes(V1_BLOB_HEX);
    assert!(
        open_blob(&blob, b"not-the-passphrase").is_err(),
        "the old format must not have become more permissive"
    );
}

#[test]
fn new_payloads_round_trip_and_are_tagged_v2() {
    use stegcore_engine::crypto::Cipher;
    use stegcore_engine::forensics::WIRE_FORMAT_VERSION;
    use stegcore_engine::steg::seal_blob;

    let payload = b"written after the change";
    let blob = seal_blob(
        b"pass-for-the-new-format",
        payload,
        Cipher::ChaCha20Poly1305,
    )
    .unwrap();

    // The metadata is plaintext JSON ahead of the ciphertext; read the tag
    // straight out of it rather than trusting the constant alone.
    let text = String::from_utf8_lossy(&blob[..blob.len().min(400)]);
    assert!(
        text.contains(&format!("\"engine\":\"{WIRE_FORMAT_VERSION}\"")),
        "new payloads should carry the current wire-format tag"
    );
    assert_eq!(WIRE_FORMAT_VERSION, "rust-v2");

    let recovered = open_blob(&blob, b"pass-for-the-new-format").unwrap();
    assert_eq!(recovered, payload);
}
