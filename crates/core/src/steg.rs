// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

use crate::errors::StegError;
use crate::keyfile::KeyFile;
use std::path::{Path, PathBuf};

// ── Cipher string → engine enum conversion ───────────────────────────────────

/// Parse a cipher identifier string into the engine's enum.
/// Accepted values: "ascon-128", "chacha20-poly1305", "aes-256-gcm".
pub(crate) fn parse_cipher(s: &str) -> Result<stegcore_engine::crypto::Cipher, StegError> {
    match s {
        "ascon-128" => Ok(stegcore_engine::crypto::Cipher::Ascon128),
        "chacha20-poly1305" => Ok(stegcore_engine::crypto::Cipher::ChaCha20Poly1305),
        "aes-256-gcm" => Ok(stegcore_engine::crypto::Cipher::Aes256Gcm),
        other => Err(StegError::UnsupportedFormat(format!(
            "unknown cipher: {other}"
        ))),
    }
}

/// Convert an engine `KeyFile` into the public `KeyFile` via JSON round-trip.
/// Both types serialise identically, so this is always safe.
fn convert_keyfile(engine_kf: stegcore_engine::keyfile::KeyFile) -> Result<KeyFile, StegError> {
    let json = serde_json::to_vec(&engine_kf)?;
    let kf: KeyFile = serde_json::from_slice(&json)?;
    Ok(kf)
}

/// Convert a public `KeyFile` into the engine's `KeyFile` via JSON round-trip.
fn to_engine_keyfile(kf: &KeyFile) -> Result<stegcore_engine::keyfile::KeyFile, StegError> {
    let json = serde_json::to_vec(kf)?;
    let engine_kf: stegcore_engine::keyfile::KeyFile = serde_json::from_slice(&json)?;
    Ok(engine_kf)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Score a cover file for embedding suitability. Returns 0.0–1.0.
pub fn assess(path: &Path) -> Result<f64, StegError> {
    stegcore_engine::steg::assess(path).map_err(StegError::from)
}

/// Convert the engine's `(written_path, keyfile)` result into the public shape,
/// translating the engine key file when present.
fn convert_embed_result(
    result: (PathBuf, Option<stegcore_engine::keyfile::KeyFile>),
) -> Result<(PathBuf, Option<KeyFile>), StegError> {
    let (path, kf) = result;
    match kf {
        Some(kf) => Ok((path, Some(convert_keyfile(kf)?))),
        None => Ok((path, None)),
    }
}

/// Embed payload using adaptive mode. Returns the path actually written (which
/// can differ from `out`, e.g. a JPEG cover forces a `.jpg` extension) plus an
/// optional key file.
pub fn embed_adaptive(
    cover: &Path,
    payload: &[u8],
    passphrase: &[u8],
    cipher: &str,
    out: &Path,
    export_key: bool,
) -> Result<(PathBuf, Option<KeyFile>), StegError> {
    let c = parse_cipher(cipher)?;
    let result =
        stegcore_engine::steg::embed(cover, payload, passphrase, c, "adaptive", out, export_key)
            .map_err(StegError::from)?;
    convert_embed_result(result)
}

/// Embed payload using sequential LSB mode. Returns the path actually written
/// plus an optional key file.
pub fn embed_sequential(
    cover: &Path,
    payload: &[u8],
    passphrase: &[u8],
    cipher: &str,
    out: &Path,
    export_key: bool,
) -> Result<(PathBuf, Option<KeyFile>), StegError> {
    let c = parse_cipher(cipher)?;
    let result =
        stegcore_engine::steg::embed(cover, payload, passphrase, c, "sequential", out, export_key)
            .map_err(StegError::from)?;
    convert_embed_result(result)
}

/// Embed payload into a WAV audio file (always sequential). Returns the path
/// actually written plus an optional key file.
pub fn embed_wav(
    cover: &Path,
    payload: &[u8],
    passphrase: &[u8],
    cipher: &str,
    out: &Path,
    export_key: bool,
) -> Result<(PathBuf, Option<KeyFile>), StegError> {
    let c = parse_cipher(cipher)?;
    let result =
        stegcore_engine::steg::embed(cover, payload, passphrase, c, "sequential", out, export_key)
            .map_err(StegError::from)?;
    convert_embed_result(result)
}

/// Embed two independent payloads (deniable mode).
pub fn embed_deniable(
    cover: &Path,
    real_payload: &[u8],
    decoy_payload: &[u8],
    real_pass: &[u8],
    decoy_pass: &[u8],
    cipher: &str,
    out: &Path,
) -> Result<(KeyFile, KeyFile), StegError> {
    let c = parse_cipher(cipher)?;
    let (real_kf, decoy_kf) = stegcore_engine::steg::embed_deniable(
        cover,
        real_payload,
        decoy_payload,
        real_pass,
        decoy_pass,
        c,
        out,
    )
    .map_err(StegError::from)?;
    Ok((convert_keyfile(real_kf)?, convert_keyfile(decoy_kf)?))
}

/// Extract hidden payload using only passphrase.
pub fn extract(stego: &Path, passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    stegcore_engine::steg::extract(stego, passphrase).map_err(StegError::from)
}

/// Extract hidden payload using an external key file.
pub fn extract_with_keyfile(
    stego: &Path,
    keyfile: &KeyFile,
    passphrase: &[u8],
) -> Result<Vec<u8>, StegError> {
    let engine_kf = to_engine_keyfile(keyfile)?;
    stegcore_engine::steg::extract_with_keyfile(stego, &engine_kf, passphrase)
        .map_err(StegError::from)
}

/// Read the embedded metadata header without decrypting the payload.
pub fn read_meta(path: &Path, passphrase: &[u8]) -> Result<serde_json::Value, StegError> {
    let json_str = stegcore_engine::steg::read_meta(path, passphrase).map_err(StegError::from)?;
    serde_json::from_str::<serde_json::Value>(&json_str).map_err(StegError::Json)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use stegcore_engine::crypto::Cipher as EngineCipher;

    fn sample_keyfile() -> KeyFile {
        KeyFile {
            engine: "rust-v1".into(),
            cipher: "chacha20-poly1305".into(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            salt: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            deniable: false,
            partition_seed: None,
            partition_half: None,
        }
    }

    // ── parse_cipher ────────────────────────────────────────────────────────

    #[test]
    fn parse_cipher_maps_ascon() {
        let got = parse_cipher("ascon-128").unwrap();
        assert!(matches!(got, EngineCipher::Ascon128));
    }

    #[test]
    fn parse_cipher_maps_chacha() {
        let got = parse_cipher("chacha20-poly1305").unwrap();
        assert!(matches!(got, EngineCipher::ChaCha20Poly1305));
    }

    #[test]
    fn parse_cipher_maps_aes() {
        let got = parse_cipher("aes-256-gcm").unwrap();
        assert!(matches!(got, EngineCipher::Aes256Gcm));
    }

    #[test]
    fn parse_cipher_rejects_unknown() {
        let e = parse_cipher("rot13").unwrap_err();
        match e {
            StegError::UnsupportedFormat(msg) => assert!(msg.contains("rot13")),
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn parse_cipher_rejects_empty_string() {
        let e = parse_cipher("").unwrap_err();
        assert!(matches!(e, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn parse_cipher_is_case_sensitive() {
        // We deliberately don't accept "AES-256-GCM" or "ChaCha20-Poly1305" —
        // canonical lowercase only.
        assert!(parse_cipher("AES-256-GCM").is_err());
        assert!(parse_cipher("ChaCha20-Poly1305").is_err());
    }

    // ── keyfile round-trip helpers ──────────────────────────────────────────

    #[test]
    fn keyfile_roundtrips_through_engine_and_back() {
        let original = sample_keyfile();
        // public → engine → public should produce an identical struct.
        let engine = to_engine_keyfile(&original).expect("to_engine ok");
        let back = convert_keyfile(engine).expect("convert ok");
        assert_eq!(back.engine, original.engine);
        assert_eq!(back.cipher, original.cipher);
        assert_eq!(back.nonce, original.nonce);
        assert_eq!(back.salt, original.salt);
        assert_eq!(back.deniable, original.deniable);
    }

    #[test]
    fn keyfile_roundtrip_preserves_deniable_partition_fields() {
        let mut original = sample_keyfile();
        original.deniable = true;
        original.partition_seed = Some("c2VlZA==".into());
        original.partition_half = Some(1);
        let engine = to_engine_keyfile(&original).unwrap();
        let back = convert_keyfile(engine).unwrap();
        assert!(back.deniable);
        assert_eq!(back.partition_seed.as_deref(), Some("c2VlZA=="));
        assert_eq!(back.partition_half, Some(1));
    }

    // ── Public wrappers surface parse_cipher errors cleanly ─────────────

    #[test]
    fn embed_adaptive_rejects_unknown_cipher() {
        let r = embed_adaptive(
            std::path::Path::new("/tmp/anything.png"),
            b"payload",
            b"pass",
            "rot13",
            std::path::Path::new("/tmp/out.png"),
            false,
        );
        match r {
            Err(StegError::UnsupportedFormat(msg)) => assert!(msg.contains("rot13")),
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn embed_sequential_rejects_unknown_cipher() {
        let r = embed_sequential(
            std::path::Path::new("/tmp/anything.png"),
            b"payload",
            b"pass",
            "nonsense",
            std::path::Path::new("/tmp/out.png"),
            false,
        );
        assert!(matches!(r, Err(StegError::UnsupportedFormat(_))));
    }

    #[test]
    fn embed_wav_rejects_unknown_cipher() {
        let r = embed_wav(
            std::path::Path::new("/tmp/anything.wav"),
            b"payload",
            b"pass",
            "twofish",
            std::path::Path::new("/tmp/out.wav"),
            false,
        );
        assert!(matches!(r, Err(StegError::UnsupportedFormat(_))));
    }

    #[test]
    fn embed_deniable_rejects_unknown_cipher() {
        let r = embed_deniable(
            std::path::Path::new("/tmp/anything.png"),
            b"real",
            b"decoy",
            b"realpass",
            b"decoypass",
            "fictional-cipher",
            std::path::Path::new("/tmp/out.png"),
        );
        assert!(matches!(r, Err(StegError::UnsupportedFormat(_))));
    }

    // ── Public wrappers surface engine errors (e.g. missing file) ───────

    #[test]
    fn assess_propagates_missing_file_error() {
        let p = std::path::PathBuf::from("/tmp/stegcore-core-assess-nope-987654.png");
        let _ = std::fs::remove_file(&p);
        let r = assess(&p);
        assert!(r.is_err());
    }

    #[test]
    fn extract_propagates_missing_file_error() {
        let p = std::path::PathBuf::from("/tmp/stegcore-core-extract-nope-987654.png");
        let _ = std::fs::remove_file(&p);
        let r = extract(&p, b"pass");
        assert!(r.is_err());
    }

    #[test]
    fn read_meta_propagates_missing_file_error() {
        let p = std::path::PathBuf::from("/tmp/stegcore-core-readmeta-nope-987654.png");
        let _ = std::fs::remove_file(&p);
        let r = read_meta(&p, b"pass");
        assert!(r.is_err());
    }

    #[test]
    fn extract_with_keyfile_propagates_missing_file_error() {
        let p = std::path::PathBuf::from("/tmp/stegcore-core-extkf-nope-987654.png");
        let _ = std::fs::remove_file(&p);
        let kf = sample_keyfile();
        let r = extract_with_keyfile(&p, &kf, b"pass");
        assert!(r.is_err());
    }
}
