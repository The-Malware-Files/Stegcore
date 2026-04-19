// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Session 3 — KeyFile serialisation/deserialisation, legacy detection.
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::Cipher;
use crate::errors::StegError;

// ── KeyFile struct ────────────────────────────────────────────────────────────

/// Optional export format. Stego files are self-contained; this is only
/// produced when the user explicitly requests `--export-key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    /// Engine version tag — used to detect legacy files.
    pub engine: String,
    pub cipher: Cipher,
    #[serde(with = "b64_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "b64_bytes")]
    pub salt: Vec<u8>,
    pub deniable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_half: Option<u8>,
}

impl KeyFile {
    pub fn new(cipher: Cipher, nonce: Vec<u8>, salt: Vec<u8>) -> Self {
        KeyFile {
            engine: "rust-v1".into(),
            cipher,
            nonce,
            salt,
            deniable: false,
            partition_seed: None,
            partition_half: None,
        }
    }
}

// ── I/O ───────────────────────────────────────────────────────────────────────

pub fn write_key_file(path: &Path, kf: &KeyFile) -> Result<(), StegError> {
    let json = serde_json::to_string_pretty(kf)?;
    std::fs::write(path, json).map_err(StegError::Io)
}

pub fn read_key_file(path: &Path) -> Result<KeyFile, StegError> {
    if !path.exists() {
        return Err(StegError::FileNotFound(path.display().to_string()));
    }
    let raw = std::fs::read(path).map_err(StegError::Io)?;

    // Legacy Python key files use a different schema: they contain a "cipher"
    // field but no "engine" field. Detect and reject them with a clear error.
    let probe: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|_| StegError::CorruptedFile)?;

    if probe.get("engine").is_none() {
        return Err(StegError::LegacyKeyFile);
    }

    let engine = probe["engine"].as_str().unwrap_or("");
    if !engine.starts_with("rust-") {
        return Err(StegError::LegacyKeyFile);
    }

    let kf: KeyFile = serde_json::from_slice(&raw)?;
    Ok(kf)
}

// ── base64 serde helper ───────────────────────────────────────────────────────

mod b64_bytes {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_kf() -> KeyFile {
        KeyFile::new(Cipher::ChaCha20Poly1305, vec![0u8; 12], vec![1u8; 32])
    }

    #[test]
    fn roundtrip_write_read() {
        let kf = make_kf();
        let tmp = NamedTempFile::new().unwrap();
        write_key_file(tmp.path(), &kf).unwrap();
        let restored = read_key_file(tmp.path()).unwrap();
        assert_eq!(restored.engine, "rust-v1");
        assert_eq!(restored.nonce, kf.nonce);
        assert_eq!(restored.salt, kf.salt);
        assert_eq!(restored.cipher, kf.cipher);
        assert!(!restored.deniable);
    }

    #[test]
    fn missing_file_returns_file_not_found() {
        let result = read_key_file(Path::new("/tmp/does_not_exist_stegcore_xyz.json"));
        assert!(matches!(result, Err(StegError::FileNotFound(_))));
    }

    #[test]
    fn legacy_python_key_file_returns_legacy_error() {
        // Simulate a Python-era key file: has cipher/nonce/salt but no "engine".
        let json = r#"{"cipher": "chacha20-poly1305", "nonce": "AAAA", "salt": "BBBB"}"#;
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), json).unwrap();
        let result = read_key_file(tmp.path());
        assert!(
            matches!(result, Err(StegError::LegacyKeyFile)),
            "got: {result:?}"
        );
    }

    #[test]
    fn malformed_json_returns_corrupted_file() {
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"not json at all !!").unwrap();
        let result = read_key_file(tmp.path());
        assert!(
            matches!(result, Err(StegError::CorruptedFile)),
            "got: {result:?}"
        );
    }

    #[test]
    fn valid_json_with_missing_required_fields_returns_json_error() {
        // Has engine but missing cipher/nonce/salt — serde should fail.
        let json = r#"{"engine": "rust-v1"}"#;
        let tmp = NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), json).unwrap();
        let result = read_key_file(tmp.path());
        assert!(matches!(result, Err(StegError::Json(_))), "got: {result:?}");
    }

    #[test]
    fn base64_fields_survive_roundtrip() {
        let nonce: Vec<u8> = (0u8..12).collect();
        let salt: Vec<u8> = (0u8..32).collect();
        let kf = KeyFile::new(Cipher::Ascon128, nonce.clone(), salt.clone());
        let json = serde_json::to_string(&kf).unwrap();
        let restored: KeyFile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.nonce, nonce);
        assert_eq!(restored.salt, salt);
    }

    #[test]
    fn deniable_key_file_roundtrip() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let mut kf = make_kf();
        kf.deniable = true;
        kf.partition_seed = Some(B64.encode([0xABu8; 32]));
        kf.partition_half = Some(0);
        let tmp = NamedTempFile::new().unwrap();
        write_key_file(tmp.path(), &kf).unwrap();
        let restored = read_key_file(tmp.path()).unwrap();
        assert!(restored.deniable);
        assert_eq!(restored.partition_half, Some(0));
    }
}
