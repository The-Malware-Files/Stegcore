// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use crate::errors::StegError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Optional export format. Stego files are self-contained; this is only
/// produced when the user explicitly requests key file export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    pub engine: String,
    /// Cipher identifier string (e.g. "chacha20-poly1305").
    pub cipher: String,
    /// Base64-encoded nonce.
    pub nonce: String,
    /// Base64-encoded salt.
    pub salt: String,
    pub deniable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_half: Option<u8>,
}

/// Write a key file to disk as JSON with restricted permissions (0o600 on Unix).
pub fn write_key_file(path: &Path, keyfile: &KeyFile) -> Result<(), StegError> {
    let json = serde_json::to_string_pretty(keyfile)?;
    std::fs::write(path, json).map_err(StegError::Io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(StegError::Io)?;
    }
    Ok(())
}

/// Read a key file from disk, detecting legacy Python format.
pub fn read_key_file(path: &Path) -> Result<KeyFile, StegError> {
    if !path.exists() {
        return Err(StegError::FileNotFound(path.display().to_string()));
    }
    let raw = std::fs::read(path).map_err(StegError::Io)?;

    // Detect legacy Python key files: they lack the "engine" field.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_keyfile() -> KeyFile {
        KeyFile {
            engine: "rust-v1".into(),
            cipher: "chacha20-poly1305".into(),
            nonce: "dGVzdG5vbmNl".into(),
            salt: "dGVzdHNhbHQ=".into(),
            deniable: false,
            partition_seed: None,
            partition_half: None,
        }
    }

    #[test]
    fn round_trip_write_read() {
        let kf = sample_keyfile();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.json");
        write_key_file(&path, &kf).unwrap();
        let loaded = read_key_file(&path).unwrap();
        assert_eq!(loaded.engine, "rust-v1");
        assert_eq!(loaded.cipher, "chacha20-poly1305");
        assert_eq!(loaded.nonce, kf.nonce);
        assert_eq!(loaded.salt, kf.salt);
        assert!(!loaded.deniable);
        assert!(loaded.partition_seed.is_none());
    }

    #[test]
    fn deniable_keyfile_round_trip() {
        let kf = KeyFile {
            engine: "rust-v1".into(),
            cipher: "aes-256-gcm".into(),
            nonce: "bm9uY2U=".into(),
            salt: "c2FsdA==".into(),
            deniable: true,
            partition_seed: Some("c2VlZA==".into()),
            partition_half: Some(0),
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("deny.json");
        write_key_file(&path, &kf).unwrap();
        let loaded = read_key_file(&path).unwrap();
        assert!(loaded.deniable);
        assert_eq!(loaded.partition_half, Some(0));
        assert!(loaded.partition_seed.is_some());
    }

    #[test]
    fn read_nonexistent_returns_file_not_found() {
        let r = read_key_file(Path::new("/tmp/does_not_exist_xyz.json"));
        assert!(matches!(r, Err(StegError::FileNotFound(_))));
    }

    #[test]
    fn read_legacy_python_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.json");
        // Python key file lacks "engine" field
        std::fs::write(&path, r#"{"cipher":"aes","nonce":"abc","salt":"def"}"#).unwrap();
        let r = read_key_file(&path);
        assert!(matches!(r, Err(StegError::LegacyKeyFile)));
    }

    #[test]
    fn read_wrong_engine_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.json");
        std::fs::write(
            &path,
            r#"{"engine":"python-v2","cipher":"aes","nonce":"abc","salt":"def","deniable":false}"#,
        )
        .unwrap();
        let r = read_key_file(&path);
        assert!(matches!(r, Err(StegError::LegacyKeyFile)));
    }

    #[test]
    fn read_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json at all {{{").unwrap();
        let r = read_key_file(&path);
        assert!(matches!(r, Err(StegError::CorruptedFile)));
    }

    #[test]
    fn serialise_omits_none_fields() {
        let kf = sample_keyfile();
        let json = serde_json::to_string(&kf).unwrap();
        assert!(!json.contains("partition_seed"));
        assert!(!json.contains("partition_half"));
    }

    #[cfg(unix)]
    #[test]
    fn keyfile_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let kf = sample_keyfile();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("perms.json");
        write_key_file(&path, &kf).unwrap();
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
