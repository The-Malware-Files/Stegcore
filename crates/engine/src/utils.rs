// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

// Session 3 — format detection, temp file helpers.
use std::path::Path;

use tempfile::NamedTempFile;

use crate::errors::StegError;

// ── Format detection ──────────────────────────────────────────────────────────

/// Canonical lowercase format string from file extension.
pub fn detect_format(path: &Path) -> Result<String, StegError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .ok_or_else(|| StegError::UnsupportedFormat("no extension".into()))?;

    match ext.as_str() {
        "png" | "bmp" | "jpg" | "jpeg" | "webp" | "wav" | "flac" => Ok(ext),
        other => Err(StegError::UnsupportedFormat(other.into())),
    }
}

/// All extensions accepted as cover/stego input.
pub fn supported_extensions() -> &'static [&'static str] {
    &["png", "bmp", "jpg", "jpeg", "webp", "wav", "flac"]
}

/// Formats valid for embedding (FLAC is extract/analyze only).
pub fn embed_extensions() -> &'static [&'static str] {
    &["png", "bmp", "jpg", "jpeg", "webp", "wav"]
}

// ── Temp file helper ──────────────────────────────────────────────────────────

/// Creates a `NamedTempFile` with restrictive permissions (0o600 on Unix).
pub fn temp_file() -> Result<NamedTempFile, StegError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let f = tempfile::NamedTempFile::new().map_err(StegError::Io)?;
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(StegError::Io)?;
        Ok(f)
    }
    #[cfg(not(unix))]
    {
        tempfile::NamedTempFile::new().map_err(StegError::Io)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_formats_detected() {
        let cases = [
            ("image.png", "png"),
            ("image.PNG", "png"),
            ("image.bmp", "bmp"),
            ("image.jpg", "jpg"),
            ("image.JPEG", "jpeg"),
            ("image.webp", "webp"),
            ("audio.wav", "wav"),
            ("audio.flac", "flac"),
        ];
        for (name, expected) in cases {
            let path = Path::new(name);
            let result = detect_format(path).unwrap();
            assert_eq!(result, expected, "format mismatch for {name}");
        }
    }

    #[test]
    fn unsupported_format_returns_error() {
        let cases = ["image.tiff", "video.mp4", "document.pdf", "archive.zip"];
        for name in cases {
            let result = detect_format(Path::new(name));
            assert!(
                matches!(result, Err(StegError::UnsupportedFormat(_))),
                "expected UnsupportedFormat for {name}"
            );
        }
    }

    #[test]
    fn no_extension_returns_error() {
        let result = detect_format(Path::new("noextension"));
        assert!(matches!(result, Err(StegError::UnsupportedFormat(_))));
    }

    #[test]
    fn temp_file_created_successfully() {
        let f = temp_file().unwrap();
        assert!(f.path().exists());
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let f = temp_file().unwrap();
        let meta = std::fs::metadata(f.path()).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "temp file permissions should be 0o600, got {mode:o}"
        );
    }

    #[test]
    fn embed_formats_are_subset_of_supported() {
        let supported: std::collections::HashSet<_> = supported_extensions().iter().collect();
        for ext in embed_extensions() {
            assert!(
                supported.contains(ext),
                "{ext} in embed_extensions but not in supported_extensions"
            );
        }
    }

    #[test]
    fn flac_not_in_embed_formats() {
        assert!(
            !embed_extensions().contains(&"flac"),
            "FLAC should not be in embed formats"
        );
    }
}
