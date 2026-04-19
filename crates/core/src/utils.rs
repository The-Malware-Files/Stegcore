// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use crate::errors::StegError;
use std::path::Path;

/// All supported image file extensions (lowercase).
pub fn supported_image_extensions() -> &'static [&'static str] {
    &["png", "bmp", "jpg", "jpeg", "webp"]
}

/// All supported audio file extensions (lowercase).
pub fn supported_audio_extensions() -> &'static [&'static str] {
    &["wav", "flac"]
}

/// All supported extensions for embedding (FLAC is analyse/extract only).
pub fn supported_embed_extensions() -> &'static [&'static str] {
    &["png", "bmp", "jpg", "jpeg", "webp", "wav"]
}

/// All extensions accepted by the application (embed + analyse).
pub fn supported_extensions() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = supported_image_extensions().to_vec();
    all.extend_from_slice(supported_audio_extensions());
    all
}

/// Detect canonical format string from file extension, then verify the
/// file header (magic bytes) matches. Returns an error if the extension
/// is unsupported or the header disagrees with the declared type.
pub fn detect_format(path: &Path) -> Result<String, StegError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .ok_or_else(|| StegError::UnsupportedFormat("(no extension)".to_string()))?;

    let format = match ext.as_str() {
        "png" => "png",
        "bmp" => "bmp",
        "jpg" | "jpeg" => "jpeg",
        "webp" => "webp",
        "wav" => "wav",
        "flac" => "flac",
        other => return Err(StegError::UnsupportedFormat(other.to_string())),
    };

    // Verify magic bytes if the file is readable
    if path.exists() {
        verify_magic_bytes(path, format)?;
    }

    Ok(format.to_string())
}

/// Check the first few bytes of a file against expected magic signatures.
fn verify_magic_bytes(path: &Path, expected_format: &str) -> Result<(), StegError> {
    use std::io::Read;

    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Ok(()), // can't read — let the engine handle the error
    };

    let mut header = [0u8; 12];
    let n = f.read(&mut header).unwrap_or(0);
    if n < 2 {
        return Ok(()); // too short to check
    }

    let ok = match expected_format {
        "png" => n >= 8 && header[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        "bmp" => header[..2] == [b'B', b'M'],
        "jpeg" => n >= 3 && header[..3] == [0xFF, 0xD8, 0xFF],
        "wav" => n >= 12 && &header[..4] == b"RIFF" && &header[8..12] == b"WAVE",
        "webp" => n >= 12 && &header[..4] == b"RIFF" && &header[8..12] == b"WEBP",
        "flac" => n >= 4 && &header[..4] == b"fLaC",
        _ => true, // unknown format — skip check
    };

    if !ok {
        return Err(StegError::CorruptedFile);
    }

    Ok(())
}

/// Validate a file before passing it to the engine.
/// Checks existence, size limits, and emptiness.
/// Uses direct metadata call to avoid TOCTOU race conditions.
pub fn validate_file(path: &Path, max_bytes: u64) -> Result<(), StegError> {
    let meta = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StegError::FileNotFound(path.display().to_string())
        } else {
            StegError::Io(e)
        }
    })?;
    if meta.len() == 0 {
        return Err(StegError::EmptyPayload);
    }
    if meta.len() > max_bytes {
        return Err(StegError::FileTooLarge {
            size_mb: meta.len() / (1024 * 1024),
            max_mb: max_bytes / (1024 * 1024),
        });
    }
    Ok(())
}

/// Create a temporary file with the given suffix. Permissions: owner-only (0o600).
pub fn temp_file(suffix: &str) -> Result<tempfile::NamedTempFile, StegError> {
    let file = tempfile::Builder::new()
        .prefix("stegcore-")
        .suffix(suffix)
        .tempfile()
        .map_err(StegError::Io)?;

    // Set owner-only permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(file.path(), perms).map_err(StegError::Io)?;
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn supported_image_exts_includes_png() {
        assert!(supported_image_extensions().contains(&"png"));
    }

    #[test]
    fn supported_image_exts_includes_jpeg() {
        assert!(supported_image_extensions().contains(&"jpeg"));
        assert!(supported_image_extensions().contains(&"jpg"));
    }

    #[test]
    fn supported_audio_exts() {
        assert!(supported_audio_extensions().contains(&"wav"));
        assert!(supported_audio_extensions().contains(&"flac"));
    }

    #[test]
    fn supported_embed_excludes_flac() {
        assert!(!supported_embed_extensions().contains(&"flac"));
    }

    #[test]
    fn supported_extensions_includes_all() {
        let all = supported_extensions();
        assert!(all.contains(&"png"));
        assert!(all.contains(&"wav"));
        assert!(all.contains(&"flac"));
    }

    #[test]
    fn detect_format_png() {
        let p = Path::new("/tmp/nonexistent_test.png");
        assert_eq!(detect_format(p).unwrap(), "png");
    }

    #[test]
    fn detect_format_jpg_normalises_to_jpeg() {
        let p = Path::new("/tmp/test.jpg");
        assert_eq!(detect_format(p).unwrap(), "jpeg");
    }

    #[test]
    fn detect_format_jpeg() {
        let p = Path::new("/tmp/test.jpeg");
        assert_eq!(detect_format(p).unwrap(), "jpeg");
    }

    #[test]
    fn detect_format_wav() {
        assert_eq!(detect_format(Path::new("/tmp/t.wav")).unwrap(), "wav");
    }

    #[test]
    fn detect_format_flac() {
        assert_eq!(detect_format(Path::new("/tmp/t.flac")).unwrap(), "flac");
    }

    #[test]
    fn detect_format_unsupported() {
        let r = detect_format(Path::new("/tmp/test.gif"));
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("gif"));
    }

    #[test]
    fn detect_format_no_extension() {
        let r = detect_format(Path::new("/tmp/noext"));
        assert!(r.is_err());
    }

    #[test]
    fn validate_file_nonexistent() {
        let r = validate_file(Path::new("/tmp/surely_does_not_exist_xyz.png"), 1_000_000);
        assert!(matches!(r, Err(StegError::FileNotFound(_))));
    }

    #[test]
    fn validate_file_empty() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // file is empty (0 bytes)
        let _ = f.flush();
        let r = validate_file(f.path(), 1_000_000);
        assert!(matches!(r, Err(StegError::EmptyPayload)));
    }

    #[test]
    fn validate_file_too_large() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        f.flush().unwrap();
        let r = validate_file(f.path(), 50); // max 50 bytes
        assert!(matches!(r, Err(StegError::FileTooLarge { .. })));
    }

    #[test]
    fn validate_file_ok() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"hello").unwrap();
        f.flush().unwrap();
        assert!(validate_file(f.path(), 1_000_000).is_ok());
    }

    #[test]
    fn temp_file_creates_with_suffix() {
        let f = temp_file(".png").unwrap();
        assert!(f.path().to_str().unwrap().ends_with(".png"));
    }

    #[test]
    fn temp_file_has_stegcore_prefix() {
        let f = temp_file(".wav").unwrap();
        let name = f.path().file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("stegcore-"));
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let f = temp_file(".test").unwrap();
        let perms = std::fs::metadata(f.path()).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn magic_bytes_png_valid() {
        let mut f = tempfile::Builder::new().suffix(".png").tempfile().unwrap();
        f.write_all(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
            .unwrap();
        f.flush().unwrap();
        assert!(detect_format(f.path()).is_ok());
    }

    #[test]
    fn magic_bytes_png_invalid() {
        let mut f = tempfile::Builder::new().suffix(".png").tempfile().unwrap();
        f.write_all(b"NOT A PNG FILE AT ALL").unwrap();
        f.flush().unwrap();
        assert!(matches!(
            detect_format(f.path()),
            Err(StegError::CorruptedFile)
        ));
    }

    #[test]
    fn magic_bytes_bmp_valid() {
        let mut f = tempfile::Builder::new().suffix(".bmp").tempfile().unwrap();
        f.write_all(b"BM\x00\x00\x00\x00").unwrap();
        f.flush().unwrap();
        assert!(detect_format(f.path()).is_ok());
    }

    #[test]
    fn magic_bytes_jpeg_valid() {
        let mut f = tempfile::Builder::new().suffix(".jpg").tempfile().unwrap();
        f.write_all(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap();
        f.flush().unwrap();
        assert!(detect_format(f.path()).is_ok());
    }

    #[test]
    fn magic_bytes_wav_valid() {
        let mut f = tempfile::Builder::new().suffix(".wav").tempfile().unwrap();
        f.write_all(b"RIFF\x00\x00\x00\x00WAVE").unwrap();
        f.flush().unwrap();
        assert!(detect_format(f.path()).is_ok());
    }
}
