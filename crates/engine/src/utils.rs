// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

// Session 3 — format detection, temp file helpers.
use std::path::Path;

use image::{DynamicImage, ImageReader};
use tempfile::NamedTempFile;

use crate::errors::StegError;

// ── Format detection ──────────────────────────────────────────────────────────

/// Inspect the first bytes of a file and return its canonical format string
/// (`png`, `bmp`, `jpg`, `webp`, `wav`, `flac`) if the magic bytes match a
/// known signature. Returns `None` if the file cannot be read or doesn't
/// match any known signature.
///
/// This is the authoritative dispatch — file content is truth. The
/// extension fallback below is only used when the file cannot be opened
/// (e.g. it doesn't exist yet, or the caller hasn't created it).
fn detect_format_by_magic(path: &Path) -> Option<&'static str> {
    use std::io::Read;
    let mut head = [0u8; 16];
    let n = std::fs::File::open(path).ok()?.read(&mut head).ok()?;
    if n < 4 {
        return None;
    }

    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if n >= 8 && head[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A] {
        return Some("png");
    }
    // BMP: "BM"
    if head[..2] == *b"BM" {
        return Some("bmp");
    }
    // JPEG: FF D8 FF
    if head[..3] == [0xFF, 0xD8, 0xFF] {
        return Some("jpg");
    }
    // FLAC: "fLaC"
    if head[..4] == *b"fLaC" {
        return Some("flac");
    }
    // WebP and WAV share the RIFF container prefix; distinguish by the
    // form-type bytes at offset 8-12.
    if n >= 12 && &head[..4] == b"RIFF" {
        match &head[8..12] {
            b"WEBP" => return Some("webp"),
            b"WAVE" => return Some("wav"),
            _ => {}
        }
    }
    None
}

/// Canonical lowercase format string for a file.
///
/// Magic-byte content sniffing is authoritative when the file exists and
/// matches a known signature. Falls back to the file extension only when
/// the magic-byte check is inconclusive (file unreadable, signature
/// unknown), so a mis-extensioned file (PNG bytes named `data.jpg`) is
/// dispatched by content, not by lie.
pub fn detect_format(path: &Path) -> Result<String, StegError> {
    if let Some(fmt) = detect_format_by_magic(path) {
        return Ok(fmt.to_string());
    }
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

// ── Content-sniffing image loader ────────────────────────────────────────────

/// Load an image by **content-sniffing** the format rather than trusting
/// the file extension. A PNG file named `data.jpg` decodes as PNG; a JPEG
/// file named `data.png` decodes as JPEG. The image crate's plain
/// `image::open()` uses the extension and mis-routes deliberately
/// disguised files. This helper is the engine's single source of truth
/// for image loading.
pub fn open_image_by_content(path: &Path) -> Result<DynamicImage, StegError> {
    let mut reader = ImageReader::open(path)
        .map_err(StegError::Io)?
        .with_guessed_format()
        .map_err(StegError::Io)?;

    // Own the resource cap explicitly rather than inheriting the dependency
    // default. `Limits::default()` already caps allocation at 512 MiB; we add
    // strict dimension bounds so a crafted header claiming an enormous image
    // is refused up front rather than relying on the allocation cap alone.
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(50_000);
    limits.max_image_height = Some(50_000);
    reader.limits(limits);

    // Malformed input has been observed to panic inside third-party image
    // decoders. This is the single chokepoint every caller (embed, assess,
    // extract, analyse) funnels through, so catch any decoder panic here and
    // return a clean error instead of unwinding out of the engine.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || reader.decode())) {
        Ok(result) => result.map_err(StegError::Image),
        Err(_) => Err(StegError::Internal(
            "panic in image decoder (caught)".to_string(),
        )),
    }
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
