// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Watermarking: write an encrypted ownership/identity mark into a carrier and
//! read it back to prove provenance.
//!
//! A watermark is an ordinary Stegcore payload (the same encrypted, length
//! prefixed wire format the rest of the engine produces) put in the carrier for
//! attribution rather than secrecy. The single difference from embedding is
//! intent, which is why the consent gate lives one layer up in the application
//! surfaces (CLI/GUI), not here: this module is the mechanism, the gate is the
//! policy.
//!
//! Carriers:
//!
//! - **Lossless images** (PNG, BMP, WebP): the mark rides the existing LSB path
//!   ([`crate::steg::embed`] in sequential mode). Read-back is the existing
//!   [`crate::steg::extract`]. JPEG is deliberately excluded: its lossy DCT path
//!   is a poor home for a mark meant to survive intact.
//!
//! Document carriers (PDF, OOXML) are added behind the same two entry points so
//! callers dispatch on nothing but the file.

use std::path::{Path, PathBuf};

use crate::crypto::Cipher;
use crate::errors::StegError;
use crate::steg;

/// Lossless image formats that can carry a watermark.
pub fn image_watermark_extensions() -> &'static [&'static str] {
    &["png", "bmp", "webp"]
}

/// Every format that accepts a watermark.
pub fn watermark_extensions() -> &'static [&'static str] {
    image_watermark_extensions()
}

/// Lowercased file extension, or `None` when the path has no extension.
fn ext_of(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
}

/// True when `path`'s extension names a watermarkable carrier.
pub fn is_watermarkable(path: &Path) -> bool {
    ext_of(path)
        .map(|e| watermark_extensions().contains(&e.as_str()))
        .unwrap_or(false)
}

/// Apply `mark` to `cover`, writing the watermarked carrier to `out`.
///
/// Returns the path actually written (which can differ from `out` when the
/// underlying carrier forces an extension, mirroring [`crate::steg::embed`]).
/// `mark` is encrypted under `passphrase` with `cipher` exactly as a normal
/// payload, so a watermark cannot be read or forged without the passphrase.
pub fn watermark(
    cover: &Path,
    mark: &[u8],
    passphrase: &[u8],
    cipher: Cipher,
    out: &Path,
) -> Result<PathBuf, StegError> {
    if mark.is_empty() {
        return Err(StegError::EmptyPayload);
    }
    let ext = ext_of(cover)
        .ok_or_else(|| StegError::UnsupportedFormat("file has no extension".to_string()))?;
    match ext.as_str() {
        "png" | "bmp" | "webp" => {
            // Sequential mode: deterministic placement, maximum capacity, and
            // the read-back path below (plain extract) tries sequential first.
            let (written, _none) =
                steg::embed(cover, mark, passphrase, cipher, "sequential", out, false)?;
            Ok(written)
        }
        other => Err(StegError::UnsupportedFormat(format!(
            "{other} cannot carry a watermark (supported: PNG, BMP, WebP)"
        ))),
    }
}

/// Read a watermark back out of a carrier and return its plaintext bytes.
///
/// The inverse of [`watermark`]. A wrong passphrase or an unmarked carrier
/// surfaces as the same oracle-resistant error the rest of the engine uses, so
/// "no mark here" and "wrong key" are indistinguishable to a caller probing
/// blindly.
pub fn read_watermark(path: &Path, passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    let ext =
        ext_of(path).ok_or_else(|| StegError::UnsupportedFormat("file has no extension".into()))?;
    match ext.as_str() {
        "png" | "bmp" | "webp" => steg::extract(path, passphrase),
        other => Err(StegError::UnsupportedFormat(format!(
            "{other} is not a watermark carrier"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    /// A textured PNG cover that passes the embed quality gate.
    fn noisy_png(path: &Path, w: u32, h: u32, seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let img = ImageBuffer::from_fn(w, h, |_, _| {
            Rgb([rng.gen::<u8>(), rng.gen::<u8>(), rng.gen::<u8>()])
        });
        img.save(path).unwrap();
    }

    #[test]
    fn png_watermark_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("cover.png");
        let out = dir.path().join("marked.png");
        noisy_png(&cover, 64, 64, 1);

        let mark = b"owner: Acme Corp; ref: INV-2026-001";
        let pass = b"watermark-pass";
        let written = watermark(&cover, mark, pass, Cipher::ChaCha20Poly1305, &out).unwrap();
        assert_eq!(written, out);

        let recovered = read_watermark(&out, pass).unwrap();
        assert_eq!(recovered, mark);
    }

    #[test]
    fn wrong_passphrase_does_not_reveal_mark() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("cover.png");
        let out = dir.path().join("marked.png");
        noisy_png(&cover, 64, 64, 2);

        watermark(&cover, b"secret mark", b"right", Cipher::Aes256Gcm, &out).unwrap();
        assert!(read_watermark(&out, b"wrong").is_err());
    }

    #[test]
    fn empty_mark_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("cover.png");
        noisy_png(&cover, 32, 32, 3);
        let out = dir.path().join("out.png");
        let err = watermark(&cover, b"", b"pass", Cipher::ChaCha20Poly1305, &out).unwrap_err();
        assert!(matches!(err, StegError::EmptyPayload));
    }

    #[test]
    fn bmp_watermark_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("cover.bmp");
        let out = dir.path().join("marked.bmp");
        noisy_png(&cover, 48, 48, 4); // ImageBuffer::save picks BMP from the extension

        let mark = b"provenance mark";
        let written = watermark(&cover, mark, b"p", Cipher::ChaCha20Poly1305, &out).unwrap();
        assert_eq!(read_watermark(&written, b"p").unwrap(), mark);
    }

    #[test]
    fn jpeg_is_not_a_watermark_carrier() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("cover.jpg");
        std::fs::write(&cover, b"not really a jpeg").unwrap();
        let out = dir.path().join("out.jpg");
        let err = watermark(&cover, b"mark", b"p", Cipher::ChaCha20Poly1305, &out).unwrap_err();
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn extensionless_path_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("noext");
        std::fs::write(&cover, b"data").unwrap();
        let out = dir.path().join("out");
        assert!(matches!(
            watermark(&cover, b"m", b"p", Cipher::ChaCha20Poly1305, &out),
            Err(StegError::UnsupportedFormat(_))
        ));
        assert!(matches!(
            read_watermark(&cover, b"p"),
            Err(StegError::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn is_watermarkable_matches_extensions() {
        assert!(is_watermarkable(Path::new("a.png")));
        assert!(is_watermarkable(Path::new("a.BMP")));
        assert!(is_watermarkable(Path::new("a.webp")));
        assert!(!is_watermarkable(Path::new("a.jpg")));
        assert!(!is_watermarkable(Path::new("a.wav")));
        assert!(!is_watermarkable(Path::new("noext")));
    }

    #[test]
    fn read_watermark_rejects_non_carrier_extension() {
        assert!(matches!(
            read_watermark(Path::new("x.wav"), b"p"),
            Err(StegError::UnsupportedFormat(_))
        ));
    }
}
