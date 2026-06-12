// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Public watermarking surface consumed by the CLI and the GUI.
//!
//! Thin wrapper over [`stegcore_engine::watermark`]: it parses the cipher
//! string both front-ends speak and maps engine errors into the public error
//! type. The consent gate is the caller's responsibility; see [`crate::consent`].

use std::path::{Path, PathBuf};

use crate::errors::StegError;
use crate::steg::parse_cipher;

/// Every format that accepts a watermark (lowercase extensions).
pub fn watermark_extensions() -> &'static [&'static str] {
    stegcore_engine::watermark::watermark_extensions()
}

/// True when `path`'s extension names a watermarkable carrier.
pub fn is_watermarkable(path: &Path) -> bool {
    stegcore_engine::watermark::is_watermarkable(path)
}

/// Apply `mark` to `cover`, writing the watermarked carrier to `out`.
///
/// `cipher` is one of `"ascon-128"`, `"chacha20-poly1305"`, `"aes-256-gcm"`.
/// Returns the path actually written.
pub fn watermark(
    cover: &Path,
    mark: &[u8],
    passphrase: &[u8],
    cipher: &str,
    out: &Path,
) -> Result<PathBuf, StegError> {
    let c = parse_cipher(cipher)?;
    stegcore_engine::watermark::watermark(cover, mark, passphrase, c, out).map_err(StegError::from)
}

/// Read a watermark back out of a carrier.
pub fn read_watermark(path: &Path, passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    stegcore_engine::watermark::read_watermark(path, passphrase).map_err(StegError::from)
}

#[cfg(test)]
mod tests {
    // Core's job here is cipher-string parsing and error mapping; the real
    // embed/extract round-trip is proven in the engine's watermark tests. These
    // tests exercise the boundary without pulling an image toolchain into core.
    use super::*;

    #[test]
    fn unknown_cipher_is_rejected_before_touching_the_file() {
        // A bad cipher fails at parse time, so the (missing) cover is never read.
        let err = watermark(
            Path::new("/tmp/does-not-exist-stegcore-wm.png"),
            b"mark",
            b"pass",
            "rot13",
            Path::new("/tmp/out.png"),
        )
        .unwrap_err();
        match err {
            StegError::UnsupportedFormat(s) => assert!(s.contains("rot13")),
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn valid_cipher_passes_parsing_and_dispatches_to_engine() {
        // A valid cipher with a missing cover must surface FileNotFound (mapped
        // from the engine), proving the cipher string was accepted and dispatch
        // proceeded rather than being rejected as unknown.
        let err = watermark(
            Path::new("/tmp/stegcore-wm-missing-cover-123456.png"),
            b"mark",
            b"pass",
            "chacha20-poly1305",
            Path::new("/tmp/out.png"),
        )
        .unwrap_err();
        assert!(matches!(err, StegError::FileNotFound(_)));
    }

    #[test]
    fn read_watermark_maps_missing_file_error() {
        let err =
            read_watermark(Path::new("/tmp/stegcore-wm-missing-987654.png"), b"pass").unwrap_err();
        assert!(matches!(err, StegError::FileNotFound(_)));
    }

    #[test]
    fn extensions_and_predicate_exposed() {
        assert!(watermark_extensions().contains(&"png"));
        assert!(is_watermarkable(Path::new("a.webp")));
        assert!(!is_watermarkable(Path::new("a.jpg")));
    }
}
