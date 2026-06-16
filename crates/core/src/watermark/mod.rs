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
//! Writes an encrypted ownership mark into a carrier and reads it back. Three
//! carrier families dispatch behind one pair of entry points:
//!
//! - **Lossless images** (PNG, BMP, WebP): the mark rides the engine's LSB
//!   pipeline ([`stegcore_engine::watermark`]).
//! - **PDF**: the mark is stored as an encrypted blob in the document
//!   Information dictionary (see [`pdf`]).
//! - **OOXML** (DOCX, PPTX, XLSX): the mark is stored in the ZIP archive
//!   comment, which leaves the document's part structure untouched (see
//!   [`ooxml`]).
//!
//! For documents the encrypted blob is the engine's own wire format (so a
//! document mark and an image mark share one cryptographic format), base64
//! encoded for safe storage in a text field. The consent gate is the caller's
//! responsibility; see [`crate::consent`].

pub mod ooxml;
pub mod pdf;

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use tempfile::NamedTempFile;

use crate::errors::StegError;
use crate::steg::parse_cipher;

const IMAGE_EXTS: &[&str] = &["png", "bmp", "webp"];
const PDF_EXTS: &[&str] = &["pdf"];
const OOXML_EXTS: &[&str] = &["docx", "pptx", "xlsx"];

/// Largest document we will hand to the PDF/ZIP parsers. Bounds the parser
/// attack surface at the boundary; the parsers themselves impose no input cap.
pub(crate) const MAX_DOC_BYTES: u64 = 100 * 1024 * 1024;

/// Every file extension that accepts a watermark (lowercase).
pub fn watermark_extensions() -> Vec<&'static str> {
    IMAGE_EXTS
        .iter()
        .chain(PDF_EXTS)
        .chain(OOXML_EXTS)
        .copied()
        .collect()
}

/// True when `path`'s extension names a watermarkable carrier.
pub fn is_watermarkable(path: &Path) -> bool {
    kind_of(path).is_some()
}

fn ext_of(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
}

enum Kind {
    Image,
    Pdf,
    Ooxml,
}

fn kind_of(path: &Path) -> Option<Kind> {
    let e = ext_of(path)?;
    if IMAGE_EXTS.contains(&e.as_str()) {
        Some(Kind::Image)
    } else if PDF_EXTS.contains(&e.as_str()) {
        Some(Kind::Pdf)
    } else if OOXML_EXTS.contains(&e.as_str()) {
        Some(Kind::Ooxml)
    } else {
        None
    }
}

fn unsupported(path: &Path) -> StegError {
    StegError::UnsupportedFormat(format!(
        "{} is not a watermark carrier (supported: PNG, BMP, WebP, PDF, DOCX, PPTX, XLSX)",
        ext_of(path).unwrap_or_else(|| "(no extension)".into())
    ))
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
    match kind_of(cover) {
        Some(Kind::Image) => stegcore_engine::watermark::watermark(cover, mark, passphrase, c, out)
            .map_err(StegError::from),
        Some(Kind::Pdf) => {
            let bytes = read_doc(cover)?;
            let blob_b64 = seal_b64(passphrase, mark, c)?;
            let written = pdf::set_watermark(&bytes, &blob_b64)?;
            atomic_write(out, &written)?;
            Ok(out.to_path_buf())
        }
        Some(Kind::Ooxml) => {
            let bytes = read_doc(cover)?;
            let blob_b64 = seal_b64(passphrase, mark, c)?;
            let written = ooxml::set_watermark(&bytes, &blob_b64)?;
            atomic_write(out, &written)?;
            Ok(out.to_path_buf())
        }
        None => Err(unsupported(cover)),
    }
}

/// Read a watermark back out of a carrier.
pub fn read_watermark(path: &Path, passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    match kind_of(path) {
        Some(Kind::Image) => {
            stegcore_engine::watermark::read_watermark(path, passphrase).map_err(StegError::from)
        }
        Some(Kind::Pdf) => {
            let bytes = read_doc(path)?;
            let blob_b64 = pdf::get_watermark(&bytes)?.ok_or(StegError::NoPayloadFound)?;
            open_b64(&blob_b64, passphrase)
        }
        Some(Kind::Ooxml) => {
            let bytes = read_doc(path)?;
            let blob_b64 = ooxml::get_watermark(&bytes)?.ok_or(StegError::NoPayloadFound)?;
            open_b64(&blob_b64, passphrase)
        }
        None => Err(unsupported(path)),
    }
}

/// Seal `mark` into the engine wire format and base64-encode it for storage in
/// a document text field.
fn seal_b64(
    passphrase: &[u8],
    mark: &[u8],
    cipher: stegcore_engine::crypto::Cipher,
) -> Result<String, StegError> {
    if mark.is_empty() {
        return Err(StegError::EmptyPayload);
    }
    let blob =
        stegcore_engine::steg::seal_blob(passphrase, mark, cipher).map_err(StegError::from)?;
    Ok(B64.encode(blob))
}

/// Inverse of [`seal_b64`]. A malformed field collapses to the oracle-resistant
/// "no payload" error so a probe cannot tell a corrupt mark from a wrong key.
fn open_b64(blob_b64: &str, passphrase: &[u8]) -> Result<Vec<u8>, StegError> {
    let blob = B64
        .decode(blob_b64.trim())
        .map_err(|_| StegError::NoPayloadFound)?;
    stegcore_engine::steg::open_blob(&blob, passphrase).map_err(StegError::from)
}

/// Read a whole document into memory, bounding the size at the boundary.
fn read_doc(path: &Path) -> Result<Vec<u8>, StegError> {
    read_doc_capped(path, MAX_DOC_BYTES)
}

fn read_doc_capped(path: &Path, max_bytes: u64) -> Result<Vec<u8>, StegError> {
    let meta =
        std::fs::metadata(path).map_err(|_| StegError::FileNotFound(path.display().to_string()))?;
    if meta.len() > max_bytes {
        return Err(StegError::FileTooLarge {
            size_mb: meta.len() / (1024 * 1024),
            max_mb: max_bytes / (1024 * 1024),
        });
    }
    std::fs::read(path).map_err(StegError::Io)
}

/// Write `bytes` to `out` atomically (temp file beside the target, then rename).
fn atomic_write(out: &Path, bytes: &[u8]) -> Result<(), StegError> {
    let dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let tmp = NamedTempFile::new_in(dir)?;
    std::fs::write(tmp.path(), bytes)?;
    tmp.persist(out).map_err(|e| StegError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_cover_all_three_families() {
        let exts = watermark_extensions();
        for e in ["png", "bmp", "webp", "pdf", "docx", "pptx", "xlsx"] {
            assert!(exts.contains(&e), "missing {e}");
        }
        assert!(!exts.contains(&"jpg"));
    }

    #[test]
    fn is_watermarkable_classifies_each_family() {
        assert!(is_watermarkable(Path::new("a.png")));
        assert!(is_watermarkable(Path::new("a.PDF")));
        assert!(is_watermarkable(Path::new("a.docx")));
        assert!(!is_watermarkable(Path::new("a.jpg")));
        assert!(!is_watermarkable(Path::new("a.wav")));
        assert!(!is_watermarkable(Path::new("noext")));
    }

    #[test]
    fn unknown_cipher_rejected_before_io() {
        let err = watermark(
            Path::new("/tmp/none.pdf"),
            b"m",
            b"p",
            "rot13",
            Path::new("/tmp/o.pdf"),
        )
        .unwrap_err();
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn unsupported_extension_rejected() {
        let err = watermark(
            Path::new("/tmp/x.gif"),
            b"m",
            b"p",
            "chacha20-poly1305",
            Path::new("/tmp/o.gif"),
        )
        .unwrap_err();
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
        assert!(matches!(
            read_watermark(Path::new("/tmp/x.gif"), b"p"),
            Err(StegError::UnsupportedFormat(_))
        ));
    }

    #[test]
    fn read_doc_maps_missing_file() {
        let err = read_doc(Path::new("/tmp/stegcore-wm-no-doc-123.pdf")).unwrap_err();
        assert!(matches!(err, StegError::FileNotFound(_)));
    }

    #[test]
    fn read_doc_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("big.pdf");
        std::fs::write(&f, vec![0u8; 4096]).unwrap();
        // A 1-byte cap forces the size branch on a 4 KiB file.
        let err = read_doc_capped(&f, 1).unwrap_err();
        assert!(matches!(err, StegError::FileTooLarge { .. }));
        // Under the real cap the same file reads fine.
        assert!(read_doc(&f).is_ok());
    }

    // ── Full dispatcher round-trips through real files on disk ──────────────

    fn write_minimal_pdf(path: &Path) {
        use lopdf::content::{Content, Operation};
        use lopdf::{dictionary, Document, Object, Stream};
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let content = Content {
            operations: vec![Operation::new("BT", vec![]), Operation::new("ET", vec![])],
        };
        let content_id = doc.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
        doc.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn write_fake_ooxml(path: &Path) {
        use std::io::Write;
        use zip::write::SimpleFileOptions;
        use zip::{CompressionMethod, ZipWriter};
        let mut w = ZipWriter::new(std::io::Cursor::new(Vec::<u8>::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        w.start_file("[Content_Types].xml", opts).unwrap();
        w.write_all(b"<?xml version=\"1.0\"?><Types/>").unwrap();
        w.start_file("word/document.xml", opts).unwrap();
        w.write_all(b"<document>body</document>").unwrap();
        std::fs::write(path, w.finish().unwrap().into_inner()).unwrap();
    }

    #[test]
    fn pdf_full_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("doc.pdf");
        let out = dir.path().join("marked.pdf");
        write_minimal_pdf(&cover);
        let mark = b"owner: Acme; ref: PDF-1";
        let written = watermark(&cover, mark, b"pass", "chacha20-poly1305", &out).unwrap();
        assert_eq!(written, out);
        assert_eq!(read_watermark(&out, b"pass").unwrap(), mark);
        // Wrong passphrase is oracle-resistant.
        assert!(read_watermark(&out, b"wrong").is_err());
    }

    #[test]
    fn ooxml_full_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("doc.docx");
        let out = dir.path().join("marked.docx");
        write_fake_ooxml(&cover);
        let mark = b"owner: Acme; ref: DOCX-1";
        let written = watermark(&cover, mark, b"pass", "aes-256-gcm", &out).unwrap();
        assert_eq!(written, out);
        assert_eq!(read_watermark(&out, b"pass").unwrap(), mark);
        assert!(read_watermark(&out, b"nope").is_err());
    }

    #[test]
    fn reading_an_unmarked_document_is_oracle_resistant() {
        let dir = tempfile::tempdir().unwrap();
        let cover = dir.path().join("plain.pdf");
        write_minimal_pdf(&cover);
        // No mark written: read must fail the same way a wrong key does.
        let err = read_watermark(&cover, b"pass").unwrap_err();
        assert_eq!(err.to_string(), StegError::NoPayloadFound.to_string());
    }
}
