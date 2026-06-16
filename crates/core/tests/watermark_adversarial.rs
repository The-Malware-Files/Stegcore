// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// Adversarial coverage for the document watermark parsers.
//
// The PDF (lopdf) and OOXML (zip) carriers parse untrusted input, so the bar is
// the robustness mandate: hostile bytes must surface a clean error, never a
// panic, an unbounded allocation, or a silently-wrong result. Crypto-bearing
// round-trips are covered in the engine and the core module unit tests; this
// file is about what happens when the *container* is malformed or hostile.
//
// Iteration budget: 64 cases per property in CI, override with PROPTEST_CASES.

use std::io::{Cursor, Write};

use proptest::prelude::*;
use stegcore_core::watermark::{self, ooxml, pdf};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
}

/// A minimal well-formed OOXML-shaped ZIP (no Stegcore comment).
fn fake_ooxml() -> Vec<u8> {
    let mut w = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    let opts = SimpleFileOptions::default();
    w.start_file("[Content_Types].xml", opts).unwrap();
    w.write_all(b"<?xml version=\"1.0\"?><Types/>").unwrap();
    w.start_file("word/document.xml", opts).unwrap();
    w.write_all(b"<document>body</document>").unwrap();
    w.finish().unwrap().into_inner()
}

/// A ZIP carrying an explicit archive comment.
fn ooxml_with_comment(comment: &str) -> Vec<u8> {
    let mut w = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    let opts = SimpleFileOptions::default();
    w.start_file("word/document.xml", opts).unwrap();
    w.write_all(b"<document/>").unwrap();
    w.set_comment(comment).unwrap();
    w.finish().unwrap().into_inner()
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), max_shrink_iters: 64, .. ProptestConfig::default() })]

    /// Arbitrary bytes handed to the PDF carrier never panic.
    #[test]
    fn pdf_parser_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = pdf::set_watermark(&bytes, "mark");
        let _ = pdf::get_watermark(&bytes);
    }

    /// Bytes that start like a PDF but are otherwise garbage never panic.
    #[test]
    fn pdf_prefixed_garbage_never_panics(tail in prop::collection::vec(any::<u8>(), 0..2048)) {
        let mut bytes = b"%PDF-1.5\n".to_vec();
        bytes.extend_from_slice(&tail);
        let _ = pdf::set_watermark(&bytes, "m");
        let _ = pdf::get_watermark(&bytes);
    }

    /// Arbitrary bytes handed to the OOXML carrier never panic.
    #[test]
    fn ooxml_parser_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = ooxml::set_watermark(&bytes, "mark");
        let _ = ooxml::get_watermark(&bytes);
    }

    /// Bytes with the ZIP local-file magic then garbage never panic.
    #[test]
    fn zip_prefixed_garbage_never_panics(tail in prop::collection::vec(any::<u8>(), 0..2048)) {
        let mut bytes = vec![0x50, 0x4b, 0x03, 0x04]; // "PK\x03\x04"
        bytes.extend_from_slice(&tail);
        let _ = ooxml::set_watermark(&bytes, "m");
        let _ = ooxml::get_watermark(&bytes);
    }

    /// An OOXML carrying an arbitrary Stegcore-prefixed comment never panics on
    /// read, whatever follows the prefix.
    #[test]
    fn arbitrary_marked_comment_never_panics(s in "stegcore-wm:[ -~]{0,64}") {
        let bytes = ooxml_with_comment(&s);
        let _ = ooxml::get_watermark(&bytes);
    }
}

// ── Fixed hostile fixtures ───────────────────────────────────────────────────

#[test]
fn empty_input_is_rejected_not_panicked() {
    assert!(pdf::set_watermark(b"", "m").is_err());
    assert!(pdf::get_watermark(b"").is_err());
    assert!(ooxml::set_watermark(b"", "m").is_err());
    assert!(ooxml::get_watermark(b"").is_err());
}

#[test]
fn truncated_zip_is_rejected_cleanly() {
    let z = fake_ooxml();
    let truncated = &z[..z.len() / 2];
    assert!(ooxml::set_watermark(truncated, "m").is_err());
    // get may classify it as no-mark or as unparseable; either is a clean
    // Result, never a panic.
    let _ = ooxml::get_watermark(truncated);
}

#[test]
fn truncated_pdf_is_rejected_cleanly() {
    let trunc = b"%PDF-1.5\n1 0 obj<<".to_vec();
    assert!(pdf::set_watermark(&trunc, "m").is_err());
    let _ = pdf::get_watermark(&trunc);
}

#[test]
fn corrupt_marked_pdf_read_is_oracle_resistant() {
    // A real PDF carrying our key, but with non-base64 garbage as the value.
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("doc.pdf");
    // Build a minimal PDF, then poke a bad mark into it via the public setter.
    let base = minimal_pdf();
    let marked = pdf::set_watermark(&base, "!!!not valid base64!!!").unwrap();
    std::fs::write(&f, &marked).unwrap();

    // The dispatcher must collapse this to the oracle-resistant "no payload"
    // error, identical to a wrong passphrase, not a parser-specific message.
    let err = watermark::read_watermark(&f, b"pass").unwrap_err();
    assert_eq!(
        err.to_string(),
        stegcore_core::errors::StegError::NoPayloadFound.to_string()
    );
}

#[test]
fn corrupt_marked_ooxml_read_is_oracle_resistant() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("doc.docx");
    let bytes = ooxml_with_comment("stegcore-wm:%%%not base64%%%");
    std::fs::write(&f, &bytes).unwrap();
    let err = watermark::read_watermark(&f, b"pass").unwrap_err();
    assert_eq!(
        err.to_string(),
        stegcore_core::errors::StegError::NoPayloadFound.to_string()
    );
}

#[test]
fn reading_a_hostile_pdf_file_never_panics() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("x.pdf");
    std::fs::write(&f, b"%PDF-1.5\nnot a real pdf body").unwrap();
    // Unparseable PDF: a clean error, no panic.
    assert!(watermark::read_watermark(&f, b"pass").is_err());
}

// ── G-forensic: atomic write leaves no debris ────────────────────────────────

#[test]
fn successful_watermark_leaves_no_temp_residue() {
    let src = TempDir::new().unwrap();
    let dst = TempDir::new().unwrap();
    let cover = src.path().join("cover.pdf");
    std::fs::write(&cover, minimal_pdf()).unwrap();
    let out = dst.path().join("marked.pdf");

    watermark::watermark(&cover, b"mark", b"pass", "chacha20-poly1305", &out).unwrap();

    // The output directory holds exactly the finished file: the atomic write's
    // temp file was renamed into place, not left behind.
    let entries: Vec<_> = std::fs::read_dir(dst.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("marked.pdf")]);
}

#[test]
fn failed_watermark_writes_no_output() {
    let dir = TempDir::new().unwrap();
    let cover = dir.path().join("cover.pdf");
    std::fs::write(&cover, b"%PDF-1.5\nnot a parseable body").unwrap();
    let out = dir.path().join("marked.pdf");

    assert!(watermark::watermark(&cover, b"mark", b"pass", "aes-256-gcm", &out).is_err());
    // A parse failure happens before the write, so no partial output exists.
    assert!(!out.exists());
}

// ── E-timing: every read failure collapses to one error shape ────────────────

#[test]
fn all_document_read_failures_share_one_error_shape() {
    let dir = TempDir::new().unwrap();

    // (a) Wrong passphrase on a genuinely marked PDF.
    let marked = dir.path().join("marked.pdf");
    std::fs::write(&marked, minimal_pdf()).unwrap();
    watermark::watermark(&marked, b"mark", b"right", "chacha20-poly1305", &marked).unwrap();
    let wrong_key = watermark::read_watermark(&marked, b"wrong").unwrap_err();

    // (b) A valid PDF with no Stegcore mark at all.
    let unmarked = dir.path().join("plain.pdf");
    std::fs::write(&unmarked, minimal_pdf()).unwrap();
    let no_mark = watermark::read_watermark(&unmarked, b"right").unwrap_err();

    // (c) A PDF carrying a corrupt (non-decodable) mark.
    let corrupt = dir.path().join("corrupt.pdf");
    std::fs::write(&corrupt, pdf::set_watermark(&minimal_pdf(), "@@@").unwrap()).unwrap();
    let corrupt_err = watermark::read_watermark(&corrupt, b"right").unwrap_err();

    // All three render identical user-facing text: a blind probe cannot tell
    // "wrong key" from "no mark" from "corrupt mark".
    let expected = stegcore_core::errors::StegError::NoPayloadFound.to_string();
    assert_eq!(wrong_key.to_string(), expected);
    assert_eq!(no_mark.to_string(), expected);
    assert_eq!(corrupt_err.to_string(), expected);
}

/// A minimal single-page PDF lopdf can load and round-trip.
fn minimal_pdf() -> Vec<u8> {
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
    bytes
}
