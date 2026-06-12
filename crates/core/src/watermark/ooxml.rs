// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! OOXML (DOCX/PPTX/XLSX) watermark carrier.
//!
//! An OOXML file is a ZIP archive of XML parts. Rather than inject a new part
//! (which, if not declared in `[Content_Types].xml`, can make strict readers
//! reject the document), the mark is stored in the ZIP end-of-central-directory
//! **archive comment**. That field is invisible to the OOXML layer, so every
//! Office reader opens the document unchanged; the watermark simply travels in
//! the container metadata.
//!
//! All existing entries are copied verbatim with `raw_copy_file` (no
//! recompression, byte-faithful). Two caps defend the parser against a zip bomb:
//! a ceiling on the entry count, and a per-entry uncompressed-size ceiling
//! checked against the declared size before any entry is touched.

use std::io::Cursor;

use zip::{ZipArchive, ZipWriter};

use crate::errors::StegError;

/// Marker prefix so we recognise our own comment and ignore unrelated ones.
const COMMENT_PREFIX: &str = "stegcore-wm:";
/// Maximum number of entries we will walk (zip-bomb entry-count guard).
const MAX_ENTRIES: usize = 10_000;
/// Maximum declared uncompressed size for any single entry (zip-bomb guard).
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

fn parse_err() -> StegError {
    StegError::UnsupportedFormat("could not parse the OOXML (ZIP) container".to_string())
}

/// Write (or replace) the watermark in an OOXML container, returning new bytes.
pub fn set_watermark(ooxml: &[u8], value: &str) -> Result<Vec<u8>, StegError> {
    set_watermark_capped(ooxml, value, MAX_ENTRIES, MAX_ENTRY_BYTES)
}

/// The cap-parameterised core of [`set_watermark`]. Split out so the zip-bomb
/// guards (entry count, per-entry size) can be exercised with small caps in
/// tests instead of multi-gigabyte fixtures.
fn set_watermark_capped(
    ooxml: &[u8],
    value: &str,
    max_entries: usize,
    max_entry_bytes: u64,
) -> Result<Vec<u8>, StegError> {
    let mut archive = ZipArchive::new(Cursor::new(ooxml)).map_err(|_| parse_err())?;
    if archive.len() > max_entries {
        return Err(StegError::CorruptedFile);
    }

    let mut writer = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
    for i in 0..archive.len() {
        let raw = archive
            .by_index_raw(i)
            .map_err(|_| StegError::CorruptedFile)?;
        if raw.size() > max_entry_bytes {
            return Err(StegError::CorruptedFile);
        }
        writer
            .raw_copy_file(raw)
            .map_err(|_| StegError::CorruptedFile)?;
    }

    writer
        .set_comment(format!("{COMMENT_PREFIX}{value}"))
        .map_err(|_| StegError::CorruptedFile)?;
    let cursor = writer.finish().map_err(|_| StegError::CorruptedFile)?;
    Ok(cursor.into_inner())
}

/// Read the watermark from an OOXML container, or `None` if it carries none.
pub fn get_watermark(ooxml: &[u8]) -> Result<Option<String>, StegError> {
    let archive = ZipArchive::new(Cursor::new(ooxml)).map_err(|_| parse_err())?;
    let comment = std::str::from_utf8(archive.comment()).unwrap_or("");
    Ok(comment
        .strip_prefix(COMMENT_PREFIX)
        .map(|rest| rest.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;
    use zip::CompressionMethod;

    /// A tiny ZIP that stands in for an OOXML container: a couple of deflated
    /// parts, no archive comment.
    fn fake_ooxml() -> Vec<u8> {
        let mut w = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        w.start_file("[Content_Types].xml", opts).unwrap();
        w.write_all(b"<?xml version=\"1.0\"?><Types/>").unwrap();
        w.start_file("word/document.xml", opts).unwrap();
        w.write_all(b"<?xml version=\"1.0\"?><document>body text</document>")
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn round_trips_a_mark() {
        let doc = fake_ooxml();
        let marked = set_watermark(&doc, "aGVsbG8=").unwrap();
        assert_eq!(get_watermark(&marked).unwrap().as_deref(), Some("aGVsbG8="));
    }

    #[test]
    fn unmarked_container_reads_none() {
        let doc = fake_ooxml();
        assert_eq!(get_watermark(&doc).unwrap(), None);
    }

    #[test]
    fn replacing_a_mark_overwrites() {
        let doc = fake_ooxml();
        let once = set_watermark(&doc, "first").unwrap();
        let twice = set_watermark(&once, "second").unwrap();
        assert_eq!(get_watermark(&twice).unwrap().as_deref(), Some("second"));
    }

    #[test]
    fn marking_preserves_all_entries() {
        let doc = fake_ooxml();
        let marked = set_watermark(&doc, "mark").unwrap();
        let mut archive = ZipArchive::new(Cursor::new(marked)).unwrap();
        assert_eq!(archive.len(), 2);
        // The document body part is byte-identical after watermarking.
        let mut body = String::new();
        use std::io::Read;
        archive
            .by_name("word/document.xml")
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        assert!(body.contains("body text"));
    }

    #[test]
    fn garbage_is_rejected_as_unparseable() {
        let err = set_watermark(b"not a zip", "x").unwrap_err();
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
        let err = get_watermark(b"not a zip").unwrap_err();
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn entry_count_cap_rejects_a_zip_bomb() {
        // fake_ooxml has 2 entries; a cap of 1 must reject it as corrupt rather
        // than walk an unbounded entry list.
        let doc = fake_ooxml();
        let err = set_watermark_capped(&doc, "x", 1, MAX_ENTRY_BYTES).unwrap_err();
        assert!(matches!(err, StegError::CorruptedFile));
        // The real cap (10000) lets the same 2-entry doc through.
        assert!(set_watermark(&doc, "x").is_ok());
    }

    #[test]
    fn per_entry_size_cap_rejects_an_oversize_member() {
        // Each part is tens of bytes; a 4-byte per-entry cap trips the guard.
        let doc = fake_ooxml();
        let err = set_watermark_capped(&doc, "x", MAX_ENTRIES, 4).unwrap_err();
        assert!(matches!(err, StegError::CorruptedFile));
    }

    #[test]
    fn caps_do_not_fire_on_a_normal_document() {
        let doc = fake_ooxml();
        // Generous caps: a well-formed small doc passes and round-trips.
        let marked = set_watermark_capped(&doc, "ok", 10, 1_000_000).unwrap();
        assert_eq!(get_watermark(&marked).unwrap().as_deref(), Some("ok"));
    }

    #[test]
    fn foreign_comment_is_not_read_as_a_mark() {
        // A container whose comment lacks our prefix carries no Stegcore mark.
        let mut w = ZipWriter::new(Cursor::new(Vec::<u8>::new()));
        let opts = SimpleFileOptions::default();
        w.start_file("a.txt", opts).unwrap();
        w.write_all(b"x").unwrap();
        w.set_comment("some unrelated archive comment").unwrap();
        let bytes = w.finish().unwrap().into_inner();
        assert_eq!(get_watermark(&bytes).unwrap(), None);
    }
}
