// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! PDF watermark carrier.
//!
//! The mark is stored as a string in the document Information dictionary (the
//! trailer's `/Info`) under a private key. PDF readers ignore unknown `/Info`
//! keys, so the watermark rides along without altering any visible content. The
//! caller bounds the input size before reaching this module; `lopdf` itself
//! imposes no input cap.

use lopdf::{Dictionary, Document, Object};

use crate::errors::StegError;

/// Private `/Info` key under which the base64 mark is stored.
const WATERMARK_KEY: &str = "StegcoreWatermark";

fn parse_err() -> StegError {
    StegError::UnsupportedFormat("could not parse the PDF".to_string())
}

/// Write (or replace) the watermark string in a PDF, returning the new bytes.
pub fn set_watermark(pdf: &[u8], value: &str) -> Result<Vec<u8>, StegError> {
    let mut doc = Document::load_mem(pdf).map_err(|_| parse_err())?;

    // Find the /Info dictionary, creating one if the PDF has none.
    let info_id = match doc.trailer.get(b"Info") {
        Ok(obj) => obj.as_reference().map_err(|_| StegError::CorruptedFile)?,
        Err(_) => {
            let id = doc.add_object(Object::Dictionary(Dictionary::new()));
            doc.trailer.set("Info", Object::Reference(id));
            id
        }
    };

    let info = doc
        .get_dictionary_mut(info_id)
        .map_err(|_| StegError::CorruptedFile)?;
    info.set(WATERMARK_KEY.to_string(), Object::string_literal(value));

    let mut out = Vec::new();
    doc.save_to(&mut out).map_err(StegError::Io)?;
    Ok(out)
}

/// Read the watermark string from a PDF, or `None` if it carries no Stegcore
/// mark.
pub fn get_watermark(pdf: &[u8]) -> Result<Option<String>, StegError> {
    let doc = Document::load_mem(pdf).map_err(|_| parse_err())?;

    let info_id = match doc.trailer.get(b"Info") {
        Ok(obj) => match obj.as_reference() {
            Ok(id) => id,
            Err(_) => return Ok(None),
        },
        Err(_) => return Ok(None),
    };

    let info = match doc.get_dictionary(info_id) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };

    match info.get(WATERMARK_KEY.as_bytes()) {
        Ok(obj) => {
            let bytes = obj.as_str().map_err(|_| StegError::CorruptedFile)?;
            Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
        }
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but valid single-page PDF lopdf can load and round-trip.
    fn minimal_pdf() -> Vec<u8> {
        use lopdf::content::{Content, Operation};
        use lopdf::dictionary;
        let mut doc = Document::with_version("1.5");
        let pages_id = doc.new_object_id();
        let content = Content {
            operations: vec![Operation::new("BT", vec![]), Operation::new("ET", vec![])],
        };
        let content_id = doc.add_object(lopdf::Stream::new(
            dictionary! {},
            content.encode().unwrap(),
        ));
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "Contents" => content_id,
        });
        let pages = dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_id.into()],
            "Count" => 1,
            "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        };
        doc.objects.insert(pages_id, Object::Dictionary(pages));
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn round_trips_a_mark() {
        let pdf = minimal_pdf();
        let marked = set_watermark(&pdf, "aGVsbG8=").unwrap();
        assert_eq!(get_watermark(&marked).unwrap().as_deref(), Some("aGVsbG8="));
    }

    #[test]
    fn unmarked_pdf_reads_none() {
        let pdf = minimal_pdf();
        assert_eq!(get_watermark(&pdf).unwrap(), None);
    }

    #[test]
    fn replacing_a_mark_overwrites() {
        let pdf = minimal_pdf();
        let once = set_watermark(&pdf, "first").unwrap();
        let twice = set_watermark(&once, "second").unwrap();
        assert_eq!(get_watermark(&twice).unwrap().as_deref(), Some("second"));
    }

    #[test]
    fn garbage_is_rejected_as_unparseable() {
        let err = set_watermark(b"this is not a pdf at all", "x").unwrap_err();
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
        let err = get_watermark(b"this is not a pdf at all").unwrap_err();
        assert!(matches!(err, StegError::UnsupportedFormat(_)));
    }

    #[test]
    fn marking_preserves_page_count() {
        // The mark must not disturb the document body.
        let pdf = minimal_pdf();
        let marked = set_watermark(&pdf, "mark").unwrap();
        let doc = Document::load_mem(&marked).unwrap();
        assert_eq!(doc.get_pages().len(), 1);
    }
}
