// Author:  Daniel Iwugo
// Comment: Christ is King
// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Where weights come from.
//!
//! A trait, because the scale rules want storage behind a boundary and because
//! the three sources this release needs (a local cache, a GitHub release asset,
//! a Hugging Face repository) differ only in how bytes arrive.
//!
//! # Two rules this module enforces
//!
//! **Inference never touches the filesystem.** A [`WeightStore`] returns bytes;
//! [`crate::model::Model`] is built from bytes. So the IO policy, the size
//! pre-flight and any sandboxing stay with the caller, and the inference path is
//! testable from a byte literal.
//!
//! **Nothing is trusted on its filename.** A model artefact is executable
//! content in every sense that matters: it decides what the tool tells a user
//! about a file. Every load verifies the SHA-256 against the digest in the model
//! card, and a mismatch is [`MlError::WeightsCorrupt`], never a warning.
//!
//! # Why fetching is off by default
//!
//! The `fetch` feature is opt-in. A library that reaches the network on a
//! developer's machine without being asked is a surprise, and under baseline
//! section 5 a download is dependency surface: the CLI or GUI layer is the right
//! place to decide a download is acceptable and to tell the user it is
//! happening.

use std::path::{Path, PathBuf};

use crate::error::{MlError, Result};
use crate::model::ModelCard;

/// A fetched artefact: the graph and its card, already reconciled.
#[derive(Debug)]
pub struct Artefact {
    /// The validated card describing what the graph is and what it measured.
    pub card: ModelCard,
    /// The ONNX graph itself, already verified against the card's digest.
    pub onnx: Vec<u8>,
}

/// Somewhere weights can be obtained from.
///
/// `name` is a stable identifier such as `"yedroudj-net-spatial-v1"`. An
/// implementation decides what that means on its medium; nothing else in this
/// crate parses it.
pub trait WeightStore {
    /// Fetch an artefact by name, verifying it before returning it.
    fn load(&self, name: &str) -> Result<Artefact>;

    /// Whether `load` would succeed without going to the network. Lets a caller
    /// tell "not downloaded yet" from "download failed" before it starts, which
    /// is the pre-flight the baseline asks for rather than discovering it
    /// halfway through a batch.
    fn is_cached(&self, name: &str) -> bool;
}

/// Hex SHA-256 of a byte slice.
fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Reconcile a card and a graph, rejecting the pair if the digest disagrees.
///
/// Public because every store must go through it and a store implemented
/// elsewhere should not have to reimplement the check.
pub fn verify(name: &str, card: ModelCard, onnx: Vec<u8>) -> Result<Artefact> {
    let got = digest(&onnx);
    if !got.eq_ignore_ascii_case(&card.weights_sha256) {
        return Err(MlError::WeightsCorrupt {
            model: name.to_string(),
            detail: format!(
                "card declares sha256 {} but the file is {got}",
                card.weights_sha256
            ),
        });
    }
    Ok(Artefact { card, onnx })
}

/// A directory holding `<name>.onnx` and `<name>.card.json` pairs.
///
/// This is the cache every other store writes into, so it is also the whole
/// implementation of the offline case.
pub struct FsWeightStore {
    root: PathBuf,
}

impl FsWeightStore {
    /// A store rooted at `root`. The directory need not exist yet; a load from a
    /// missing directory reports the artefact as missing rather than as an IO
    /// error, which is the distinction a caller acts on.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Reject a name that could escape the cache directory. The name reaches
    /// here from a caller, so it is untrusted input at a boundary: a traversal
    /// or an absolute path would make `load` read an arbitrary file and present
    /// it as a model.
    fn safe_name(name: &str) -> Result<&str> {
        let ok = !name.is_empty()
            && name.len() <= 128
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            && !name.contains("..")
            && !name.starts_with('.');
        if ok {
            Ok(name)
        } else {
            Err(MlError::WeightsCorrupt {
                model: name.to_string(),
                detail: "model name is not a plain cache identifier".to_string(),
            })
        }
    }

    fn onnx_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self.root.join(format!("{}.onnx", Self::safe_name(name)?)))
    }

    fn card_path(&self, name: &str) -> Result<PathBuf> {
        Ok(self
            .root
            .join(format!("{}.card.json", Self::safe_name(name)?)))
    }

    fn read(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).map_err(|source| MlError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

impl WeightStore for FsWeightStore {
    fn load(&self, name: &str) -> Result<Artefact> {
        let card_path = self.card_path(name)?;
        let onnx_path = self.onnx_path(name)?;
        if !card_path.exists() || !onnx_path.exists() {
            return Err(MlError::WeightsMissing {
                model: name.to_string(),
            });
        }
        let card_bytes = Self::read(&card_path)?;
        let card_text = String::from_utf8(card_bytes).map_err(|e| MlError::CardInvalid {
            model: name.to_string(),
            detail: format!("card is not UTF-8: {e}"),
        })?;
        let card = ModelCard::from_json(&card_text)?;
        let onnx = Self::read(&onnx_path)?;
        verify(name, card, onnx)
    }

    fn is_cached(&self, name: &str) -> bool {
        match (self.card_path(name), self.onnx_path(name)) {
            (Ok(c), Ok(o)) => c.exists() && o.exists(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::valid_card;
    use crate::representation::Domain;

    fn write_pair(dir: &Path, name: &str, onnx: &[u8], digest_override: Option<&str>) {
        let mut card = valid_card(Domain::Spatial);
        card.weights_sha256 = digest_override
            .map(str::to_string)
            .unwrap_or_else(|| digest(onnx));
        std::fs::write(dir.join(format!("{name}.onnx")), onnx).unwrap();
        std::fs::write(
            dir.join(format!("{name}.card.json")),
            serde_json::to_vec(&card).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn digest_matches_a_known_vector() {
        // SHA-256 of the empty string, so this test pins the hash function
        // rather than trusting it. If the dependency ever changes algorithm
        // under us, every stored card would silently stop verifying; this
        // catches that in one line.
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_matching_pair_loads() {
        let dir = tempdir();
        write_pair(dir.path(), "m", b"fake onnx bytes", None);
        let store = FsWeightStore::new(dir.path());
        assert!(store.is_cached("m"));
        let a = store.load("m").expect("load");
        assert_eq!(a.onnx, b"fake onnx bytes");
    }

    #[test]
    fn a_digest_mismatch_is_refused_not_warned_about() {
        let dir = tempdir();
        write_pair(dir.path(), "m", b"fake onnx bytes", Some(&"b".repeat(64)));
        let err = FsWeightStore::new(dir.path()).load("m").unwrap_err();
        match err {
            MlError::WeightsCorrupt { detail, .. } => {
                assert!(detail.contains("card declares"), "{detail}");
            }
            other => panic!("expected WeightsCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_artefact_says_so_rather_than_an_io_error() {
        let dir = tempdir();
        let err = FsWeightStore::new(dir.path()).load("absent").unwrap_err();
        assert!(matches!(err, MlError::WeightsMissing { .. }), "{err:?}");
        assert!(!FsWeightStore::new(dir.path()).is_cached("absent"));
    }

    #[test]
    fn a_traversing_name_cannot_read_outside_the_cache() {
        let dir = tempdir();
        let store = FsWeightStore::new(dir.path());
        for bad in [
            "../../etc/passwd",
            "/etc/passwd",
            "..",
            ".hidden",
            "has space",
            "",
        ] {
            assert!(store.load(bad).is_err(), "{bad:?} was not refused");
            assert!(!store.is_cached(bad), "{bad:?} reported as cached");
        }
    }

    #[test]
    fn a_card_that_is_not_utf8_is_reported_as_an_unusable_card() {
        let dir = tempdir();
        std::fs::write(dir.path().join("m.onnx"), b"x").unwrap();
        std::fs::write(dir.path().join("m.card.json"), [0xff, 0xfe, 0x00]).unwrap();
        let err = FsWeightStore::new(dir.path()).load("m").unwrap_err();
        assert!(matches!(err, MlError::CardInvalid { .. }), "{err:?}");
    }

    #[test]
    fn an_invalid_card_blocks_the_load_even_when_the_digest_would_match() {
        let dir = tempdir();
        let onnx = b"bytes";
        let mut card = valid_card(Domain::Spatial);
        card.weights_sha256 = digest(onnx);
        card.envelope.held_out.clear(); // makes the card invalid
        std::fs::write(dir.path().join("m.onnx"), onnx).unwrap();
        std::fs::write(
            dir.path().join("m.card.json"),
            serde_json::to_vec(&card).unwrap(),
        )
        .unwrap();
        let err = FsWeightStore::new(dir.path()).load("m").unwrap_err();
        assert!(matches!(err, MlError::CardInvalid { .. }), "{err:?}");
    }

    /// Minimal temp dir so this crate needs no `tempfile` dev-dependency.
    fn tempdir() -> TempDir {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!(
            "detego-ml-test-{n}-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
