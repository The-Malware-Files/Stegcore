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

//! Does a local sample set match the manifest?
//!
//! # Safe by construction, and what that actually means
//!
//! This module reads sample bytes. It is therefore the one piece of the
//! wild-sample machinery that touches untrusted content, and it is built so
//! that touching it cannot go wrong:
//!
//! - **It hashes. It does not parse.** The only operation performed on a byte
//!   read from a sample file is `Sha256::update`. No decoder, no sniffer, no
//!   magic-byte check, no `serde`, no allocation sized from file content.
//!   Nothing in this file can be made to interpret a sample, so a malformed,
//!   hostile or bomb-shaped file is just a number.
//! - **The property is pinned, not asserted.** `tests/wild_verifier_never_parses.rs`
//!   reads this file's own source and fails if a decoder is ever named in it,
//!   and feeds the verifier deliberately malformed content to prove the result
//!   depends on nothing but the bytes.
//! - **Memory is bounded** at [`CHUNK_BYTES`] regardless of file size, so a
//!   40 GB file in the corpus directory costs 64 KiB of RAM.
//! - **Size is checked before content.** A file whose length already disagrees
//!   with the manifest is never read at all, which is both a pre-flight saving
//!   and the thing that keeps a mis-sized 40 GB file from being streamed.
//! - **Symlinks inside the corpus directory are refused, never followed.** A
//!   corpus directory is written by whatever delivered the samples, and a
//!   symlink in it is a request to hash something outside it.
//! - **The read is capped** at the declared length plus one byte, so a file
//!   growing underneath the verifier is reported rather than followed.
//!
//! # The naming convention, and why matching is by name and not by content
//!
//! Samples on disk are named by their lowercase SHA-256, optionally with an
//! extension: `3f2a...9c` or `3f2a...9c.png`. That is what the sample-sharing
//! services do and it is what makes this check cheap, because the name says
//! which manifest entry a file claims to be, so size and digest can then be
//! tested against that claim independently.
//!
//! Matching by content instead would collapse the two findings into one: a
//! digest search can only ever say "found" or "not found", and it could never
//! report the interesting case, which is **a file of exactly the right length
//! whose digest is wrong**. That is not truncation, it is substitution, and it
//! is the finding worth waking somebody up for.
//!
//! The extension is treated as opaque text. It is never used to decide
//! anything.

use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bruteforce::digest::{hex, Sha256};
use crate::errors::StegError;
use crate::wild::manifest::WildManifest;

/// Bytes held in memory while hashing, whatever the file size.
pub const CHUNK_BYTES: usize = 64 * 1024;

/// Most entries the verifier will look at in one corpus directory.
///
/// The same bound the manifest carries, applied to the directory as well, so a
/// directory holding a million files cannot make the verifier allocate a
/// million names before it notices.
pub const MAX_DIRECTORY_ENTRIES: usize = 100_000;

/// Where a size disagreement was noticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeNoticed {
    /// On the directory entry's metadata, before anything was read. The normal
    /// case: truncation, or the wrong file under the right name.
    BeforeReading,
    /// While hashing, meaning the file changed length underneath the verifier.
    /// Rare and worth a second look: on a corpus directory nothing should be
    /// writing to, it means something is.
    WhileHashing,
}

/// A file whose length is not the length the manifest recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeMismatch {
    /// Manifest id.
    pub id: String,
    /// What the manifest says.
    pub declared: u64,
    /// What was found. With [`SizeNoticed::WhileHashing`] this is a floor
    /// rather than the length: the read stops one byte past the declared size.
    pub found: u64,
    /// Where the disagreement surfaced.
    pub noticed: SizeNoticed,
}

/// A file of the recorded length whose content is not the recorded content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestMismatch {
    /// Manifest id.
    pub id: String,
    /// What the manifest says.
    pub declared: String,
    /// What the bytes actually hash to.
    pub found: String,
}

/// A file that is present and could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unreadable {
    /// Manifest id, where the file could be matched to one.
    pub id: String,
    /// Plain-language reason, safe to put in a report.
    pub reason: String,
}

/// The outcome of checking one corpus directory against one manifest.
///
/// Every list is sorted, so two runs over the same directory produce the same
/// report, and a report is a diffable artefact rather than a snapshot of a
/// filesystem's iteration order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Corpus name from the manifest.
    pub corpus: String,
    /// Manifest ids whose file is present, the right length, and hashes to the
    /// recorded digest.
    pub matched: Vec<String>,
    /// Entries with no file present.
    pub missing: Vec<String>,
    /// Entries whose digest field is still a stand-in, so there is nothing to
    /// check them against. Reported separately from `missing`, because the fix
    /// is to fill the manifest in rather than to go and find a file.
    pub placeholders: Vec<String>,
    /// Entries whose file is the wrong length.
    pub size_mismatch: Vec<SizeMismatch>,
    /// Entries whose file is the right length and the wrong content.
    pub digest_mismatch: Vec<DigestMismatch>,
    /// Entries whose file could not be read.
    pub unreadable: Vec<Unreadable>,
    /// File names in the directory that no manifest entry accounts for, which
    /// includes anything not named after a digest at all.
    pub unexpected: Vec<String>,
    /// Digests present twice in the directory under different extensions. One
    /// of them is checked, arbitrarily, and the collision is reported, because
    /// two files claiming one digest means somebody's copy went wrong.
    pub duplicates: Vec<String>,
}

impl VerifyReport {
    /// Whether the directory is exactly what the manifest describes.
    ///
    /// Placeholders count against it. A manifest that has not been filled in
    /// has not been verified, and reporting that as clean is how a corpus ends
    /// up trusted on the strength of a draft.
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty()
            && self.placeholders.is_empty()
            && self.size_mismatch.is_empty()
            && self.digest_mismatch.is_empty()
            && self.unreadable.is_empty()
            && self.unexpected.is_empty()
            && self.duplicates.is_empty()
    }

    /// One paragraph a person can read, for the top of a run log.
    pub fn human_summary(&self) -> String {
        if self.is_clean() {
            return format!(
                "Corpus {}: all {} samples present, the right size, and hashing to the \
                 recorded digests.",
                self.corpus,
                self.matched.len()
            );
        }
        let mut parts = Vec::new();
        parts.push(format!("{} matched", self.matched.len()));
        if !self.missing.is_empty() {
            parts.push(format!("{} missing", self.missing.len()));
        }
        if !self.placeholders.is_empty() {
            parts.push(format!(
                "{} with a digest not yet filled in",
                self.placeholders.len()
            ));
        }
        if !self.size_mismatch.is_empty() {
            parts.push(format!("{} the wrong size", self.size_mismatch.len()));
        }
        if !self.digest_mismatch.is_empty() {
            parts.push(format!(
                "{} the right size with the wrong content",
                self.digest_mismatch.len()
            ));
        }
        if !self.unreadable.is_empty() {
            parts.push(format!("{} unreadable", self.unreadable.len()));
        }
        if !self.unexpected.is_empty() {
            parts.push(format!("{} unaccounted for", self.unexpected.len()));
        }
        if !self.duplicates.is_empty() {
            parts.push(format!("{} duplicated", self.duplicates.len()));
        }
        format!("Corpus {}: {}.", self.corpus, parts.join(", "))
    }
}

/// Check a corpus directory against a manifest.
///
/// Reads nothing but the bytes of files the manifest names, and interprets
/// none of them. See the module documentation for the properties this holds to
/// and the tests that pin them.
pub fn verify_directory(manifest: &WildManifest, dir: &Path) -> Result<VerifyReport, StegError> {
    verify_directory_with(manifest, dir, &mut |_, _, _| {})
}

/// [`verify_directory`], with a progress callback.
///
/// Called once per manifest entry with `(done, total, id)`. A corpus of ten
/// thousand files is a long silent wait otherwise, and baseline Section 2 wants
/// a heartbeat out of any long loop. The callback decides its own interval; the
/// verifier does not read a clock, so the report stays reproducible.
pub fn verify_directory_with(
    manifest: &WildManifest,
    dir: &Path,
    progress: &mut dyn FnMut(usize, usize, &str),
) -> Result<VerifyReport, StegError> {
    let listing = list_corpus_directory(dir)?;

    let mut report = VerifyReport {
        corpus: manifest.corpus.clone(),
        duplicates: listing.duplicates,
        ..Default::default()
    };

    let mut accounted: Vec<&str> = Vec::with_capacity(manifest.samples.len());
    let total = manifest.samples.len();

    for (index, sample) in manifest.samples.iter().enumerate() {
        progress(index, total, &sample.id);

        if sample.digest_is_a_placeholder() {
            report.placeholders.push(sample.id.clone());
            continue;
        }

        let Some(found) = listing.by_digest.iter().find(|f| f.digest == sample.sha256) else {
            report.missing.push(sample.id.clone());
            continue;
        };
        accounted.push(found.digest.as_str());

        let path = dir.join(&found.name);
        // symlink_metadata, never metadata: a symlink in a corpus directory is
        // a request to hash something that is not in the corpus.
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                report.unreadable.push(Unreadable {
                    id: sample.id.clone(),
                    reason: format!("the file {} could not be inspected: {e}", found.name),
                });
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            report.unreadable.push(Unreadable {
                id: sample.id.clone(),
                reason: format!(
                    "{} is a symbolic link. A corpus directory holds files, and a link in \
                     one points at something that was never verified, so it is refused \
                     rather than followed.",
                    found.name
                ),
            });
            continue;
        }
        if !meta.file_type().is_file() {
            report.unreadable.push(Unreadable {
                id: sample.id.clone(),
                reason: format!("{} is not a regular file.", found.name),
            });
            continue;
        }
        if meta.len() != sample.bytes {
            report.size_mismatch.push(SizeMismatch {
                id: sample.id.clone(),
                declared: sample.bytes,
                found: meta.len(),
                noticed: SizeNoticed::BeforeReading,
            });
            continue;
        }

        match digest_file(&path, sample.bytes) {
            Ok(Hashed::Exactly { digest }) => {
                if digest == sample.sha256 {
                    report.matched.push(sample.id.clone());
                } else {
                    report.digest_mismatch.push(DigestMismatch {
                        id: sample.id.clone(),
                        declared: sample.sha256.clone(),
                        found: digest,
                    });
                }
            }
            Ok(Hashed::Differently { read }) => {
                report.size_mismatch.push(SizeMismatch {
                    id: sample.id.clone(),
                    declared: sample.bytes,
                    found: read,
                    noticed: SizeNoticed::WhileHashing,
                });
            }
            Err(e) => {
                report.unreadable.push(Unreadable {
                    id: sample.id.clone(),
                    reason: format!("the file {} could not be read: {e}", found.name),
                });
            }
        }
    }
    progress(total, total, "");

    accounted.sort_unstable();
    for file in &listing.by_digest {
        if accounted.binary_search(&file.digest.as_str()).is_err() {
            report.unexpected.push(file.name.clone());
        }
    }
    report.unexpected.extend(listing.unnamed);

    report.matched.sort();
    report.missing.sort();
    report.placeholders.sort();
    report.size_mismatch.sort_by(|a, b| a.id.cmp(&b.id));
    report.digest_mismatch.sort_by(|a, b| a.id.cmp(&b.id));
    report.unreadable.sort_by(|a, b| a.id.cmp(&b.id));
    report.unexpected.sort();
    report.duplicates.sort();
    Ok(report)
}

/// A directory entry whose name claims a digest.
struct NamedFile {
    digest: String,
    name: String,
}

struct Listing {
    by_digest: Vec<NamedFile>,
    unnamed: Vec<String>,
    duplicates: Vec<String>,
}

fn list_corpus_directory(dir: &Path) -> Result<Listing, StegError> {
    // Pre-flight, so the common operator mistakes fail with a sentence rather
    // than an errno.
    let meta = fs::metadata(dir).map_err(|e| {
        StegError::Internal(format!(
            "the corpus directory {} could not be opened: {e}. Check the path, and check \
             the isolated machine has the sample volume mounted.",
            dir.display()
        ))
    })?;
    if !meta.is_dir() {
        return Err(StegError::Internal(format!(
            "{} is not a directory, so it cannot be a corpus directory.",
            dir.display()
        )));
    }

    let mut by_digest: Vec<NamedFile> = Vec::new();
    let mut unnamed: Vec<String> = Vec::new();
    let mut duplicates: Vec<String> = Vec::new();
    let mut seen = 0usize;

    for entry in fs::read_dir(dir)
        .map_err(|e| StegError::Internal(format!("{} could not be listed: {e}", dir.display())))?
    {
        let entry = entry.map_err(|e| {
            StegError::Internal(format!(
                "an entry in {} could not be read: {e}",
                dir.display()
            ))
        })?;
        seen += 1;
        if seen > MAX_DIRECTORY_ENTRIES {
            return Err(StegError::Internal(format!(
                "{} holds more than {MAX_DIRECTORY_ENTRIES} entries. That is past what a \
                 wild-sample corpus should be, so the directory is probably not the one \
                 intended.",
                dir.display()
            )));
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        match digest_from_name(&name) {
            Some(digest) => {
                if by_digest.iter().any(|f| f.digest == digest) {
                    duplicates.push(digest);
                } else {
                    by_digest.push(NamedFile { digest, name });
                }
            }
            None => unnamed.push(name),
        }
    }
    Ok(Listing {
        by_digest,
        unnamed,
        duplicates,
    })
}

/// The digest a file name claims, if it claims one.
///
/// `<64 lowercase hex>` with an optional `.anything` suffix. The suffix is
/// never looked at beyond being allowed to exist: this function decides which
/// manifest entry a file claims to be, and nothing else in this module decides
/// anything from a name.
fn digest_from_name(name: &str) -> Option<String> {
    let stem = match name.find('.') {
        Some(dot) => &name[..dot],
        None => name,
    };
    if stem.len() != 64 {
        return None;
    }
    if !stem
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    Some(stem.to_string())
}

enum Hashed {
    Exactly { digest: String },
    Differently { read: u64 },
}

/// Stream a file into SHA-256, holding [`CHUNK_BYTES`] at a time and reading at
/// most `expect` plus one byte.
///
/// The one byte past the expected length is what turns "this file is growing
/// while we read it" from an undetected wrong answer into a reported finding.
///
/// **The only thing done with the bytes is `hasher.update`.** That is the whole
/// safety argument of this module, and it is checked by
/// `tests/wild_verifier_never_parses.rs` against this file's source.
fn digest_file(path: &Path, expect: u64) -> Result<Hashed, std::io::Error> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; CHUNK_BYTES];
    let ceiling = expect.saturating_add(1);
    let mut read_total: u64 = 0;

    loop {
        let room = (ceiling - read_total).min(CHUNK_BYTES as u64) as usize;
        if room == 0 {
            return Ok(Hashed::Differently { read: read_total });
        }
        let n = match file.read(&mut buffer[..room]) {
            Ok(0) => break,
            Ok(n) => n,
            // A short read is not an error and not an end: retrying is what
            // keeps a signal during the read from being reported as a corpus
            // problem.
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        hasher.update(&buffer[..n]);
        read_total += n as u64;
    }

    if read_total != expect {
        return Ok(Hashed::Differently { read: read_total });
    }
    Ok(Hashed::Exactly {
        digest: hex(&hasher.finalise()),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bruteforce::digest::sha256_bytes;
    use crate::wild::manifest::tests::{manifest, sample};
    use crate::wild::manifest::Payload;

    /// A manifest describing bytes we are about to write, so the digests are
    /// measured rather than invented.
    fn corpus(files: &[(&str, &[u8])]) -> (tempfile::TempDir, WildManifest) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut m = manifest();
        m.samples.clear();
        for (id, bytes) in files {
            let digest = hex(&sha256_bytes(bytes));
            fs::write(dir.path().join(&digest), bytes).expect("write");
            let mut s = sample(id, 'a', Payload::Carries);
            s.sha256 = digest;
            s.bytes = bytes.len() as u64;
            m.samples.push(s);
        }
        m.validate().expect("the fixture manifest is valid");
        (dir, m)
    }

    #[test]
    fn a_matching_corpus_verifies_clean() {
        let (dir, m) = corpus(&[("a-001", b"one"), ("b-002", b"two")]);
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.matched, vec!["a-001", "b-002"]);
        assert!(report.human_summary().contains("all 2 samples"));
    }

    #[test]
    fn content_that_no_decoder_would_accept_still_verifies() {
        // The point of the module: the verifier's answer depends on the bytes
        // and on nothing about their shape. A PNG signature followed by
        // nonsense, a truncated zip header and a pile of zero bytes all pass,
        // because none of them is ever parsed.
        let png_header_then_rubbish: &[u8] = b"\x89PNG\r\n\x1a\n\xff\xff\xff\xff not a png";
        let zip_header_only: &[u8] = b"PK\x03\x04";
        let zeroes = vec![0u8; 4096];
        let (dir, m) = corpus(&[
            ("a-001", png_header_then_rubbish),
            ("b-002", zip_header_only),
            ("c-003", &zeroes),
        ]);
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert!(report.is_clean(), "{report:?}");
    }

    #[test]
    fn a_missing_file_is_reported_as_missing() {
        let (dir, m) = corpus(&[("a-001", b"one"), ("b-002", b"two")]);
        fs::remove_file(dir.path().join(&m.samples[1].sha256)).expect("remove");
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert_eq!(report.missing, vec!["b-002"]);
        assert!(!report.is_clean());
    }

    #[test]
    fn a_truncated_file_is_a_size_mismatch_and_is_never_read() {
        let (dir, m) = corpus(&[("a-001", b"the original bytes")]);
        fs::write(dir.path().join(&m.samples[0].sha256), b"short").expect("truncate");
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert_eq!(report.size_mismatch.len(), 1);
        assert_eq!(report.size_mismatch[0].noticed, SizeNoticed::BeforeReading);
        assert_eq!(report.size_mismatch[0].found, 5);
        assert!(
            report.digest_mismatch.is_empty(),
            "a size mismatch is reported instead of hashing the file"
        );
    }

    #[test]
    fn a_substituted_file_of_the_right_length_is_a_digest_mismatch() {
        let (dir, m) = corpus(&[("a-001", b"the original bytes")]);
        fs::write(dir.path().join(&m.samples[0].sha256), b"the swapped bytes!").expect("swap");
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert!(report.size_mismatch.is_empty(), "same length");
        assert_eq!(report.digest_mismatch.len(), 1);
        assert_eq!(report.digest_mismatch[0].declared, m.samples[0].sha256);
        assert_ne!(report.digest_mismatch[0].found, m.samples[0].sha256);
    }

    #[test]
    fn a_file_that_is_not_in_the_manifest_is_reported_as_unexpected() {
        let (dir, m) = corpus(&[("a-001", b"one")]);
        let stray = hex(&sha256_bytes(b"stray"));
        fs::write(dir.path().join(&stray), b"stray").expect("write");
        fs::write(dir.path().join("notes.txt"), b"my notes").expect("write");
        let report = verify_directory(&m, dir.path()).expect("verify");
        let mut expected = vec![stray, "notes.txt".to_string()];
        expected.sort();
        assert_eq!(report.unexpected, expected);
        assert!(!report.is_clean());
    }

    #[test]
    fn a_symlink_is_refused_rather_than_followed() {
        #[cfg(unix)]
        {
            let (dir, m) = corpus(&[("a-001", b"one")]);
            let target = dir.path().join(&m.samples[0].sha256);
            let elsewhere = dir.path().join("elsewhere");
            fs::write(&elsewhere, b"one").expect("write");
            fs::remove_file(&target).expect("remove");
            std::os::unix::fs::symlink(&elsewhere, &target).expect("symlink");
            let report = verify_directory(&m, dir.path()).expect("verify");
            assert_eq!(report.unreadable.len(), 1, "{report:?}");
            assert!(report.unreadable[0].reason.contains("symbolic link"));
            assert!(report.matched.is_empty());
        }
    }

    #[test]
    fn a_placeholder_digest_is_reported_separately_from_a_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut m = manifest();
        m.samples.clear();
        m.samples.push(sample("a-001", '0', Payload::Carries));
        m.validate().expect("valid");
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert_eq!(report.placeholders, vec!["a-001"]);
        assert!(report.missing.is_empty());
        assert!(!report.is_clean(), "a draft manifest is not a verified one");
    }

    #[test]
    fn one_digest_under_two_names_is_reported_as_a_duplicate() {
        let (dir, m) = corpus(&[("a-001", b"one")]);
        let digest = m.samples[0].sha256.clone();
        fs::write(dir.path().join(format!("{digest}.png")), b"one").expect("write");
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert_eq!(report.duplicates, vec![digest]);
        assert!(!report.is_clean());
    }

    #[test]
    fn an_extension_is_allowed_and_never_interpreted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut m = manifest();
        m.samples.clear();
        let bytes = b"this is not a png at all";
        let digest = hex(&sha256_bytes(bytes));
        fs::write(dir.path().join(format!("{digest}.png")), bytes).expect("write");
        let mut s = sample("a-001", 'a', Payload::Carries);
        s.sha256 = digest;
        s.bytes = bytes.len() as u64;
        m.samples.push(s);
        let report = verify_directory(&m, dir.path()).expect("verify");
        assert!(report.is_clean(), "{report:?}");
    }

    #[test]
    fn a_missing_directory_fails_with_a_sentence() {
        let m = manifest();
        let err = verify_directory(&m, Path::new("/nonexistent/corpus/dir")).expect_err("no dir");
        assert!(err.to_string().contains("could not be opened"));
    }

    #[test]
    fn a_file_in_place_of_a_directory_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("not-a-dir");
        fs::write(&file, b"x").expect("write");
        let err = verify_directory(&manifest(), &file).expect_err("not a dir");
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn progress_is_reported_once_per_entry_plus_a_final_call() {
        let (dir, m) = corpus(&[("a-001", b"one"), ("b-002", b"two")]);
        let mut seen = Vec::new();
        verify_directory_with(&m, dir.path(), &mut |done, total, id| {
            seen.push((done, total, id.to_string()));
        })
        .expect("verify");
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], (0, 2, "a-001".to_string()));
        assert_eq!(seen[2], (2, 2, String::new()));
    }

    #[test]
    fn a_name_is_only_a_digest_claim_when_it_really_is_one() {
        let real = hex(&sha256_bytes(b"x"));
        assert_eq!(digest_from_name(&real).as_deref(), Some(real.as_str()));
        assert_eq!(
            digest_from_name(&format!("{real}.png")).as_deref(),
            Some(real.as_str())
        );
        assert!(digest_from_name(&real.to_uppercase()).is_none());
        assert!(digest_from_name("notes.txt").is_none());
        assert!(digest_from_name(&real[..63]).is_none());
        assert!(digest_from_name(&format!("{real}f")).is_none());
        assert!(digest_from_name("").is_none());
    }

    #[test]
    fn the_report_round_trips_through_json_so_results_can_leave_the_machine() {
        let (dir, m) = corpus(&[("a-001", b"one")]);
        let report = verify_directory(&m, dir.path()).expect("verify");
        let text = serde_json::to_string_pretty(&report).expect("write");
        let read: VerifyReport = serde_json::from_str(&text).expect("read");
        assert_eq!(report, read);
    }

    #[test]
    fn hashing_is_bounded_and_matches_the_one_shot_digest_across_chunk_boundaries() {
        let dir = tempfile::tempdir().expect("tempdir");
        for size in [0usize, 1, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1] {
            let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let path = dir.path().join(format!("f{size}"));
            fs::write(&path, &bytes).expect("write");
            match digest_file(&path, size as u64).expect("hash") {
                Hashed::Exactly { digest } => {
                    assert_eq!(digest, hex(&sha256_bytes(&bytes)), "size {size}");
                }
                Hashed::Differently { read } => panic!("size {size} read {read}"),
            }
        }
    }

    #[test]
    fn a_file_longer_than_declared_stops_one_byte_past_rather_than_reading_it_all() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("grown");
        fs::write(&path, vec![7u8; 10_000]).expect("write");
        match digest_file(&path, 10).expect("hash") {
            Hashed::Differently { read } => assert_eq!(read, 11),
            Hashed::Exactly { .. } => panic!("a longer file must not verify"),
        }
    }
}
