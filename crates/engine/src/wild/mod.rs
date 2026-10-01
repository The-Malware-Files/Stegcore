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

//! Wild-sample corpora: the record, the integrity check, and the grading
//! harness, with the sample side left deliberately empty.
//!
//! # What this is for
//!
//! Deferred item D2 wants real malware samples (Worok's PNG loaders, SteamHide
//! carriers, MalwareBazaar artefacts) graded against ground truth so the
//! detection claims in the README stop resting entirely on synthesised stego.
//! Those are live malware. Baseline Section 5 is explicit that untrusted
//! third-party material never touches the machine holding the operator's keys,
//! so the samples live on an isolated machine that does not exist yet
//! (`private/plans/wild-sample-isolation.md` is what it has to provide).
//!
//! This module is everything that can be built, tested and reviewed *before*
//! the first sample exists, so provisioning that machine is a download and a
//! run rather than a build.
//!
//! | module | what it is |
//! |---|---|
//! | [`manifest`] | the corpus record: digests, labels, provenance, terms. No content, ever |
//! | [`verify`] | does a local sample set match the manifest? Hashes bytes, never reads them |
//! | [`grade`] | detector scores to per-family true-positive rates at a fixed false-positive rate |
//!
//! # The seam, and why it is empty
//!
//! [`grade::SampleSource`] is the interface the sample bytes arrive through,
//! and **nothing in this tree implements it**. That is the design, not an
//! omission. A fetcher that exists will eventually be called, and the one place
//! it must never be called is here. The isolated machine supplies its own
//! implementation, locally, and the harness it plugs into is already tested
//! against synthetic fixtures.
//!
//! [`grade::Detector`] is the other half of the seam, and it is the
//! cross-validation point as well: our own detectors are one implementation and
//! an Aletheia adapter is a second, so the comparison D2 asks for is two
//! gradings over one manifest rather than a second harness. Neither
//! implementation is written here, for the same reason: both of them end in
//! handing sample bytes to a parser.
//!
//! # What never appears in this module
//!
//! No network client, no URL, no subprocess, no decoder. The manifest format
//! has no field of type `Vec<u8>`, so there is nowhere for sample content to
//! sit even by accident, and the verifier's refusal to parse is pinned by
//! `tests/wild_verifier_never_parses.rs` rather than left to review.

pub mod grade;
pub mod manifest;
pub mod verify;
