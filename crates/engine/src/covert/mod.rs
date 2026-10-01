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

//! Covert-channel detection: the defender surface.
//!
//! # What this module is, and what it deliberately is not
//!
//! This is statistical detection of covert channels in a captured file. It
//! reads PCAP and it writes PCAP. **It opens no sockets, resolves no names and
//! requires no privilege**, in the shipped path and in its tests alike, and
//! there is nothing here that could be pointed at a network by a flag.
//!
//! It contains no tunnel. The fixture generator in [`fixtures`] exists so the
//! detector can be measured against ground truth, and it is built to be a test
//! instrument rather than a capability: it writes capture files only, it encodes
//! a seeded pseudorandom pattern rather than any payload a caller supplies, and
//! it has no jitter, padding or shaping controls. Those absences are the point.
//! Generating traffic that is *hard* to detect is a different artefact with a
//! different risk profile and is not in this module.
//!
//! Per AUP Section 3.2, this surface is ungated: "The defensive companion
//! (statistical detection of covert-channel patterns from PCAP input) is
//! ungated; that is the surface defenders need."
//!
//! # Layout
//!
//! ```text
//!   capture file
//!       │
//!    pcap ──────► records, under hard caps, streaming
//!       │
//!    packet ────► link / IP / transport stripped to a payload
//!       │
//!    dns ───────► query names, labels, record types
//!       │
//!    detect ────► per-channel feature records, no verdict
//! ```
//!
//! [`detect`] reports measurements. It does not decide, for the reason A3
//! gives: a threshold that was not set against a corpus at a documented
//! false-positive ceiling is a guess, and a guess in a detector is worse than
//! no detector because it is believed.

pub mod detect;
pub mod dns;
pub mod packet;
pub mod pcap;

/// Capture fixtures for measuring the detector.
///
/// Behind a non-default feature so a published library carries no traffic
/// generator at all, however constrained that generator is. Always compiled for
/// the crate's own tests, which need it to have anything to measure against.
#[cfg(any(test, feature = "covert-fixtures"))]
pub mod fixtures;
