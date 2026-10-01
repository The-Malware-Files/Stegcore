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

//! Reproducibility: records of what was measured, in forms that survive being
//! written down.
//!
//! Three pieces, in dependency order:
//!
//! | module | what it is |
//! |---|---|
//! | [`real`] | a number that survives a JSON round trip, which turned out not to be free |
//! | [`manifest`] | the per-analysis record, digested so a re-run can be compared |
//! | [`corpus`] | the contribution format for the shared calibration corpus |
//!
//! None of them opens a socket. The corpus is federated by git and pull request,
//! so the transport is a reviewer reading a diff.

pub mod corpus;
pub mod manifest;
pub mod real;
