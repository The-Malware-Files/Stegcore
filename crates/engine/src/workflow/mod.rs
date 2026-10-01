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

//! Declarative analysis pipelines: the file format, its validator, and the
//! starter templates.
//!
//! | module | what it is |
//! |---|---|
//! | [`dsl`] | the TOML pipeline file, parsed and validated whole before anything runs |
//! | [`condition`] | the one-comparison condition language, and why it is only that |
//! | [`templates`] | the three curated starter pipelines, embedded and version-stamped |
//!
//! Nothing here executes a step. Parsing and validation are pure: no file is
//! read beyond the pipeline file itself, no directory is created, no network is
//! touched, and no step is run. Executing a validated pipeline is the runner's
//! job, which keeps "is this file sane" answerable about a file somebody sent
//! you without side effects.

pub mod condition;
pub mod dsl;
pub mod templates;
