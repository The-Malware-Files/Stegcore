// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! `build-info`: report the binary's build provenance.
//!
//! The fields are baked in at compile time by `build.rs`. They let anyone tell
//! an official release (a clean tree at a tagged commit) from a fork or local
//! rebuild (a different commit, or a dirty tree). This is the binary-provenance
//! half of the copyright-detection layer; the wire-format and permutation
//! vectors cover output forensics.

use crate::output::{self, JsonOut};

/// Compile-time provenance, baked in by `build.rs`.
#[derive(serde::Serialize)]
pub struct BuildInfo {
    pub version: &'static str,
    pub git_commit: &'static str,
    pub git_short: &'static str,
    pub git_dirty: bool,
    pub commit_date: &'static str,
    pub rustc_version: &'static str,
    pub target: &'static str,
    pub profile: &'static str,
}

pub fn current() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION"),
        git_commit: env!("STEGCORE_GIT_COMMIT"),
        git_short: env!("STEGCORE_GIT_SHORT"),
        git_dirty: matches!(env!("STEGCORE_GIT_DIRTY"), "true"),
        commit_date: env!("STEGCORE_COMMIT_DATE"),
        rustc_version: env!("STEGCORE_RUSTC_VERSION"),
        target: env!("STEGCORE_TARGET"),
        profile: env!("STEGCORE_PROFILE"),
    }
}

pub fn run(json: bool) -> ! {
    let info = current();

    if json {
        output::emit_json(&JsonOut::success(&info), 0);
    }

    output::print_info(&format!("Stegcore {}", info.version));
    let dirty = if info.git_dirty {
        " (dirty tree, not an official build)"
    } else {
        ""
    };
    eprintln!("  commit:  {} ({}){dirty}", info.git_short, info.git_commit);
    eprintln!("  date:    {}", info.commit_date);
    eprintln!("  target:  {}", info.target);
    eprintln!("  profile: {}", info.profile);
    eprintln!("  rustc:   {}", info.rustc_version);

    std::process::exit(0);
}
