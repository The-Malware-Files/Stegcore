// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Build-time provenance fingerprint.
//!
//! Captures which source the binary was built from and bakes it into the
//! executable as compile-time environment variables, surfaced by the
//! `build-info` subcommand. An official release is built from a clean tree at
//! a tagged commit; a fork or local rebuild shows a different commit or a
//! dirty tree, which is what makes the two distinguishable. Everything degrades
//! gracefully: outside a git checkout (a crates.io build, a release tarball)
//! the git fields are simply "unknown" and the build still succeeds.

use std::process::Command;

fn main() {
    // Rebuild when the checked-out commit moves so the fingerprint stays
    // current. The .git directory lives at the workspace root, two levels up
    // from this crate.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    let commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let short = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = match git(&["status", "--porcelain"]) {
        Some(s) => !s.trim().is_empty(),
        None => false,
    };
    // Commit date (ISO 8601), not wall-clock build time, so two builds of the
    // same source stay byte-identical (reproducibility, not a moving clock).
    let commit_date =
        git(&["show", "-s", "--format=%cI", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let rustc_version = rustc_version().unwrap_or_else(|| "unknown".to_string());

    emit("STEGCORE_GIT_COMMIT", &commit);
    emit("STEGCORE_GIT_SHORT", &short);
    emit("STEGCORE_GIT_DIRTY", if dirty { "true" } else { "false" });
    emit("STEGCORE_COMMIT_DATE", &commit_date);
    emit("STEGCORE_RUSTC_VERSION", &rustc_version);
    // TARGET and PROFILE are provided to every build script by Cargo.
    emit(
        "STEGCORE_TARGET",
        &std::env::var("TARGET").unwrap_or_default(),
    );
    emit(
        "STEGCORE_PROFILE",
        &std::env::var("PROFILE").unwrap_or_default(),
    );
}

fn emit(key: &str, value: &str) {
    println!("cargo:rustc-env={key}={value}");
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn rustc_version() -> Option<String> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = Command::new(rustc).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}
