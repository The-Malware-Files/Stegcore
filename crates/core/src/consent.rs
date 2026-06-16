// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Machine-local watermarking consent.
//!
//! Watermarking can mark a document the operator does not own, so it is gated
//! behind a one-time consent acknowledgement (the GUI consent dialog, or the
//! CLI `--i-am-authorised` flag). The acknowledgement is recorded once and
//! honoured everywhere: both surfaces resolve the *same* marker path through
//! [`config_dir`], so granting consent on one surface suppresses the prompt on
//! the other. The record is kept as evidence that the operator saw the gate.
//!
//! The platform config directory is resolved by the `dirs` crate (the same
//! crate the CLI already uses for `config.toml`), so the marker lives beside
//! the rest of Stegcore's per-user state rather than under a Tauri
//! bundle-identifier directory the CLI would never look in.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::errors::StegError;

/// File name of the consent marker inside the Stegcore config directory.
const MARKER_FILE: &str = ".watermarking_consent";

/// A recorded consent acknowledgement. Persisted as JSON so the record is
/// human-readable evidence rather than an opaque flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Always true for a written marker; a `false` (or absent) record is
    /// treated as "no consent" by [`has_consent_in`].
    pub granted: bool,
    /// Which surface recorded the grant: `"cli"` or `"gui"`.
    pub surface: String,
    /// Wall-clock time of the grant, in seconds since the Unix epoch. `0` when
    /// the system clock is unavailable (the grant still stands; only the
    /// timestamp is missing).
    pub granted_at_unix: u64,
}

/// Environment override for the shared config directory. When set, it wins over
/// the platform default. Lets a power user relocate Stegcore's per-user state
/// and keeps tests hermetic (no writes to the real `~/.config`).
const CONFIG_DIR_ENV: &str = "STEGCORE_CONFIG_DIR";

/// The canonical machine-local Stegcore config directory, shared by every
/// surface. Honours the `STEGCORE_CONFIG_DIR` override; otherwise falls back to
/// the platform config directory. Returns `None` only when neither is available
/// (a headless environment with no `HOME`/`XDG_CONFIG_HOME`/`APPDATA` and no
/// override set).
pub fn config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV) {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    dirs::config_dir().map(|d| d.join("stegcore"))
}

fn marker_in(dir: &Path) -> PathBuf {
    dir.join(MARKER_FILE)
}

/// Read the consent record from `dir`, if a valid one is present.
pub fn consent_record_in(dir: &Path) -> Option<ConsentRecord> {
    let raw = std::fs::read_to_string(marker_in(dir)).ok()?;
    serde_json::from_str::<ConsentRecord>(&raw).ok()
}

/// True when a valid, granted consent marker exists in `dir`.
pub fn has_consent_in(dir: &Path) -> bool {
    consent_record_in(dir).map(|r| r.granted).unwrap_or(false)
}

/// Record watermarking consent in `dir` and return the written record.
///
/// Idempotent: re-granting overwrites the marker with a refreshed record
/// rather than failing. The directory is created if missing and clamped to
/// `0o700` on Unix; the marker is written atomically (temp file + rename) so
/// an interrupted write never leaves a half-written marker that
/// [`has_consent_in`] would misread.
pub fn grant_consent_in(dir: &Path, surface: &str) -> Result<ConsentRecord, StegError> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    let record = ConsentRecord {
        granted: true,
        surface: surface.to_string(),
        granted_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let json = serde_json::to_string_pretty(&record)?;

    let tmp = NamedTempFile::new_in(dir)?;
    std::fs::write(tmp.path(), json.as_bytes())?;
    tmp.persist(marker_in(dir))
        .map_err(|e| StegError::Io(e.error))?;
    Ok(record)
}

/// True when watermarking consent has been recorded on this machine. Resolves
/// the shared [`config_dir`]; returns `false` when no config directory exists.
pub fn has_consent() -> bool {
    config_dir().map(|d| has_consent_in(&d)).unwrap_or(false)
}

/// Record watermarking consent in the shared [`config_dir`].
///
/// `surface` is `"cli"` or `"gui"`. Errors only when no config directory
/// exists or the marker cannot be written.
pub fn grant_consent(surface: &str) -> Result<ConsentRecord, StegError> {
    let dir = config_dir().ok_or_else(|| {
        StegError::Io(std::io::Error::other(
            "no per-user config directory is available to record consent",
        ))
    })?;
    grant_consent_in(&dir, surface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_marker_reads_as_no_consent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_consent_in(dir.path()));
        assert!(consent_record_in(dir.path()).is_none());
    }

    #[test]
    fn grant_then_has_consent() {
        let dir = tempfile::tempdir().unwrap();
        let rec = grant_consent_in(dir.path(), "cli").unwrap();
        assert!(rec.granted);
        assert_eq!(rec.surface, "cli");
        assert!(has_consent_in(dir.path()));
    }

    #[test]
    fn record_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let written = grant_consent_in(dir.path(), "gui").unwrap();
        let read = consent_record_in(dir.path()).unwrap();
        assert_eq!(written, read);
        assert_eq!(read.surface, "gui");
    }

    #[test]
    fn regrant_refreshes_rather_than_fails() {
        let dir = tempfile::tempdir().unwrap();
        grant_consent_in(dir.path(), "cli").unwrap();
        // Second grant from the other surface must succeed and overwrite.
        let second = grant_consent_in(dir.path(), "gui").unwrap();
        assert_eq!(second.surface, "gui");
        assert_eq!(consent_record_in(dir.path()).unwrap().surface, "gui");
    }

    #[test]
    fn corrupt_marker_reads_as_no_consent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(marker_in(dir.path()), b"{ not valid json").unwrap();
        assert!(!has_consent_in(dir.path()));
        assert!(consent_record_in(dir.path()).is_none());
    }

    #[test]
    fn explicit_ungranted_record_is_not_consent() {
        let dir = tempfile::tempdir().unwrap();
        let rec = ConsentRecord {
            granted: false,
            surface: "cli".into(),
            granted_at_unix: 0,
        };
        std::fs::write(marker_in(dir.path()), serde_json::to_string(&rec).unwrap()).unwrap();
        // The record parses, but granted=false means no consent.
        assert!(consent_record_in(dir.path()).is_some());
        assert!(!has_consent_in(dir.path()));
    }

    #[test]
    fn grant_creates_missing_directory() {
        let parent = tempfile::tempdir().unwrap();
        let nested = parent.path().join("a").join("b").join("stegcore");
        assert!(!nested.exists());
        grant_consent_in(&nested, "cli").unwrap();
        assert!(has_consent_in(&nested));
    }

    #[cfg(unix)]
    #[test]
    fn grant_clamps_directory_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("stegcore");
        grant_consent_in(&dir, "cli").unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn shared_config_dir_is_under_stegcore() {
        // Whatever the platform resolves, the shared marker lives under a
        // `stegcore` directory so both CLI and GUI agree on the path.
        if let Some(d) = config_dir() {
            assert!(d.ends_with("stegcore"));
        }
    }

    #[test]
    fn granted_timestamp_is_populated() {
        let dir = tempfile::tempdir().unwrap();
        let rec = grant_consent_in(dir.path(), "cli").unwrap();
        // The clock is available in CI, so the timestamp should be a plausible
        // post-2020 epoch value (1577836800 = 2020-01-01T00:00:00Z).
        assert!(rec.granted_at_unix > 1_577_836_800);
    }
}
