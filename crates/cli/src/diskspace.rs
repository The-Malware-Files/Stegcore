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

//! Free space on the filesystem holding a path.
//!
//! This used to shell out to `df -h` and parse the second line of its output,
//! and that had three defects of its own rather than one:
//!
//! 1. **The path reached `df`'s argument list unseparated**, and the path comes
//!    from the environment via `TMPDIR`. `TMPDIR=--version` made `df` print its
//!    own version banner, whose second line the parser read as a disk figure, so
//!    `stegcore doctor` reported a green `Disk` check whose value was a version
//!    string. A health check that lies is worse than one that is missing, because
//!    the missing one does not get believed. No shell was ever involved, so this
//!    was argument injection rather than command injection, and `;id` or a
//!    newline in `TMPDIR` was always inert.
//! 2. **No timeout.** A `df` against a hung network mount never returns, and
//!    `Command::output` waits forever, so a diagnostic command would hang.
//! 3. **PATH and locale dependence.** The parse assumed `df` exists, that it is
//!    the GNU one, and that its column order and human-readable suffixes are
//!    stable. None of that is guaranteed on a minimal container image.
//!
//! A `statvfs` call answers the same question with no argument parsing, no
//! subprocess, no PATH lookup and no output format to depend on. It can still
//! block on a hung mount, which is a property of the filesystem rather than of
//! how we ask, so the call runs on its own thread behind a deadline and the
//! caller gets "unknown" rather than a hang.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long to wait for the filesystem to answer before giving up.
///
/// A healthy local or network filesystem answers a `statvfs` in well under a
/// millisecond. Anything near this deadline is a filesystem in trouble, which is
/// itself worth reporting, and reporting it beats blocking a diagnostic command
/// that someone ran precisely because something was already wrong.
const STATVFS_DEADLINE: Duration = Duration::from_secs(3);

/// Why a space check could not produce a number.
///
/// Carried rather than collapsed to an `Option` so `doctor` can say which of
/// these happened. "The path does not exist" and "the filesystem did not answer"
/// are different problems for whoever is reading the output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceError {
    /// The path is not an existing directory, so there is no filesystem to ask
    /// about. This is the case a hostile or mistaken `TMPDIR` lands in.
    NotADirectory(PathBuf),
    /// The filesystem did not answer within [`STATVFS_DEADLINE`].
    TimedOut,
    /// The platform refused the query, carrying the OS error number.
    Unavailable(i32),
    /// No implementation on this platform. Only ever constructed off Unix, so a
    /// Unix build sees it as dead; it is kept in the shared enum rather than
    /// cfg-gated out so the `Display` arm and the test below cover it everywhere.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported,
}

impl std::fmt::Display for SpaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Plain language, no raw error strings: this goes in front of a user.
            Self::NotADirectory(p) => {
                write!(f, "not a directory: {}", p.display())
            }
            Self::TimedOut => write!(f, "the filesystem did not respond"),
            Self::Unavailable(e) => write!(f, "could not be read (OS error {e})"),
            Self::Unsupported => write!(f, "not supported on this platform"),
        }
    }
}

/// Bytes available to an unprivileged process on the filesystem holding `path`.
///
/// Deliberately the unprivileged figure (`f_bavail`), not the total free figure
/// (`f_bfree`), because the reserved blocks a filesystem keeps for root are not
/// space this program can write into, and reporting them would overstate what is
/// usable by exactly the amount that matters when a disk is nearly full.
pub fn available_bytes(path: &Path) -> Result<u64, SpaceError> {
    // Checked before asking the platform, so a path out of the environment is
    // rejected here rather than becoming an argument to anything.
    if !path.is_dir() {
        return Err(SpaceError::NotADirectory(path.to_path_buf()));
    }
    available_bytes_inner(path)
}

#[cfg(unix)]
fn available_bytes_inner(path: &Path) -> Result<u64, SpaceError> {
    use std::sync::mpsc;

    let owned = path.to_path_buf();
    let (tx, rx) = mpsc::channel();

    // A detached thread on purpose. If the filesystem never answers, this thread
    // stays blocked in the kernel for the life of the process, and that is the
    // better of the two available outcomes: the alternative is blocking the
    // caller. It holds nothing but its own path copy, so the leak is bounded and
    // one-off rather than growing.
    let spawned = std::thread::Builder::new()
        .name("stegcore-statvfs".into())
        .spawn(move || {
            let _ = tx.send(statvfs_available(&owned));
        });

    if spawned.is_err() {
        // Out of threads. Asking on this thread would risk the hang the deadline
        // exists to prevent, so report rather than gamble.
        return Err(SpaceError::TimedOut);
    }

    match rx.recv_timeout(STATVFS_DEADLINE) {
        Ok(result) => result,
        Err(_) => Err(SpaceError::TimedOut),
    }
}

#[cfg(unix)]
fn statvfs_available(path: &Path) -> Result<u64, SpaceError> {
    use std::os::unix::ffi::OsStrExt;

    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        // An interior nul byte cannot name a real path.
        return Err(SpaceError::NotADirectory(path.to_path_buf()));
    };

    // SAFETY: `stat` is a zeroed, correctly-sized `statvfs` owned by this frame,
    // and `c_path` is a nul-terminated string that outlives the call. The return
    // value is checked before any field is read.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(SpaceError::Unavailable(errno));
    }

    // f_frsize is the fragment size and is the correct multiplier for the block
    // counts; f_bsize is a preferred IO size and is not. They are equal on most
    // filesystems, which is why using the wrong one survives casual testing.
    let frsize = if stat.f_frsize == 0 {
        stat.f_bsize as u64
    } else {
        stat.f_frsize as u64
    };
    Ok((stat.f_bavail as u64).saturating_mul(frsize))
}

#[cfg(not(unix))]
fn available_bytes_inner(_path: &Path) -> Result<u64, SpaceError> {
    Err(SpaceError::Unsupported)
}

/// Render a byte count the way a person reads one.
///
/// Binary units, because that is what a filesystem reports and what every other
/// disk tool on the machine will show, so a user comparing two numbers is
/// comparing like with like.
pub fn humanise(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Space below which `doctor` should stop calling the disk healthy.
///
/// Sized against what this program actually does rather than picked round: a
/// cover image, its stego output and a temporary file alongside both, with room
/// for the largest cover the engine will accept. Under this, an embed of a large
/// cover can fail partway, which is the failure a health check exists to warn
/// about before it happens.
pub const HEALTHY_FLOOR_BYTES: u64 = 512 * 1024 * 1024;

/// The `doctor` line for a path: whether it passes, and what to show.
pub fn report(path: &Path) -> (bool, String) {
    match available_bytes(path) {
        Ok(bytes) => {
            let healthy = bytes >= HEALTHY_FLOOR_BYTES;
            let note = if healthy {
                format!("{} available on {}", humanise(bytes), path.display())
            } else {
                format!(
                    "only {} available on {}, which is below the {} this needs for a large cover",
                    humanise(bytes),
                    path.display(),
                    humanise(HEALTHY_FLOOR_BYTES),
                )
            };
            (healthy, note)
        }
        // A space check that could not run is not a pass. The previous code
        // hardcoded this check to `true`, so it reported success even when it had
        // nothing to report, which is the other half of why the injection was
        // invisible: there was no state in which the line went red.
        Err(e) => (false, e.to_string()),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_real_directory_reports_some_space() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = available_bytes(dir.path()).expect("a temp dir has a filesystem");
        assert!(bytes > 0, "a writable temp dir reported no available space");
    }

    /// The exact input that made the old check lie. `TMPDIR=--version` is not a
    /// directory, so it must be refused here rather than reaching anything that
    /// treats it as an argument.
    #[test]
    fn an_option_looking_path_is_refused_as_a_path() {
        let e = available_bytes(Path::new("--version")).unwrap_err();
        assert_eq!(e, SpaceError::NotADirectory(PathBuf::from("--version")));
    }

    #[test]
    fn a_missing_path_is_refused() {
        let e = available_bytes(Path::new("/definitely/not/here/stegcore")).unwrap_err();
        assert!(matches!(e, SpaceError::NotADirectory(_)));
    }

    /// A file is not a directory, even though `statvfs` would happily answer for
    /// one. Keeping the check strict means the reported path is always the thing
    /// whose space was measured.
    #[test]
    fn a_file_is_not_accepted_as_a_directory() {
        let f = tempfile::NamedTempFile::new().expect("temp file");
        let e = available_bytes(f.path()).unwrap_err();
        assert!(matches!(e, SpaceError::NotADirectory(_)));
    }

    /// The regression that matters: a check which cannot produce a number must
    /// report failure. The previous implementation passed unconditionally.
    #[test]
    fn a_check_that_cannot_run_does_not_report_success() {
        let (ok, note) = report(Path::new("--version"));
        assert!(!ok, "an unmeasurable path reported a healthy disk");
        assert!(
            !note.is_empty(),
            "a failing check must say something a user can act on"
        );
    }

    #[test]
    fn a_real_directory_reports_a_verdict_and_a_number() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (ok, note) = report(dir.path());
        // Not asserting `ok`: a CI runner genuinely close to full should report
        // false here, and a test that demanded true would be asserting something
        // about the machine rather than about this code.
        assert!(note.contains(&dir.path().display().to_string()));
        if ok {
            assert!(note.contains("available on"));
        } else {
            assert!(note.contains("below the"));
        }
    }

    #[test]
    fn humanise_uses_binary_units_and_keeps_bytes_exact() {
        assert_eq!(humanise(0), "0 B");
        assert_eq!(humanise(512), "512 B");
        assert_eq!(humanise(1024), "1.0 KiB");
        assert_eq!(humanise(1536), "1.5 KiB");
        assert_eq!(humanise(1024 * 1024), "1.0 MiB");
        assert_eq!(humanise(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    /// The largest value must not overflow into a smaller unit or panic.
    #[test]
    fn humanise_handles_the_extremes() {
        let s = humanise(u64::MAX);
        assert!(s.ends_with("TiB"), "u64::MAX rendered as {s}");
    }

    #[test]
    fn errors_read_as_plain_language() {
        for e in [
            SpaceError::NotADirectory(PathBuf::from("/x")),
            SpaceError::TimedOut,
            SpaceError::Unavailable(13),
            SpaceError::Unsupported,
        ] {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert!(
                !s.contains("Err(") && !s.contains("SpaceError"),
                "a raw debug string reached the user: {s}"
            );
        }
    }

    /// The deadline only helps if it is short enough that a person waiting on a
    /// diagnostic does not assume the command itself has hung.
    #[test]
    fn the_deadline_is_short_enough_to_be_useful() {
        assert!(STATVFS_DEADLINE <= Duration::from_secs(5));
        assert!(STATVFS_DEADLINE >= Duration::from_secs(1));
    }
}
