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

//! Narrowing the app's write permission from "anywhere" to "the one file the
//! user just chose in a save dialog".
//!
//! **What the capability grants today, which is not what it looks like.**
//! `capabilities/default.json` holds `fs:allow-write-file` and
//! `fs:allow-write-text-file`, and the plugin documents both as enabling the
//! command "without any pre-configured scope". There is no scope anywhere else
//! either: `tauri.conf.json` has no `plugins` section, and nothing in this crate
//! ever calls `allow_file`. With an empty allowlist `tauri::fs::Scope::is_allowed`
//! returns false for every path, so `resolve_path` refuses the write with
//! `PathForbidden`.
//!
//! The consequence is that the two save buttons do not write anything. Both call
//! sites wrap the write in a bare `catch` that falls through to a browser blob
//! download (`routes/Extract.tsx` for an extracted payload,
//! `routes/Analyse.tsx` for a report), and in the webview that download goes
//! nowhere, so the refusal is swallowed and the user sees a save that appears to
//! succeed and produces no file. This was read out of the plugin source rather
//! than observed in a running app, and confirming it live is part of the journey
//! below.
//!
//! So the runtime grant here is not a tightening of something that works. It is
//! the missing half of a feature that has never worked, and it happens to be the
//! narrow version too: one path, the one the user just chose.
//!
//! **What this module does instead.** The write permission is denied by default
//! and one path is granted at a time, from Rust, after the dialog has returned
//! it. The frontend's sequence becomes: open the dialog, hand the chosen path to
//! [`grant_save_target`], then write to the path it hands back. A path the user
//! never chose is never in the scope, so writing to it fails whatever the
//! webview asks for.
//!
//! **It is built and switched off.** [`RUNTIME_SCOPING_ENABLED`] is `false`, the
//! capability file is unchanged, and the frontend has not been rewired. The
//! operator's decision was that this must not go live until a user journey has
//! specifically exercised saving to an unusual location, because a path
//! validation that is slightly too strict turns into "the app refuses to save my
//! file" and that is a worse failure than the one being fixed. What the journey
//! has to cover is listed at [`RUNTIME_SCOPING_ENABLED`].

use std::path::{Path, PathBuf};

/// Whether the runtime grant is live.
///
/// `false` until a user journey has exercised saving to an awkward location.
/// Flipping it to `true` is not a one-line change: it goes together with
/// removing `fs:allow-write-file` and `fs:allow-write-text-file` from
/// `capabilities/default.json` (so the default really is deny) and with the
/// frontend calling `grant_save_target` between the dialog and the write.
///
/// **What the journey has to try, because each of these is a way this breaks a
/// save that works today:**
///
/// 1. A removable drive or a mounted network share, where the chosen directory
///    is a mount point and canonicalising it may produce a path the scope then
///    does not match.
/// 2. A path under a symbolic link, such as a home directory symlinked onto
///    another disk, or macOS's `/tmp` which is a link to `/private/tmp`. The
///    validation resolves the parent, so the granted path is the resolved one
///    and the frontend must write to the path it was handed back rather than the
///    one the dialog returned.
/// 3. A directory the user can see but not write to. The grant must succeed or
///    fail in a way that produces "you cannot write there", not a bare scope
///    rejection.
/// 4. A file name with characters that need no escaping on one platform and do
///    on another: spaces, non-ASCII, a trailing dot, a very long name.
/// 5. Overwriting an existing file, which is the common case and must not be
///    confused with writing a new one.
/// 6. Saving twice in a row to different directories in one session, which is
///    what proves the grant accumulates rather than replacing.
/// 7. Windows specifically: a UNC path, a drive-relative path, and a path on a
///    second drive letter.
/// 8. A cancelled dialog, which must grant nothing at all.
pub const RUNTIME_SCOPING_ENABLED: bool = false;

/// Longest save path accepted from the webview.
///
/// A cap at the boundary rather than a trust in the dialog: the path arrives as
/// a string over IPC, and every platform's own limit is below this. Refusing
/// here means no path-handling code further in has to think about it.
const MAX_PATH_CHARS: usize = 4096;

/// Why a save target was refused, in words a user can act on.
#[derive(Debug, PartialEq, Eq)]
pub enum SaveTargetError {
    NotAbsolute,
    PathTooLong { chars: usize, max: usize },
    TraversalComponent,
    NoFileName,
    MissingFolder { folder: PathBuf },
    FolderUnreadable { folder: PathBuf, reason: String },
    TargetIsFolder { path: PathBuf },
    GrantFailed { reason: String },
}

impl std::fmt::Display for SaveTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute => write!(f, "The save location has to be a full path."),
            Self::PathTooLong { chars, max } => write!(
                f,
                "That save location is too long ({chars} characters; the limit is {max})."
            ),
            Self::TraversalComponent => write!(
                f,
                "The save location cannot contain \"..\". Please choose the folder directly."
            ),
            Self::NoFileName => write!(f, "The save location has no file name."),
            Self::MissingFolder { folder } => {
                write!(f, "The folder {} does not exist.", folder.display())
            }
            Self::FolderUnreadable { folder, reason } => write!(
                f,
                "The folder {} could not be opened: {reason}",
                folder.display()
            ),
            Self::TargetIsFolder { path } => write!(
                f,
                "{} is a folder, so a file cannot be saved over it.",
                path.display()
            ),
            Self::GrantFailed { reason } => write!(
                f,
                "Stegcore could not take permission to write there: {reason}"
            ),
        }
    }
}

/// The one thing this needs from Tauri, named so the logic can be tested
/// without standing up a runtime.
///
/// Mirrors `tauri::fs::Scope::allow_file`, which is what the production
/// implementation forwards to.
pub trait ScopeGrant {
    fn allow_file(&self, path: &Path) -> Result<(), String>;
}

/// Validate a path the save dialog returned and grant write access to exactly
/// that file.
///
/// Returns the path the caller must then write to, which is the resolved one and
/// not necessarily the one passed in: the parent is canonicalised, so a path
/// that reached here through a symbolic link comes back as its real location.
/// Writing to the unresolved path afterwards would miss the scope entry.
///
/// Why the parent and not the whole path: the file itself usually does not exist
/// yet, so it cannot be canonicalised, and the directory is where a symbolic
/// link could redirect the write somewhere the user did not choose. Resolving
/// the parent and then rejoining the file name closes that, and it narrows the
/// window between the check and the write to the single `allow_file` call rather
/// than leaving it open across the whole save. It does not close that window
/// completely, and nothing short of holding an open handle would: the honest
/// claim is that a replaced directory between this call and the write is still
/// possible, and that the user chose the directory themselves a moment ago.
pub fn grant_save_target(
    scope: &dyn ScopeGrant,
    requested: &Path,
) -> Result<PathBuf, SaveTargetError> {
    let as_text = requested.to_string_lossy();
    if as_text.chars().count() > MAX_PATH_CHARS {
        return Err(SaveTargetError::PathTooLong {
            chars: as_text.chars().count(),
            max: MAX_PATH_CHARS,
        });
    }
    if !requested.is_absolute() {
        return Err(SaveTargetError::NotAbsolute);
    }
    if requested
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(SaveTargetError::TraversalComponent);
    }

    let name = match requested.file_name() {
        Some(n) if !n.is_empty() => n.to_owned(),
        _ => return Err(SaveTargetError::NoFileName),
    };
    let parent = requested.parent().ok_or(SaveTargetError::NoFileName)?;

    if !parent.exists() {
        return Err(SaveTargetError::MissingFolder {
            folder: parent.to_path_buf(),
        });
    }
    let resolved_parent = parent
        .canonicalize()
        .map_err(|e| SaveTargetError::FolderUnreadable {
            folder: parent.to_path_buf(),
            reason: e.to_string(),
        })?;

    let target = resolved_parent.join(&name);
    if target.is_dir() {
        return Err(SaveTargetError::TargetIsFolder { path: target });
    }

    scope
        .allow_file(&target)
        .map_err(|reason| SaveTargetError::GrantFailed { reason })?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records what it was asked to allow, so a test can assert the scope was
    /// widened by exactly one file and no more.
    struct Recorder {
        granted: RefCell<Vec<PathBuf>>,
        fail: Option<String>,
    }

    impl Recorder {
        fn new() -> Self {
            Self {
                granted: RefCell::new(Vec::new()),
                fail: None,
            }
        }
        fn failing(reason: &str) -> Self {
            Self {
                granted: RefCell::new(Vec::new()),
                fail: Some(reason.to_string()),
            }
        }
    }

    impl ScopeGrant for Recorder {
        fn allow_file(&self, path: &Path) -> Result<(), String> {
            if let Some(r) = &self.fail {
                return Err(r.clone());
            }
            self.granted.borrow_mut().push(path.to_path_buf());
            Ok(())
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("stegcore_save_scope_{name}"));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn it_is_off_until_a_journey_has_exercised_it() {
        // The flag is the gate. If this ever fails without the capability file
        // and the frontend having moved with it, the deny-by-default half is
        // missing and the app can no longer save anything.
        assert!(!RUNTIME_SCOPING_ENABLED);
    }

    #[test]
    fn a_chosen_file_is_granted_and_handed_back() {
        let dir = temp_dir("chosen");
        let scope = Recorder::new();
        let out = grant_save_target(&scope, &dir.join("report.json")).unwrap();
        assert_eq!(out, dir.canonicalize().unwrap().join("report.json"));
        assert_eq!(scope.granted.borrow().as_slice(), &[out]);
    }

    #[test]
    fn two_saves_in_one_session_each_grant_their_own_file() {
        let a = temp_dir("sessiona");
        let b = temp_dir("sessionb");
        let scope = Recorder::new();
        grant_save_target(&scope, &a.join("one.txt")).unwrap();
        grant_save_target(&scope, &b.join("two.txt")).unwrap();
        assert_eq!(scope.granted.borrow().len(), 2);
    }

    #[test]
    fn an_existing_file_can_be_overwritten() {
        let dir = temp_dir("overwrite");
        let path = dir.join("already-there.bin");
        std::fs::write(&path, b"old").unwrap();
        let scope = Recorder::new();
        assert!(grant_save_target(&scope, &path).is_ok());
    }

    #[test]
    fn a_relative_path_is_refused() {
        let scope = Recorder::new();
        let err = grant_save_target(&scope, Path::new("report.json")).unwrap_err();
        assert_eq!(err, SaveTargetError::NotAbsolute);
        assert!(scope.granted.borrow().is_empty(), "nothing may be granted");
    }

    #[test]
    fn a_traversal_component_is_refused_even_inside_an_absolute_path() {
        let dir = temp_dir("traversal");
        let scope = Recorder::new();
        let sneaky = dir.join("..").join("..").join("etc").join("passwd");
        let err = grant_save_target(&scope, &sneaky).unwrap_err();
        assert_eq!(err, SaveTargetError::TraversalComponent);
        assert!(scope.granted.borrow().is_empty());
    }

    #[test]
    fn a_missing_folder_is_named_rather_than_guessed_at() {
        let scope = Recorder::new();
        let path = std::env::temp_dir()
            .join("stegcore_save_scope_nope_nope")
            .join("x.txt");
        match grant_save_target(&scope, &path).unwrap_err() {
            SaveTargetError::MissingFolder { folder } => {
                assert!(folder.to_string_lossy().contains("nope_nope"))
            }
            other => panic!("expected MissingFolder, got {other:?}"),
        }
        assert!(scope.granted.borrow().is_empty());
    }

    #[test]
    fn a_folder_cannot_be_saved_over() {
        let dir = temp_dir("isdir");
        std::fs::create_dir_all(dir.join("subfolder")).unwrap();
        let scope = Recorder::new();
        match grant_save_target(&scope, &dir.join("subfolder")).unwrap_err() {
            SaveTargetError::TargetIsFolder { .. } => {}
            other => panic!("expected TargetIsFolder, got {other:?}"),
        }
        assert!(scope.granted.borrow().is_empty());
    }

    #[test]
    fn an_over_long_path_is_refused_at_the_boundary() {
        let scope = Recorder::new();
        let long = std::env::temp_dir().join("x".repeat(MAX_PATH_CHARS + 1));
        match grant_save_target(&scope, &long).unwrap_err() {
            SaveTargetError::PathTooLong { max, .. } => assert_eq!(max, MAX_PATH_CHARS),
            other => panic!("expected PathTooLong, got {other:?}"),
        }
    }

    #[test]
    fn a_path_with_no_file_name_is_refused() {
        let scope = Recorder::new();
        let err = grant_save_target(&scope, Path::new("/")).unwrap_err();
        assert_eq!(err, SaveTargetError::NoFileName);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_folder_comes_back_resolved() {
        // macOS's /tmp is a link to /private/tmp, so this is the ordinary case
        // there rather than an exotic one. The caller has to write to the path
        // it is handed, or it writes outside the scope entry.
        let real = temp_dir("symlink_real");
        let link = std::env::temp_dir().join("stegcore_save_scope_symlink_link");
        std::fs::remove_file(&link).ok();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let scope = Recorder::new();
        let out = grant_save_target(&scope, &link.join("payload.bin")).unwrap();
        assert_eq!(out, real.canonicalize().unwrap().join("payload.bin"));
        std::fs::remove_file(&link).ok();
    }

    #[test]
    fn a_failed_grant_says_so_rather_than_reporting_success() {
        let dir = temp_dir("grantfail");
        let scope = Recorder::failing("scope is locked");
        match grant_save_target(&scope, &dir.join("x.txt")).unwrap_err() {
            SaveTargetError::GrantFailed { reason } => assert_eq!(reason, "scope is locked"),
            other => panic!("expected GrantFailed, got {other:?}"),
        }
    }

    #[test]
    fn every_refusal_reads_as_plain_language() {
        let cases = [
            SaveTargetError::NotAbsolute,
            SaveTargetError::PathTooLong {
                chars: 9000,
                max: MAX_PATH_CHARS,
            },
            SaveTargetError::TraversalComponent,
            SaveTargetError::NoFileName,
            SaveTargetError::MissingFolder {
                folder: PathBuf::from("/a/b"),
            },
            SaveTargetError::FolderUnreadable {
                folder: PathBuf::from("/a/b"),
                reason: "denied".into(),
            },
            SaveTargetError::TargetIsFolder {
                path: PathBuf::from("/a/b"),
            },
            SaveTargetError::GrantFailed {
                reason: "locked".into(),
            },
        ];
        for case in cases {
            let text = case.to_string();
            assert!(text.ends_with('.') || text.ends_with("locked") || text.ends_with("denied"));
            assert!(
                !text.contains("Err(") && !text.contains("Error {"),
                "a raw error string reached the user: {text}"
            );
        }
    }
}
