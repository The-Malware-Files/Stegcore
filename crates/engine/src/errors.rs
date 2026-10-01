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

use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StegError {
    #[error(
        "Cover file is too small to hold this payload (need {required} bytes, have {available})"
    )]
    InsufficientCapacity { required: usize, available: usize },

    // Deliberately identical to NoPayloadFound. Telling the two apart would
    // require a passphrase-independent marker in the file, which is exactly the
    // fixed structure our own fingerprint detectors hunt for, so it would make
    // hidden data detectable. See ADR-002 option B, rejected.
    #[error("No hidden message was recovered: either the passphrase is wrong, or this file carries nothing")]
    DecryptionFailed,

    #[error("This file was created with an older version of Stegcore and is not compatible")]
    LegacyKeyFile,

    #[error("Unsupported file format: {0}")]
    UnsupportedFormat(String),

    #[error("Cover file is not suitable for steganography (score: {score:.2})")]
    PoorCoverQuality { score: f64 },

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Payload file is empty")]
    EmptyPayload,

    // Identical user-facing message to DecryptionFailed, deliberately: the code
    // genuinely cannot tell which case it is in, and measured, the two fail at
    // the same parse in indistinguishable time (49.55 ms against 50.51 ms on an
    // 800x600 cover, inside an IQR of 4.77).
    #[error("No hidden message was recovered: either the passphrase is wrong, or this file carries nothing")]
    NoPayloadFound,

    #[error("Invalid or corrupted stego file")]
    CorruptedFile,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Image(#[from] image::ImageError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// A deliberate internal invariant failure: our own code found a state it
    /// says cannot happen. Not a statement about the user's file.
    #[error("Internal error processing file: {0}")]
    Internal(String),

    /// A panic was caught at an engine boundary, typically a third-party
    /// decoder choking on malformed input.
    ///
    /// This is a bug in Stegcore or in something Stegcore depends on, and the
    /// file that triggered it may be perfectly valid, so it is a separate
    /// variant from [`StegError::CorruptedFile`]. Reporting it as a corrupt
    /// file blamed the user for our crash. `detail` is the panic payload, kept
    /// for the diagnostic file and never shown to the user; `diagnostic` is
    /// where that file landed, when one could be written.
    #[error(
        "Stegcore itself failed while reading this file.{}",
        diagnostic_note(diagnostic)
    )]
    CaughtPanic {
        detail: String,
        diagnostic: Option<PathBuf>,
    },
}

/// The sentence that tells a user where to find the crash detail, or says
/// plainly that there is none to find.
fn diagnostic_note(diagnostic: &Option<PathBuf>) -> String {
    match diagnostic {
        Some(p) => format!(" Diagnostic written to {}", p.display()),
        None => " No diagnostic file could be written.".to_string(),
    }
}

/// Catch a panic and turn it into a [`StegError::CaughtPanic`], writing the
/// detail to a diagnostic file first.
///
/// `operation` and `subject` name what was being done and to what, so the file
/// is useful in a bug report without the reporter having to remember.
pub fn caught_panic(
    operation: &str,
    subject: Option<&std::path::Path>,
    payload: &(dyn std::any::Any + Send),
) -> StegError {
    let detail = panic_message(payload);
    let diagnostic = write_diagnostic(operation, subject, &detail);
    StegError::CaughtPanic { detail, diagnostic }
}

/// Best-effort text of a panic payload. A panic can carry any type; the two
/// that `panic!` produces are covered and anything else is named as unknown
/// rather than discarded silently.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic in engine dependency (caught), payload was not a string".to_string()
    }
}

/// Write one crash diagnostic and return its path.
///
/// Returns `None` when the file could not be written, with the reason folded
/// into the returned path's absence rather than into a swallowed error: the
/// caller's message then says plainly that there is no diagnostic, which is the
/// loud version of this failing.
///
/// The directory is `$STEGCORE_DIAGNOSTIC_DIR` when set, otherwise a
/// `stegcore-diagnostics` directory inside the platform temporary directory. The
/// file is written to a temporary name and renamed into place, so a reader never
/// sees a half-written diagnostic, and nothing partial is left behind if the
/// process dies mid-write.
fn write_diagnostic(
    operation: &str,
    subject: Option<&std::path::Path>,
    detail: &str,
) -> Option<PathBuf> {
    let dir = match std::env::var_os("STEGCORE_DIAGNOSTIC_DIR") {
        Some(d) => PathBuf::from(d),
        None => std::env::temp_dir().join("stegcore-diagnostics"),
    };
    std::fs::create_dir_all(&dir).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A diagnostic names a file the user was working on, so it is theirs to
        // read and nobody else's on a shared machine.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).ok()?;
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let name = format!("panic-{}-{stamp}.txt", std::process::id());

    let body = format!(
        "Stegcore crash diagnostic\n\
         version:   {}\n\
         operation: {operation}\n\
         subject:   {}\n\
         panic:     {detail}\n\
         \n\
         This is a bug in Stegcore or in one of its dependencies, not \
         necessarily a problem with the file. Please attach this file to a \
         report at https://github.com/The-Malware-Files/Stegcore/issues\n",
        env!("CARGO_PKG_VERSION"),
        subject.map_or_else(|| "(none)".to_string(), |p| p.display().to_string()),
    );

    let mut temp = tempfile::NamedTempFile::new_in(&dir).ok()?;
    std::io::Write::write_all(&mut temp, body.as_bytes()).ok()?;
    let path = dir.join(name);
    temp.persist(&path).ok()?;
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_resistance() {
        // DecryptionFailed and NoPayloadFound must produce identical user-facing text.
        assert_eq!(
            StegError::DecryptionFailed.to_string(),
            StegError::NoPayloadFound.to_string(),
        );
    }

    #[test]
    fn error_messages_are_user_friendly() {
        let errors: &[(&str, StegError)] = &[
            ("passphrase", StegError::DecryptionFailed),
            ("not found", StegError::FileNotFound("/tmp/x.png".into())),
            (
                "too small",
                StegError::InsufficientCapacity {
                    required: 100,
                    available: 10,
                },
            ),
            ("empty", StegError::EmptyPayload),
            ("Unsupported", StegError::UnsupportedFormat("tiff".into())),
        ];
        for (keyword, err) in errors {
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains(&keyword.to_lowercase()),
                "Error message for {:?} should contain '{}', got: {}",
                err,
                keyword,
                msg
            );
        }
    }
}
