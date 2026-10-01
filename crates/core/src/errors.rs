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

use serde::Serialize;

#[derive(thiserror::Error, Debug)]
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

    #[error("This file was created with an older version of Stegcore and cannot be used here")]
    LegacyKeyFile,

    #[error("Unsupported file format: {0}")]
    UnsupportedFormat(String),

    #[error("Cover file is not suitable for embedding")]
    PoorCoverQuality { score: f64 },

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Payload file is empty")]
    EmptyPayload,

    /// Same user-facing text as DecryptionFailed, deliberately: the code
    /// genuinely cannot tell which case it is in, so the identical message is
    /// honest as well as oracle-resistant.
    #[error("No hidden message was recovered: either the passphrase is wrong, or this file carries nothing")]
    NoPayloadFound,

    #[error("Invalid or corrupted stego file")]
    CorruptedFile,

    /// Stegcore, or something Stegcore depends on, failed while handling the
    /// file. Distinct from [`StegError::CorruptedFile`] because the file may be
    /// perfectly valid: this is our bug, and saying "your file is corrupt" sent
    /// users off re-downloading a file that was never the problem.
    #[error("Something inside Stegcore failed while reading this file, so the file itself may well be fine.{}", diagnostic_note(diagnostic))]
    InternalFailure {
        diagnostic: Option<std::path::PathBuf>,
    },

    #[error("File is too large ({size_mb} MB). Maximum supported size is {max_mb} MB.")]
    FileTooLarge { size_mb: u64, max_mb: u64 },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Image error: {0}")]
    Image(String),

    #[error("Watermarking authorisation has not been recorded on this machine")]
    ConsentRequired,

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Convert from the engine's error type into the public error type.
impl From<stegcore_engine::errors::StegError> for StegError {
    fn from(e: stegcore_engine::errors::StegError) -> Self {
        use stegcore_engine::errors::StegError as E;
        match e {
            E::InsufficientCapacity {
                required,
                available,
            } => StegError::InsufficientCapacity {
                required,
                available,
            },
            E::DecryptionFailed => StegError::DecryptionFailed,
            E::LegacyKeyFile => StegError::LegacyKeyFile,
            E::UnsupportedFormat(s) => StegError::UnsupportedFormat(s),
            E::PoorCoverQuality { score } => StegError::PoorCoverQuality { score },
            E::FileNotFound(s) => StegError::FileNotFound(s),
            E::EmptyPayload => StegError::EmptyPayload,
            E::NoPayloadFound => StegError::NoPayloadFound,
            E::CorruptedFile => StegError::CorruptedFile,
            E::Io(e) => StegError::Io(e),
            E::Image(e) => StegError::Image(e.to_string()),
            E::Json(e) => StegError::Json(e),
            // Both of these are failures in our own code or in a dependency,
            // and neither is a statement about the user's file. The detail stays
            // out of the user-facing message (don't leak which decoder path
            // crashed) and goes to the diagnostic file instead, which is where a
            // bug report can pick it up.
            E::CaughtPanic { diagnostic, .. } => StegError::InternalFailure { diagnostic },
            E::Internal(_) => StegError::InternalFailure { diagnostic: None },
        }
    }
}

/// The sentence that tells a user where to find the crash detail, or says
/// plainly that there is none to find.
fn diagnostic_note(diagnostic: &Option<std::path::PathBuf>) -> String {
    match diagnostic {
        Some(p) => format!(" Diagnostic written to {}", p.display()),
        None => " No diagnostic file was written.".to_string(),
    }
}

impl StegError {
    /// Actionable suggestion for the user. Helps them recover from the error
    /// instead of just showing "something went wrong".
    pub fn suggestion(&self) -> Option<&'static str> {
        match self {
            StegError::InsufficientCapacity { .. } => Some(
                "Try a larger cover file, switch to sequential mode (+30% capacity), or compress your payload first.",
            ),
            // Says plainly that the two cases cannot be told apart, and why.
            // A user who could not distinguish them abandoned the task, because
            // guessing passphrases is unbounded work with no way to know
            // whether the work is even possible. The information genuinely does
            // not exist, so the honest answer is to say so rather than to leave
            // them inferring it. Telling them apart would need a marker in the
            // file that did not depend on the passphrase, and that marker is the
            // fixed structure steganalysis looks for.
            StegError::DecryptionFailed | StegError::NoPayloadFound => Some(
                "Check the passphrase, and the key file if you used one. Stegcore cannot tell a wrong passphrase from a file that holds nothing, and will not: a file that could answer that question would be detectable as a stego file.",
            ),
            StegError::PoorCoverQuality { .. } => Some(
                "Use a high-resolution photo with natural texture (landscapes, cityscapes work well). Avoid flat-colour or synthetic images.",
            ),
            StegError::EmptyPayload => Some(
                "The payload file is empty. Check the file path and ensure it contains data.",
            ),
            StegError::UnsupportedFormat(_) => Some(
                "Supported formats: PNG, BMP, JPEG, WebP, WAV. FLAC is supported for analysis and extraction only.",
            ),
            StegError::FileTooLarge { .. } => Some(
                "Cover files up to 2 GB and payloads up to 500 MB are supported. Try a smaller file.",
            ),
            StegError::CorruptedFile => Some(
                "The file may be truncated or damaged. Try re-downloading or using a different file.",
            ),
            StegError::InternalFailure { .. } => Some(
                "This is a fault in Stegcore, not in your file. Please report it with the diagnostic file attached: https://github.com/The-Malware-Files/Stegcore/issues",
            ),
            StegError::LegacyKeyFile => Some(
                "This key file was created by an older version. Re-embed with the current version to generate a compatible key file.",
            ),
            StegError::ConsentRequired => Some(
                "Confirm you are authorised to watermark this file. In the app, accept the watermarking consent; on the CLI, pass --i-am-authorised.",
            ),
            _ => None,
        }
    }
}

/// Serialise to a plain string for Tauri IPC.
impl Serialize for StegError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_oracle_resistant() {
        // DecryptionFailed and NoPayloadFound must have identical messages
        let df = StegError::DecryptionFailed;
        let np = StegError::NoPayloadFound;
        assert_eq!(df.to_string(), np.to_string());
    }

    #[test]
    fn nothing_user_visible_separates_the_two_indistinguishable_cases() {
        // The invariant is not "the Display strings match", it is "no surface a
        // user or a script can observe tells these two apart". Display was
        // already guarded; `suggestion` was not, and it is printed directly
        // beneath the error by `output::die`. A different suggestion for each
        // would be an oracle in prose, which is still an oracle.
        let df = StegError::DecryptionFailed;
        let np = StegError::NoPayloadFound;
        assert_eq!(df.to_string(), np.to_string(), "Display diverged");
        assert_eq!(df.suggestion(), np.suggestion(), "suggestion() diverged");
    }

    #[test]
    fn the_indistinguishable_cases_say_so_rather_than_implying_a_wrong_passphrase() {
        // The old text named only one of the two causes, so a user reading it
        // concluded their passphrase was wrong and kept guessing against a file
        // that may have held nothing. Both causes have to appear, and the
        // guidance has to say the tool cannot separate them.
        let msg = StegError::NoPayloadFound.to_string();
        assert!(msg.contains("passphrase"), "must name the passphrase case");
        assert!(
            msg.contains("nothing"),
            "must name the empty-file case too: {msg}"
        );
        let hint = StegError::NoPayloadFound.suggestion().unwrap();
        assert!(
            hint.contains("cannot tell"),
            "guidance must say the two cannot be separated: {hint}"
        );
    }

    #[test]
    fn display_insufficient_capacity() {
        let e = StegError::InsufficientCapacity {
            required: 1000,
            available: 500,
        };
        let msg = e.to_string();
        assert!(msg.contains("1000"));
        assert!(msg.contains("500"));
    }

    #[test]
    fn display_unsupported_format() {
        let e = StegError::UnsupportedFormat("tiff".into());
        assert!(e.to_string().contains("tiff"));
    }

    #[test]
    fn display_file_not_found() {
        let e = StegError::FileNotFound("/tmp/nope.png".into());
        assert!(e.to_string().contains("/tmp/nope.png"));
    }

    #[test]
    fn display_file_too_large() {
        let e = StegError::FileTooLarge {
            size_mb: 3000,
            max_mb: 2000,
        };
        let msg = e.to_string();
        assert!(msg.contains("3000"));
        assert!(msg.contains("2000"));
    }

    #[test]
    fn suggestion_for_insufficient_capacity() {
        let e = StegError::InsufficientCapacity {
            required: 100,
            available: 50,
        };
        assert!(e.suggestion().unwrap().contains("sequential"));
    }

    #[test]
    fn suggestion_for_decryption_failed() {
        assert!(StegError::DecryptionFailed
            .suggestion()
            .unwrap()
            .contains("passphrase"));
    }

    #[test]
    fn suggestion_for_no_payload_also_mentions_passphrase() {
        assert!(StegError::NoPayloadFound
            .suggestion()
            .unwrap()
            .contains("passphrase"));
    }

    #[test]
    fn suggestion_for_poor_cover() {
        let e = StegError::PoorCoverQuality { score: 0.05 };
        assert!(e.suggestion().unwrap().contains("high-resolution"));
    }

    #[test]
    fn suggestion_for_empty_payload() {
        assert!(StegError::EmptyPayload
            .suggestion()
            .unwrap()
            .contains("empty"));
    }

    #[test]
    fn suggestion_for_unsupported_format() {
        let e = StegError::UnsupportedFormat("gif".into());
        assert!(e.suggestion().unwrap().contains("PNG"));
    }

    #[test]
    fn suggestion_for_file_too_large() {
        let e = StegError::FileTooLarge {
            size_mb: 5000,
            max_mb: 2000,
        };
        assert!(e.suggestion().unwrap().contains("2 GB"));
    }

    #[test]
    fn suggestion_for_io_returns_none() {
        let e = StegError::Io(std::io::Error::other("test"));
        assert!(e.suggestion().is_none());
    }

    #[test]
    fn serialize_to_string() {
        let e = StegError::EmptyPayload;
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"Payload file is empty\"");
    }

    #[test]
    fn io_error_converts() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let e: StegError = io_err.into();
        assert!(e.to_string().contains("gone"));
    }

    // ── Engine to core From conversion (one test per variant) ──────────────

    #[test]
    fn from_engine_insufficient_capacity() {
        let e = stegcore_engine::errors::StegError::InsufficientCapacity {
            required: 100,
            available: 50,
        };
        let c: StegError = e.into();
        match c {
            StegError::InsufficientCapacity {
                required,
                available,
            } => {
                assert_eq!(required, 100);
                assert_eq!(available, 50);
            }
            other => panic!("expected InsufficientCapacity, got {other:?}"),
        }
    }

    #[test]
    fn from_engine_decryption_failed() {
        let c: StegError = stegcore_engine::errors::StegError::DecryptionFailed.into();
        assert!(matches!(c, StegError::DecryptionFailed));
    }

    #[test]
    fn from_engine_legacy_key_file() {
        let c: StegError = stegcore_engine::errors::StegError::LegacyKeyFile.into();
        assert!(matches!(c, StegError::LegacyKeyFile));
    }

    #[test]
    fn from_engine_unsupported_format_preserves_label() {
        let c: StegError =
            stegcore_engine::errors::StegError::UnsupportedFormat("heic".into()).into();
        match c {
            StegError::UnsupportedFormat(s) => assert_eq!(s, "heic"),
            other => panic!("expected UnsupportedFormat, got {other:?}"),
        }
    }

    #[test]
    fn from_engine_poor_cover_quality_preserves_score() {
        let c: StegError =
            stegcore_engine::errors::StegError::PoorCoverQuality { score: 0.12 }.into();
        match c {
            StegError::PoorCoverQuality { score } => {
                assert!((score - 0.12).abs() < 1e-9);
            }
            other => panic!("expected PoorCoverQuality, got {other:?}"),
        }
    }

    #[test]
    fn from_engine_file_not_found_preserves_path() {
        let c: StegError =
            stegcore_engine::errors::StegError::FileNotFound("/tmp/x.png".into()).into();
        match c {
            StegError::FileNotFound(s) => assert_eq!(s, "/tmp/x.png"),
            other => panic!("expected FileNotFound, got {other:?}"),
        }
    }

    #[test]
    fn from_engine_empty_payload() {
        let c: StegError = stegcore_engine::errors::StegError::EmptyPayload.into();
        assert!(matches!(c, StegError::EmptyPayload));
    }

    #[test]
    fn from_engine_no_payload_found() {
        let c: StegError = stegcore_engine::errors::StegError::NoPayloadFound.into();
        assert!(matches!(c, StegError::NoPayloadFound));
    }

    #[test]
    fn from_engine_corrupted_file() {
        let c: StegError = stegcore_engine::errors::StegError::CorruptedFile.into();
        assert!(matches!(c, StegError::CorruptedFile));
    }

    #[test]
    fn from_engine_io_preserves_io_error() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let c: StegError = stegcore_engine::errors::StegError::Io(inner).into();
        match c {
            StegError::Io(io) => {
                assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn from_engine_internal_panic_does_not_blame_the_users_file() {
        // Two invariants at once. The first is the one this test always
        // carried: a caught panic never leaks the internal message to the
        // user, so the error shape stays uniform whichever decoder fell over.
        //
        // The second is why the expected variant changed. Mapping this to
        // CorruptedFile told the user their file was damaged when the truth was
        // that our own code crashed, and the file may have been perfectly
        // valid. Everything a user does next from that message (re-download,
        // find another file, give up on the file) is wasted work aimed at the
        // wrong thing.
        let c: StegError =
            stegcore_engine::errors::StegError::Internal("decoder ABCDEF panicked".into()).into();
        assert!(matches!(c, StegError::InternalFailure { .. }), "got {c:?}");
        assert!(!c.to_string().contains("ABCDEF"));
        assert!(!c.to_string().contains("panicked"));
        assert!(
            !c.to_string().to_lowercase().contains("corrupt"),
            "must not call the file corrupt: {c}"
        );
    }

    #[test]
    fn from_engine_caught_panic_carries_the_diagnostic_path_through() {
        let path = std::path::PathBuf::from("/tmp/stegcore-diagnostics/panic-1-2.txt");
        let c: StegError = stegcore_engine::errors::StegError::CaughtPanic {
            detail: "decoder ABCDEF panicked".into(),
            diagnostic: Some(path.clone()),
        }
        .into();
        match &c {
            StegError::InternalFailure { diagnostic } => {
                assert_eq!(diagnostic.as_deref(), Some(path.as_path()))
            }
            other => panic!("expected InternalFailure, got {other:?}"),
        }
        let shown = c.to_string();
        // The user is told plainly that this was us, that their file may be
        // fine, and where the detail went.
        assert!(shown.contains("inside Stegcore"), "{shown}");
        assert!(shown.contains("may well be fine"), "{shown}");
        assert!(shown.contains(&path.display().to_string()), "{shown}");
        assert!(!shown.contains("ABCDEF"), "{shown}");
        assert!(c.suggestion().unwrap().contains("not in your file"));
    }

    #[test]
    fn an_internal_failure_without_a_diagnostic_admits_it() {
        let c = StegError::InternalFailure { diagnostic: None };
        assert!(
            c.to_string().contains("No diagnostic file was written"),
            "{c}"
        );
    }

    // ── Serialize impl ─────────────────────────────────────────────────────

    #[test]
    fn serialize_renders_decryption_failed_as_user_facing_message() {
        let json = serde_json::to_string(&StegError::DecryptionFailed).unwrap();
        // Oracle-resistant: same string as NoPayloadFound.
        assert_eq!(
            json,
            serde_json::to_string(&StegError::NoPayloadFound).unwrap()
        );
    }

    #[test]
    fn serialize_renders_insufficient_capacity_with_numbers() {
        let json = serde_json::to_string(&StegError::InsufficientCapacity {
            required: 1024,
            available: 256,
        })
        .unwrap();
        assert!(json.contains("1024"));
        assert!(json.contains("256"));
    }

    // ── Remaining suggestion match arms ─────────────────────────────────────

    #[test]
    fn suggestion_for_corrupted_file_mentions_truncation() {
        let e = StegError::CorruptedFile;
        assert!(
            e.suggestion().unwrap().to_lowercase().contains("truncat")
                || e.suggestion().unwrap().to_lowercase().contains("damag")
        );
    }

    #[test]
    fn suggestion_for_legacy_key_file_mentions_reembed() {
        let e = StegError::LegacyKeyFile;
        assert!(
            e.suggestion().unwrap().to_lowercase().contains("re-embed")
                || e.suggestion()
                    .unwrap()
                    .to_lowercase()
                    .contains("older version")
        );
    }

    #[test]
    fn suggestion_for_image_error_returns_none() {
        let e = StegError::Image("decode error".into());
        assert!(e.suggestion().is_none());
    }

    #[test]
    fn suggestion_for_json_error_returns_none() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let e = StegError::Json(json_err);
        assert!(e.suggestion().is_none());
    }

    #[test]
    fn suggestion_for_file_not_found_returns_none() {
        let e = StegError::FileNotFound("/tmp/x".into());
        assert!(e.suggestion().is_none());
    }
}
