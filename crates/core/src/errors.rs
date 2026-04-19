// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use serde::Serialize;

#[derive(thiserror::Error, Debug)]
pub enum StegError {
    #[error(
        "Cover file is too small to hold this payload (need {required} bytes, have {available})"
    )]
    InsufficientCapacity { required: usize, available: usize },

    #[error("Wrong passphrase or corrupted stego file")]
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

    /// Same user-facing text as DecryptionFailed — prevents oracle attacks.
    #[error("Wrong passphrase or corrupted stego file")]
    NoPayloadFound,

    #[error("Invalid or corrupted stego file")]
    CorruptedFile,

    #[error("File is too large ({size_mb} MB). Maximum supported size is {max_mb} MB.")]
    FileTooLarge { size_mb: u64, max_mb: u64 },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Image error: {0}")]
    Image(String),

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
        }
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
            StegError::DecryptionFailed | StegError::NoPayloadFound => Some(
                "Double-check your passphrase. If using a key file, ensure it matches the stego file.",
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
            StegError::LegacyKeyFile => Some(
                "This key file was created by an older version. Re-embed with the current version to generate a compatible key file.",
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
}
