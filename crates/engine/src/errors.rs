// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StegError {
    #[error(
        "Cover file is too small to hold this payload (need {required} bytes, have {available})"
    )]
    InsufficientCapacity { required: usize, available: usize },

    #[error("Wrong passphrase or corrupted stego file")]
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

    // Identical user-facing message to DecryptionFailed — oracle resistance.
    #[error("Wrong passphrase or corrupted stego file")]
    NoPayloadFound,

    #[error("Invalid or corrupted stego file")]
    CorruptedFile,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Image(#[from] image::ImageError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
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
