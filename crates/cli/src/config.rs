// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

//! CLI configuration file support.
//!
//! Reads `~/.config/stegcore/config.toml` (Linux/macOS) or
//! `%APPDATA%/stegcore/config.toml` (Windows). Values act as defaults
//! that CLI flags override.

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub default_cipher: Option<String>,
    pub default_mode: Option<String>,
    pub default_output_folder: Option<String>,
    pub export_key: Option<bool>,
    pub verbose: Option<bool>,
    pub verses: Option<bool>,
}

impl Config {
    /// Load config from the platform-specific path. Returns defaults if
    /// the file doesn't exist or can't be parsed.
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        toml::from_str(&content).unwrap_or_default()
    }
}

fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("stegcore").join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_all_none() {
        let cfg = Config::default();
        assert!(cfg.default_cipher.is_none());
        assert!(cfg.default_mode.is_none());
        assert!(cfg.default_output_folder.is_none());
        assert!(cfg.export_key.is_none());
        assert!(cfg.verbose.is_none());
        assert!(cfg.verses.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
            default_cipher = "aes-256-gcm"
            default_mode = "sequential"
            export_key = true
            verbose = false
            verses = true
        "#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.default_cipher.as_deref(), Some("aes-256-gcm"));
        assert_eq!(cfg.default_mode.as_deref(), Some("sequential"));
        assert_eq!(cfg.export_key, Some(true));
        assert_eq!(cfg.verbose, Some(false));
        assert_eq!(cfg.verses, Some(true));
    }

    #[test]
    fn parse_partial_config() {
        let toml = "default_cipher = \"ascon-128\"\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.default_cipher.as_deref(), Some("ascon-128"));
        assert!(cfg.default_mode.is_none());
    }

    #[test]
    fn parse_empty_config() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.default_cipher.is_none());
    }

    #[test]
    fn parse_unknown_keys_ignored() {
        let toml = "unknown_key = \"value\"\ndefault_cipher = \"chacha20-poly1305\"\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.default_cipher.as_deref(), Some("chacha20-poly1305"));
    }

    #[test]
    fn load_returns_defaults_when_no_file() {
        // Config::load() should not panic even if the file doesn't exist
        let cfg = Config::load();
        // Just verify it returns something — the file may or may not exist on the test machine
        let _ = cfg.default_cipher;
    }
}
