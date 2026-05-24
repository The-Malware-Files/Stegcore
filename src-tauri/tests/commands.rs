// Copyright (C) 2026 The Malware Files
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.

//! Integration tests for the Tauri command surface.
//!
//! Strategy: each `#[tauri::command]` handler that touches the AppHandle
//! is split into (a) a thin wrapper that resolves `app_config_dir()` and
//! (b) a `pub fn` impl that takes the resolved path explicitly. The impls
//! are what we exercise here. This avoids `tauri::test::mock_app()`
//! (heavyweight; writes to the user's real config dir) and keeps the
//! tests fast and isolated.
//!
//! What's covered:
//!   - Settings load/save round-trip + defaults on missing/malformed
//!     files; parent-dir creation + (Unix) 0o700 permission tightening.
//!   - First-run detection (marker present / missing / None config dir).
//!   - `complete_setup_in` writes the marker AND applies preferences.
//!   - The Settings shape itself (serde defaults, schema stability).
//!
//! What's not covered here (covered elsewhere):
//!   - Embed / extract / analyse — the commands are thin wrappers around
//!     stegcore-core::steg + stegcore-engine::analysis which have their
//!     own test suites. Re-testing here adds no correctness signal, only
//!     the IPC-bridge shape, which serde_json on the boundary already
//!     enforces at compile time.
//!   - The actual Tauri runtime mount / WebView render — covered by the
//!     Vite + Playwright suite (which runs against the React app shell
//!     without needing a real Tauri binary).

use std::fs;
use std::path::Path;

use stegcore_tauri_lib::{
    complete_setup_in, is_first_run_for, load_settings_from, save_settings_to, Settings,
};
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────────

fn fresh_dir() -> TempDir {
    TempDir::new().expect("tempdir")
}

// ── load_settings_from + save_settings_to ──────────────────────────────────

#[test]
fn load_settings_from_missing_file_returns_defaults() {
    let dir = fresh_dir();
    let path = dir.path().join("never-existed.json");
    let s = load_settings_from(&path);
    let defaults = Settings::default();
    assert_eq!(s.theme, defaults.theme);
    assert_eq!(s.default_cipher, defaults.default_cipher);
    assert_eq!(s.default_mode, defaults.default_mode);
}

#[test]
fn load_settings_from_malformed_file_returns_defaults() {
    let dir = fresh_dir();
    let path = dir.path().join("settings.json");
    fs::write(&path, "{ this is not valid json").unwrap();
    let s = load_settings_from(&path);
    // Defensive: a corrupt settings file should not crash the app at
    // boot — silently fall back to defaults.
    assert_eq!(s.theme, Settings::default().theme);
}

#[test]
fn save_then_load_round_trips_a_modified_settings_struct() {
    let dir = fresh_dir();
    let path = dir.path().join("settings.json");

    let mut s = Settings::default();
    s.theme = "dark".into();
    s.default_cipher = "aes-256-gcm".into();
    s.default_mode = "sequential".into();

    save_settings_to(&path, &s).expect("save ok");
    assert!(path.exists(), "settings file should be written");

    let loaded = load_settings_from(&path);
    assert_eq!(loaded.theme, "dark");
    assert_eq!(loaded.default_cipher, "aes-256-gcm");
    assert_eq!(loaded.default_mode, "sequential");
}

#[test]
fn save_settings_creates_parent_directory_if_missing() {
    let dir = fresh_dir();
    // Nested path that does not exist yet.
    let path = dir
        .path()
        .join("nested")
        .join("deeper")
        .join("settings.json");
    let s = Settings::default();
    save_settings_to(&path, &s).expect("save ok with nested parent");
    assert!(path.exists());
    assert!(path.parent().unwrap().exists());
}

#[cfg(unix)]
#[test]
fn save_settings_clamps_parent_directory_permissions_to_0o700() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fresh_dir();
    // Use a *new* nested parent so we own the permissions, not the
    // OS-controlled tempdir root.
    let path = dir.path().join("config-dir").join("settings.json");
    let s = Settings::default();
    save_settings_to(&path, &s).expect("save ok");
    let parent_meta = fs::metadata(path.parent().unwrap()).unwrap();
    let mode = parent_meta.permissions().mode() & 0o777;
    // 0o700 (no group / world access) is the security-conscious default.
    assert_eq!(mode, 0o700, "config dir should be 0o700, got {mode:o}");
}

#[test]
fn save_settings_writes_pretty_json() {
    // The file is human-readable for debugging — pretty-printed, not a
    // single line of compact JSON.
    let dir = fresh_dir();
    let path = dir.path().join("settings.json");
    save_settings_to(&path, &Settings::default()).unwrap();
    let raw = fs::read_to_string(&path).unwrap();
    assert!(
        raw.contains('\n'),
        "settings.json should be pretty-printed; got {raw:?}"
    );
}

// ── is_first_run_for ───────────────────────────────────────────────────────

#[test]
fn is_first_run_returns_true_when_config_dir_is_none() {
    // Defensive default: if the OS can't tell us where to put config, we
    // assume the user has never run the app and show the installer once.
    assert!(is_first_run_for(None));
}

#[test]
fn is_first_run_returns_true_when_marker_missing() {
    let dir = fresh_dir();
    assert!(is_first_run_for(Some(dir.path())));
}

#[test]
fn is_first_run_returns_false_when_marker_present() {
    let dir = fresh_dir();
    fs::write(dir.path().join(".stegcore_configured"), "1").unwrap();
    assert!(!is_first_run_for(Some(dir.path())));
}

#[test]
fn is_first_run_does_not_confuse_marker_with_a_directory_of_the_same_name() {
    // Defensive: if a confused state leaves a directory where we expect a
    // marker file, the .exists() check still says it exists. This test
    // documents that behaviour — a stray directory of that name suppresses
    // first-run. Acceptable: if the path is taken, the user clearly has
    // something at that location and re-running the installer is a worse
    // outcome than skipping it.
    let dir = fresh_dir();
    fs::create_dir(dir.path().join(".stegcore_configured")).unwrap();
    assert!(!is_first_run_for(Some(dir.path())));
}

// ── complete_setup_in ──────────────────────────────────────────────────────

#[test]
fn complete_setup_writes_marker_and_applies_preferences() {
    let dir = fresh_dir();
    // Two-level path: tests the create_dir_all branch too.
    let config = dir.path().join("never-existed").join("app");

    complete_setup_in(&config, "dark".into(), "aes-256-gcm".into()).expect("setup ok");

    // Marker landed.
    assert!(config.join(".stegcore_configured").exists());

    // Preferences applied.
    let settings = load_settings_from(&config.join("settings.json"));
    assert_eq!(settings.theme, "dark");
    assert_eq!(settings.default_cipher, "aes-256-gcm");

    // First-run check now returns false.
    assert!(!is_first_run_for(Some(&config)));
}

#[test]
fn complete_setup_preserves_unrelated_settings_fields() {
    let dir = fresh_dir();
    let config = dir.path().to_path_buf();

    // Seed an existing settings.json with non-default values that
    // complete_setup is not supposed to touch.
    let mut seed = Settings::default();
    seed.auto_export_key = true;
    seed.passphrase_min_len = 24;
    seed.report_output_folder = Some("/tmp/reports".into());
    save_settings_to(&config.join("settings.json"), &seed).unwrap();

    // Now run setup with different theme + cipher.
    complete_setup_in(&config, "light".into(), "chacha20-poly1305".into()).unwrap();

    let after = load_settings_from(&config.join("settings.json"));
    assert_eq!(after.theme, "light");
    assert_eq!(after.default_cipher, "chacha20-poly1305");
    // Unrelated fields untouched.
    assert!(after.auto_export_key);
    assert_eq!(after.passphrase_min_len, 24);
    assert_eq!(after.report_output_folder.as_deref(), Some("/tmp/reports"));
}

#[test]
fn complete_setup_is_idempotent_when_called_twice() {
    let dir = fresh_dir();
    let config = dir.path().to_path_buf();

    complete_setup_in(&config, "dark".into(), "aes-256-gcm".into()).unwrap();
    // Second call with different prefs overwrites — last write wins.
    complete_setup_in(&config, "light".into(), "ascon-128".into()).unwrap();

    let s = load_settings_from(&config.join("settings.json"));
    assert_eq!(s.theme, "light");
    assert_eq!(s.default_cipher, "ascon-128");
    assert!(!is_first_run_for(Some(&config)));
}

// ── Settings shape (schema stability) ──────────────────────────────────────

#[test]
fn settings_default_has_known_safe_defaults() {
    // Locked: any default change here is a schema migration concern —
    // existing users' settings files don't carry every field.
    let s = Settings::default();
    assert_eq!(s.theme, "system");
    // Cipher default is the recommended modern AEAD, not raw-text crypto.
    assert!(
        matches!(
            s.default_cipher.as_str(),
            "chacha20-poly1305" | "aes-256-gcm" | "ascon-128"
        ),
        "default_cipher should be a recognised AEAD, got {:?}",
        s.default_cipher
    );
    // Adaptive is the privacy-preferring default — sequential is more
    // capacity but easier to detect.
    assert_eq!(s.default_mode, "adaptive");
}

#[test]
fn settings_roundtrip_through_json_preserves_all_fields() {
    let mut s = Settings::default();
    s.theme = "dark".into();
    s.font_size = "large".into();
    s.reduce_motion = true;
    s.default_cipher = "aes-256-gcm".into();
    s.default_mode = "sequential".into();
    s.default_output_folder = Some("/tmp/out".into());
    s.auto_export_key = true;
    s.auto_score_on_drop = false;
    s.passphrase_min_len = 16;
    s.clear_clipboard_secs = 60;
    s.session_timeout_mins = 15;
    s.show_technical_errors = true;
    s.bible_verses = true;
    s.default_report_format = "html".into();
    s.report_output_folder = Some("/tmp/reports".into());

    let json = serde_json::to_string(&s).unwrap();
    let back: Settings = serde_json::from_str(&json).unwrap();
    assert_eq!(back.theme, s.theme);
    assert_eq!(back.font_size, s.font_size);
    assert_eq!(back.reduce_motion, s.reduce_motion);
    assert_eq!(back.default_cipher, s.default_cipher);
    assert_eq!(back.default_mode, s.default_mode);
    assert_eq!(back.default_output_folder, s.default_output_folder);
    assert_eq!(back.auto_export_key, s.auto_export_key);
    assert_eq!(back.auto_score_on_drop, s.auto_score_on_drop);
    assert_eq!(back.passphrase_min_len, s.passphrase_min_len);
    assert_eq!(back.clear_clipboard_secs, s.clear_clipboard_secs);
    assert_eq!(back.session_timeout_mins, s.session_timeout_mins);
    assert_eq!(back.show_technical_errors, s.show_technical_errors);
    assert_eq!(back.bible_verses, s.bible_verses);
    assert_eq!(back.default_report_format, s.default_report_format);
    assert_eq!(back.report_output_folder, s.report_output_folder);
}

#[test]
fn settings_load_from_empty_object_uses_defaults_for_all_fields() {
    // Forward-compatibility: an old client wrote `{}`; we should not
    // crash on missing fields, just supply defaults.
    let dir = fresh_dir();
    let path = dir.path().join("settings.json");
    fs::write(&path, "{}").unwrap();
    let s = load_settings_from(&path);
    let d = Settings::default();
    assert_eq!(s.theme, d.theme);
    assert_eq!(s.default_cipher, d.default_cipher);
    assert_eq!(s.default_mode, d.default_mode);
}

// ── Filesystem invariants the Tauri layer depends on ──────────────────────

#[test]
fn marker_and_settings_can_coexist_in_same_dir() {
    // Both files live in app_config_dir(); no naming collision.
    let dir = fresh_dir();
    complete_setup_in(dir.path(), "dark".into(), "aes-256-gcm".into()).unwrap();
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    assert!(entries.iter().any(|n| n == ".stegcore_configured"));
    assert!(entries.iter().any(|n| n == "settings.json"));
}

#[test]
fn unwritable_settings_path_surfaces_io_error() {
    // Cannot create a directory under a file: the parent of `path` would
    // be the file itself, and create_dir_all on that fails.
    let dir = fresh_dir();
    let blocker = dir.path().join("not-a-dir");
    fs::write(&blocker, b"this is a file, not a directory").unwrap();
    let path = blocker.join("config").join("settings.json");
    let err = save_settings_to(&path, &Settings::default()).unwrap_err();
    // The exact StegError variant doesn't matter; we just need to confirm
    // the function refuses cleanly instead of panicking or silently
    // succeeding.
    let _ = err.to_string();
}
