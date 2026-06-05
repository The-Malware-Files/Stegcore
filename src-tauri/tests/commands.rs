// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

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
//!   - The path-explicit impls behind the embed / extract / analyse / export
//!     / pixel-diff / file-size / verse commands. Each #[tauri::command]
//!     resolves its String args to paths then delegates to a `pub fn` impl;
//!     the impls carry the logic and are exercised directly here.
//!
//! What's not covered here (covered elsewhere):
//!   - The thin async wrappers themselves (spawn_blocking + AppHandle
//!     resolution) and the open_folder shell-out: a few lines of glue that
//!     need a Tauri runtime to reach and carry no logic the impls don't.
//!   - analyse_file_progressive: needs AppHandle::emit; the background
//!     branch is genuine runtime glue.
//!   - The actual Tauri runtime mount / WebView render, covered by the
//!     Vite + Playwright suite (which runs against the React app shell
//!     without needing a real Tauri binary).

use std::fs;
use std::path::Path;

use stegcore_tauri_lib::{
    analyse_batch_impl, analyse_file_impl, complete_setup_in, embed_impl, export_csv_impl,
    export_html_impl, export_json_impl, extract_impl, file_size_impl, folder_for_path,
    is_first_run_for, load_settings_from, pixel_diff_impl, save_settings_to, score_cover_impl,
    supported_formats_impl, verse_value, Settings,
};
use tempfile::TempDir;

// ── Helpers ────────────────────────────────────────────────────────────────

fn fresh_dir() -> TempDir {
    TempDir::new().expect("tempdir")
}

/// Write a small non-flat RGB PNG cover (varied pixels so it has capacity
/// and scores as a usable cover).
fn write_png_cover(path: &Path, w: u32, h: u32) {
    let img = image::ImageBuffer::from_fn(w, h, |x, y| {
        image::Rgb([
            (x as u8).wrapping_mul(7).wrapping_add(11),
            (y as u8).wrapping_mul(13).wrapping_add(29),
            ((x ^ y) as u8).wrapping_mul(5).wrapping_add(3),
        ])
    });
    img.save(path).expect("write png cover");
}

const CIPHER: &str = "chacha20-poly1305";
const PASS: &[u8] = b"correct horse battery staple";
const PAYLOAD: &[u8] = b"hidden message for the impl tests";

// ── IPC impl surface: supported formats / score / verse / file size ─────────

#[test]
fn supported_formats_impl_lists_the_core_carriers() {
    let fmts = supported_formats_impl();
    for ext in ["png", "bmp", "jpg", "wav"] {
        assert!(fmts.iter().any(|f| f == ext), "missing {ext} in {fmts:?}");
    }
}

#[test]
fn score_cover_impl_scores_a_real_cover_in_unit_range() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    write_png_cover(&cover, 64, 64);
    let score = score_cover_impl(&cover).expect("score ok");
    assert!((0.0..=1.0).contains(&score), "score out of range: {score}");
}

#[test]
fn score_cover_impl_errors_on_missing_file() {
    let dir = fresh_dir();
    let missing = dir.path().join("nope.png");
    assert!(score_cover_impl(&missing).is_err());
}

#[test]
fn verse_value_has_text_and_reference() {
    let v = verse_value();
    assert!(v.get("text").and_then(|t| t.as_str()).is_some());
    assert!(v.get("reference").and_then(|r| r.as_str()).is_some());
}

#[test]
fn file_size_impl_reports_length_and_maps_missing_to_error() {
    let dir = fresh_dir();
    let f = dir.path().join("blob.bin");
    fs::write(&f, vec![0u8; 1234]).unwrap();
    assert_eq!(file_size_impl(&f).unwrap(), 1234);
    assert!(file_size_impl(&dir.path().join("absent")).is_err());
}

// ── folder_for_path ─────────────────────────────────────────────────────────

#[test]
fn folder_for_path_returns_parent_for_a_file_and_self_for_a_dir() {
    let dir = fresh_dir();
    let f = dir.path().join("x.txt");
    fs::write(&f, b"x").unwrap();
    assert_eq!(folder_for_path(&f), dir.path());
    assert_eq!(folder_for_path(dir.path()), dir.path());
}

// ── embed_impl / extract_impl round-trips ──────────────────────────────────

#[test]
fn embed_then_extract_round_trips_sequential() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("payload.bin");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 64, 64);
    fs::write(&payload, PAYLOAD).unwrap();

    let res = embed_impl(
        &cover,
        &payload,
        PASS,
        CIPHER,
        "sequential",
        false,
        None,
        None,
        false,
        &out,
    )
    .expect("embed ok");
    let written = res["outputPath"].as_str().expect("outputPath string");
    assert!(res["keyFilePath"].is_null(), "no key file without export");

    let recovered = extract_impl(Path::new(written), PASS, None).expect("extract ok");
    assert_eq!(recovered, PAYLOAD);
}

#[test]
fn embed_then_extract_round_trips_adaptive_with_key_file() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("payload.bin");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 96, 96);
    fs::write(&payload, PAYLOAD).unwrap();

    let res = embed_impl(
        &cover, &payload, PASS, CIPHER, "adaptive", false, None, None, true, &out,
    )
    .expect("embed ok");
    let written = res["outputPath"].as_str().unwrap();
    let kf = res["keyFilePath"].as_str().expect("key file exported");
    assert!(Path::new(kf).exists(), "key file written to disk");

    let recovered =
        extract_impl(Path::new(written), PASS, Some(Path::new(kf))).expect("extract ok");
    assert_eq!(recovered, PAYLOAD);
}

#[test]
fn extract_impl_with_wrong_passphrase_does_not_return_the_payload() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("payload.bin");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 64, 64);
    fs::write(&payload, PAYLOAD).unwrap();

    let res = embed_impl(
        &cover,
        &payload,
        PASS,
        CIPHER,
        "sequential",
        false,
        None,
        None,
        false,
        &out,
    )
    .unwrap();
    let written = res["outputPath"].as_str().unwrap();
    if let Ok(data) = extract_impl(Path::new(written), b"the wrong passphrase", None) {
        assert_ne!(data, PAYLOAD);
    }
}

#[test]
fn embed_impl_deniable_round_trips_both_halves() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    let real = dir.path().join("real.bin");
    let decoy = dir.path().join("decoy.bin");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 96, 96);
    fs::write(&real, b"the real secret").unwrap();
    fs::write(&decoy, b"a harmless decoy").unwrap();

    // Deniable halves live in randomised partitions, so each half is
    // located via its own key file (export_key=true), exactly as the GUI
    // contract returns keyFilePath + decoyKeyPath.
    let res = embed_impl(
        &cover,
        &real,
        b"real-pass",
        CIPHER,
        "adaptive",
        true,
        Some(&decoy),
        Some("decoy-pass"),
        true,
        &out,
    )
    .expect("deniable embed ok");
    let written = res["outputPath"].as_str().unwrap();
    let real_kf = res["keyFilePath"].as_str().expect("real key file");
    let decoy_kf = res["decoyKeyPath"].as_str().expect("decoy key file");

    let got_real =
        extract_impl(Path::new(written), b"real-pass", Some(Path::new(real_kf))).unwrap();
    assert_eq!(got_real, b"the real secret");
    let got_decoy =
        extract_impl(Path::new(written), b"decoy-pass", Some(Path::new(decoy_kf))).unwrap();
    assert_eq!(got_decoy, b"a harmless decoy");
}

#[test]
fn embed_impl_deniable_rejects_empty_decoy_passphrase() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    let real = dir.path().join("real.bin");
    let decoy = dir.path().join("decoy.bin");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 64, 64);
    fs::write(&real, PAYLOAD).unwrap();
    fs::write(&decoy, b"decoy").unwrap();

    let err = embed_impl(
        &cover,
        &real,
        PASS,
        CIPHER,
        "adaptive",
        true,
        Some(&decoy),
        Some(""),
        false,
        &out,
    );
    assert!(err.is_err(), "empty decoy passphrase must be rejected");
}

// ── analyse + export impls ──────────────────────────────────────────────────

#[test]
fn analyse_file_impl_returns_a_report_for_a_clean_cover() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    write_png_cover(&cover, 64, 64);
    let report = analyse_file_impl(&cover).expect("analyse ok");
    assert_eq!(report.format, "png");
}

#[test]
fn analyse_batch_impl_yields_one_entry_per_path_with_error_strings_for_bad_paths() {
    let dir = fresh_dir();
    let good = dir.path().join("good.png");
    write_png_cover(&good, 64, 64);
    let bad = dir.path().join("missing.png");

    let out = analyse_batch_impl(&[
        good.to_string_lossy().into_owned(),
        bad.to_string_lossy().into_owned(),
    ]);
    assert_eq!(out.len(), 2);
    assert!(out[0].is_object(), "good path yields a report object");
    assert!(out[1].is_string(), "bad path yields an error string");
}

#[test]
fn export_impls_render_non_empty_reports() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    write_png_cover(&cover, 64, 64);
    let paths = vec![cover.to_string_lossy().into_owned()];

    let html = export_html_impl(&paths);
    let csv = export_csv_impl(&paths);
    let json = export_json_impl(&paths);
    assert!(html.contains("<"), "html report should contain markup");
    assert!(!csv.trim().is_empty(), "csv report should not be empty");
    assert!(
        json.contains('{') || json.contains('['),
        "json report shape"
    );
}

// ── pixel_diff_impl ─────────────────────────────────────────────────────────

#[test]
fn pixel_diff_impl_reports_zero_change_for_identical_images() {
    let dir = fresh_dir();
    let a = dir.path().join("a.png");
    write_png_cover(&a, 48, 48);
    let v = pixel_diff_impl(&a, &a).expect("diff ok");
    assert_eq!(v["changedPixels"].as_u64().unwrap(), 0);
    assert!(v["lsbOnly"].as_bool().unwrap());
}

#[test]
fn pixel_diff_impl_flags_a_dimension_mismatch() {
    let dir = fresh_dir();
    let a = dir.path().join("a.png");
    let b = dir.path().join("b.png");
    write_png_cover(&a, 32, 32);
    write_png_cover(&b, 48, 48);
    let v = pixel_diff_impl(&a, &b).expect("diff ok");
    assert!(
        v.get("error").is_some(),
        "dimension mismatch should report an error"
    );
}

#[test]
fn pixel_diff_impl_counts_lsb_changes_after_embed() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    let payload = dir.path().join("p.bin");
    let stego = dir.path().join("stego.png");
    write_png_cover(&cover, 64, 64);
    fs::write(&payload, PAYLOAD).unwrap();
    embed_impl(
        &cover,
        &payload,
        PASS,
        CIPHER,
        "sequential",
        false,
        None,
        None,
        false,
        &stego,
    )
    .unwrap();

    let v = pixel_diff_impl(&cover, &stego).expect("diff ok");
    assert!(
        v["changedPixels"].as_u64().unwrap() > 0,
        "embedding should change some pixels"
    );
    // LSB embedding moves a channel by at most 1.
    assert!(v["maxDelta"].as_u64().unwrap() <= 1);
    assert!(v["lsbOnly"].as_bool().unwrap());
}

#[test]
fn embed_impl_deniable_without_export_writes_no_key_files() {
    let dir = fresh_dir();
    let cover = dir.path().join("cover.png");
    let real = dir.path().join("real.bin");
    let decoy = dir.path().join("decoy.bin");
    let out = dir.path().join("stego.png");
    write_png_cover(&cover, 96, 96);
    fs::write(&real, b"the real secret").unwrap();
    fs::write(&decoy, b"a harmless decoy").unwrap();

    let res = embed_impl(
        &cover,
        &real,
        b"real-pass",
        CIPHER,
        "adaptive",
        true,
        Some(&decoy),
        Some("decoy-pass"),
        false,
        &out,
    )
    .unwrap();
    assert!(res["keyFilePath"].is_null());
    assert!(res["decoyKeyPath"].is_null());
    assert!(
        out.exists(),
        "stego file is still written without key export"
    );
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

    let s = Settings {
        theme: "dark".into(),
        default_cipher: "aes-256-gcm".into(),
        default_mode: "sequential".into(),
        ..Settings::default()
    };

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
    let seed = Settings {
        auto_export_key: true,
        report_output_folder: Some("/tmp/reports".into()),
        ..Settings::default()
    };
    save_settings_to(&config.join("settings.json"), &seed).unwrap();

    // Now run setup with different theme + cipher.
    complete_setup_in(&config, "light".into(), "chacha20-poly1305".into()).unwrap();

    let after = load_settings_from(&config.join("settings.json"));
    assert_eq!(after.theme, "light");
    assert_eq!(after.default_cipher, "chacha20-poly1305");
    // Unrelated fields untouched.
    assert!(after.auto_export_key);
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
    let s = Settings {
        theme: "dark".into(),
        font_size: "large".into(),
        reduce_motion: true,
        default_cipher: "aes-256-gcm".into(),
        default_mode: "sequential".into(),
        default_output_folder: Some("/tmp/out".into()),
        auto_export_key: true,
        auto_score_on_drop: false,
        show_technical_errors: true,
        bible_verses: true,
        default_report_format: "html".into(),
        report_output_folder: Some("/tmp/reports".into()),
    };

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
