// Copyright (C) 2026 Daniel Iwugo
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Stegcore-Commercial
//
// This file is part of Stegcore. Stegcore is free software: you can
// redistribute it and/or modify it under the terms of the GNU Affero
// General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// Commercial licensing: daniel@themalwarefiles.com

//! Path-explicit logic behind the Tauri command surface.
//!
//! Every `#[tauri::command]` wrapper (in `runtime.rs`) resolves its String
//! args to paths, or the AppHandle's config dir, then delegates to one of the
//! `*_impl` functions here. The impls take plain paths/args and carry all the
//! correctness story, so they are unit-tested directly in `tests/commands.rs`
//! without standing up a Tauri runtime. The runtime glue stays in `runtime.rs`,
//! which is the one file excluded from the coverage gate (CLAUDE.md A7).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use stegcore_core::{analysis, errors::StegError, steg, utils, verses};

mod runtime;
pub use runtime::run;

// ── Settings ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_font_size")]
    pub font_size: String,
    #[serde(default)]
    pub reduce_motion: bool,
    #[serde(default = "default_cipher")]
    pub default_cipher: String,
    #[serde(default = "default_mode")]
    pub default_mode: String,
    #[serde(default)]
    pub default_output_folder: Option<String>,
    #[serde(default)]
    pub auto_export_key: bool,
    #[serde(default = "default_true")]
    pub auto_score_on_drop: bool,
    #[serde(default)]
    pub show_technical_errors: bool,
    #[serde(default)]
    pub bible_verses: bool,
    #[serde(default = "default_report_format")]
    pub default_report_format: String,
    #[serde(default)]
    pub report_output_folder: Option<String>,
}

fn default_theme() -> String {
    "system".into()
}
fn default_font_size() -> String {
    "default".into()
}
fn default_cipher() -> String {
    "chacha20-poly1305".into()
}
fn default_mode() -> String {
    "adaptive".into()
}
fn default_true() -> bool {
    true
}
fn default_report_format() -> String {
    "pdf".into()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: default_theme(),
            font_size: default_font_size(),
            reduce_motion: false,
            default_cipher: default_cipher(),
            default_mode: default_mode(),
            default_output_folder: None,
            auto_export_key: false,
            auto_score_on_drop: true,
            show_technical_errors: false,
            bible_verses: false,
            default_report_format: default_report_format(),
            report_output_folder: None,
        }
    }
}

/// Read settings.json from `path`. Returns defaults if the file is missing,
/// unreadable, or malformed.
pub fn load_settings_from(path: &Path) -> Settings {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Write settings to `path`. Creates the parent directory if missing and
/// clamps its permissions to 0o700 on Unix.
pub fn save_settings_to(path: &Path, s: &Settings) -> Result<(), StegError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StegError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let json = serde_json::to_string_pretty(s).map_err(StegError::Json)?;
    std::fs::write(path, json).map_err(StegError::Io)
}

/// True when no `.stegcore_configured` marker exists in `config_dir`.
/// Returns true when `config_dir` is None (defensive: better to show the
/// installer once than to silently miss first-run).
pub fn is_first_run_for(config_dir: Option<&Path>) -> bool {
    let Some(d) = config_dir else { return true };
    !d.join(".stegcore_configured").exists()
}

/// Write the first-run marker + apply initial preferences to `config_dir`.
pub fn complete_setup_in(
    config_dir: &Path,
    theme: String,
    default_cipher: String,
) -> Result<(), StegError> {
    std::fs::create_dir_all(config_dir).map_err(StegError::Io)?;
    let marker = config_dir.join(".stegcore_configured");
    std::fs::write(&marker, "1").map_err(StegError::Io)?;
    let settings_path = config_dir.join("settings.json");
    let mut settings = load_settings_from(&settings_path);
    settings.theme = theme;
    settings.default_cipher = default_cipher;
    save_settings_to(&settings_path, &settings)
}

// ── Cover/payload size caps ─────────────────────────────────────────────────

const MAX_COVER_BYTES: u64 = 2_000_000_000; // 2 GB
#[allow(dead_code)]
const MAX_PAYLOAD_BYTES: u64 = 500_000_000; // 500 MB, used in embed validation

// ── Path-explicit command impls (testable without a Tauri runtime) ───────────

/// The file extensions Stegcore can operate on.
pub fn supported_formats_impl() -> Vec<String> {
    utils::supported_extensions()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Validate the cover against the size cap, then score its suitability.
pub fn score_cover_impl(path: &Path) -> Result<f64, StegError> {
    utils::validate_file(path, MAX_COVER_BYTES)?;
    steg::assess(path)
}

/// Embed a payload into a cover. Handles the deniable dual-payload branch
/// and the normal adaptive/sequential branch. Returns the JSON the GUI
/// expects: the path actually written (a JPEG cover forces a .jpg name) and
/// any exported key-file paths.
#[allow(clippy::too_many_arguments)]
pub fn embed_impl(
    cover: &Path,
    payload: &Path,
    passphrase: &[u8],
    cipher: &str,
    mode: &str,
    deniable: bool,
    decoy_payload: Option<&Path>,
    decoy_passphrase: Option<&str>,
    export_key: bool,
    output: &Path,
) -> Result<serde_json::Value, StegError> {
    let payload_bytes = std::fs::read(payload).map_err(StegError::Io)?;
    let output_str = output.to_string_lossy().to_string();

    if deniable {
        let decoy_path = decoy_payload.ok_or(StegError::EmptyPayload)?;
        let decoy_pass_str = decoy_passphrase.unwrap_or("");
        if decoy_pass_str.is_empty() {
            return Err(StegError::EmptyPayload);
        }
        let decoy_pass = decoy_pass_str.as_bytes().to_vec();
        let decoy_bytes = std::fs::read(decoy_path).map_err(StegError::Io)?;

        let (real_kf, decoy_kf) = steg::embed_deniable(
            cover,
            &payload_bytes,
            &decoy_bytes,
            passphrase,
            &decoy_pass,
            cipher,
            output,
        )?;

        // Only write key files if the user explicitly requested export.
        let (real_kf_path, decoy_kf_path) = if export_key {
            let rkp = format!("{output_str}.real.json");
            let dkp = format!("{output_str}.decoy.json");
            stegcore_core::keyfile::write_key_file(Path::new(&rkp), &real_kf)?;
            stegcore_core::keyfile::write_key_file(Path::new(&dkp), &decoy_kf)?;
            (Some(rkp), Some(dkp))
        } else {
            (None, None)
        };

        return Ok(serde_json::json!({
            "outputPath":     output_str,
            "keyFilePath":    real_kf_path,
            "decoyKeyPath":   decoy_kf_path,
        }));
    }

    let (written_path, maybe_kf) = if mode == "sequential" {
        steg::embed_sequential(
            cover,
            &payload_bytes,
            passphrase,
            cipher,
            output,
            export_key,
        )?
    } else {
        steg::embed_adaptive(
            cover,
            &payload_bytes,
            passphrase,
            cipher,
            output,
            export_key,
        )?
    };
    // Report the path actually written (a JPEG cover forces a .jpg name).
    let written = written_path.to_string_lossy().to_string();

    let key_file_path = if export_key {
        if let Some(kf) = maybe_kf {
            let p = format!("{written}.json");
            stegcore_core::keyfile::write_key_file(Path::new(&p), &kf)?;
            Some(p)
        } else {
            None
        }
    } else {
        None
    };

    Ok(serde_json::json!({
        "outputPath":  written,
        "keyFilePath": key_file_path,
    }))
}

/// Extract a payload, using a key file when one is supplied.
pub fn extract_impl(
    stego: &Path,
    passphrase: &[u8],
    key_file: Option<&Path>,
) -> Result<Vec<u8>, StegError> {
    if let Some(kf_path) = key_file {
        let kf = stegcore_core::keyfile::read_key_file(kf_path)?;
        steg::extract_with_keyfile(stego, &kf, passphrase)
    } else {
        steg::extract(stego, passphrase)
    }
}

/// Full analysis of a single file.
pub fn analyse_file_impl(path: &Path) -> Result<analysis::AnalysisReport, StegError> {
    analysis::analyse(path)
}

/// Batch analysis. Each result is either the report JSON or the error string,
/// matching the shape the GUI consumes.
pub fn analyse_batch_impl(paths: &[String]) -> Vec<serde_json::Value> {
    let path_refs: Vec<&Path> = paths.iter().map(|s| Path::new(s.as_str())).collect();
    analysis::analyse_batch(&path_refs)
        .into_iter()
        .map(|r| match r {
            Ok(report) => serde_json::to_value(report).unwrap_or(serde_json::Value::Null),
            Err(e) => serde_json::Value::String(e.to_string()),
        })
        .collect()
}

/// Analyse every path and keep only the successful reports (errors dropped).
/// Shared by the HTML / CSV / JSON exporters.
fn collect_reports(paths: &[String]) -> Vec<analysis::AnalysisReport> {
    let path_refs: Vec<&Path> = paths.iter().map(|s| Path::new(s.as_str())).collect();
    analysis::analyse_batch(&path_refs)
        .into_iter()
        .filter_map(|r| r.ok())
        .collect()
}

pub fn export_html_impl(paths: &[String]) -> String {
    analysis::generate_html_report(&collect_reports(paths))
}

pub fn export_csv_impl(paths: &[String]) -> String {
    analysis::generate_csv_report(&collect_reports(paths))
}

pub fn export_json_impl(paths: &[String]) -> String {
    analysis::generate_json_report(&collect_reports(paths))
}

/// Compare two images pixel-by-pixel for the before/after embed view.
/// Returns a JSON `{ error }` on a dimension mismatch rather than failing,
/// so the GUI can show a friendly message.
pub fn pixel_diff_impl(original: &Path, stego: &Path) -> Result<serde_json::Value, StegError> {
    let orig = image::open(original)
        .map_err(|e| StegError::Image(e.to_string()))?
        .to_rgb8();
    let steg_img = image::open(stego)
        .map_err(|e| StegError::Image(e.to_string()))?
        .to_rgb8();

    if orig.dimensions() != steg_img.dimensions() {
        return Ok(serde_json::json!({ "error": "Different dimensions" }));
    }

    let (w, h) = orig.dimensions();
    let total = (w * h) as usize;
    let orig_raw = orig.as_raw();
    let steg_raw = steg_img.as_raw();

    let mut changed = 0usize;
    let mut max_delta: u8 = 0;
    let mut lsb_only = true;

    for p in 0..total {
        let i = p * 3;
        if orig_raw[i] != steg_raw[i]
            || orig_raw[i + 1] != steg_raw[i + 1]
            || orig_raw[i + 2] != steg_raw[i + 2]
        {
            changed += 1;
            for c in 0..3 {
                let d = orig_raw[i + c].abs_diff(steg_raw[i + c]);
                if d > max_delta {
                    max_delta = d;
                }
                if d > 1 {
                    lsb_only = false;
                }
            }
        }
    }

    Ok(serde_json::json!({
        "totalPixels": total,
        "changedPixels": changed,
        "percentChanged": (changed as f64 / total as f64) * 100.0,
        "maxDelta": max_delta,
        "lsbOnly": lsb_only,
    }))
}

/// Resolve the directory to reveal: the parent when given a file, otherwise
/// the path itself. The actual platform open (explorer/open/xdg-open) is the
/// thin, untestable shell-out in the wrapper.
pub fn folder_for_path(path: &Path) -> PathBuf {
    if path.is_file() {
        path.parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| path.to_path_buf())
    } else {
        path.to_path_buf()
    }
}

/// File length in bytes, mapping a missing file to a friendly error.
pub fn file_size_impl(path: &Path) -> Result<u64, StegError> {
    let meta = std::fs::metadata(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StegError::FileNotFound(path.to_string_lossy().into_owned())
        } else {
            StegError::Io(e)
        }
    })?;
    Ok(meta.len())
}

/// The current daily verse, shaped as the GUI footer expects.
pub fn verse_value() -> serde_json::Value {
    let v = verses::current_verse();
    serde_json::json!({ "text": v.text, "reference": v.reference })
}
